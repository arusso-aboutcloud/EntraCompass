/**
 * Cloudflare Pages Function: /ai/ask
 *
 * Optional assistant for EntraCompass. The browser sends a question plus an
 * aggregated, non-identifying summary of the assessment (scores, counts,
 * finding titles). No tenant objects, names, UPNs or IP ranges.
 *
 * Bindings: AI (Workers AI). Variables: ALLOWED_ORIGIN (comma-separated),
 * AI_MODEL (optional).
 */

const MAX_BODY_BYTES = 64 * 1024;
const MAX_INPUT_LENGTH = 2000;
const MAX_HISTORY_MSGS = 10;
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;
const DEFAULT_MODEL = '@cf/meta/llama-4-scout-17b-16e-instruct';

const rate = new Map();
function allowed(ip) {
  const now = Date.now();
  let e = rate.get(ip);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + RATE_WINDOW_MS };
  e.count++;
  rate.set(ip, e);
  if (rate.size > 5000) for (const [k, v] of rate) if (now > v.resetAt) rate.delete(k);
  return e.count <= RATE_LIMIT;
}

function cors(env, origin) {
  const list = String(env?.ALLOWED_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean);
  const h = { 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', Vary: 'Origin' };
  if (origin && list.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

const json = (body, status, headers) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

function sse(text, headers) {
  const enc = new TextEncoder();
  return new Response(new ReadableStream({
    start(c) {
      c.enqueue(enc.encode(`data: ${JSON.stringify({ response: text })}\n\n`));
      c.enqueue(enc.encode('data: [DONE]\n\n'));
      c.close();
    },
  }), { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...headers } });
}

const INJECTION = [
  /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
  /disregard\s+(all|previous|prior|above|any)\s+(instructions?|prompts?|rules?)/i,
  /(reveal|show|print)\s+(me\s+)?(your|the)\s*(system|initial|original)?\s*(prompt|instructions?)/i,
  /you\s+are\s+now\s+(a|an|the)\b/i,
  /jailbreak|DAN\s+mode|do\s+anything\s+now/i,
  /\[INST\]|<\|system\|>/i,
];
const HARMFUL = [
  /how\s+(?:to\s+)?(?:bypass|evade|get\s+around)\s+(?:conditional\s+access|mfa|ca\s+polic)/i,
  /\b(steal|exfiltrat\w*|dump)\s+(?:credential|password|token|secret)s?\b/i,
  /\b(mimikatz|cobalt[\s-]strike|pass[\s-]the[\s-]hash|token\s+theft\s+tool)\b/i,
];

const SYSTEM_PROMPT = `You are the EntraCompass assistant: an expert in Microsoft Entra Conditional Access, \
Microsoft Purview DLP and identity security, speaking to IT leaders and business stakeholders.

EntraCompass is a free, open-source, browser-only, read-only assessment tool (github.com/arusso-aboutcloud/EntraCompass). \
It reviews Conditional Access from a business angle: which business applications are protected, which exceptions \
(exclusions) exist and whether they are justified, named locations, workload identities (apps with secrets or \
certificates), identity-side data protection (session controls, managed devices, authentication contexts, guests, \
token protection, insider risk), AI agents (Microsoft Entra Agent ID identities, blueprints, agent user accounts, \
Conditional Access for agents, agent risk, sponsors, application permissions), Microsoft Purview (sensitivity labels and, \
from an optional export, DLP policies and locations including Microsoft 365 Copilot), crown-jewel applications tagged by \
the customer, a simplified what-if tool and an executive report.

Key positions:
- An app that signs in through Entra (SAML, OIDC, App Proxy) is subject to Conditional Access. Excluding it removes \
control. A dedicated policy the app can meet (for example compliant or hybrid-joined device, or trusted network plus \
MFA) is usually better than an exclusion.
- Exclusions should have an owner, a reason and an expiry. Emergency (break-glass) accounts are the expected exception.
- Purview DLP decides what can be done with data; Conditional Access decides who reaches it, from where and on which \
device. Endpoint DLP needs managed devices; unmanaged devices need session controls.
- AI agents: secure each access pattern separately. On behalf of a user, user policies apply. An agent acting on its own \
(agent identity) is only covered by agent policies, whose only control is block: recommend "block high agent risk" and \
"block all agents except approved ones" (by blueprint or custom security attribute), report-only first. "All users" \
policies do not include agent user accounts. Agents need sponsors and least-privilege permissions; tenant-wide \
application permissions on an agent are its real blast radius.
- Purview: Copilot and agents read what the user or agent can reach; the Microsoft 365 Copilot DLP location stops them \
processing sensitive or labelled content. Labels that require an authentication context need a Conditional Access policy \
for that context. DLP policies in test mode only log.
- Microsoft has changed how policies that target All resources apply when an app asks only for basic sign-in scopes; \
apps relying on exclusions may start prompting. Recommend testing in report-only.

Exception verdicts in the data: gap (real exposure), review (needs an owner), cleanup (unused app), stale (deleted \
object), justified.

Rules: answer from the assessment summary when given; never invent tenant facts; say when data is missing. Use plain \
business language, short paragraphs or bullets, under 250 words. Prefer report-only testing before enforcement. \
Only link to learn.microsoft.com pages you are confident exist. Decline questions unrelated to identity, \
Conditional Access, DLP or this tool, and never explain how to bypass security controls.`;

export async function onRequest({ request, env }) {
  const h = cors(env, request.headers.get('Origin') || '');
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, h);
  if (!h['Access-Control-Allow-Origin']) return json({ error: 'Origin not allowed' }, 403, h);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!allowed(ip)) return json({ error: 'Too many questions in a short time. Please wait a minute and try again.', quota: true }, 429, h);
  if (Number(request.headers.get('Content-Length') || 0) > MAX_BODY_BYTES) return json({ error: 'Request too large.' }, 413, h);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON.' }, 400, h); }
  const { question, results, history } = body || {};
  if (typeof question !== 'string' || !question.trim()) return json({ error: 'A question is required.' }, 400, h);
  if (question.length > MAX_INPUT_LENGTH) return json({ error: 'Question too long (2000 characters max).' }, 400, h);
  const q = question.normalize('NFKC');
  if (INJECTION.some((p) => p.test(q)) || HARMFUL.some((p) => p.test(q))) {
    return json({ error: 'This type of question cannot be processed.' }, 400, h);
  }

  const summary = results && typeof results === 'object' ? JSON.stringify(results).slice(0, 12000) : null;
  const safeHistory = Array.isArray(history)
    ? history.filter((m) => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
      .slice(-MAX_HISTORY_MSGS).map((m) => ({ role: m.role, content: m.content.slice(0, 1500) }))
    : [];

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    ...safeHistory,
    { role: 'user', content: summary ? `Assessment summary (JSON): ${summary}\n\nQuestion: ${question}` : `Question: ${question}` },
  ];

  try {
    if (!env.AI) throw new Error('AI binding not configured');
    const stream = await env.AI.run(env.AI_MODEL || DEFAULT_MODEL, { messages, max_tokens: 700, temperature: 0.3, stream: true });
    return new Response(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...h } });
  } catch (err) {
    const msg = String(err?.message || err).toLowerCase();
    if (/quota|rate|limit|429|too many/.test(msg)) {
      return json({ error: 'The free AI tier has reached its limit for now. Please try again later.', quota: true }, 429, h);
    }
    console.error('AI error', err);
    return sse('The AI assistant is not available right now. The assessment itself does not depend on it: see the Overview and Executive report tabs.', h);
  }
}
