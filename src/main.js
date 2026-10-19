import { PublicClientApplication } from '@azure/msal-browser';
import { GraphClient } from './graph.js';
import { collectTenantData } from './collect.js';
import { analyze, AREAS, plural } from './analyzer.js';
import { evaluate } from './whatif.js';
import { buildReportHtml } from './report.js';
import { fixture as demoData } from './demo-data.js';
import { DOCS, PRIVILEGED_ROLES } from './knowledge.js';
import { esc, fmtDate, toCsv, download, stamp } from './util.js';

// ---------------------------------------------------------------------------
// Configuration and state
// ---------------------------------------------------------------------------
// Privacy contract: everything lives in sessionStorage (cleared when the tab
// closes) or in memory. No localStorage, no cookies, no backend storage.

const SCOPES = ['User.Read', 'Policy.Read.All', 'Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All'];
const KEYS = {
  config: 'entracompass_config',
  raw: 'entracompass_raw',
  crown: 'entracompass_crown',
  demo: 'entracompass_demo',
};
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const state = {
  msal: null,
  raw: null,
  results: null,
  demo: false,
  crown: new Set(),
  tab: 'overview',
  appFilter: 'all',
  appQuery: '',
  appLimit: 150,
  excVerdict: 'all',
  excKind: 'all',
  excQuery: '',
  findingArea: 'all',
  whatIf: null,
  chat: [],
};

const ss = {
  get(k) { try { return JSON.parse(sessionStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } },
  del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } },
};

const $ = (id) => document.getElementById(id);

function show(screen) {
  for (const id of ['landing', 'scanning', 'dashboard']) $(id).classList.toggle('hidden', id !== screen);
  window.scrollTo(0, 0);
}

// ---------------------------------------------------------------------------
// Authentication (MSAL, PKCE, redirect flow)
// ---------------------------------------------------------------------------

function loadConfig() {
  const c = ss.get(KEYS.config);
  return c && GUID.test(c.clientId) && GUID.test(c.tenantId) ? c : null;
}

async function createMsal(cfg) {
  const msal = new PublicClientApplication({
    auth: {
      clientId: cfg.clientId,
      authority: `https://login.microsoftonline.com/${cfg.tenantId}`,
      redirectUri: window.location.origin,
      postLogoutRedirectUri: window.location.origin,
    },
    cache: { cacheLocation: 'sessionStorage' },
  });
  await msal.initialize();
  return msal;
}

// Turns common sign-in errors into something an admin can act on.
function explainAuthError(err) {
  const msg = String(err?.errorMessage || err?.message || err || '');
  const code = (msg.match(/AADSTS\d+/) || [])[0];
  const hints = {
    AADSTS9002326: 'The redirect URI is registered under the "Web" platform. Move it to "Single-page application" in the app registration (Authentication blade).',
    AADSTS50011: `The redirect URI does not match. Add ${window.location.origin} as a Single-page application redirect URI.`,
    AADSTS65001: 'Admin consent has not been granted for the Graph permissions. Open API permissions and select "Grant admin consent".',
    AADSTS700016: 'The application (client) ID was not found in this tenant. Check both IDs.',
    AADSTS90002: 'The tenant ID was not found. Check the Directory (tenant) ID.',
    AADSTS50105: 'Your account is not assigned to this app. Assign it, or turn off "Assignment required" on the enterprise app.',
    AADSTS53003: 'A Conditional Access policy blocked this sign-in. Try from a compliant device or ask your CA administrator.',
  };
  return (code && hints[code]) ? `${code}: ${hints[code]}` : `Sign-in failed. ${msg.slice(0, 300)}`;
}

function showSetupError(text) {
  const el = $('setup-error');
  el.textContent = text;
  el.classList.remove('hidden');
  show('landing');
}

async function signIn(cfg) {
  ss.set(KEYS.config, cfg);
  ss.del(KEYS.demo);
  state.msal = await createMsal(cfg);
  await state.msal.loginRedirect({ scopes: SCOPES, prompt: 'select_account' });
}

async function signOut() {
  const account = state.msal?.getActiveAccount();
  for (const k of Object.values(KEYS)) ss.del(k);
  if (state.msal && account) {
    await state.msal.logoutRedirect({ account });
  } else {
    window.location.replace(window.location.origin);
  }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

async function runScan() {
  show('scanning');
  const status = $('scan-status');
  try {
    const graph = new GraphClient(state.msal, SCOPES);
    const raw = await collectTenantData(graph, (t) => { status.textContent = t; });
    if (!raw.sources.policies?.ok) {
      const reason = raw.sources.policies?.reason;
      throw new Error(reason === 'permission_denied'
        ? 'Conditional Access policies could not be read. The signed-in account needs Conditional Access Administrator, Security Reader or Global Reader, and the app needs Policy.Read.All with admin consent.'
        : `Conditional Access policies could not be read (${reason}).`);
    }
    state.raw = raw;
    if (!ss.set(KEYS.raw, raw)) console.warn('Scan too large for sessionStorage; kept in memory only.');
    openDashboard();
  } catch (err) {
    if (/Re-authentication required/.test(err.message)) return;
    console.error(err);
    showSetupError(err.message);
  }
}

function loadDemo() {
  state.demo = true;
  ss.set(KEYS.demo, true);
  state.raw = demoData;
  if (!ss.get(KEYS.crown)) {
    state.crown = new Set([demoData.servicePrincipals[0].appId]);
    saveCrown();
  }
  openDashboard();
}

// ---------------------------------------------------------------------------
// Crown jewels (tagged by the user; kept in sessionStorage, exportable)
// ---------------------------------------------------------------------------

function saveCrown() {
  ss.set(KEYS.crown, [...state.crown]);
}

function toggleCrown(appId) {
  if (state.crown.has(appId)) state.crown.delete(appId); else state.crown.add(appId);
  saveCrown();
  recompute();
  render();
}

function exportCrown() {
  const apps = state.results.apps.filter((a) => a.crownJewel).map((a) => ({ appId: a.appId, name: a.name }));
  download(`entracompass-crown-jewels-${stamp()}.json`, JSON.stringify({ tenantId: state.results.summary.tenantId, exported: new Date().toISOString(), apps }, null, 2), 'application/json');
}

function importCrown(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      const ids = (Array.isArray(data) ? data : data.apps || []).map((x) => (typeof x === 'string' ? x : x.appId)).filter((x) => GUID.test(x));
      ids.forEach((id) => state.crown.add(id));
      saveCrown();
      recompute();
      render();
      toast(`${plural(ids.length, 'crown jewel')} imported.`);
    } catch {
      toast('That file is not a valid crown-jewel export.');
    }
  };
  reader.readAsText(file);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

const TABS = [
  ['overview', 'Overview'],
  ['apps', 'Applications'],
  ['exceptions', 'Exceptions'],
  ['policies', 'Policies'],
  ['locations', 'Named locations'],
  ['workload', 'Workload identities'],
  ['dlp', 'Data protection'],
  ['whatif', 'What-if'],
  ['report', 'Executive report'],
  ['ai', 'Ask AI'],
];

function recompute() {
  state.results = analyze(state.raw, {
    crownJewels: [...state.crown],
    now: state.demo ? state.raw.scannedAt : undefined,
  });
}

function openDashboard() {
  state.crown = new Set(ss.get(KEYS.crown) || [...state.crown]);
  recompute();
  $('tenant-name').textContent = state.results.summary.tenantName;
  $('demo-chip').classList.toggle('hidden', !state.demo);
  $('rescan-btn').classList.toggle('hidden', state.demo);
  show('dashboard');
  render();
}

function render() {
  $('tabs').innerHTML = TABS.map(([id, label]) =>
    `<button role="tab" class="tab ${state.tab === id ? 'active' : ''}" aria-selected="${state.tab === id}" data-tab="${id}">${label}${tabBadge(id)}</button>`).join('');
  const views = { overview: viewOverview, apps: viewApps, exceptions: viewExceptions, policies: viewPolicies, locations: viewLocations, workload: viewWorkload, dlp: viewDlp, whatif: viewWhatIf, report: viewReport, ai: viewAi };
  $('view').innerHTML = views[state.tab]();
  if (state.tab === 'whatif') runWhatIf();
  if (state.tab === 'ai') renderChat();
}

function tabBadge(id) {
  const r = state.results;
  const n = {
    exceptions: r.summary.exclusions.gap || 0,
    apps: r.summary.apps.unprotected,
  }[id];
  return n ? ` <span class="tab-badge">${n}</span>` : '';
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const sev = (s) => `<span class="sev sev-${s}">${SEV_LABEL[s] || s}</span>`;
const CTRL = { present: ['In place', 'good'], partial: ['Partial', 'warn'], missing: ['Missing', 'danger'], info: ['Info', 'info'] };
const ctrl = (s) => `<span class="pill pill-${CTRL[s]?.[1] || 'info'}">${CTRL[s]?.[0] || s}</span>`;
const VERDICT = { gap: ['Opens a gap', 'danger'], review: ['Review', 'warn'], cleanup: ['Likely removable', 'info'], stale: ['Deleted object', 'muted'], justified: ['Justified', 'good'] };
const verdict = (v) => `<span class="pill pill-${VERDICT[v][1]}">${VERDICT[v][0]}</span>`;
const PROT = { strong: ['Always MFA', 'good'], conditional: ['MFA with conditions', 'warn'], partial: ['Some users', 'warn'], none: ['No MFA policy', 'danger'] };
const prot = (p) => `<span class="pill pill-${PROT[p][1]}">${PROT[p][0]}</span>`;
const yes = (b) => (b ? '<span class="tick" title="Yes">&#10003;</span>' : '<span class="dash" title="No">&ndash;</span>');
const learn = (url) => (url ? `<a href="${esc(url)}" target="_blank" rel="noopener">Learn more</a>` : '');

function findingCard(f) {
  return `<details class="finding sev-border-${f.severity}">
    <summary>${sev(f.severity)} <span class="area-tag">${esc(AREAS[f.area]?.label || f.area)}</span>${f.business ? '<span class="area-tag biz">Business impact</span>' : ''}<span class="finding-title">${esc(f.title)}</span></summary>
    <div class="finding-body">
      ${f.detail ? `<p class="muted">${esc(f.detail)}</p>` : ''}
      ${f.impact ? `<p><b>Why it matters:</b> ${esc(f.impact)}</p>` : ''}
      ${f.fix ? `<p><b>What to do:</b> ${esc(f.fix)}</p>` : ''}
      <p class="small">${learn(f.ref)}</p>
    </div>
  </details>`;
}

function sourceWarnings() {
  const failed = Object.values(state.results.sources || {}).filter((s) => s && s.ok === false);
  if (!failed.length) return '';
  const why = { permission_denied: 'permission denied', not_available: 'not available (licence or preview)', throttled: 'throttled', service_error: 'service error', network_error: 'network error' };
  return `<div class="alert alert-warn"><b>Partial data.</b> These sources could not be read, so related checks are incomplete:
    ${failed.map((f) => `${esc(f.label)} (${why[f.reason] || f.reason})`).join(', ')}.</div>`;
}

function ring(score, tone) {
  const c = 2 * Math.PI * 52;
  const off = c * (1 - score / 100);
  return `<svg viewBox="0 0 120 120" class="ring" role="img" aria-label="Score ${score} out of 100">
    <circle cx="60" cy="60" r="52" class="ring-track"/>
    <circle cx="60" cy="60" r="52" class="ring-val ring-${tone}" stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 60 60)"/>
    <text x="60" y="58" class="ring-num">${score}</text><text x="60" y="78" class="ring-sub">of 100</text></svg>`;
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

function viewOverview() {
  const r = state.results;
  const s = r.summary;
  const sc = r.scores;
  const w = s.workforceOutsideMfa;
  const dlpIn = r.dlp.controls.filter((c) => c.status === 'present').length;
  const tiles = [
    ['Policies enforced', `${s.policyCounts.enabled}`, `${s.policyCounts.reportOnly} report-only, ${s.policyCounts.disabled} off`],
    ['Outside main MFA policy', w.covered ? `${w.approximate ? '≥' : ''}${(w.people || 0).toLocaleString()}` : 'All', w.covered ? (w.percent !== null ? `${w.percent}% of accounts` : 'accounts') : 'no MFA-for-everyone policy'],
    ['Business apps without MFA', `${s.apps.unprotected}`, `of ${s.apps.business} assessed`],
    ['Exceptions opening a gap', `${s.exclusions.gap || 0}`, `of ${s.exclusionTotal} exceptions`],
    ['Apps with secrets', `${r.workload.totals.withSecrets}`, `${r.workload.totals.dormant} dormant`],
    ['DLP controls in place', `${dlpIn}/${r.dlp.controls.length}`, 'identity side'],
  ];
  const areaFilter = state.findingArea;
  const list = r.findings.filter((f) => areaFilter === 'all' || f.area === areaFilter);
  return `
  ${state.demo ? '<div class="alert alert-info">You are viewing a fictional sample tenant (Contoso Ltd). Sign out and connect your own tenant for a real assessment.</div>' : ''}
  ${sourceWarnings()}
  <div class="overview-top">
    <div class="card score-card">
      ${ring(sc.overall, sc.rating.tone)}
      <div>
        <div class="score-label tone-${sc.rating.tone}">${esc(sc.rating.label)}</div>
        <div class="muted small">Scanned ${esc(fmtDate(s.scannedAt, true))}</div>
        <div class="areas">${Object.entries(sc.areas).map(([k, a]) => `
          <button class="area-row ${areaFilter === k ? 'active' : ''}" data-area="${k}">
            <span>${esc(a.label)}</span>
            ${a.score === null ? '<span class="muted small">tag crown jewels</span>' : `<span class="mini-bar"><span class="tone-bg-${a.score >= 85 ? 'good' : a.score >= 65 ? 'warn' : 'danger'}" style="width:${a.score}%"></span></span><b>${a.score}</b>`}
          </button>`).join('')}</div>
      </div>
    </div>
    <div class="tiles">${tiles.map(([l, v, sub]) => `<div class="tile"><div class="tile-v">${esc(v)}</div><div class="tile-l">${esc(l)}</div><div class="tile-s">${esc(sub)}</div></div>`).join('')}</div>
  </div>

  <h2 class="section-title">Answers for management</h2>
  <div class="qa-grid">${r.questions.map((q) => `
    <div class="qa qa-${q.status}"><div class="qa-q">${esc(q.q)}</div><div class="qa-a">${esc(q.a)}</div></div>`).join('')}</div>

  <div class="section-head">
    <h2 class="section-title">Findings ${areaFilter !== 'all' ? `<span class="muted">in ${esc(AREAS[areaFilter].label)}</span> <button class="link-btn" data-area="all">show all</button>` : ''}</h2>
    <button class="btn btn-ghost btn-sm" data-action="export-findings">Export CSV</button>
  </div>
  <div class="findings">${list.map(findingCard).join('') || '<p class="muted">No findings in this area.</p>'}</div>`;
}

function filteredApps() {
  const q = state.appQuery.toLowerCase();
  return state.results.apps.filter((a) => {
    const f = state.appFilter;
    if (f === 'none' && a.protection !== 'none') return false;
    if (f === 'excluded' && !a.excludedBy.length) return false;
    if (f === 'onprem' && !['appProxy', 'saml', 'passwordSso'].includes(a.category)) return false;
    if (f === 'crown' && !a.crownJewel) return false;
    if (f === 'suggested' && !a.suggestedCrownJewel) return false;
    return !q || a.name.toLowerCase().includes(q) || a.appId.includes(q);
  });
}

function viewApps() {
  const apps = filteredApps();
  const all = state.results.apps;
  const filters = [
    ['all', 'All', all.length],
    ['none', 'No MFA policy', all.filter((a) => a.protection === 'none').length],
    ['excluded', 'Excluded', all.filter((a) => a.excludedBy.length).length],
    ['onprem', 'SAML / On-prem', all.filter((a) => ['appProxy', 'saml', 'passwordSso'].includes(a.category)).length],
    ['crown', 'Crown jewels', all.filter((a) => a.crownJewel).length],
    ['suggested', 'Suggested crown jewels', all.filter((a) => a.suggestedCrownJewel).length],
  ];
  const shown = apps.slice(0, state.appLimit);
  return `
  <div class="intro">
    <p><b>Business applications</b> and the protection each one gets from Conditional Access. Mark your <b>crown jewels</b> with the star: the assessment then checks them against a higher bar (always MFA, phishing-resistant, device or session control, no exclusions).</p>
    <p class="muted small">SAML and App Proxy apps sign in through Entra, so Conditional Access applies to them. Excluding them removes control; a dedicated policy is usually the better fix.</p>
  </div>
  <div class="toolbar">
    <div class="pills">${filters.map(([id, l, n]) => `<button class="fpill ${state.appFilter === id ? 'active' : ''}" data-app-filter="${id}">${l} <span>${n}</span></button>`).join('')}</div>
    <div class="toolbar-right">
      <input type="search" class="search" placeholder="Search apps" value="${esc(state.appQuery)}" data-input="appQuery" />
      <button class="btn btn-ghost btn-sm" data-action="export-apps">Export CSV</button>
      <button class="btn btn-ghost btn-sm" data-action="export-crown">Export crown jewels</button>
      <label class="btn btn-ghost btn-sm file-btn">Import crown jewels<input type="file" accept="application/json" data-action="import-crown" hidden /></label>
    </div>
  </div>
  <div class="rows">
    <div class="row-head app-grid"><span></span><span>Application</span><span>Type</span><span>Protection</span><span title="Phishing-resistant MFA">Phish-res.</span><span title="Managed device, app protection or session control">Device / session</span><span>Excluded by</span><span>Last used</span></div>
    ${shown.map((a) => `
    <details class="row">
      <summary class="app-grid">
        <button class="star ${a.crownJewel ? 'on' : ''}" data-crown="${esc(a.appId)}" title="${a.crownJewel ? 'Remove crown jewel' : 'Mark as crown jewel'}" aria-label="Crown jewel">${a.crownJewel ? '&#9733;' : '&#9734;'}</button>
        <span class="app-name">${esc(a.name)}${a.suggestedCrownJewel ? ' <span class="hint-tag">suggested crown jewel</span>' : ''}${a.enabled === false ? ' <span class="hint-tag">disabled</span>' : ''}</span>
        <span class="muted">${esc(a.categoryLabel)}</span>
        <span>${prot(a.protection)}</span>
        <span>${yes(a.phishingResistant)}</span>
        <span>${yes(a.managedDevice || a.sessionControl)}</span>
        <span>${a.excludedBy.length ? `<span class="pill pill-danger">${a.excludedBy.length}</span>` : '<span class="dash">&ndash;</span>'}</span>
        <span class="muted small">${a.lastUsed ? esc(fmtDate(a.lastUsed)) : a.unused === null ? 'n/a' : 'none'}</span>
      </summary>
      <div class="row-body">
        <div class="muted small">App ID ${esc(a.appId)}${a.assignmentRequired ? ' &middot; user assignment required' : ''}</div>
        <h4>Policies that apply</h4>
        ${a.applying.length ? `<ul>${a.applying.map((p) => `<li><b>${esc(p.name)}</b>: ${esc(p.controls)}${p.allUsers ? '' : ' <span class="muted">(some users)</span>'}${p.conditions.length ? ` <span class="muted">when: ${esc(p.conditions.join(', '))}</span>` : ''}</li>`).join('')}</ul>` : '<p class="muted">No enforced policy applies to this app.</p>'}
        ${a.excludedBy.length ? `<h4>Excluded from</h4><ul>${a.excludedBy.map((p) => `<li>${esc(p.name)} <span class="muted">(${esc(p.state === 'enabled' ? 'on' : 'report-only')})</span></li>`).join('')}</ul>` : ''}
        <button class="btn btn-ghost btn-sm" data-whatif-app="${esc(a.appId)}">Test in what-if</button>
      </div>
    </details>`).join('') || '<p class="muted pad">No apps match.</p>'}
  </div>
  ${apps.length > shown.length ? `<div class="center pad"><button class="btn btn-ghost" data-action="more-apps">Show more (${apps.length - shown.length} remaining)</button></div>` : ''}`;
}

function viewExceptions() {
  const r = state.results;
  const q = state.excQuery.toLowerCase();
  const list = r.exclusions.filter((e) =>
    (state.excVerdict === 'all' || e.verdict === state.excVerdict) &&
    (state.excKind === 'all' || e.kind === state.excKind) &&
    (!q || `${e.targetName} ${e.policyName}`.toLowerCase().includes(q)));
  const kinds = [...new Set(r.exclusions.map((e) => e.kind))];
  const counts = r.summary.exclusions;
  return `
  <div class="intro"><p>Every exclusion across active policies, classified. <b>Opens a gap</b>: real exposure. <b>Review</b>: needs an owner and a reason on record. <b>Likely removable</b>: tied to an unused app. <b>Deleted object</b>: safe to remove. <b>Justified</b>: expected (for example emergency accounts), still keep it documented.</p></div>
  <div class="toolbar">
    <div class="pills">
      <button class="fpill ${state.excVerdict === 'all' ? 'active' : ''}" data-exc-verdict="all">All <span>${r.exclusions.length}</span></button>
      ${Object.entries(VERDICT).map(([k, [l]]) => `<button class="fpill ${state.excVerdict === k ? 'active' : ''}" data-exc-verdict="${k}">${l} <span>${counts[k] || 0}</span></button>`).join('')}
    </div>
    <div class="toolbar-right">
      <select data-input="excKind" class="select"><option value="all">All types</option>${kinds.map((k) => `<option ${state.excKind === k ? 'selected' : ''}>${esc(k)}</option>`).join('')}</select>
      <input type="search" class="search" placeholder="Search" value="${esc(state.excQuery)}" data-input="excQuery" />
      <button class="btn btn-ghost btn-sm" data-action="export-exceptions">Export CSV</button>
    </div>
  </div>
  <div class="rows">
    <div class="row-head exc-grid"><span>Verdict</span><span>Type</span><span>Excluded</span><span>Policy</span><span>Policy demands</span></div>
    ${list.map((e) => `
    <details class="row">
      <summary class="exc-grid">
        <span>${verdict(e.verdict)}</span>
        <span class="muted">${esc(e.kind)}</span>
        <span><b>${esc(e.targetName)}</b>${e.size > 1 ? ` <span class="muted">(${e.size.toLocaleString()} members)</span>` : ''}${e.category ? ` <span class="muted small">${esc(e.category)}</span>` : ''}</span>
        <span>${esc(e.policyName)} ${e.policyState !== 'enabled' ? '<span class="hint-tag">report-only</span>' : ''}</span>
        <span class="muted">${esc(e.policyControls)}</span>
      </summary>
      <div class="row-body">
        <p>${esc(e.reason)}</p>
        <p><b>What to do:</b> ${esc(e.fix)}</p>
        ${e.detail ? `<p class="muted small">${esc(e.detail)}</p>` : ''}
        ${e.lastUsed ? `<p class="muted small">Last used ${esc(fmtDate(e.lastUsed))}</p>` : ''}
      </div>
    </details>`).join('') || '<p class="muted pad">No exceptions match.</p>'}
  </div>`;
}

function viewPolicies() {
  const r = state.results;
  return `
  <h2 class="section-title">Modern baseline</h2>
  <div class="baseline">${r.baseline.map((c) => `
    <div class="base-item">${ctrl(c.status)}<div><b>${esc(c.title)}</b><div class="muted small">${esc(c.detail)}${c.policies.length ? ` <span>Policies: ${esc(c.policies.join(', '))}</span>` : ''} ${learn(c.ref)}</div></div></div>`).join('')}</div>
  <div class="section-head"><h2 class="section-title">All policies (${r.policies.length})</h2><button class="btn btn-ghost btn-sm" data-action="export-policies">Export CSV</button></div>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>State</th><th>Policy</th><th>Users</th><th>Target</th><th>Conditions</th><th>Grant</th><th>Session</th><th>Exclusions</th></tr></thead>
    <tbody>${r.policies.map((p) => `<tr>
      <td><span class="pill pill-${p.state === 'enabled' ? 'good' : p.state === 'disabled' ? 'muted' : 'warn'}">${esc(p.stateLabel)}</span></td>
      <td><b>${esc(p.name)}</b>${p.microsoftManaged ? ' <span class="hint-tag">Microsoft-managed</span>' : ''}<div class="muted small">${esc(p.kind)}${p.reportOnlyDays !== null ? ` &middot; report-only for ${p.reportOnlyDays} days` : ''}</div></td>
      <td>${esc(p.users)}</td><td>${esc(p.apps)}</td>
      <td class="muted">${esc(p.conditions.join(', ') || 'Any')}</td>
      <td>${p.block ? '<span class="pill pill-danger">Block</span>' : esc(p.controls)}</td>
      <td class="muted">${esc(p.session || '')}</td>
      <td>${p.exclusions ? `<button class="link-btn" data-exc-policy="${esc(p.name)}">${p.exclusions}</button>` : '0'}</td></tr>`).join('')}</tbody>
  </table></div>`;
}

function viewLocations() {
  const r = state.results;
  if (!r.locations.length) return '<div class="card pad"><p>No named locations are defined.</p></div>';
  return `
  <div class="intro"><p>Named locations decide where policies apply or relax. A trusted location with broad IP ranges quietly extends trust to networks you do not control. <a href="${DOCS.namedLocations}" target="_blank" rel="noopener">How named locations work</a></p></div>
  <div class="cards">${r.locations.map((l) => `
    <div class="card loc-card">
      <div class="loc-head"><b>${esc(l.name)}</b>${l.trusted ? '<span class="pill pill-warn">Trusted</span>' : ''}<span class="pill pill-muted">${l.type === 'ip' ? 'IP ranges' : l.type === 'country' ? 'Countries' : 'Other'}</span></div>
      ${l.type === 'ip' ? `<div class="muted small mono">${l.ranges.slice(0, 8).map(esc).join(', ')}${l.ranges.length > 8 ? `, +${l.ranges.length - 8} more` : ''}</div>` : ''}
      ${l.type === 'country' ? `<div class="muted small">${esc(l.countries.join(', '))}${l.includeUnknown ? ' + unknown' : ''}${l.lookup ? ` &middot; lookup: ${esc(l.lookup)}` : ''}</div>` : ''}
      <div class="small">Used by: ${l.usedBy.length ? l.usedBy.map((u) => `${esc(u.name)} <span class="muted">(${esc(u.how)})</span>`).join(', ') : '<span class="muted">no active policy</span>'}</div>
      ${l.issues.length ? `<ul class="issues">${l.issues.map((i) => `<li>${sev(i.severity)} ${esc(i.text)}</li>`).join('')}</ul>` : '<p class="small tone-good">No issues found.</p>'}
    </div>`).join('')}</div>`;
}

function viewWorkload() {
  const w = state.results.workload;
  const t = w.totals;
  return `
  <div class="intro"><p>Workload identities are apps and services that sign in on their own with a secret or certificate. Conditional Access for workload identities can restrict single-tenant apps by location and risk (needs Workload Identities Premium). Managed identities need no secret and are the preferred option. <a href="${DOCS.workloadCa}" target="_blank" rel="noopener">Learn more</a></p></div>
  <div class="tiles tiles-row">
    ${[['With credentials', w.apps.length], ['Client secrets', t.withSecrets], ['Dormant (valid, unused)', t.dormant], ['Secrets > 1 year', t.longLived], ['Expiring in 30 days', t.expiringSoon], ['Managed identities', w.managedIdentities]]
      .map(([l, v]) => `<div class="tile"><div class="tile-v">${v}</div><div class="tile-l">${l}</div></div>`).join('')}
  </div>
  <h2 class="section-title">Workload identity policies</h2>
  ${w.policies.length ? `<ul class="plain">${w.policies.map((p) => `<li><span class="pill pill-${p.state === 'enabled' ? 'good' : 'muted'}">${esc(p.stateLabel)}</span> <b>${esc(p.name)}</b> <span class="muted">${esc(p.scope)} &middot; ${esc(p.controls)}${p.conditions.length ? ` when ${esc(p.conditions.join(', '))}` : ''}</span></li>`).join('')}</ul>` : '<p class="muted">None.</p>'}
  <div class="section-head"><h2 class="section-title">App registrations with credentials</h2><button class="btn btn-ghost btn-sm" data-action="export-workload">Export CSV</button></div>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>App</th><th>Secrets</th><th>Certificates</th><th>Expired</th><th>Expiring</th><th>Long-lived</th><th>Audience</th><th>Last used</th></tr></thead>
    <tbody>${w.apps.slice(0, 500).map((a) => `<tr>
      <td><b>${esc(a.name)}</b>${a.dormant ? ' <span class="pill pill-danger">dormant</span>' : ''}</td>
      <td>${a.secrets}</td><td>${a.certificates}</td><td>${a.expired || ''}</td>
      <td>${a.expiringSoon ? `<span class="pill pill-warn">${a.expiringSoon}</span>` : ''}</td>
      <td>${a.longLivedSecrets ? `<span class="pill pill-warn">${a.longLivedSecrets}</span>` : ''}</td>
      <td class="muted">${a.multiTenant ? 'Multi-tenant' : 'This tenant'}</td>
      <td class="muted small">${a.lastUsed ? esc(fmtDate(a.lastUsed)) : 'none'}</td></tr>`).join('')}</tbody>
  </table></div>`;
}

function viewDlp() {
  const d = state.results.dlp;
  return `
  <div class="intro">
    <p><b>Identity side of DLP.</b> Purview DLP decides what can be done with sensitive data. Conditional Access decides <i>who</i> reaches it, <i>from where</i> and <i>on which device</i>. A DLP project needs both: DLP for endpoints only works on onboarded devices, and browser sessions on personal devices need session controls.</p>
    <p class="muted small">${esc(d.note)}</p>
  </div>
  <div class="dlp-list">${d.controls.map((c) => `
    <div class="card dlp-item">
      <div class="dlp-head">${ctrl(c.status)}<b>${esc(c.title)}</b></div>
      <p class="muted">${esc(c.detail)}</p>
      <p><b>Why it matters:</b> ${esc(c.why)} ${learn(c.ref)}</p>
    </div>`).join('')}</div>
  ${d.rmsExcluded.length ? `<div class="alert alert-info"><b>Rights Management Services is excluded</b> in: ${esc(d.rmsExcluded.join(', '))}. This changes who can open encrypted, labelled content. Record it as a DLP decision.</div>` : ''}
  <h2 class="section-title">Checklist for the Purview DLP assessment</h2>
  <ul class="checklist">
    <li>Map each crown-jewel app to the sensitivity labels and DLP policies that protect its data.</li>
    <li>For every label that uses an authentication context, confirm a Conditional Access policy enforces it (see above).</li>
    <li>Endpoint DLP needs onboarded devices: confirm a policy requires compliant devices for desktop sync clients.</li>
    <li>Personal devices: decide between browser-only access (app-enforced restrictions) and Defender for Cloud Apps session policies.</li>
    <li>Guests: confirm MFA and decide whether they may download labelled content.</li>
    <li>If Adaptive Protection is licensed, connect insider risk levels to a Conditional Access policy.</li>
  </ul>
  <p class="small">${learn(DOCS.purviewDlp)}</p>`;
}

// ---------------------------------------------------------------------------
// What-if
// ---------------------------------------------------------------------------

function defaultWhatIf() {
  const apps = state.results.apps;
  return {
    userType: 'member', userId: '', groupIds: [], roleIds: [],
    appId: (apps.find((a) => a.crownJewel) || apps[0] || {}).appId || '',
    locationId: 'untrusted', platform: 'windows', clientApp: 'browser', device: 'unmanaged',
    signInRisk: 'none', userRisk: 'none',
  };
}

function viewWhatIf() {
  const r = state.results;
  if (!state.whatIf) state.whatIf = defaultWhatIf();
  const w = state.whatIf;
  const opt = (v, l, cur) => `<option value="${esc(v)}" ${v === cur ? 'selected' : ''}>${esc(l)}</option>`;
  const byCat = {};
  for (const a of r.apps) (byCat[a.categoryLabel] ||= []).push(a);
  const roleIds = new Set();
  for (const p of state.raw.policies || []) for (const id of [...(p.conditions?.users?.includeRoles || []), ...(p.conditions?.users?.excludeRoles || [])]) roleIds.add(id);
  const roles = [...roleIds].map((id) => ({ id, name: r.lookups.roles.find((x) => x.id === id)?.name || PRIVILEGED_ROLES[id] || 'Directory role' }));
  return `
  <div class="intro"><p>Test a sign-in before you change anything. Pick who, which app, from where and on what device: EntraCompass shows which policies apply and what the user experiences, today and if report-only policies were switched on.</p>
  <p class="muted small">Simplified engine: device filters, authentication flows and insider risk are listed as "not evaluated". For a specific person, confirm with Microsoft's <a href="${DOCS.whatIf}" target="_blank" rel="noopener">What If tool</a>.</p></div>
  <div class="whatif">
    <form class="card whatif-form" id="whatif-form">
      <label>User type<select name="userType">${opt('member', 'Member (employee)', w.userType)}${opt('guest', 'Guest / external', w.userType)}</select></label>
      <label>Specific user <span class="muted small">(users named in policies)</span><select name="userId">${opt('', 'Any user', w.userId)}${r.lookups.users.map((u) => opt(u.id, `${u.name}${u.upn ? ' (' + u.upn + ')' : ''}`, w.userId)).join('')}</select></label>
      ${r.lookups.groups.length ? `<fieldset><legend>Member of</legend>${r.lookups.groups.map((g) => `<label class="check"><input type="checkbox" name="groupIds" value="${esc(g.id)}" ${w.groupIds.includes(g.id) ? 'checked' : ''}/> ${esc(g.name)}${g.size !== null ? ` <span class="muted">(${g.size})</span>` : ''}</label>`).join('')}</fieldset>` : ''}
      ${roles.length ? `<fieldset><legend>Holds role</legend>${roles.map((x) => `<label class="check"><input type="checkbox" name="roleIds" value="${esc(x.id)}" ${w.roleIds.includes(x.id) ? 'checked' : ''}/> ${esc(x.name)}</label>`).join('')}</fieldset>` : ''}
      <label>Application<select name="appId">${Object.entries(byCat).map(([cat, list]) => `<optgroup label="${esc(cat)}">${list.map((a) => opt(a.appId, (a.crownJewel ? '★ ' : '') + a.name, w.appId)).join('')}</optgroup>`).join('')}</select></label>
      <label>Location<select name="locationId">${opt('untrusted', 'Internet (no named location)', w.locationId)}${r.lookups.locations.map((l) => opt(l.id, `${l.name}${l.trusted ? ' (trusted)' : ''}`, w.locationId)).join('')}</select></label>
      <div class="two">
        <label>Platform<select name="platform">${[['windows', 'Windows'], ['macOS', 'macOS'], ['iOS', 'iOS'], ['android', 'Android'], ['linux', 'Linux']].map(([v, l]) => opt(v, l, w.platform)).join('')}</select></label>
        <label>Device<select name="device">${opt('unmanaged', 'Personal / unmanaged', w.device)}${opt('compliant', 'Compliant (Intune)', w.device)}${opt('hybrid', 'Hybrid-joined', w.device)}</select></label>
      </div>
      <label>Client app<select name="clientApp">${opt('browser', 'Browser', w.clientApp)}${opt('mobileAppsAndDesktopClients', 'Mobile app or desktop client', w.clientApp)}${opt('exchangeActiveSync', 'Exchange ActiveSync (legacy)', w.clientApp)}${opt('other', 'Other legacy client (IMAP, POP, SMTP)', w.clientApp)}</select></label>
      <div class="two">
        <label>Sign-in risk<select name="signInRisk">${['none', 'low', 'medium', 'high'].map((v) => opt(v, v, w.signInRisk)).join('')}</select></label>
        <label>User risk<select name="userRisk">${['none', 'low', 'medium', 'high'].map((v) => opt(v, v, w.userRisk)).join('')}</select></label>
      </div>
    </form>
    <div id="whatif-result" class="whatif-result"></div>
  </div>`;
}

function readWhatIfForm() {
  const f = $('whatif-form');
  if (!f) return;
  const fd = new FormData(f);
  state.whatIf = {
    userType: fd.get('userType'), userId: fd.get('userId'),
    groupIds: fd.getAll('groupIds'), roleIds: fd.getAll('roleIds'),
    appId: fd.get('appId'), locationId: fd.get('locationId'), platform: fd.get('platform'),
    clientApp: fd.get('clientApp'), device: fd.get('device'), signInRisk: fd.get('signInRisk'), userRisk: fd.get('userRisk'),
  };
}

function runWhatIf() {
  const out = $('whatif-result');
  if (!out) return;
  const strengthById = Object.fromEntries((state.raw.authStrengths || []).map((s) => [s.id, s]));
  const res = evaluate(state.raw.policies || [], state.whatIf, { strengthById, namedLocations: state.raw.namedLocations || [] });
  const tone = { blocked: 'danger', fails: 'danger', open: 'warn', challenge: 'good', allowed: 'good' };
  const outcome = (o, title) => `
    <div class="verdict verdict-${tone[o.verdict]}">
      <div class="small muted">${title}</div>
      <div class="verdict-label">${esc(o.label)}</div>
      <div>${esc(o.detail)}</div>
      ${o.session?.length ? `<div class="small">Session controls from: ${esc(o.session.join(', '))}</div>` : ''}
    </div>`;
  const changed = res.reportOnlyOutcome && res.reportOnlyOutcome.verdict !== res.outcome.verdict;
  out.innerHTML = `
    ${outcome(res.outcome, 'Today (enforced policies)')}
    ${res.reportOnlyOutcome ? outcome(res.reportOnlyOutcome, changed ? 'If report-only policies were switched on: outcome changes' : 'If report-only policies were switched on: no change') : ''}
    <h3>Policy by policy</h3>
    <div class="table-wrap"><table class="table compact">
      <thead><tr><th>Policy</th><th>State</th><th>Result</th><th>Demands</th></tr></thead>
      <tbody>${res.results.map((p) => `<tr class="${p.applies ? '' : 'dim'}">
        <td>${esc(p.name)}</td><td class="muted">${esc(p.stateLabel)}</td>
        <td>${p.applies ? '<span class="pill pill-info">Applies</span>' : `<span class="muted">${esc(p.reason)}</span>`}${p.notEvaluated.length ? `<div class="small muted">Not evaluated: ${esc(p.notEvaluated.join(', '))}</div>` : ''}</td>
        <td>${p.applies ? esc(p.gs.block ? 'Block' : p.controls) : ''}</td></tr>`).join('')}</tbody>
    </table></div>`;
}

// ---------------------------------------------------------------------------
// Executive report
// ---------------------------------------------------------------------------

function viewReport() {
  return `
  <div class="intro report-intro">
    <p>A plain-language report for management: answers, scores, priority actions, a 30/60/90-day roadmap, exceptions, crown jewels, data protection and workload identities.</p>
    <div class="btn-row">
      <button class="btn btn-primary" data-action="print-report">Print or save as PDF</button>
      <button class="btn btn-ghost" data-action="download-report">Download HTML</button>
      <button class="btn btn-ghost" data-action="download-json">Download full results (JSON)</button>
    </div>
    ${state.crown.size ? '' : '<p class="muted small">Tip: mark crown-jewel applications first (Applications tab) so the report can answer whether they are protected.</p>'}
  </div>
  <iframe class="report-frame" title="Executive report preview" sandbox="allow-same-origin" srcdoc="${esc(buildReportHtml(state.results, { demo: state.demo }))}"></iframe>`;
}

function printReport() {
  const html = buildReportHtml(state.results, { demo: state.demo });
  const frame = document.createElement('iframe');
  frame.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  document.body.appendChild(frame);
  frame.srcdoc = html;
  frame.onload = () => {
    frame.contentWindow.focus();
    frame.contentWindow.print();
    setTimeout(() => frame.remove(), 2000);
  };
}

// ---------------------------------------------------------------------------
// AI assistant (optional, Cloudflare Workers AI through /ai/ask)
// ---------------------------------------------------------------------------

// Only aggregated, non-identifying data leaves the browser: scores, counts and
// finding titles with quoted names removed. No user names, UPNs, IDs or IPs.
function aiSummary() {
  const r = state.results;
  const scrub = (t) => String(t).replace(/"[^"]*"/g, '"an app"');
  return {
    score: r.scores.overall,
    rating: r.scores.rating.label,
    areas: Object.fromEntries(Object.entries(r.scores.areas).map(([k, a]) => [a.label, a.score])),
    policies: r.summary.policyCounts,
    users: { total: r.summary.users.total, guests: r.summary.users.guests },
    peopleOutsideMfaPercent: r.summary.workforceOutsideMfa.percent,
    apps: r.summary.apps,
    exceptions: r.summary.exclusions,
    workload: r.workload.totals,
    dlpControls: r.dlp.controls.map((c) => ({ control: c.title, status: c.status })),
    baseline: r.baseline.map((c) => ({ check: c.title, status: c.status })),
    findings: r.findings.slice(0, 25).map((f) => ({ severity: f.severity, area: AREAS[f.area]?.label, title: f.area === 'locations' ? scrub(f.title.replace(/^[^:]+: /, 'A named location: ')) : scrub(f.title) })),
  };
}

const AI_PROMPTS = [
  'Summarise our posture for the leadership team in five bullet points.',
  'Which exceptions should we remove first, and why?',
  'How should Conditional Access support our Purview DLP project?',
  'Give me a 90-day plan to fix the top issues without breaking business apps.',
  'Explain why excluding SAML apps from MFA is risky.',
];

function viewAi() {
  return `
  <div class="intro"><p>Ask questions about this assessment. Optional and powered by Cloudflare Workers AI (free tier).</p>
  <p class="muted small">Sent with each question: scores, counts and finding titles only, with names removed. No user names, UPNs, IDs or IP ranges leave your browser. Answers can be wrong: verify before acting.</p></div>
  <div class="card chat">
    <div id="chat-log" class="chat-log"></div>
    <div class="chat-prompts">${AI_PROMPTS.map((p) => `<button class="fpill" data-prompt="${esc(p)}">${esc(p)}</button>`).join('')}</div>
    <form id="chat-form" class="chat-form">
      <input id="chat-input" maxlength="2000" placeholder="Ask about your Conditional Access posture" autocomplete="off" />
      <button class="btn btn-primary" type="submit">Ask</button>
    </form>
  </div>`;
}

function renderChat() {
  const log = $('chat-log');
  if (!log) return;
  log.innerHTML = state.chat.map((m) => `<div class="msg msg-${m.role}">${m.role === 'assistant' ? formatAnswer(m.content) : esc(m.content)}</div>`).join('') ||
    '<p class="muted center">Pick a suggested question or type your own.</p>';
  log.scrollTop = log.scrollHeight;
}

// Minimal, safe formatting: escape first, then bold, links to learn.microsoft.com, lists.
function formatAnswer(text) {
  let h = esc(text);
  h = h.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
  h = h.replace(/\[([^\]]+)\]\((https:\/\/learn\.microsoft\.com\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  h = h.replace(/^\s*[-*] (.*)$/gm, '&bull; $1');
  return h.replace(/\n/g, '<br>');
}

async function askAi(question) {
  if (!question.trim()) return;
  const history = state.chat.slice(-10);
  state.chat.push({ role: 'user', content: question });
  const answer = { role: 'assistant', content: 'Thinking...' };
  state.chat.push(answer);
  renderChat();
  try {
    const resp = await fetch('/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, results: aiSummary(), history }),
    });
    if (!resp.ok) {
      const j = await resp.json().catch(() => ({}));
      answer.content = j.error || `The assistant is unavailable (HTTP ${resp.status}).`;
    } else if ((resp.headers.get('Content-Type') || '').includes('text/event-stream')) {
      answer.content = '';
      await readSse(resp.body, (t) => { answer.content = t; renderChat(); });
    } else {
      const j = await resp.json();
      answer.content = j.answer || j.error || 'No answer.';
    }
  } catch {
    answer.content = 'The assistant could not be reached. It is only available on the hosted site.';
  }
  renderChat();
}

async function readSse(body, onText) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let text = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const data = line.slice(6).trim();
      if (data === '[DONE]') return text;
      try {
        const j = JSON.parse(data);
        const tok = j.response ?? j.choices?.[0]?.delta?.content ?? '';
        if (tok) { text += tok; onText(text); }
      } catch { /* ignore partial lines */ }
    }
  }
  return text;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

function exportCsv(kind) {
  const r = state.results;
  const t = r.summary.tenantName.replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  const defs = {
    findings: [r.findings, [
      { label: 'Severity', value: 'severity' }, { label: 'Area', value: (f) => AREAS[f.area]?.label },
      { label: 'Title', value: 'title' }, { label: 'Detail', value: 'detail' }, { label: 'Business impact', value: 'impact' },
      { label: 'Action', value: 'fix' }, { label: 'Reference', value: 'ref' }]],
    apps: [r.apps, [
      { label: 'Application', value: 'name' }, { label: 'App ID', value: 'appId' }, { label: 'Type', value: 'categoryLabel' },
      { label: 'Crown jewel', value: (a) => (a.crownJewel ? 'Yes' : '') }, { label: 'Protection', value: (a) => PROT[a.protection][0] },
      { label: 'Phishing-resistant', value: (a) => (a.phishingResistant ? 'Yes' : 'No') },
      { label: 'Device or session control', value: (a) => (a.managedDevice || a.sessionControl ? 'Yes' : 'No') },
      { label: 'Excluded by', value: (a) => a.excludedBy.map((p) => p.name).join('; ') },
      { label: 'Policies applying', value: (a) => a.applying.map((p) => `${p.name} (${p.controls})`).join('; ') },
      { label: 'Last used', value: 'lastUsed' }]],
    exceptions: [r.exclusions, [
      { label: 'Verdict', value: (e) => VERDICT[e.verdict][0] }, { label: 'Type', value: 'kind' }, { label: 'Excluded', value: 'targetName' },
      { label: 'Object ID', value: 'targetId' }, { label: 'Members', value: 'size' }, { label: 'Policy', value: 'policyName' },
      { label: 'Policy state', value: 'policyState' }, { label: 'Policy demands', value: 'policyControls' },
      { label: 'Reason', value: 'reason' }, { label: 'Action', value: 'fix' }, { label: 'Owner (fill in)', value: () => '' }, { label: 'Review date (fill in)', value: () => '' }]],
    policies: [r.policies, [
      { label: 'Policy', value: 'name' }, { label: 'State', value: 'stateLabel' }, { label: 'Kind', value: 'kind' },
      { label: 'Users', value: 'users' }, { label: 'Target', value: 'apps' }, { label: 'Conditions', value: (p) => p.conditions.join('; ') },
      { label: 'Grant', value: 'controls' }, { label: 'Session', value: 'session' }, { label: 'Exclusions', value: 'exclusions' }, { label: 'Modified', value: 'modified' }]],
    workload: [r.workload.apps, [
      { label: 'App', value: 'name' }, { label: 'App ID', value: 'appId' }, { label: 'Secrets', value: 'secrets' }, { label: 'Certificates', value: 'certificates' },
      { label: 'Expired', value: 'expired' }, { label: 'Expiring in 30 days', value: 'expiringSoon' }, { label: 'Secrets over 1 year', value: 'longLivedSecrets' },
      { label: 'Multi-tenant', value: (a) => (a.multiTenant ? 'Yes' : 'No') }, { label: 'Dormant', value: (a) => (a.dormant ? 'Yes' : '') }, { label: 'Last used', value: 'lastUsed' }]],
  };
  const [rows, cols] = defs[kind];
  download(`entracompass-${kind}-${t}-${stamp()}.csv`, '﻿' + toCsv(rows, cols), 'text/csv');
}

let toastTimer;
function toast(text) {
  let el = $('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.className = 'toast';
    el.setAttribute('role', 'status');
    document.body.appendChild(el);
  }
  el.textContent = text;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

function wireEvents() {
  $('redirect-uri-hint').textContent = window.location.origin;
  const cfg = loadConfig();
  if (cfg) {
    $('cfg-tenant').value = cfg.tenantId;
    $('cfg-client').value = cfg.clientId;
  }

  $('setup-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const tenantId = $('cfg-tenant').value.trim();
    const clientId = $('cfg-client').value.trim();
    if (!GUID.test(tenantId) || !GUID.test(clientId)) {
      showSetupError('Both IDs must be GUIDs (for example 00000000-0000-0000-0000-000000000000).');
      return;
    }
    signIn({ tenantId, clientId }).catch((err) => showSetupError(explainAuthError(err)));
  });

  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-action],[data-tab],[data-crown],[data-app-filter],[data-exc-verdict],[data-area],[data-prompt],[data-whatif-app],[data-exc-policy]');
    if (!t) return;
    if (t.dataset.crown) { e.preventDefault(); e.stopPropagation(); toggleCrown(t.dataset.crown); return; }
    if (t.dataset.tab) { state.tab = t.dataset.tab; render(); return; }
    if (t.dataset.appFilter) { state.appFilter = t.dataset.appFilter; state.appLimit = 150; render(); return; }
    if (t.dataset.excVerdict) { state.excVerdict = t.dataset.excVerdict; render(); return; }
    if (t.dataset.area) { state.findingArea = t.dataset.area === state.findingArea ? 'all' : t.dataset.area; render(); return; }
    if (t.dataset.prompt) { askAi(t.dataset.prompt); return; }
    if (t.dataset.whatifApp) { state.whatIf = { ...(state.whatIf || defaultWhatIf()), appId: t.dataset.whatifApp }; state.tab = 'whatif'; render(); return; }
    if (t.dataset.excPolicy) { state.excQuery = t.dataset.excPolicy; state.excVerdict = 'all'; state.excKind = 'all'; state.tab = 'exceptions'; render(); return; }
    switch (t.dataset.action) {
      case 'toggle-setup-help': e.preventDefault(); $('setup-help').classList.toggle('hidden'); break;
      case 'demo': loadDemo(); break;
      case 'rescan': runScan(); break;
      case 'signout': signOut(); break;
      case 'more-apps': state.appLimit += 300; render(); break;
      case 'export-findings': exportCsv('findings'); break;
      case 'export-apps': exportCsv('apps'); break;
      case 'export-exceptions': exportCsv('exceptions'); break;
      case 'export-policies': exportCsv('policies'); break;
      case 'export-workload': exportCsv('workload'); break;
      case 'export-crown': exportCrown(); break;
      case 'print-report': printReport(); break;
      case 'download-report': download(`entracompass-report-${stamp()}.html`, buildReportHtml(state.results, { demo: state.demo }), 'text/html'); break;
      case 'download-json': download(`entracompass-results-${stamp()}.json`, JSON.stringify(state.results, null, 2), 'application/json'); break;
      default: break;
    }
  });

  document.addEventListener('change', (e) => {
    const t = e.target;
    if (t.dataset?.action === 'import-crown' && t.files?.[0]) { importCrown(t.files[0]); t.value = ''; return; }
    if (t.closest('#whatif-form')) { readWhatIfForm(); runWhatIf(); return; }
    if (t.dataset?.input === 'excKind') { state.excKind = t.value; render(); }
  });

  // Debounced search boxes keep focus across re-renders.
  let searchTimer;
  document.addEventListener('input', (e) => {
    const key = e.target.dataset?.input;
    if (key !== 'appQuery' && key !== 'excQuery') return;
    state[key] = e.target.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const pos = e.target.selectionStart;
      render();
      const el = document.querySelector(`[data-input="${key}"]`);
      if (el) { el.focus(); el.setSelectionRange(pos, pos); }
    }, 200);
  });

  document.addEventListener('submit', (e) => {
    if (e.target.id !== 'chat-form') return;
    e.preventDefault();
    const input = $('chat-input');
    const q = input.value;
    input.value = '';
    askAi(q);
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function boot() {
  wireEvents();
  if (ss.get(KEYS.demo)) { loadDemo(); return; }
  const cfg = loadConfig();
  if (!cfg) { show('landing'); return; }
  try {
    state.msal = await createMsal(cfg);
    const res = await state.msal.handleRedirectPromise();
    if (res?.account) state.msal.setActiveAccount(res.account);
  } catch (err) {
    showSetupError(explainAuthError(err));
    return;
  }
  const account = state.msal.getActiveAccount() || state.msal.getAllAccounts()[0];
  if (!account) { show('landing'); return; }
  state.msal.setActiveAccount(account);
  const raw = ss.get(KEYS.raw);
  if (raw) { state.raw = raw; openDashboard(); } else { runScan(); }
}

boot();
