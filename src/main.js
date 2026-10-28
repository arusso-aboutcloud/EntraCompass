import { PublicClientApplication } from '@azure/msal-browser';
import { GraphClient } from './graph.js';
import { collectTenantData } from './collect.js';
import { analyze, AREAS, plural } from './analyzer.js';
import { evaluate } from './whatif.js';
import { buildReportHtml } from './report.js';
import { fixture as demoData, purviewExport as demoPurview } from './demo-data.js';
import { parsePurviewExport, LOCATIONS, CORE_LOCATIONS } from './purview.js';
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
  purview: 'entracompass_purview',
};
const THEME_KEY = 'entracompass_theme';
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
  findingSev: 'all',
  findingQuery: '',
  agentFilter: 'all',
  purview: null,
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
  state.purview = null;
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
  if (!ss.get(KEYS.purview)) {
    state.purview = parsePurviewExport(JSON.stringify(demoPurview), { fileName: 'contoso-purview-export.json' });
    ss.set(KEYS.purview, state.purview);
  }
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
// Purview export (parsed in the browser, kept in sessionStorage only)
// ---------------------------------------------------------------------------

function importPurview(file) {
  if (file.size > 5 * 1024 * 1024) { toast('That file is larger than 5 MB.'); return; }
  const reader = new FileReader();
  reader.onload = () => {
    try {
      state.purview = parsePurviewExport(String(reader.result), { fileName: file.name });
      if (!ss.set(KEYS.purview, state.purview)) console.warn('Purview export kept in memory only.');
      recompute();
      render();
      const p = state.purview;
      toast(`Loaded ${plural(p.dlpPolicies.length, 'DLP policy', 'DLP policies')} and ${plural(p.labels.length, 'label')}.`);
    } catch (err) {
      toast(err.message || 'That file could not be read.');
    }
  };
  reader.readAsText(file);
}

function clearPurview() {
  state.purview = null;
  ss.del(KEYS.purview);
  recompute();
  render();
  toast('Purview export removed from this tab.');
}

// ---------------------------------------------------------------------------
// Theme (sessionStorage only)
// ---------------------------------------------------------------------------

function currentTheme() {
  const set = document.documentElement.dataset.theme;
  if (set) return set;
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  ss.set(THEME_KEY, next);
  paintThemeButtons();
}

function paintThemeButtons() {
  const dark = currentTheme() === 'dark';
  document.querySelectorAll('.theme-toggle').forEach((b) => {
    b.innerHTML = dark ? ICON.sun : ICON.moon;
    b.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    b.title = dark ? 'Light theme' : 'Dark theme';
  });
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

// Small inline icons (stroke = currentColor), no external assets.
const svg = (d) => `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const ICON = {
  overview: svg('<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z"/>'),
  apps: svg('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>'),
  exceptions: svg('<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'),
  policies: svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
  locations: svg('<path d="M12 21s-7-6.2-7-11a7 7 0 1 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>'),
  workload: svg('<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9z"/>'),
  agents: svg('<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4M8 4h8"/><circle cx="9" cy="14" r="1.2"/><circle cx="15" cy="14" r="1.2"/>'),
  dlp: svg('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
  purview: svg('<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z"/><circle cx="7.5" cy="7.5" r="1.5"/>'),
  whatif: svg('<path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/><circle cx="12" cy="12" r="10"/>'),
  report: svg('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>'),
  ai: svg('<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/><path d="M19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>'),
  sun: svg('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
  moon: svg('<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>'),
  arrow: svg('<path d="M5 12h14M13 6l6 6-6 6"/>'),
};

const NAV = [
  [null, [['overview', 'Overview']]],
  ['Access', [['apps', 'Applications'], ['exceptions', 'Exceptions'], ['policies', 'Policies'], ['locations', 'Named locations']]],
  ['Identities', [['workload', 'Workload identities'], ['agents', 'AI agents']]],
  ['Data', [['dlp', 'Data protection'], ['purview', 'Purview']]],
  ['Act', [['whatif', 'What-if'], ['report', 'Executive report'], ['ai', 'Ask AI']]],
];
const TAB_IDS = NAV.flatMap(([, items]) => items.map(([id]) => id));

function recompute() {
  state.results = analyze(state.raw, {
    crownJewels: [...state.crown],
    now: state.demo ? state.raw.scannedAt : undefined,
    purview: state.purview,
  });
}

function openDashboard() {
  state.crown = new Set(ss.get(KEYS.crown) || [...state.crown]);
  state.purview = ss.get(KEYS.purview) || state.purview;
  recompute();
  $('tenant-name').textContent = state.results.summary.tenantName;
  $('demo-chip').classList.toggle('hidden', !state.demo);
  $('rescan-btn').classList.toggle('hidden', state.demo);
  show('dashboard');
  render();
}

function render() {
  if (!TAB_IDS.includes(state.tab)) state.tab = 'overview';
  $('tabs').innerHTML = NAV.map(([group, items]) => `
    <div class="nav-group">${group ? `<div class="nav-label">${group}</div>` : ''}
      ${items.map(([id, label]) => `<button class="nav-item ${state.tab === id ? 'active' : ''}" ${state.tab === id ? 'aria-current="page"' : ''} data-tab="${id}">${ICON[id]}<span>${label}</span>${tabBadge(id)}</button>`).join('')}
    </div>`).join('');
  const views = { overview: viewOverview, apps: viewApps, exceptions: viewExceptions, policies: viewPolicies, locations: viewLocations, workload: viewWorkload, agents: viewAgents, dlp: viewDlp, purview: viewPurview, whatif: viewWhatIf, report: viewReport, ai: viewAi };
  $('view').innerHTML = views[state.tab]();
  if (state.tab === 'whatif') runWhatIf();
  if (state.tab === 'ai') renderChat();
  paintThemeButtons();
}

function tabBadge(id) {
  const r = state.results;
  const sevCount = (area) => r.findings.filter((f) => f.area === area && (f.severity === 'critical' || f.severity === 'high')).length;
  const n = {
    exceptions: r.summary.exclusions.gap || 0,
    apps: r.summary.apps.unprotected,
    agents: sevCount('agents'),
    workload: sevCount('workload'),
    purview: r.findings.filter((f) => f.purview && (f.severity === 'critical' || f.severity === 'high')).length,
  }[id];
  if (id === 'purview' && !r.purview.imported) return ' <span class="nav-badge muted-badge" title="Load a Purview export">+</span>';
  return n ? ` <span class="nav-badge">${n}</span>` : '';
}

function goTo(tab) {
  state.tab = tab;
  render();
  window.scrollTo(0, 0);
  $('view').focus({ preventScroll: true });
  // On narrow screens the navigation is a horizontal strip: keep the active item visible.
  document.querySelector('.nav-item.active')?.scrollIntoView({ block: 'nearest', inline: 'center' });
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const sev = (s) => `<span class="sev sev-${s}">${SEV_LABEL[s] || s}</span>`;
const CTRL = { present: ['In place', 'good'], partial: ['Partial', 'warn'], missing: ['Missing', 'danger'], info: ['n/a', 'muted'], unknown: ['Needs export', 'muted'] };
const ctrl = (s) => `<span class="pill pill-${CTRL[s]?.[1] || 'info'}">${CTRL[s]?.[0] || s}</span>`;
const VERDICT = { gap: ['Opens a gap', 'danger'], review: ['Review', 'warn'], cleanup: ['Likely removable', 'info'], stale: ['Deleted object', 'muted'], justified: ['Justified', 'good'] };
const verdict = (v) => `<span class="pill pill-${VERDICT[v][1]}">${VERDICT[v][0]}</span>`;
const PROT = { strong: ['Always MFA', 'good'], conditional: ['MFA with conditions', 'warn'], partial: ['Some users', 'warn'], none: ['No MFA policy', 'danger'] };
const prot = (p) => `<span class="pill pill-${PROT[p][1]}">${PROT[p][0]}</span>`;
const yes = (b) => (b ? '<span class="tick" title="Yes">&#10003;</span>' : '<span class="dash" title="No">&ndash;</span>');
const learn = (url) => (url ? `<a href="${esc(url)}" target="_blank" rel="noopener">Learn more</a>` : '');

function findingCard(f) {
  return `<details class="finding sev-border-${f.severity}">
    <summary>${sev(f.severity)}<span class="finding-title">${esc(f.title)}</span><span class="finding-tags"><span class="area-tag">${esc(AREAS[f.area]?.label || f.area)}</span>${f.purview ? '<span class="area-tag">Purview</span>' : ''}${f.business ? '<span class="area-tag biz">Business impact</span>' : ''}</span></summary>
    <div class="finding-body">
      ${f.detail ? `<p class="muted">${esc(f.detail)}</p>` : ''}
      ${f.impact ? `<p><b>Why it matters:</b> ${esc(f.impact)}</p>` : ''}
      ${f.fix ? `<p><b>What to do:</b> ${esc(f.fix)}</p>` : ''}
      <p class="small">${learn(f.ref)}</p>
    </div>
  </details>`;
}

function sourceWarnings() {
  const failed = Object.values(state.results.sources || {}).filter((s) => s && s.ok === false && !s.optional);
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

const AREA_TAB = { access: 'policies', exceptions: 'exceptions', dlp: 'dlp', workload: 'workload', agents: 'agents', locations: 'locations', crown: 'apps' };

function viewOverview() {
  const r = state.results;
  const s = r.summary;
  const sc = r.scores;
  const w = s.workforceOutsideMfa;
  const at = r.agents.totals;
  const dlpIn = r.dlp.controls.filter((c) => c.status === 'present').length;
  const pvc = r.purview.checks.filter((c) => !['unknown', 'info'].includes(c.status));
  const fixFirst = r.findings.filter((f) => f.severity !== 'info').slice(0, 4);

  const domains = [
    { tab: 'apps', icon: 'apps', title: 'People and apps', score: sc.areas.access.score, lines: [
      [w.covered ? `${w.approximate ? '≥' : ''}${(w.people || 0).toLocaleString()}` : 'All', w.covered ? `outside the main MFA policy${w.percent !== null ? ` (${w.percent}%)` : ''}` : 'no MFA-for-everyone policy'],
      [`${s.apps.unprotected}/${s.apps.business}`, 'business apps without MFA'],
    ] },
    { tab: 'exceptions', icon: 'exceptions', title: 'Exceptions', score: sc.areas.exceptions.score, lines: [
      [`${s.exclusions.gap || 0}`, 'open a security gap'],
      [`${s.exclusionTotal}`, 'exceptions in total'],
    ] },
    { tab: 'workload', icon: 'workload', title: 'Workload identities', score: sc.areas.workload.score, lines: [
      [`${r.workload.totals.withSecrets}`, 'apps with client secrets'],
      [`${r.workload.totals.highPrivilege}`, 'can change tenant security'],
    ] },
    { tab: 'agents', icon: 'agents', title: 'AI agents', score: sc.areas.agents.score, isNew: true, lines: r.agents.inUse ? [
      [`${at.governed}/${at.identities}`, 'covered by an enforced policy'],
      [`${at.atRisk + at.critical}`, 'risky or over-privileged'],
    ] : [['0', 'agents found'], ['', 'Set up agent policies before the first agent']] },
    { tab: 'purview', icon: 'purview', title: 'Data and Purview', score: sc.areas.dlp.score, isNew: true, lines: [
      [`${dlpIn}/${r.dlp.controls.length}`, 'identity-side DLP controls'],
      r.purview.imported ? [`${pvc.filter((c) => c.status === 'present').length}/${pvc.length}`, 'Purview checks passed'] : [`${r.purview.labels.length}`, 'labels found. Load a DLP export'],
    ] },
  ];

  const areaFilter = state.findingArea;
  const q = state.findingQuery.toLowerCase();
  const list = r.findings.filter((f) => (areaFilter === 'all' || f.area === areaFilter) &&
    (state.findingSev === 'all' || f.severity === state.findingSev) &&
    (!q || `${f.title} ${f.detail}`.toLowerCase().includes(q)));
  const sevCounts = Object.fromEntries(Object.keys(SEV_LABEL).map((k) => [k, r.findings.filter((f) => f.severity === k && (areaFilter === 'all' || f.area === areaFilter)).length]));
  const tone = (n) => (n === null ? 'muted' : n >= 85 ? 'good' : n >= 65 ? 'warn' : 'danger');

  return `
  ${state.demo ? '<div class="alert alert-info"><b>Sample tenant.</b> You are viewing Contoso Ltd, a fictional organisation with AI agents and a Purview export pre-loaded. Sign out and connect your own tenant for a real assessment.</div>' : ''}
  ${sourceWarnings()}
  <div class="page-head">
    <div>
      <h1 class="page-title">${esc(s.tenantName)}</h1>
      <div class="muted small">Scanned ${esc(fmtDate(s.scannedAt, true))} &middot; ${s.policyCounts.enabled} of ${s.policyCounts.total} policies enforced &middot; ${(s.users.total || 0).toLocaleString()} accounts</div>
    </div>
    <div class="btn-row">
      <button class="btn btn-ghost btn-sm" data-goto="whatif">Test a change</button>
      <button class="btn btn-primary btn-sm" data-goto="report">Executive report</button>
    </div>
  </div>

  <div class="overview-top">
    <div class="card score-card">
      ${ring(sc.overall, sc.rating.tone)}
      <div>
        <div class="score-label tone-${sc.rating.tone}">${esc(sc.rating.label)}</div>
        <div class="muted small">Overall posture, weighted across areas</div>
        <div class="areas">${Object.entries(sc.areas).map(([k, a]) => `
          <button class="area-row ${areaFilter === k ? 'active' : ''}" data-area="${k}" title="Filter findings">
            <span>${esc(a.label)}</span>
            ${a.score === null ? `<span class="muted small">${k === 'crown' ? 'tag crown jewels' : 'not in use'}</span><span></span>` : `<span class="mini-bar"><span class="tone-bg-${tone(a.score)}" style="width:${a.score}%"></span></span><b>${a.score}</b>`}
          </button>`).join('')}</div>
      </div>
    </div>
    <div class="card fix-card">
      <div class="card-head"><h2 class="section-title">Fix first</h2><span class="muted small">${plural(r.findings.filter((f) => f.severity === 'critical').length, 'critical finding')}</span></div>
      <ol class="fix-list">${fixFirst.map((f) => `
        <li><button class="fix-item" data-goto="${AREA_TAB[f.area] || 'overview'}">
          ${sev(f.severity)}<span class="fix-title">${esc(f.title)}</span><span class="fix-area muted small">${esc(AREAS[f.area]?.label || '')}</span>
        </button></li>`).join('') || '<li class="muted">No significant issues found.</li>'}</ol>
    </div>
  </div>

  <div class="domains">${domains.map((d) => `
    <button class="domain tone-edge-${tone(d.score)}" data-goto="${d.tab}">
      <div class="domain-head">${ICON[d.icon]}<b>${esc(d.title)}</b>${d.isNew ? '<span class="new-tag">New</span>' : ''}<span class="domain-score tone-${tone(d.score)}">${d.score === null ? '&ndash;' : d.score}</span></div>
      ${d.lines.map(([v, l]) => `<div class="domain-line"><span class="domain-v">${esc(v)}</span> <span class="muted">${esc(l)}</span></div>`).join('')}
      <span class="domain-go">Open ${ICON.arrow}</span>
    </button>`).join('')}</div>

  <details class="qa-wrap" open>
    <summary><h2 class="section-title">Answers for management</h2><span class="muted small">${r.questions.filter((x) => x.status === 'good').length} of ${r.questions.length} answered "yes"</span></summary>
    <div class="qa-grid">${r.questions.map((x) => `
      <div class="qa qa-${x.status}"><div class="qa-q"><span class="qa-dot" aria-hidden="true"></span>${esc(x.q)}</div><div class="qa-a">${esc(x.a)}</div></div>`).join('')}</div>
  </details>

  <div class="section-head">
    <h2 class="section-title">Findings <span class="muted">(${list.length})</span> ${areaFilter !== 'all' ? `<span class="muted">in ${esc(AREAS[areaFilter].label)}</span> <button class="link-btn" data-area="all">show all areas</button>` : ''}</h2>
    <button class="btn btn-ghost btn-sm" data-action="export-findings">Export CSV</button>
  </div>
  <div class="toolbar">
    <div class="pills">
      <button class="fpill ${state.findingSev === 'all' ? 'active' : ''}" data-sev="all">All</button>
      ${Object.entries(SEV_LABEL).filter(([k]) => sevCounts[k]).map(([k, l]) => `<button class="fpill fpill-${k} ${state.findingSev === k ? 'active' : ''}" data-sev="${k}">${l} <span>${sevCounts[k]}</span></button>`).join('')}
    </div>
    <div class="toolbar-right"><input type="search" class="search" placeholder="Search findings" value="${esc(state.findingQuery)}" data-input="findingQuery" aria-label="Search findings" /></div>
  </div>
  <div class="findings">${list.map(findingCard).join('') || '<p class="muted pad">No findings match.</p>'}</div>`;
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

const pageHead = (title, sub = '') => `<div class="page-head"><div><h1 class="page-title">${title}</h1>${sub ? `<p class="muted page-sub">${sub}</p>` : ''}</div></div>`;

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
  ${pageHead('Applications')}
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
  ${pageHead('Exceptions')}
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
  ${pageHead('Policies', `${r.policies.length} Conditional Access policies: ${r.summary.policyCounts.enabled} on, ${r.summary.policyCounts.reportOnly} report-only, ${r.summary.policyCounts.disabled} off.`)}
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
  if (!r.locations.length) return `${pageHead('Named locations')}<div class="card pad"><p>No named locations are defined.</p></div>`;
  return `
  ${pageHead('Named locations')}
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
  ${pageHead('Workload identities')}
  <div class="intro"><p>Workload identities are apps and services that sign in on their own with a secret or certificate. Conditional Access for workload identities can restrict single-tenant apps by location and risk (needs Workload Identities Premium). Managed identities need no secret and are the preferred option. AI agents have their own view. <a href="${DOCS.workloadCa}" target="_blank" rel="noopener">Learn more</a></p></div>
  <div class="tiles tiles-row">
    ${[['With credentials', w.apps.length], ['Client secrets', t.withSecrets], ['Can change tenant security', t.highPrivilege], ['Dormant (valid, unused)', t.dormant], ['Secrets > 1 year', t.longLived], ['Expiring in 30 days', t.expiringSoon]]
      .map(([l, v]) => `<div class="tile"><div class="tile-v">${v}</div><div class="tile-l">${l}</div></div>`).join('')}
  </div>
  <h2 class="section-title">Workload identity policies</h2>
  ${w.policies.length ? `<ul class="plain">${w.policies.map((p) => `<li><span class="pill pill-${p.state === 'enabled' ? 'good' : 'muted'}">${esc(p.stateLabel)}</span> <b>${esc(p.name)}</b> <span class="muted">${esc(p.scope)} &middot; ${esc(p.controls)}${p.conditions.length ? ` when ${esc(p.conditions.join(', '))}` : ''}</span></li>`).join('')}</ul>` : '<p class="muted">None.</p>'}
  <div class="section-head"><h2 class="section-title">App registrations with credentials</h2><button class="btn btn-ghost btn-sm" data-action="export-workload">Export CSV</button></div>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>App</th><th>High-impact permissions</th><th>Secrets</th><th>Certificates</th><th>Expired</th><th>Expiring</th><th>Long-lived</th><th>Audience</th><th>Last used</th></tr></thead>
    <tbody>${w.apps.slice(0, 500).map((a) => `<tr>
      <td><b>${esc(a.name)}</b>${a.dormant ? ' <span class="pill pill-danger">dormant</span>' : ''}${a.agentBlueprint ? ' <span class="hint-tag">agent blueprint</span>' : ''}</td>
      <td>${permPills(a.permissions, 3)}${a.permissions.roles.length ? ` <span class="pill pill-danger pill-sm">${esc(a.permissions.roles.join(', '))}</span>` : ''}</td>
      <td>${a.secrets}</td><td>${a.certificates}</td><td>${a.expired || ''}</td>
      <td>${a.expiringSoon ? `<span class="pill pill-warn">${a.expiringSoon}</span>` : ''}</td>
      <td>${a.longLivedSecrets ? `<span class="pill pill-warn">${a.longLivedSecrets}</span>` : ''}</td>
      <td class="muted">${a.multiTenant ? 'Multi-tenant' : 'This tenant'}</td>
      <td class="muted small">${a.lastUsed ? esc(fmtDate(a.lastUsed)) : 'none'}</td></tr>`).join('')}</tbody>
  </table></div>`;
}

const RISK_TONE = { high: 'danger', medium: 'warn', low: 'info' };
const permPills = (sum, max = 4) => {
  const items = [...sum.critical.map((x) => [x, 'danger']), ...sum.high.map((x) => [x, 'warn'])];
  if (!items.length) return '<span class="dash">&ndash;</span>';
  return items.slice(0, max).map(([x, t]) => `<span class="pill pill-${t} pill-sm">${esc(x)}</span>`).join(' ') + (items.length > max ? ` <span class="muted small">+${items.length - max}</span>` : '');
};

function checkList(checks) {
  return `<div class="baseline">${checks.map((c) => `
    <div class="base-item">${ctrl(c.status)}<div><b>${esc(c.title)}</b><div class="muted small">${esc(c.detail)} ${learn(c.ref)}</div>${c.why ? `<div class="small why">${esc(c.why)}</div>` : ''}</div></div>`).join('')}</div>`;
}

function viewAgents() {
  const ag = state.results.agents;
  const t = ag.totals;
  const filters = [
    ['all', 'All', ag.agents.length],
    ['risk', 'Risky or over-privileged', ag.agents.filter((a) => ['critical', 'high'].includes(a.severity)).length],
    ['ungoverned', 'Not covered', ag.agents.filter((a) => !a.governed).length],
    ['nosponsor', 'No sponsor', ag.agents.filter((a) => a.sponsors === 0).length],
    ['thirdparty', 'Third party', ag.agents.filter((a) => a.publisher === 'Third party').length],
  ];
  const f = state.agentFilter;
  const list = ag.agents.filter((a) => f === 'all' || (f === 'risk' && ['critical', 'high'].includes(a.severity)) || (f === 'ungoverned' && !a.governed) || (f === 'nosponsor' && a.sponsors === 0) || (f === 'thirdparty' && a.publisher === 'Third party'));
  return `
  <div class="page-head"><div><h1 class="page-title">AI agents <span class="new-tag">New</span></h1>
    <p class="muted page-sub">Microsoft Entra Agent ID gives AI agents their own identities. Conditional Access treats them differently from people: you secure each <b>access pattern</b> separately.</p></div>
    <button class="btn btn-ghost btn-sm" data-action="export-agents">Export CSV</button></div>

  <div class="patterns">
    <div class="pattern"><div class="pattern-k">On behalf of a user</div><p>The agent uses the signed-in user's token. <b>User policies apply</b> (MFA, device, location).</p></div>
    <div class="pattern"><div class="pattern-k">Autonomous (agent identity)</div><p>The agent acts on its own. Only <b>agent policies</b> apply, and the only control is block (by approval list or agent risk).</p></div>
    <div class="pattern"><div class="pattern-k">Agent user account</div><p>An agent with a mailbox and Teams presence. <b>"All users" policies do not include it</b>: it needs an agent-user policy.</p></div>
  </div>

  ${ag.sourceNotes.length ? `<div class="alert alert-info">${ag.sourceNotes.map(esc).join('<br>')}</div>` : ''}
  ${!ag.inUse ? `<div class="card pad empty"><h3>No AI agents found</h3><p class="muted">No Entra Agent ID identities, agent user accounts or AI-like apps were found. Set up the recommended agent policies in report-only now, so the first agent starts governed. ${learn(DOCS.agentCaAutonomous)}</p></div>` : `
  <div class="tiles tiles-row">
    ${[['Agent identities', t.identities, ''], ['Covered by an enforced policy', `${t.governed}/${t.identities}`, t.governed < t.identities ? 'warn' : 'good'], ['Org-wide permissions', t.highPrivilege, t.highPrivilege ? 'warn' : ''], ['Risky (ID Protection)', t.atRisk, t.atRisk ? 'danger' : ''], ['No sponsor', t.noSponsor, t.noSponsor ? 'warn' : ''], ['AI-like apps outside Agent ID', t.candidates, t.candidates ? 'warn' : '']]
    .map(([l, v, tone]) => `<div class="tile ${tone ? 'tile-' + tone : ''}"><div class="tile-v">${esc(v)}</div><div class="tile-l">${esc(l)}</div></div>`).join('')}
  </div>`}

  <h2 class="section-title">Agent security baseline</h2>
  ${checkList(ag.checks)}

  <h2 class="section-title spaced">Conditional Access policies for agents</h2>
  ${ag.policies.length ? `<div class="table-wrap"><table class="table">
    <thead><tr><th>State</th><th>Policy</th><th>Targets</th><th>Scope</th><th>Type</th><th>Agent risk</th><th>Exclusions</th></tr></thead>
    <tbody>${ag.policies.map((p) => `<tr>
      <td><span class="pill pill-${p.state === 'enabled' ? 'good' : p.state === 'disabled' ? 'muted' : 'warn'}">${esc(p.stateLabel)}</span></td>
      <td><b>${esc(p.name)}</b></td><td>${esc(p.target)}</td><td>${esc(p.scope)}</td><td>${esc(p.kind)}</td>
      <td>${p.risk.length ? esc(p.risk.join(', ')) : '<span class="dash">&ndash;</span>'}</td>
      <td>${p.exclusions ? `<button class="link-btn" data-exc-policy="${esc(p.name)}">${p.exclusions}</button>` : '0'}</td></tr>`).join('')}</tbody>
  </table></div>` : `<div class="card pad"><p>No Conditional Access policy targets agents. Microsoft recommends, in report-only first: <b>block high-risk agent identities</b>, and <b>block all agents except approved ones</b>. ${learn(DOCS.agentCaAutonomous)}</p></div>`}

  ${ag.agents.length ? `
  <div class="section-head"><h2 class="section-title">Agent identities (${ag.agents.length})</h2></div>
  <div class="toolbar"><div class="pills">${filters.map(([id, l, n]) => `<button class="fpill ${f === id ? 'active' : ''}" data-agent-filter="${id}">${l} <span>${n}</span></button>`).join('')}</div></div>
  <div class="rows">
    <div class="row-head agent-grid"><span>Agent</span><span>Blueprint / publisher</span><span>Sponsor</span><span>Risk</span><span>Permissions</span><span>Conditional Access</span></div>
    ${list.map((a) => `
    <details class="row">
      <summary class="agent-grid">
        <span class="app-name">${a.severity !== 'none' ? sev(a.severity) + ' ' : ''}${esc(a.name)}${a.enabled ? '' : ' <span class="hint-tag">disabled</span>'}${a.agentUsers.length ? ' <span class="hint-tag">has user account</span>' : ''}</span>
        <span class="muted">${esc(a.blueprintName || 'Unknown')}<div class="small">${esc(a.publisher)}${a.publisher === 'Third party' && !a.verifiedPublisher ? ', unverified' : ''}</div></span>
        <span>${a.sponsors === null ? '<span class="muted small">unknown</span>' : a.sponsors ? esc(a.sponsorNames.join(', ') || a.sponsors) : '<span class="pill pill-warn">None</span>'}</span>
        <span>${a.risk ? `<span class="pill pill-${RISK_TONE[a.risk.level] || 'muted'}">${esc(a.risk.level)}</span>` : '<span class="dash">&ndash;</span>'}</span>
        <span>${permPills(a.permissionSummary, 2)}${a.roles.some((r) => r.privileged) ? ' <span class="pill pill-danger pill-sm">admin role</span>' : ''}</span>
        <span>${a.governed ? '<span class="pill pill-good">Enforced</span>' : a.coveredBy.length ? '<span class="pill pill-warn">Report-only</span>' : '<span class="pill pill-danger">None</span>'}</span>
      </summary>
      <div class="row-body">
        ${a.issues.length ? `<ul class="issues">${a.issues.map((i) => `<li>${sev(i.severity)} ${esc(i.text)}</li>`).join('')}</ul>` : '<p class="tone-good small">No issues found.</p>'}
        <div class="two-col">
          <div><h4>Application permissions</h4>${a.appPermissions.length ? `<ul>${a.appPermissions.map((x) => `<li><span class="pill pill-${x.tier === 'critical' ? 'danger' : x.tier === 'high' ? 'warn' : 'muted'} pill-sm">${esc(x.tier)}</span> ${esc(x.permission)} <span class="muted small">${esc(x.resource)}${x.inherited ? ', inherited from blueprint' : ''}</span></li>`).join('')}</ul>` : '<p class="muted">None.</p>'}
            ${a.delegated.length ? `<h4>Delegated consent</h4><ul>${a.delegated.map((d) => `<li>${d.allUsers ? '<b>All users</b>' : 'Some users'}: <span class="mono small">${esc(d.scopes.join(' '))}</span></li>`).join('')}</ul>` : ''}
            ${a.roles.length ? `<h4>Directory roles</h4><ul>${a.roles.map((r) => `<li>${esc(r.name)}${r.privileged ? ' <span class="pill pill-danger pill-sm">privileged</span>' : ''}</li>`).join('')}</ul>` : ''}</div>
          <div><h4>Conditional Access</h4>${a.coveredBy.length ? `<ul>${a.coveredBy.map((c) => `<li>${esc(c.name)} <span class="muted">(${esc(STATE_TXT[c.state] || c.state)}${c.risk.length ? `, agent risk ${esc(c.risk.join('/'))}` : ''})</span></li>`).join('')}</ul>` : '<p class="muted">No agent policy covers this agent.</p>'}
            ${a.excludedBy.length ? `<h4>Excluded from</h4><ul>${a.excludedBy.map((e) => `<li>${esc(e.name)} ${e.allowList ? '<span class="pill pill-good pill-sm">approved (allow-list)</span>' : '<span class="pill pill-danger pill-sm">gap</span>'}</li>`).join('')}</ul>` : ''}
            ${a.agentUsers.length ? `<h4>Agent user account</h4><ul>${a.agentUsers.map((u) => `<li>${esc(u.upn || u.name)}</li>`).join('')}</ul>` : ''}
            <div class="muted small">Object ID ${esc(a.id)}${a.created ? ` &middot; created ${esc(fmtDate(a.created))}` : ''}</div>
            <button class="btn btn-ghost btn-sm" data-whatif-agent="${esc(a.id)}">Test in what-if</button></div>
        </div>
      </div>
    </details>`).join('') || '<p class="muted pad">No agents match.</p>'}
  </div>` : ''}

  ${ag.users.length ? `<h2 class="section-title spaced">Agent user accounts (${ag.users.length})</h2>
  <div class="table-wrap"><table class="table"><thead><tr><th>Account</th><th>Agent</th><th>Covered by</th></tr></thead>
  <tbody>${ag.users.map((u) => `<tr><td><b>${esc(u.name)}</b><div class="muted small">${esc(u.upn || '')}</div></td><td>${esc(u.parentName || 'Unknown')}</td>
    <td>${u.coveredBy.length ? u.coveredBy.map((c) => `${esc(c.name)} <span class="muted">(${esc(STATE_TXT[c.state])})</span>`).join(', ') : '<span class="pill pill-danger">No policy</span> <span class="muted small">"All users" policies do not apply</span>'}</td></tr>`).join('')}</tbody></table></div>` : ''}

  ${ag.candidates.length ? `<h2 class="section-title spaced">AI-like apps outside Agent ID (${ag.candidates.length})</h2>
  <p class="muted small">Apps whose names suggest an AI agent or assistant, registered as ordinary apps. Agent policies, agent risk and sponsors do not apply to them. Name-based suggestion: confirm with the owner.</p>
  <div class="table-wrap"><table class="table"><thead><tr><th>App</th><th>Publisher</th><th>Application permissions</th><th>Tenant-wide delegated</th><th>Secrets</th></tr></thead>
  <tbody>${ag.candidates.map((c) => `<tr><td><b>${esc(c.name)}</b></td><td class="muted">${esc(c.publisher)}</td><td>${permPills(c.permissionSummary)}</td>
    <td>${c.broadDelegated.length ? c.broadDelegated.map((x) => `<span class="pill pill-warn pill-sm">${esc(x)}</span>`).join(' ') : '<span class="dash">&ndash;</span>'}</td><td>${c.secrets || ''}</td></tr>`).join('')}</tbody></table></div>` : ''}

  ${ag.blueprints.length ? `<h2 class="section-title spaced">Agent blueprints (${ag.blueprints.length})</h2>
  <div class="table-wrap"><table class="table"><thead><tr><th>Blueprint</th><th>Publisher</th><th>Agents</th><th>Permissions (inherited by every agent)</th></tr></thead>
  <tbody>${ag.blueprints.map((b) => `<tr><td><b>${esc(b.name)}</b></td><td class="muted">${esc(b.publisher)}${b.publisher === 'Third party' && !b.verifiedPublisher ? ', unverified' : ''}</td><td>${b.agents}</td><td>${permPills(b.permissionSummary)}</td></tr>`).join('')}</tbody></table></div>` : ''}
  <p class="small spaced">${learn(DOCS.agentCa)}</p>`;
}

const STATE_TXT = { enabled: 'on', enabledForReportingButNotEnforced: 'report-only', disabled: 'off' };

function viewPurview() {
  const pv = state.results.purview;
  const covRows = Object.entries(LOCATIONS);
  return `
  <div class="page-head"><div><h1 class="page-title">Purview <span class="new-tag">New</span></h1>
    <p class="muted page-sub">Sensitivity labels and DLP decide what may happen to data. Conditional Access decides who reaches it and from which device. This view checks that the two fit together, including Microsoft 365 Copilot and agents.</p></div></div>

  <div class="card import-card ${pv.imported ? 'loaded' : ''}" data-drop="purview">
    <div class="import-main">
      <div>
        <h3>${pv.imported ? 'Purview export loaded' : 'Load a Purview export'}</h3>
        ${pv.imported
          ? `<p class="muted small">${esc(pv.imported.fileName || 'export')} ${pv.imported.exportedAt ? `&middot; exported ${esc(fmtDate(pv.imported.exportedAt, true))}` : ''} &middot; ${plural(pv.totals.dlpPolicies, 'DLP policy', 'DLP policies')}, ${plural(pv.totals.labels, 'label')}. Parsed in this browser tab, never uploaded.</p>`
          : '<p class="muted small">DLP policies are not readable through Microsoft Graph. Run the export script in PowerShell (read-only, Security &amp; Compliance PowerShell), then drop the JSON file here. It is parsed in this browser tab and never uploaded.</p>'}
      </div>
      <div class="btn-row">
        <label class="btn ${pv.imported ? 'btn-ghost' : 'btn-primary'} btn-sm file-btn">${pv.imported ? 'Replace file' : 'Choose JSON file'}<input type="file" accept="application/json,.json" data-action="import-purview" hidden /></label>
        ${pv.imported ? '<button class="btn btn-ghost btn-sm" data-action="clear-purview">Remove</button>' : ''}
      </div>
    </div>
    <details class="howto"><summary>How to create the export</summary>
      <pre class="code">./Export-PurviewForEntraCompass.ps1 -OutFile purview.json</pre>
      <p class="muted small">The script is in the <a href="https://github.com/arusso-aboutcloud/EntraCompass/blob/main/infra/Export-PurviewForEntraCompass.ps1" target="_blank" rel="noopener">GitHub repo</a>. It needs the ExchangeOnlineManagement module and a Compliance Administrator, Compliance Data Administrator or Global Reader account. It reads DLP policies and rules, sensitivity labels and label policies, and writes names, modes, locations and rule actions only: no content and no matched data.</p>
    </details>
  </div>

  <h2 class="section-title spaced">Purview and Conditional Access checks</h2>
  ${checkList(pv.checks)}

  ${pv.imported ? `
  <h2 class="section-title spaced">DLP coverage by location</h2>
  <div class="coverage">${covRows.map(([k, label]) => {
    const c = pv.coverage[k];
    const status = c.enforced ? 'good' : c.test ? 'warn' : CORE_LOCATIONS.includes(k) || k === 'copilot' ? 'danger' : 'muted';
    return `<div class="cov cov-${status}"><div class="cov-l">${esc(label)}</div><div class="cov-v">${c.enforced ? `${c.enforced} enforced` : c.test ? `${c.test} in test` : 'Not covered'}</div>${c.policies.length ? `<div class="muted small">${esc(c.policies.join(', '))}</div>` : ''}</div>`;
  }).join('')}</div>

  <h2 class="section-title spaced">DLP policies (${pv.dlpPolicies.length})</h2>
  <div class="table-wrap"><table class="table"><thead><tr><th>Mode</th><th>Policy</th><th>Locations</th><th>Rules</th><th>Blocking rules</th><th>Changed</th></tr></thead>
  <tbody>${pv.dlpPolicies.map((p) => `<tr><td><span class="pill pill-${p.mode === 'enforce' ? 'good' : p.mode === 'test' ? 'warn' : 'muted'}">${p.mode === 'enforce' ? 'On' : p.mode === 'test' ? 'Test' : 'Off'}</span></td>
    <td><b>${esc(p.name)}</b></td><td class="muted">${esc(p.locations.map((l) => LOCATIONS[l]).join(', ') || 'Unknown')}</td><td>${p.rules}</td><td>${p.blockingRules}</td><td class="muted small">${esc(fmtDate(p.modified))}</td></tr>`).join('')}</tbody></table></div>` : ''}

  ${pv.labels.length ? `<h2 class="section-title spaced">Sensitivity labels (${pv.labels.length}) <span class="muted small">${pv.labelsSource === 'export' ? 'from export' : 'published to you, from Graph'}</span></h2>
  <div class="table-wrap"><table class="table"><thead><tr><th>Label</th><th>Encryption</th><th>Authentication context</th>${pv.labelsSource === 'export' ? '<th>Applies to</th>' : ''}</tr></thead>
  <tbody>${pv.labels.map((l) => `<tr><td><b>${esc(l.name)}</b></td><td>${yes(l.encryption)}</td><td>${l.authContext ? `<span class="mono small">${esc(l.authContext)}</span>` : '<span class="dash">&ndash;</span>'}</td>${pv.labelsSource === 'export' ? `<td class="muted small">${esc(l.scope || '')}</td>` : ''}</tr>`).join('')}</tbody></table></div>` : ''}

  <h2 class="section-title spaced">Checklist for the Purview DLP assessment</h2>
  <ul class="checklist">
    <li>Map each crown-jewel app to the sensitivity labels and DLP policies that protect its data.</li>
    <li>For every label that uses an authentication context, confirm a Conditional Access policy enforces it.</li>
    <li>Endpoint DLP needs onboarded devices: require compliant devices for desktop sync clients.</li>
    <li>Personal devices: choose browser-only access (app-enforced restrictions) or Defender for Cloud Apps session policies.</li>
    <li>Copilot and agents: add the Microsoft 365 Copilot DLP location and review agents' data permissions in the AI agents view.</li>
    <li>Guests: confirm MFA and decide whether they may open encrypted or labelled content.</li>
    <li>If Adaptive Protection is licensed, connect insider risk levels to a Conditional Access policy.</li>
  </ul>
  <p class="small">${learn(DOCS.purviewDlp)} &middot; <a href="${DOCS.dspmAi}" target="_blank" rel="noopener">Data security for AI</a></p>`;
}

function viewDlp() {
  const d = state.results.dlp;
  return `
  ${pageHead('Data protection', 'Identity-side controls that decide where company data can be reached from.')}
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
  <div class="card pad callout"><b>Next: Purview.</b> Sensitivity labels, DLP locations (including Copilot) and their fit with these controls are in the <button class="link-btn" data-goto="purview">Purview view</button>.</div>
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
    signInRisk: 'none', userRisk: 'none', authFlow: 'none', insiderRisk: 'none',
    agentId: '', agentUserId: '', agentRisk: 'none',
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
  ${pageHead('What-if')}
  <div class="intro"><p>Test a sign-in before you change anything. Pick who, which app, from where and on what device: EntraCompass shows which policies apply and what the user experiences, today and if report-only policies were switched on.</p>
  <p class="muted small">Simplified engine: device filters, authentication flows and insider risk are listed as "not evaluated". For a specific person, confirm with Microsoft's <a href="${DOCS.whatIf}" target="_blank" rel="noopener">What If tool</a>.</p></div>
  <div class="whatif">
    <form class="card whatif-form" id="whatif-form">
      <label>Who signs in<select name="userType" data-rerender="1">${opt('member', 'Member (employee)', w.userType)}${opt('guest', 'Guest / external', w.userType)}${opt('agent', 'AI agent acting on its own', w.userType)}${opt('agentUser', 'Agent user account', w.userType)}</select></label>
      ${w.userType === 'agent' ? `
      <label>Agent identity<select name="agentId">${r.agents.agents.length ? r.agents.agents.map((a) => opt(a.id, `${a.name}${a.blueprintName ? ' (' + a.blueprintName + ')' : ''}`, w.agentId)).join('') : opt('', 'Any agent (none found in the tenant)', '')}</select></label>
      <label>Resource<select name="appId">${Object.entries(byCat).map(([cat, list]) => `<optgroup label="${esc(cat)}">${list.map((a) => opt(a.appId, a.name, w.appId)).join('')}</optgroup>`).join('')}</select></label>
      <label>Agent risk (ID Protection)<select name="agentRisk">${['none', 'low', 'medium', 'high'].map((v) => opt(v, v, w.agentRisk)).join('')}</select></label>
      <p class="muted small">Agent identities only meet agent policies; the only control is block. Policies for users never apply.</p>
      ` : w.userType === 'agentUser' ? `
      <label>Agent user account<select name="agentUserId">${opt('', 'Any agent user', w.agentUserId)}${r.agents.users.map((u) => opt(u.id, u.upn || u.name, w.agentUserId)).join('')}</select></label>
      <label>Resource<select name="appId">${Object.entries(byCat).map(([cat, list]) => `<optgroup label="${esc(cat)}">${list.map((a) => opt(a.appId, a.name, w.appId)).join('')}</optgroup>`).join('')}</select></label>
      <label>Agent risk (ID Protection)<select name="agentRisk">${['none', 'low', 'medium', 'high'].map((v) => opt(v, v, w.agentRisk)).join('')}</select></label>
      <p class="muted small">"All users" policies do not include agent user accounts.</p>
      ` : `
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
      <div class="two">
        <label>Sign-in flow<select name="authFlow">${opt('none', 'Normal sign-in', w.authFlow)}${opt('deviceCodeFlow', 'Device code', w.authFlow)}${opt('authenticationTransfer', 'Authentication transfer', w.authFlow)}</select></label>
        <label>Insider risk<select name="insiderRisk">${['none', 'minor', 'moderate', 'elevated'].map((v) => opt(v, v, w.insiderRisk)).join('')}</select></label>
      </div>`}
    </form>
    <div id="whatif-result" class="whatif-result"></div>
  </div>`;
}

function readWhatIfForm() {
  const f = $('whatif-form');
  if (!f) return;
  const fd = new FormData(f);
  const prev = state.whatIf || defaultWhatIf();
  const get = (k) => (fd.has(k) ? fd.get(k) : prev[k]);
  state.whatIf = {
    ...prev,
    userType: get('userType'), userId: get('userId'),
    groupIds: fd.has('userId') ? fd.getAll('groupIds') : prev.groupIds, roleIds: fd.has('userId') ? fd.getAll('roleIds') : prev.roleIds,
    appId: get('appId'), locationId: get('locationId'), platform: get('platform'),
    clientApp: get('clientApp'), device: get('device'), signInRisk: get('signInRisk'), userRisk: get('userRisk'),
    authFlow: get('authFlow'), insiderRisk: get('insiderRisk'),
    agentId: get('agentId'), agentUserId: get('agentUserId'), agentRisk: get('agentRisk'),
  };
}

function runWhatIf() {
  const out = $('whatif-result');
  if (!out) return;
  const strengthById = Object.fromEntries((state.raw.authStrengths || []).map((s) => [s.id, s]));
  const w = { ...state.whatIf };
  if (w.userType === 'agent') {
    const a = state.results.agents.agents.find((x) => x.id === w.agentId) || state.results.agents.agents[0];
    const bp = (state.raw.agentBlueprints || []).find((b) => b.appId === a?.blueprintId);
    w.agentId = a?.id || '';
    w.blueprintIds = [bp?.id, a?.blueprintId].filter(Boolean);
  }
  const res = evaluate(state.raw.policies || [], w, { strengthById, namedLocations: state.raw.namedLocations || [], agentUserIds: new Set((state.raw.agentUsers || []).map((u) => u.id)) });
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
  ${pageHead('Executive report')}
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
    agents: { ...r.agents.totals, checks: r.agents.checks.map((c) => ({ check: c.title, status: c.status })) },
    purview: { imported: !!r.purview.imported, ...r.purview.totals, checks: r.purview.checks.map((c) => ({ check: c.title, status: c.status })) },
    baseline: r.baseline.map((c) => ({ check: c.title, status: c.status })),
    findings: r.findings.slice(0, 30).map((f) => ({ severity: f.severity, area: AREAS[f.area]?.label, title: f.area === 'locations' ? scrub(f.title.replace(/^[^:]+: /, 'A named location: ')) : scrub(f.title) })),
  };
}

const AI_PROMPTS = [
  'Summarise our posture for the leadership team in five bullet points.',
  'Which exceptions should we remove first, and why?',
  'How should Conditional Access support our Purview DLP project?',
  'How do we govern our AI agents with Conditional Access and Agent ID?',
  'What should we do so Copilot and agents respect our sensitivity labels?',
  'Give me a 90-day plan to fix the top issues without breaking business apps.',
  'Explain why excluding SAML apps from MFA is risky.',
];

function viewAi() {
  return `
  ${pageHead('Ask AI')}
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
      { label: 'Multi-tenant', value: (a) => (a.multiTenant ? 'Yes' : 'No') }, { label: 'Dormant', value: (a) => (a.dormant ? 'Yes' : '') }, { label: 'Last used', value: 'lastUsed' },
      { label: 'Critical permissions', value: (a) => a.permissions.critical.join('; ') }, { label: 'High permissions', value: (a) => a.permissions.high.join('; ') }, { label: 'Privileged roles', value: (a) => a.permissions.roles.join('; ') }]],
    agents: [r.agents.agents, [
      { label: 'Agent', value: 'name' }, { label: 'Object ID', value: 'id' }, { label: 'Blueprint', value: 'blueprintName' }, { label: 'Publisher', value: 'publisher' },
      { label: 'Enabled', value: (a) => (a.enabled ? 'Yes' : 'No') }, { label: 'Sponsors', value: (a) => (a.sponsors === null ? 'unknown' : a.sponsorNames.join('; ') || a.sponsors) },
      { label: 'Risk', value: (a) => (a.risk ? `${a.risk.level} (${a.risk.state})` : '') },
      { label: 'Critical permissions', value: (a) => a.permissionSummary.critical.join('; ') }, { label: 'High permissions', value: (a) => a.permissionSummary.high.join('; ') },
      { label: 'Directory roles', value: (a) => a.roles.map((x) => x.name).join('; ') },
      { label: 'Covered by', value: (a) => a.coveredBy.map((c) => `${c.name} (${STATE_TXT[c.state]})`).join('; ') },
      { label: 'Excluded from', value: (a) => a.excludedBy.map((c) => c.name).join('; ') },
      { label: 'Agent user accounts', value: (a) => a.agentUsers.map((u) => u.upn).join('; ') },
      { label: 'Issues', value: (a) => a.issues.map((i) => `[${i.severity}] ${i.text}`).join(' | ') },
      { label: 'Owner (fill in)', value: () => '' }, { label: 'Decision (fill in)', value: () => '' }]],
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
    const t = e.target.closest('[data-action],[data-tab],[data-goto],[data-crown],[data-app-filter],[data-exc-verdict],[data-area],[data-sev],[data-agent-filter],[data-prompt],[data-whatif-app],[data-whatif-agent],[data-exc-policy]');
    if (!t) return;
    if (t.dataset.action === 'import-purview' || t.dataset.action === 'import-crown') return;
    if (t.dataset.crown) { e.preventDefault(); e.stopPropagation(); toggleCrown(t.dataset.crown); return; }
    if (t.dataset.tab) { goTo(t.dataset.tab); return; }
    if (t.dataset.goto) { e.preventDefault(); goTo(t.dataset.goto); return; }
    if (t.dataset.sev) { state.findingSev = t.dataset.sev; render(); return; }
    if (t.dataset.agentFilter) { state.agentFilter = t.dataset.agentFilter; render(); return; }
    if (t.dataset.whatifAgent) { state.whatIf = { ...(state.whatIf || defaultWhatIf()), userType: 'agent', agentId: t.dataset.whatifAgent, appId: '00000003-0000-0ff1-ce00-000000000000' }; goTo('whatif'); return; }
    if (t.dataset.appFilter) { state.appFilter = t.dataset.appFilter; state.appLimit = 150; render(); return; }
    if (t.dataset.excVerdict) { state.excVerdict = t.dataset.excVerdict; render(); return; }
    if (t.dataset.area) { state.findingArea = t.dataset.area === state.findingArea ? 'all' : t.dataset.area; render(); return; }
    if (t.dataset.prompt) { askAi(t.dataset.prompt); return; }
    if (t.dataset.whatifApp) { state.whatIf = { ...(state.whatIf || defaultWhatIf()), userType: 'member', appId: t.dataset.whatifApp }; goTo('whatif'); return; }
    if (t.dataset.excPolicy) { state.excQuery = t.dataset.excPolicy; state.excVerdict = 'all'; state.excKind = 'all'; goTo('exceptions'); return; }
    switch (t.dataset.action) {
      case 'toggle-setup-help': e.preventDefault(); $('setup-help').classList.toggle('hidden'); break;
      case 'demo': loadDemo(); break;
      case 'rescan': runScan(); break;
      case 'signout': signOut(); break;
      case 'theme': toggleTheme(); break;
      case 'clear-purview': clearPurview(); break;
      case 'export-agents': exportCsv('agents'); break;
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
    if (t.dataset?.action === 'import-purview' && t.files?.[0]) { importPurview(t.files[0]); t.value = ''; return; }
    if (t.closest('#whatif-form')) {
      readWhatIfForm();
      if (t.dataset.rerender) {
        // Switching between people and agents changes the form fields.
        const w = state.whatIf;
        if (w.userType === 'agent' && !w.agentId) w.agentId = state.results.agents.agents[0]?.id || '';
        render();
      } else runWhatIf();
      return;
    }
    if (t.dataset?.input === 'excKind') { state.excKind = t.value; render(); }
  });

  // Debounced search boxes keep focus across re-renders.
  let searchTimer;
  document.addEventListener('input', (e) => {
    const key = e.target.dataset?.input;
    if (key !== 'appQuery' && key !== 'excQuery' && key !== 'findingQuery') return;
    state[key] = e.target.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const pos = e.target.selectionStart;
      render();
      const el = document.querySelector(`[data-input="${key}"]`);
      if (el) { el.focus(); el.setSelectionRange(pos, pos); }
    }, 200);
  });

  // Drag and drop a Purview export onto the import card.
  document.addEventListener('dragover', (e) => {
    const zone = e.target.closest?.('[data-drop="purview"]');
    if (!zone) return;
    e.preventDefault();
    zone.classList.add('dragging');
  });
  document.addEventListener('dragleave', (e) => {
    e.target.closest?.('[data-drop="purview"]')?.classList.remove('dragging');
  });
  document.addEventListener('drop', (e) => {
    const zone = e.target.closest?.('[data-drop="purview"]');
    if (!zone) return;
    e.preventDefault();
    zone.classList.remove('dragging');
    const file = e.dataTransfer?.files?.[0];
    if (file) importPurview(file);
  });

  // Keyboard: arrow keys move through the section navigation.
  $('tabs').addEventListener('keydown', (e) => {
    if (!['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].includes(e.key)) return;
    const items = [...$('tabs').querySelectorAll('.nav-item')];
    const i = items.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    const next = items[(i + (e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length];
    next.focus();
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
  paintThemeButtons();
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
