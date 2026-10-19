// Executive report: a self-contained HTML document built from analyzer results.
// Light theme, print-friendly, no external resources, so it can be printed to
// PDF or downloaded and emailed as a single file.

import { esc, fmtDate } from './util.js';

const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const Q_LABEL = { good: 'Yes', warn: 'Partly', bad: 'No', unknown: 'Not assessed' };
const CTRL_LABEL = { present: 'In place', partial: 'Partial', missing: 'Missing' };
const VERDICT_LABEL = { gap: 'Opens a gap', review: 'Needs owner review', cleanup: 'Likely removable', stale: 'Points to deleted object', justified: 'Looks justified' };

export function buildReportHtml(r, { demo = false } = {}) {
  const s = r.summary;
  const sc = r.scores;
  const top = r.findings.filter((f) => f.severity !== 'info').slice(0, 10);
  const roadmap = {
    '30 days': r.findings.filter((f) => f.severity === 'critical' || (f.severity === 'high' && f.area !== 'workload')),
    '60 days': r.findings.filter((f) => f.severity === 'high' && f.area === 'workload' || (f.severity === 'medium' && ['exceptions', 'crown', 'access'].includes(f.area))),
    '90 days': r.findings.filter((f) => f.severity === 'medium' && !['exceptions', 'crown', 'access'].includes(f.area)),
  };
  const crown = r.apps.filter((a) => a.crownJewel);
  const unprotected = r.apps.filter((a) => a.protection === 'none' && a.category !== 'microsoft').slice(0, 15);
  const gaps = r.exclusions.filter((e) => e.verdict === 'gap').slice(0, 15);
  const failed = Object.values(r.sources || {}).filter((x) => x && x.ok === false);
  const w = s.workforceOutsideMfa;

  const exposures = top.slice(0, 3).map((f) => esc(f.title)).join('; ');
  const intro = `Overall Conditional Access posture is <b>${esc(sc.rating.label)}</b> (${sc.overall}/100). ` +
    (exposures ? `The most important exposures are: ${exposures}. ` : 'No significant exposures were found. ') +
    `${s.policyCounts.enabled} of ${s.policyCounts.total} policies are enforced; ${s.exclusionTotal} exceptions are in place, of which ${s.exclusions.gap || 0} open a security gap.`;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Conditional Access Posture Assessment - ${esc(s.tenantName)}</title>
<style>${REPORT_CSS}</style></head>
<body><div class="rp">
<header class="rp-head">
  <div>
    <div class="rp-kicker">Conditional Access Posture Assessment</div>
    <h1>${esc(s.tenantName)}</h1>
    <div class="rp-meta">Scanned ${esc(fmtDate(s.scannedAt, true))}${demo ? ' &middot; SAMPLE DATA' : ''} &middot; Business, data protection (DLP) and security view</div>
  </div>
  <div class="rp-score ${sc.rating.tone}"><div class="n">${sc.overall}</div><div class="l">${esc(sc.rating.label)}</div></div>
</header>

<section><h2>Summary</h2><p>${intro}</p>
<table class="kv">
  <tr><td>Accounts in the directory</td><td>${(s.users.total || 0).toLocaleString()} (${(s.users.guests || 0).toLocaleString()} guests)</td></tr>
  <tr><td>Conditional Access policies</td><td>${s.policyCounts.enabled} on, ${s.policyCounts.reportOnly} report-only, ${s.policyCounts.disabled} off</td></tr>
  <tr><td>People outside the main MFA policy</td><td>${w.covered ? `${w.approximate ? 'at least ' : ''}${(w.people || 0).toLocaleString()}${w.percent !== null ? ` (${w.percent}%)` : ''}` : 'No MFA-for-everyone policy'}</td></tr>
  <tr><td>Business applications assessed</td><td>${s.apps.business} (${s.apps.unprotected} with no MFA policy, ${s.apps.excluded} excluded from a policy)</td></tr>
  <tr><td>Exceptions</td><td>${s.exclusionTotal} (${s.exclusions.gap || 0} gaps, ${s.exclusions.review || 0} to review, ${(s.exclusions.cleanup || 0) + (s.exclusions.stale || 0)} to clean up)</td></tr>
  <tr><td>App registrations with credentials</td><td>${r.workload.apps.length} (${r.workload.totals.withSecrets} with client secrets)</td></tr>
</table></section>

<section><h2>Answers for management</h2>
${r.questions.map((q) => `<div class="qa ${q.status}"><div class="qa-q"><span class="qa-tag">${Q_LABEL[q.status] || ''}</span>${esc(q.q)}</div><div class="qa-a">${esc(q.a)}</div></div>`).join('')}
</section>

<section><h2>Scores by area</h2>
<table class="grid"><thead><tr><th>Area</th><th>Score</th><th>Findings</th></tr></thead><tbody>
${Object.values(sc.areas).map((a) => `<tr><td>${esc(a.label)}</td><td>${a.score === null ? 'Not assessed' : `<span class="bar"><span style="width:${a.score}%"></span></span> ${a.score}`}</td><td>${a.findings}</td></tr>`).join('')}
</tbody></table>
<p class="note">Each area starts at 100 and loses points per finding (critical 30, high 15, medium 7, low 3). The overall score is a weighted average.</p>
</section>

<section class="pb"><h2>Priority actions</h2>
<table class="grid"><thead><tr><th>#</th><th>Severity</th><th>Issue</th><th>Business impact</th><th>Action</th></tr></thead><tbody>
${top.map((f, i) => `<tr><td>${i + 1}</td><td><span class="sev ${f.severity}">${SEV_LABEL[f.severity]}</span></td><td><b>${esc(f.title)}</b></td><td>${esc(f.impact || '')}</td><td>${esc(f.fix || '')}</td></tr>`).join('') || '<tr><td colspan="5">No significant issues found.</td></tr>'}
</tbody></table></section>

<section><h2>Roadmap</h2>
<div class="road">${Object.entries(roadmap).map(([k, list]) => `<div class="road-col"><h3>Within ${k}</h3>${list.length ? `<ul>${list.slice(0, 8).map((f) => `<li>${esc(f.title)}</li>`).join('')}${list.length > 8 ? `<li>and ${list.length - 8} more</li>` : ''}</ul>` : '<p class="note">Nothing scheduled.</p>'}</div>`).join('')}</div>
</section>

<section class="pb"><h2>Exceptions that open a gap</h2>
${gaps.length ? `<table class="grid"><thead><tr><th>Type</th><th>Excluded</th><th>Policy</th><th>Why it matters</th></tr></thead><tbody>
${gaps.map((e) => `<tr><td>${esc(e.kind)}</td><td>${esc(e.targetName)}${e.size ? ` (${e.size.toLocaleString()})` : ''}</td><td>${esc(e.policyName)}</td><td>${esc(e.reason)}</td></tr>`).join('')}
</tbody></table>` : '<p>None found.</p>'}
<p class="note">Breakdown of all ${s.exclusionTotal} exceptions: ${Object.entries(VERDICT_LABEL).map(([k, v]) => `${v}: ${s.exclusions[k] || 0}`).join(' &middot; ')}.</p>
</section>

<section><h2>Crown-jewel applications</h2>
${crown.length ? `<table class="grid"><thead><tr><th>Application</th><th>MFA</th><th>Phishing-resistant</th><th>Device / session control</th><th>Excluded from</th></tr></thead><tbody>
${crown.map((a) => `<tr><td><b>${esc(a.name)}</b><div class="note">${esc(a.categoryLabel)}</div></td><td>${esc(PROT[a.protection])}</td><td>${a.phishingResistant ? 'Yes' : 'No'}</td><td>${a.managedDevice || a.sessionControl ? 'Yes' : 'No'}</td><td>${a.excludedBy.length ? esc(a.excludedBy.map((p) => p.name).join(', ')) : 'None'}</td></tr>`).join('')}
</tbody></table>` : '<p>No crown-jewel applications were tagged for this assessment. Tagging them (with the business) gives the most useful answer to "are our most important systems protected?".</p>'}
</section>

<section><h2>Business applications with no MFA policy</h2>
${unprotected.length ? `<table class="grid"><thead><tr><th>Application</th><th>Type</th><th>Last used</th></tr></thead><tbody>
${unprotected.map((a) => `<tr><td>${esc(a.name)}</td><td>${esc(a.categoryLabel)}</td><td>${a.lastUsed ? esc(fmtDate(a.lastUsed)) : (a.unused === null ? 'Unknown' : 'No sign-ins recorded')}</td></tr>`).join('')}
</tbody></table>${s.apps.unprotected > unprotected.length ? `<p class="note">Showing ${unprotected.length} of ${s.apps.unprotected}.</p>` : ''}` : '<p>Every business application falls under at least one MFA policy.</p>'}
</section>

<section class="pb"><h2>Data protection (DLP) controls on the identity side</h2>
<table class="grid"><thead><tr><th>Control</th><th>Status</th><th>Why it matters</th></tr></thead><tbody>
${r.dlp.controls.map((c) => `<tr><td><b>${esc(c.title)}</b><div class="note">${esc(c.detail)}</div></td><td><span class="st ${c.status}">${CTRL_LABEL[c.status]}</span></td><td>${esc(c.why)}</td></tr>`).join('')}
</tbody></table>
<p class="note">${esc(r.dlp.note)}</p>
</section>

<section><h2>Named locations</h2>
${r.locations.length ? `<table class="grid"><thead><tr><th>Location</th><th>Type</th><th>Trusted</th><th>Used by</th><th>Observations</th></tr></thead><tbody>
${r.locations.map((l) => `<tr><td>${esc(l.name)}</td><td>${l.type === 'ip' ? `IP (${l.rangeCount} ranges)` : l.type === 'country' ? `Countries (${l.countries.length})` : 'Other'}</td><td>${l.trusted ? 'Yes' : 'No'}</td><td>${l.usedBy.length} policies</td><td>${l.issues.map((i) => esc(i.text)).join(' ') || 'None'}</td></tr>`).join('')}
</tbody></table>` : '<p>No named locations defined.</p>'}
</section>

<section><h2>Workload identities</h2>
<table class="kv">
<tr><td>App registrations with credentials</td><td>${r.workload.apps.length}</td></tr>
<tr><td>With client secrets</td><td>${r.workload.totals.withSecrets}</td></tr>
<tr><td>Valid credentials, no recent use</td><td>${r.workload.totals.dormant}</td></tr>
<tr><td>Secrets valid for more than a year</td><td>${r.workload.totals.longLived}</td></tr>
<tr><td>Credentials expiring within 30 days</td><td>${r.workload.totals.expiringSoon}</td></tr>
<tr><td>Workload identity policies</td><td>${r.workload.policies.length ? r.workload.policies.map((p) => `${esc(p.name)} (${esc(p.stateLabel)})`).join(', ') : 'None'}</td></tr>
<tr><td>Managed identities</td><td>${r.workload.managedIdentities}</td></tr>
</table></section>

<section><h2>Scope and method</h2>
<p>Read-only assessment of the Microsoft Entra configuration through Microsoft Graph, run in the assessor's browser. No data was stored outside the browser.
Purview DLP rules are not readable through Graph and are out of scope; this report covers the identity controls that decide who can reach data, from where and on which devices.
Application usage comes from the Entra application sign-in activity report${r.summary.usageDataAvailable ? '' : ' (not available for this tenant, so usage-based checks were skipped)'}.</p>
${failed.length ? `<p class="warn-box">Some sources could not be read and the related checks are incomplete: ${failed.map((f) => `${esc(f.label)} (${esc(f.reason)})`).join(', ')}.</p>` : ''}
<p class="note">Generated by EntraCompass (github.com/arusso-aboutcloud/EntraCompass).</p>
</section>
</div></body></html>`;
}

const PROT = { strong: 'Always', conditional: 'With conditions', partial: 'Some users only', none: 'None' };

const REPORT_CSS = `
*{box-sizing:border-box}body{margin:0;background:#fff;color:#1b1f24;font:13px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}
.rp{max-width:980px;margin:0 auto;padding:32px 28px}
.rp-head{display:flex;justify-content:space-between;align-items:center;gap:16px;border-bottom:3px solid #1d4ed8;padding-bottom:16px;margin-bottom:8px}
.rp-kicker{color:#1d4ed8;font-weight:600;text-transform:uppercase;letter-spacing:.06em;font-size:11px}
h1{margin:4px 0;font-size:26px}h2{font-size:17px;margin:26px 0 10px;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:4px}h3{font-size:13px;margin:0 0 6px}
.rp-meta,.note{color:#64748b;font-size:12px}
.rp-score{text-align:center;border-radius:12px;padding:10px 18px;border:2px solid}.rp-score .n{font-size:34px;font-weight:700;line-height:1}.rp-score .l{font-size:12px;font-weight:600}
.rp-score.good{color:#047857;border-color:#047857}.rp-score.warn{color:#b45309;border-color:#b45309}.rp-score.danger{color:#b91c1c;border-color:#b91c1c}
table{width:100%;border-collapse:collapse}td,th{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid #e2e8f0}th{background:#f1f5f9;font-size:12px}
.kv td:first-child{color:#475569;width:45%}
.qa{border-left:4px solid #94a3b8;background:#f8fafc;padding:8px 12px;margin:8px 0;border-radius:0 6px 6px 0;break-inside:avoid}
.qa.good{border-color:#059669}.qa.warn{border-color:#d97706}.qa.bad{border-color:#dc2626}.qa-q{font-weight:600}.qa-tag{display:inline-block;min-width:74px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#475569}
.qa.good .qa-tag{color:#059669}.qa.warn .qa-tag{color:#b45309}.qa.bad .qa-tag{color:#dc2626}
.bar{display:inline-block;width:120px;height:8px;background:#e2e8f0;border-radius:4px;vertical-align:middle;overflow:hidden}.bar span{display:block;height:100%;background:#1d4ed8}
.sev,.st{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:999px;white-space:nowrap}
.sev.critical{background:#fee2e2;color:#991b1b}.sev.high{background:#ffedd5;color:#9a3412}.sev.medium{background:#fef3c7;color:#92400e}.sev.low{background:#e0f2fe;color:#075985}
.st.present{background:#d1fae5;color:#065f46}.st.partial{background:#fef3c7;color:#92400e}.st.missing{background:#fee2e2;color:#991b1b}
.road{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.road-col{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px}.road-col ul{margin:0;padding-left:18px}
.warn-box{background:#fffbeb;border:1px solid #f59e0b;padding:8px 12px;border-radius:6px}
tr,.road-col{break-inside:avoid}
@media print{.rp{padding:0}.pb{break-before:page}@page{margin:16mm}}
@media (max-width:700px){.road{grid-template-columns:1fr}.rp{padding:16px}}
`;
