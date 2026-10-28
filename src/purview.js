// Microsoft Purview: sensitivity labels and DLP, cross-checked against
// Conditional Access.
//
// Purview DLP policies cannot be read through Microsoft Graph from a browser.
// Two sources are used instead:
//   1. Sensitivity labels from Graph (/me/security/informationProtection/sensitivityLabels).
//   2. An optional JSON export the admin creates with
//      infra/Export-PurviewForEntraCompass.ps1 and loads into the page. It is
//      parsed here, in the browser, and kept in sessionStorage only.
//
// Pure functions. No DOM, no network. Covered by test/purview.test.js.

import { DOCS } from './knowledge.js';

export const MAX_IMPORT_BYTES = 5 * 1024 * 1024;

export const LOCATIONS = {
  exchange: 'Exchange email',
  sharePoint: 'SharePoint sites',
  oneDrive: 'OneDrive accounts',
  teams: 'Teams chat and channels',
  endpoint: 'Devices (Endpoint DLP)',
  mdca: 'Cloud apps (Defender for Cloud Apps)',
  onPrem: 'On-premises repositories',
  powerBI: 'Power BI',
  copilot: 'Microsoft 365 Copilot and agents',
};
export const CORE_LOCATIONS = ['exchange', 'sharePoint', 'oneDrive', 'teams'];

// Microsoft 365 Copilot DLP location app ID, as used in the Locations JSON.
const COPILOT_LOCATION = /copilot|470f2276-e011-4e9d-a6ec-20768be3a4b0/i;

const WORKLOAD_MAP = [
  [/exchange/i, 'exchange'], [/sharepoint/i, 'sharePoint'], [/onedrive/i, 'oneDrive'], [/teams/i, 'teams'],
  [/endpoint/i, 'endpoint'], [/thirdparty|cloudapp|mcas/i, 'mdca'], [/onpremises|scanner/i, 'onPrem'], [/powerbi/i, 'powerBI'],
];

const LOCATION_FIELDS = {
  ExchangeLocation: 'exchange', SharePointLocation: 'sharePoint', OneDriveLocation: 'oneDrive', TeamsLocation: 'teams',
  EndpointDlpLocation: 'endpoint', ThirdPartyAppDlpLocation: 'mdca', OnPremisesScannerDlpLocation: 'onPrem', PowerBIDlpLocation: 'powerBI',
};

const str = (v) => (v === null || v === undefined ? '' : typeof v === 'string' ? v : JSON.stringify(v));
const arr = (v) => (Array.isArray(v) ? v : v === null || v === undefined || v === '' ? [] : [v]);
const pick = (o, ...keys) => { for (const k of keys) if (o && o[k] !== undefined && o[k] !== null) return o[k]; return undefined; };

function modeOf(p) {
  const m = String(pick(p, 'Mode', 'mode') ?? '').toLowerCase();
  const enabled = pick(p, 'Enabled', 'enabled');
  if (enabled === false || m === 'disable' || m === 'disabled' || m === 'pendingdeletion') return 'off';
  if (m.startsWith('test') || m === 'audit' || m === 'simulate') return 'test';
  return 'enforce';
}

function locationsOf(p) {
  const out = new Set();
  for (const [field, key] of Object.entries(LOCATION_FIELDS)) {
    if (arr(p[field]).filter((x) => str(x).trim()).length) out.add(key);
  }
  const workload = str(pick(p, 'Workload', 'workload'));
  for (const [re, key] of WORKLOAD_MAP) if (re.test(workload)) out.add(key);
  const locJson = str(pick(p, 'Locations', 'locations')) + ' ' + str(pick(p, 'EnforcementPlanes')) + ' ' + workload;
  if (COPILOT_LOCATION.test(locJson) || COPILOT_LOCATION.test(str(p.Name))) out.add('copilot');
  return out;
}

// Accepts the EntraCompass export, or loose ConvertTo-Json output of the
// individual cmdlets. Throws a readable error when the file is not usable.
export function parsePurviewExport(text, { fileName = '' } = {}) {
  if (typeof text !== 'string' || !text.trim()) throw new Error('The file is empty.');
  if (text.length > MAX_IMPORT_BYTES) throw new Error('The file is larger than 5 MB.');
  let j;
  try { j = JSON.parse(text.replace(/^﻿/, '')); } catch { throw new Error('The file is not valid JSON.'); }

  let policies; let rules; let labels; let labelPolicies; let autoLabel;
  if (Array.isArray(j)) {
    // A single cmdlet's output: guess which one from the shape.
    const first = j[0] || {};
    if ('ParentPolicyName' in first) rules = j;
    else if ('EncryptionEnabled' in first || 'LabelActions' in first || 'ContentType' in first) labels = j;
    else policies = j;
  } else if (j && typeof j === 'object') {
    policies = pick(j, 'dlpPolicies', 'DlpPolicies', 'policies');
    rules = pick(j, 'dlpRules', 'DlpRules', 'rules');
    labels = pick(j, 'labels', 'Labels', 'sensitivityLabels');
    labelPolicies = pick(j, 'labelPolicies', 'LabelPolicies');
    autoLabel = pick(j, 'autoLabelPolicies', 'AutoLabelPolicies');
  } else {
    throw new Error('Unrecognised file. Use the output of Export-PurviewForEntraCompass.ps1.');
  }
  policies = arr(policies).filter((x) => x && typeof x === 'object');
  rules = arr(rules).filter((x) => x && typeof x === 'object');
  labels = arr(labels).filter((x) => x && typeof x === 'object');
  if (!policies.length && !rules.length && !labels.length) throw new Error('No DLP policies, rules or sensitivity labels found in this file.');

  const normRules = rules.map((r) => {
    const restrictions = str(pick(r, 'EndpointDlpRestrictions')) + str(pick(r, 'RestrictAccess')) + str(pick(r, 'BlockAccessScope'));
    const blocks = pick(r, 'BlockAccess') === true || /"?(Setting|Value)"?\s*[:=]\s*"?Block/i.test(restrictions) || /\bBlock\b/.test(str(pick(r, 'Actions')));
    const sit = arr(pick(r, 'ContentContainsSensitiveInformation')).length;
    return {
      name: str(pick(r, 'Name', 'name')).slice(0, 200),
      policy: str(pick(r, 'ParentPolicyName', 'Policy')).slice(0, 200),
      disabled: pick(r, 'Disabled') === true,
      blocks: !!blocks,
      notifies: !!pick(r, 'NotifyUser') && arr(pick(r, 'NotifyUser')).length > 0,
      sensitiveTypes: sit,
      usesLabels: /label/i.test(str(pick(r, 'AdvancedRule')) + str(pick(r, 'ContentContainsSensitiveInformation'))),
    };
  });

  const normPolicies = policies.map((p) => {
    const name = str(pick(p, 'Name', 'name', 'DisplayName')).slice(0, 200) || 'Unnamed policy';
    const myRules = normRules.filter((r) => r.policy === name);
    return {
      name,
      mode: modeOf(p),
      locations: [...locationsOf(p)],
      modified: pick(p, 'WhenChangedUTC', 'WhenChanged', 'LastModifiedTime') || null,
      rules: myRules.length,
      blockingRules: myRules.filter((r) => !r.disabled && r.blocks).length,
    };
  });

  const normLabels = labels.map((l) => {
    const actions = arr(pick(l, 'LabelActions')).map(str).join(' ');
    const settings = arr(pick(l, 'Settings')).map(str).join(' ');
    const ctxMatch = (settings + ' ' + actions).match(/authenticationcontextid[^0-9a-z]*([0-9a-z-]+)/i);
    return {
      id: str(pick(l, 'Guid', 'ImmutableId', 'Id', 'id')),
      name: str(pick(l, 'DisplayName', 'Name', 'name')).slice(0, 200),
      parentId: str(pick(l, 'ParentId', 'parentId')) || null,
      disabled: pick(l, 'Disabled') === true,
      encryption: pick(l, 'EncryptionEnabled') === true || /"?type"?\s*[:=]\s*"?encrypt/i.test(actions),
      authContext: ctxMatch ? ctxMatch[1] : null,
      scope: str(pick(l, 'ContentType')),
    };
  });

  return {
    fileName: String(fileName).slice(0, 120),
    exportedAt: (j && !Array.isArray(j) && pick(j, 'exportedAt', 'ExportedAt')) || null,
    importedAt: new Date().toISOString(),
    dlpPolicies: normPolicies,
    dlpRules: normRules,
    labels: normLabels,
    labelPolicies: arr(labelPolicies).length,
    autoLabelPolicies: arr(autoLabel).map((a) => ({ name: str(pick(a, 'Name')).slice(0, 200), mode: modeOf(a) })),
  };
}

const DAY = 86400000;

// ctx: { now, dlpControls, authContexts (defined), enforcedAuthContexts: Set, agentsInUse, rmsExcluded: [] }
export function analyzePurview(raw, imported, ctx) {
  const graphLabels = (raw.sensitivityLabels || []).map((l) => ({
    id: l.id, name: l.displayName || l.name, encryption: !!(l.hasProtection ?? l.isEncryptingContent), active: l.isActive !== false,
    parent: l.parent?.name || l.parent?.displayName || null,
  }));
  const labelsKnown = !!raw.sources?.sensitivityLabels?.ok || graphLabels.length > 0 || !!imported?.labels?.length;
  const labels = imported?.labels?.length ? imported.labels : graphLabels;
  const dlp = imported?.dlpPolicies || [];
  const hasDlp = !!imported && (dlp.length > 0 || (imported.dlpRules || []).length > 0);
  const ctl = (id) => (ctx.dlpControls || []).find((c) => c.id === id);

  const coverage = Object.fromEntries(Object.keys(LOCATIONS).map((k) => {
    const pol = dlp.filter((p) => p.locations.includes(k));
    return [k, { enforced: pol.filter((p) => p.mode === 'enforce').length, test: pol.filter((p) => p.mode === 'test').length, policies: pol.map((p) => p.name) }];
  }));

  const checks = [];
  const add = (c) => checks.push(c);
  const needImport = 'Load a Purview export to assess this.';

  add({
    id: 'labels', title: 'Sensitivity labels are published',
    status: !labelsKnown ? 'unknown' : labels.length ? 'present' : 'missing',
    detail: !labelsKnown ? 'Labels could not be read (needs InformationProtectionPolicy.Read) and no export is loaded.' : labels.length ? `${labels.length} label${labels.length > 1 ? 's' : ''}${imported?.labels?.length ? ' (from export)' : ' published to the signed-in admin'}.` : 'No sensitivity labels found.',
    why: 'Labels classify data so DLP, encryption, Copilot and Conditional Access authentication contexts can act on it.',
    ref: DOCS.sensitivityLabels,
  });
  const enc = labels.filter((l) => l.encryption);
  add({
    id: 'labelsProtected', title: 'Labels protect the most sensitive data with encryption',
    status: !labelsKnown || !labels.length ? 'unknown' : enc.length ? 'present' : 'missing',
    detail: !labels.length ? 'No label data.' : enc.length ? `${enc.length} encrypting label${enc.length > 1 ? 's' : ''}: ${enc.slice(0, 6).map((l) => l.name).join(', ')}.` : 'No label applies encryption.',
    why: 'Encryption travels with the file: it keeps working after the data leaves Microsoft 365, where Conditional Access and DLP cannot reach.',
    ref: DOCS.sensitivityLabels,
  });

  const coreOn = CORE_LOCATIONS.filter((k) => coverage[k].enforced);
  add({
    id: 'dlpCore', title: 'DLP enforced on email, files and Teams',
    status: !hasDlp ? 'unknown' : coreOn.length === CORE_LOCATIONS.length ? 'present' : coreOn.length || CORE_LOCATIONS.some((k) => coverage[k].test) ? 'partial' : 'missing',
    detail: !hasDlp ? needImport : `Enforced on: ${coreOn.map((k) => LOCATIONS[k]).join(', ') || 'none'}.${CORE_LOCATIONS.filter((k) => !coverage[k].enforced).length ? ` Not enforced: ${CORE_LOCATIONS.filter((k) => !coverage[k].enforced).map((k) => LOCATIONS[k] + (coverage[k].test ? ' (test mode)' : '')).join(', ')}.` : ''}`,
    why: 'Exchange, SharePoint, OneDrive and Teams hold most business data. A location without an enforced policy only logs, or does nothing.',
    ref: DOCS.dlpLocations,
  });

  const managed = ctl('managed');
  const endpointOn = coverage.endpoint.enforced > 0;
  add({
    id: 'dlpEndpoint', title: 'Endpoint DLP is backed by a managed-device policy',
    status: !hasDlp ? 'unknown' : endpointOn && managed?.status === 'present' ? 'present' : endpointOn || coverage.endpoint.test ? 'partial' : 'missing',
    detail: !hasDlp ? needImport : endpointOn
      ? (managed?.status === 'present' ? 'Endpoint DLP is enforced and Conditional Access requires managed devices for Office 365.' : 'Endpoint DLP is enforced, but Conditional Access does not require a managed device: data can sync to devices Endpoint DLP never sees.')
      : coverage.endpoint.test ? 'Endpoint DLP is only in test mode.' : 'No DLP policy covers devices.',
    why: 'Endpoint DLP only works on onboarded devices. Conditional Access is what keeps company data off the devices it cannot see.',
    ref: DOCS.endpointDlp,
  });

  const mda = ctl('mda');
  const mdcaOn = coverage.mdca.enforced > 0;
  add({
    id: 'dlpMdca', title: 'Browser sessions on unmanaged devices are inspected',
    status: !hasDlp ? (mda?.status === 'present' ? 'partial' : 'unknown') : mdcaOn && mda?.status === 'present' ? 'present' : mdcaOn || mda?.status !== 'missing' ? 'partial' : 'missing',
    detail: !hasDlp ? (mda ? `Conditional Access session control: ${mda.status}. ${needImport}` : needImport)
      : mdcaOn && mda?.status !== 'present' ? 'DLP covers cloud apps through Defender for Cloud Apps, but no Conditional Access policy routes sessions there with a blocking control, so session policies never run.'
        : !mdcaOn && mda?.status !== 'missing' ? 'Conditional Access routes sessions to Defender for Cloud Apps, but no DLP policy covers that location.'
          : mdcaOn ? 'DLP on cloud apps and Conditional Access session control are both in place.' : 'Neither DLP for cloud apps nor Conditional Access session control is in place.',
    why: 'Session control is how DLP reaches personal devices: block download, label or encrypt on download, monitor activity.',
    ref: DOCS.appControl,
  });

  const copilotOn = coverage.copilot.enforced > 0;
  add({
    id: 'dlpCopilot', title: 'DLP covers Microsoft 365 Copilot and agents',
    status: !hasDlp ? 'unknown' : copilotOn ? 'present' : coverage.copilot.test ? 'partial' : 'missing',
    detail: !hasDlp ? needImport : copilotOn ? `Enforced: ${coverage.copilot.policies.join(', ')}.` : coverage.copilot.test ? 'A Copilot DLP policy exists in test mode only.' : `No DLP policy uses the Microsoft 365 Copilot location.${ctx.agentsInUse ? ' This tenant has AI agents.' : ''}`,
    why: 'Copilot and agents read whatever the user (or agent) can reach. The Copilot DLP location stops them processing labelled or sensitive content.',
    ref: DOCS.dlpCopilot,
  });

  const test = dlp.filter((p) => p.mode === 'test');
  const staleTest = test.filter((p) => p.modified && ctx.now && (ctx.now - new Date(p.modified)) / DAY > 60);
  add({
    id: 'dlpTestMode', title: 'DLP policies are not stuck in test mode',
    status: !hasDlp ? 'unknown' : !test.length ? 'present' : staleTest.length ? 'missing' : 'partial',
    detail: !hasDlp ? needImport : !test.length ? 'No DLP policy is in test mode.' : `${test.length} in test mode${staleTest.length ? `, ${staleTest.length} unchanged for over 60 days` : ''}: ${test.slice(0, 6).map((p) => p.name).join(', ')}.`,
    why: 'Test mode only logs. Policies left there give a false sense of protection.',
    ref: DOCS.dlpLocations,
  });

  const labelCtx = labels.filter((l) => l.authContext);
  const unenforced = labelCtx.filter((l) => !ctx.enforcedAuthContexts?.has(l.authContext));
  add({
    id: 'labelAuthContext', title: 'Labels that demand step-up have a policy behind them',
    status: !labelsKnown ? 'unknown' : !labelCtx.length ? 'info' : unenforced.length ? 'missing' : 'present',
    detail: !labelCtx.length ? 'No label references an authentication context (only visible in an export).' : unenforced.length ? `Not enforced by any Conditional Access policy: ${unenforced.map((l) => `${l.name} (context ${l.authContext})`).join(', ')}.` : 'Every authentication context used by a label is enforced.',
    why: 'A site label can require an authentication context, but without a Conditional Access policy for that context nothing extra is asked.',
    ref: DOCS.labelAuthContext,
  });

  if (enc.length && (ctx.rmsExcluded || []).length) {
    add({ id: 'rmsAccess', title: 'Access to encrypted content is excluded from a policy', status: 'info', detail: `Rights Management Services is excluded in ${ctx.rmsExcluded.join(', ')}, and ${enc.length} label${enc.length > 1 ? 's' : ''} encrypt content.`, why: 'Usually done so external recipients can open protected files. Record it as a DLP decision with an owner.', ref: DOCS.purviewDlp });
  }

  return {
    imported: imported ? { fileName: imported.fileName, exportedAt: imported.exportedAt, importedAt: imported.importedAt } : null,
    labels, labelsSource: imported?.labels?.length ? 'export' : graphLabels.length ? 'graph' : 'none',
    dlpPolicies: dlp, dlpRules: imported?.dlpRules || [], coverage,
    autoLabelPolicies: imported?.autoLabelPolicies || [],
    labelPolicies: imported?.labelPolicies || 0,
    checks,
    totals: {
      labels: labels.length, encrypting: enc.length,
      dlpPolicies: dlp.length, enforced: dlp.filter((p) => p.mode === 'enforce').length, test: test.length,
      locationsEnforced: Object.values(coverage).filter((c) => c.enforced).length,
    },
  };
}

export function purviewFindings(pv, agentsInUse, add) {
  const sev = { labels: 'medium', labelsProtected: 'low', dlpCore: 'high', dlpEndpoint: 'medium', dlpMdca: 'medium', dlpCopilot: agentsInUse ? 'high' : 'medium', dlpTestMode: 'low', labelAuthContext: 'medium' };
  const fix = {
    labels: 'Publish a simple label taxonomy (for example Public, General, Confidential, Highly Confidential).',
    labelsProtected: 'Add encryption to the Highly Confidential label (and sub-labels) for the data that must stay protected outside Microsoft 365.',
    dlpCore: 'Enforce DLP for sensitive information types and labels on Exchange, SharePoint, OneDrive and Teams. Use policy tips before blocking.',
    dlpEndpoint: 'Require a compliant device (or app protection) for Office 365 desktop and mobile apps, so data only lands where Endpoint DLP runs.',
    dlpMdca: 'Pair a Conditional Access session control (Defender for Cloud Apps, block or protect on download) with DLP for cloud apps.',
    dlpCopilot: 'Create a DLP policy on the Microsoft 365 Copilot location that excludes Highly Confidential content from Copilot and agents.',
    dlpTestMode: 'Review the test-mode matches, tune false positives, then turn the policies on.',
    labelAuthContext: 'Create a Conditional Access policy for each authentication context used by a label (for example phishing-resistant MFA plus compliant device).',
  };
  const partialTitle = {
    dlpCore: 'DLP is not enforced on every core workload',
    dlpEndpoint: 'Endpoint DLP is not backed by a managed-device policy',
    dlpMdca: 'DLP for cloud apps and session control are not paired',
    dlpCopilot: 'DLP for Copilot and agents is only in test mode',
    dlpTestMode: 'Some DLP policies are in test mode',
  };
  const missingTitle = {
    labels: 'No sensitivity labels are published',
    labelsProtected: 'No sensitivity label encrypts content',
    dlpCore: 'No DLP policy is enforced on email, files or Teams',
    dlpEndpoint: 'No DLP policy covers devices',
    dlpMdca: 'Browser sessions on unmanaged devices are not inspected',
    dlpCopilot: 'Copilot and AI agents are not covered by DLP',
    dlpTestMode: 'DLP policies have been in test mode for over 60 days',
    labelAuthContext: 'Labels require step-up authentication that no policy enforces',
  };
  for (const c of pv.checks) {
    if (!sev[c.id] || ['present', 'info', 'unknown'].includes(c.status)) continue;
    const s = c.status === 'partial' && c.id !== 'dlpEndpoint' ? SEVS[Math.min(SEVS.indexOf(sev[c.id]) + 1, 3)] : sev[c.id];
    add({ area: 'dlp', severity: s, title: (c.status === 'partial' ? partialTitle[c.id] : missingTitle[c.id]) || c.title, detail: c.detail, impact: c.why, fix: fix[c.id], ref: c.ref, purview: true, business: c.id === 'dlpEndpoint' || c.id === 'dlpCopilot' });
  }
}

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
