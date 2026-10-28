// EntraCompass analyzer.
//
// Turns raw tenant data (see collect.js) into a business-oriented assessment:
// app coverage, exception inventory, named locations, workload identities,
// data protection (DLP) controls, a modern baseline, crown-jewel checks,
// scores and plain-language answers for management.
//
// Pure function of its input. No DOM, no network. Covered by test/analyzer.test.js.

import {
  KNOWN_APPS, MICROSOFT_TENANT_IDS, PRIVILEGED_ROLES, DIRECTORY_SYNC_ROLE,
  CROWN_JEWEL_HINTS, DOCS,
} from './knowledge.js';
import {
  isEnabled, isReportOnly, usersOf, appsOf, isWorkloadPolicy, targetsAllUsers,
  targetsAllResources, isUserActionPolicy, isAuthContextPolicy, appInScope, appExcluded,
  grantSummary, sessionSummary, conditionalScope, exclusionCount, isMicrosoftManaged,
  describeGrant, STATE_LABEL, isAgentPolicy, isAgentUserPolicy, isNonUserPolicy,
} from './policy.js';
import { analyzeAgents, agentFindings, buildPermissionIndex, workloadPermissionFindings, permissionsForApp } from './agents.js';
import { analyzePurview, purviewFindings } from './purview.js';

const DAY = 86400000;
const UNUSED_DAYS = 90;
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const PENALTY = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };

export const AREAS = {
  access: { label: 'Access coverage', weight: 0.22 },
  exceptions: { label: 'Exceptions', weight: 0.18 },
  dlp: { label: 'Data protection & Purview', weight: 0.18 },
  workload: { label: 'Workload identities', weight: 0.12 },
  agents: { label: 'AI agents', weight: 0.12 },
  locations: { label: 'Named locations', weight: 0.08 },
  crown: { label: 'Crown jewels', weight: 0.1 },
};

export const CATEGORY_LABEL = {
  appProxy: 'On-prem (App Proxy)',
  saml: 'SAML SSO',
  passwordSso: 'Password SSO',
  tenantApp: 'In-house app',
  saas: 'Third-party SaaS',
  microsoft: 'Microsoft',
  managedIdentity: 'Managed identity',
  agent: 'AI agent',
  other: 'Other',
};

export function analyze(raw, options = {}) {
  const now = options.now ? new Date(options.now) : new Date();
  const crownJewels = new Set(options.crownJewels || []);
  const ctx = buildContext(raw, now);
  const findings = [];
  const add = (f) => findings.push({ id: `f${findings.length + 1}`, ...f });

  const policies = analyzePolicies(ctx);
  const apps = analyzeApps(ctx, crownJewels);
  const exclusions = analyzeExclusions(ctx, crownJewels);
  const locations = analyzeLocations(ctx);
  const workload = analyzeWorkload(ctx);
  const dlp = analyzeDlp(ctx);
  const baseline = analyzeBaseline(ctx);
  const agents = analyzeAgents(raw, ctx);
  const purview = analyzePurview(raw, options.purview || null, {
    now: ctx.now, dlpControls: dlp.controls, enforcedAuthContexts: new Set(dlp.enforcedAuthContexts),
    agentsInUse: agents.inUse, rmsExcluded: dlp.rmsExcluded,
  });

  findingsFromBaseline(baseline, ctx, add);
  findingsFromPolicies(policies, ctx, add);
  findingsFromApps(apps, ctx, add);
  findingsFromExclusions(exclusions, ctx, add);
  findingsFromLocations(locations, ctx, add);
  findingsFromWorkload(workload, ctx, add);
  workloadPermissionFindings(raw, ctx, add);
  findingsFromDlp(dlp, add);
  purviewFindings(purview, agents.inUse, add);
  agentFindings(agents, add);
  findingsFromCrownJewels(apps.filter((a) => a.crownJewel), add);

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const scores = score(findings, { crown: crownJewels.size > 0, agents: agents.inUse });
  const workforce = workforceOutsideMfa(ctx, baseline);
  const summary = {
    tenantName: ctx.org?.displayName || 'Your tenant',
    tenantId: ctx.tenantId,
    scannedAt: raw.scannedAt || now.toISOString(),
    users: ctx.userCounts,
    policyCounts: {
      total: ctx.policies.length,
      enabled: ctx.policies.filter(isEnabled).length,
      reportOnly: ctx.policies.filter(isReportOnly).length,
      disabled: ctx.policies.filter((p) => p.state === 'disabled').length,
      workload: ctx.policies.filter(isWorkloadPolicy).length,
      agents: ctx.policies.filter((p) => isAgentPolicy(p) || isAgentUserPolicy(p, ctx.agentUserIds)).length,
    },
    apps: {
      business: apps.length,
      unprotected: apps.filter((a) => a.protection === 'none').length,
      excluded: apps.filter((a) => a.excludedBy.length).length,
      crownJewels: apps.filter((a) => a.crownJewel).length,
    },
    exclusions: countBy(exclusions, 'verdict'),
    exclusionTotal: exclusions.length,
    workforceOutsideMfa: workforce,
    findings: countBy(findings, 'severity'),
    usageDataAvailable: ctx.usageKnown,
    agents: agents.totals,
    purview: { ...purview.totals, imported: !!purview.imported },
  };

  const result = {
    summary, scores, findings, policies, apps, exclusions, locations, workload, dlp, baseline, agents, purview,
    sources: raw.sources || {},
    lookups: {
      groups: Object.values(ctx.dir).filter((o) => isType(o, 'group')).map((g) => ({ id: g.id, name: g.displayName, size: ctx.groupSizes[g.id] ?? null })),
      users: Object.values(ctx.dir).filter((o) => isType(o, 'user')).map((u) => ({ id: u.id, name: u.displayName, upn: u.userPrincipalName })),
      roles: Object.entries(ctx.roleNames).map(([id, name]) => ({ id, name })),
      locations: ctx.namedLocations.map((l) => ({ id: l.id, name: l.displayName, trusted: !!l.isTrusted, type: locType(l) })),
      authContexts: ctx.authContexts.map((c) => ({ id: c.id, name: c.displayName })),
    },
  };
  result.questions = managementQuestions(result, ctx);
  return result;
}

// ---------------------------------------------------------------------------
// Context / indexes
// ---------------------------------------------------------------------------

function buildContext(raw, now) {
  const policies = raw.policies || [];
  const sps = raw.servicePrincipals || [];
  const spByAppId = new Map(sps.map((s) => [s.appId, s]));
  const strengthById = Object.fromEntries((raw.authStrengths || []).map((s) => [s.id, s]));
  const roleNames = { ...PRIVILEGED_ROLES };
  for (const r of raw.roleTemplates || []) roleNames[r.id] = r.displayName;
  const signIns = new Map();
  for (const s of raw.spSignIns || []) {
    const dates = [
      s.lastSignInActivity?.lastSignInDateTime,
      s.delegatedClientSignInActivity?.lastSignInDateTime,
      s.delegatedResourceSignInActivity?.lastSignInDateTime,
      s.applicationAuthenticationClientSignInActivity?.lastSignInDateTime,
      s.applicationAuthenticationResourceSignInActivity?.lastSignInDateTime,
    ].filter(Boolean).sort();
    signIns.set(s.appId, {
      last: dates.length ? dates[dates.length - 1] : null,
      appOnly: s.applicationAuthenticationClientSignInActivity?.lastSignInDateTime || null,
    });
  }
  const usageKnown = !!raw.sources?.spSignIns?.ok || (raw.spSignIns || []).length > 0;
  const agentUserIds = new Set((raw.agentUsers || []).map((u) => u.id));
  // Workload identity, agent and agent-user policies never apply to people.
  const enabledUserPolicies = policies.filter((p) => isEnabled(p) && !isNonUserPolicy(p, agentUserIds));
  const tenantId = raw.organization?.id || null;
  return {
    now,
    org: raw.organization,
    tenantId,
    policies,
    enabledUserPolicies,
    sps,
    spByAppId,
    spById: new Map(sps.map((s) => [s.id, s])),
    applications: raw.applications || [],
    strengthById,
    roleNames,
    namedLocations: raw.namedLocations || [],
    locById: new Map((raw.namedLocations || []).map((l) => [l.id, l])),
    authContexts: raw.authContexts || [],
    dir: raw.directoryObjects || {},
    dirResolved: !!raw.sources?.directoryObjects?.ok,
    groupSizes: raw.groupSizes || {},
    userCounts: raw.userCounts || { total: 0, guests: 0 },
    signIns,
    usageKnown,
    agentUserIds,
    agentIdentities: raw.agentIdentities || [],
    agentBlueprints: raw.agentBlueprints || [],
    agentsListed: !!raw.sources?.agentIdentities?.ok,
    perms: buildPermissionIndex(raw, roleNames),
    gs: (p) => grantSummary(p, strengthById),
  };
}

function isType(o, t) {
  return (o?.['@odata.type'] || '').toLowerCase() === `#microsoft.graph.${t}`.toLowerCase();
}

function daysSince(iso, now) {
  if (!iso) return null;
  return Math.floor((now - new Date(iso)) / DAY);
}

export function plural(n, one, many) {
  return `${Number(n || 0).toLocaleString()} ${n === 1 ? one : (many || one + 's')}`;
}

function countBy(list, key) {
  const out = {};
  for (const x of list) out[x[key]] = (out[x[key]] || 0) + 1;
  return out;
}

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

export function classifyApp(sp, tenantId) {
  const tags = sp.tags || [];
  if (tags.includes('WindowsAzureActiveDirectoryOnPremApp')) return 'appProxy';
  if (sp.preferredSingleSignOnMode === 'saml') return 'saml';
  if (sp.preferredSingleSignOnMode === 'password') return 'passwordSso';
  if (sp.servicePrincipalType === 'ManagedIdentity') return 'managedIdentity';
  if (sp.servicePrincipalType === 'ServiceIdentity' || /agentIdentity/i.test(sp['@odata.type'] || '')) return 'agent';
  if (MICROSOFT_TENANT_IDS.has(sp.appOwnerOrganizationId)) return 'microsoft';
  if (tenantId && sp.appOwnerOrganizationId === tenantId) return 'tenantApp';
  if (sp.servicePrincipalType === 'Application') return 'saas';
  return 'other';
}

function isBusinessApp(sp, category) {
  if (['appProxy', 'saml', 'passwordSso'].includes(category)) return true;
  if (category === 'tenantApp') return (sp.replyUrls || []).length > 0 || !!sp.homepage || !!sp.loginUrl;
  if (category === 'saas') return (sp.tags || []).includes('WindowsAzureActiveDirectoryIntegratedApp');
  return false;
}

export function suggestCrownJewel(name = '') {
  const n = ` ${name.toLowerCase()} `;
  return CROWN_JEWEL_HINTS.some((h) => n.includes(` ${h} `) || n.includes(` ${h}`) && h.length > 3);
}

function coverageFor(ctx, appId) {
  const applying = ctx.enabledUserPolicies.filter((p) =>
    !isUserActionPolicy(p) && !isAuthContextPolicy(p) && appInScope(p, appId));
  const excludedBy = ctx.policies.filter((p) => p.state !== 'disabled' && appExcluded(p, appId));
  const rows = applying.map((p) => ({ p, gs: ctx.gs(p), ss: sessionSummary(p), cond: conditionalScope(p), all: targetsAllUsers(p) }));
  const mfaAlwaysAll = rows.some((r) => r.all && (r.gs.requiresMfa || r.gs.block) && r.cond.length === 0);
  // A conditional block (for example "block high-risk countries") is not MFA
  // coverage: it only stops some sign-ins. Only an unconditional block counts.
  const protects = (r) => r.gs.requiresMfa || (!r.gs.block && r.gs.strong);
  const mfaCondAll = rows.some((r) => r.all && protects(r));
  const mfaSome = rows.some(protects);
  const protection = mfaAlwaysAll ? 'strong' : mfaCondAll ? 'conditional' : mfaSome ? 'partial' : 'none';
  return {
    protection,
    phishingResistant: rows.some((r) => r.gs.requiresPhishingResistant),
    managedDevice: rows.some((r) => r.gs.requiresManagedDevice || r.gs.requiresAppProtection),
    sessionControl: rows.some((r) => r.ss.mda || r.ss.appEnforcedRestrictions),
    applying: rows.map((r) => ({ id: r.p.id, name: r.p.displayName, controls: describeGrant(r.gs), allUsers: r.all, conditions: r.cond })),
    excludedBy: excludedBy.map((p) => ({ id: p.id, name: p.displayName, state: p.state })),
  };
}

function analyzeApps(ctx, crownJewels) {
  const out = [];
  const seen = new Set();
  const push = (sp, appId, name, category) => {
    if (seen.has(appId)) return;
    seen.add(appId);
    const cov = coverageFor(ctx, appId);
    const usage = ctx.signIns.get(appId);
    const days = daysSince(usage?.last, ctx.now);
    out.push({
      appId,
      id: sp?.id || null,
      name,
      category,
      categoryLabel: CATEGORY_LABEL[category] || category,
      enabled: sp ? sp.accountEnabled !== false : null,
      assignmentRequired: !!sp?.appRoleAssignmentRequired,
      lastUsed: usage?.last || null,
      unused: ctx.usageKnown && category !== 'microsoft' ? (days === null || days > UNUSED_DAYS) : null,
      crownJewel: crownJewels.has(appId),
      suggestedCrownJewel: !crownJewels.has(appId) && suggestCrownJewel(name),
      ...cov,
    });
  };

  for (const sp of ctx.sps) {
    const category = classifyApp(sp, ctx.tenantId);
    if (isBusinessApp(sp, category) || crownJewels.has(sp.appId)) push(sp, sp.appId, sp.displayName, category);
  }
  // Key Microsoft data stores and anything a policy names explicitly.
  for (const [appId, k] of Object.entries(KNOWN_APPS)) {
    if (k.dataStore || crownJewels.has(appId)) push(ctx.spByAppId.get(appId), appId, k.name, 'microsoft');
  }
  for (const p of ctx.policies) {
    for (const appId of [...(appsOf(p).includeApplications || []), ...(appsOf(p).excludeApplications || [])]) {
      if (!/^[0-9a-f-]{36}$/i.test(appId)) continue;
      const sp = ctx.spByAppId.get(appId);
      if (!sp) continue;
      push(sp, appId, sp.displayName, classifyApp(sp, ctx.tenantId));
    }
  }
  const protRank = { none: 0, partial: 1, conditional: 2, strong: 3 };
  return out.sort((a, b) => (b.crownJewel - a.crownJewel) || (protRank[a.protection] - protRank[b.protection]) || a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

function analyzePolicies(ctx) {
  return ctx.policies.map((p) => {
    const gs = ctx.gs(p);
    const ss = sessionSummary(p);
    const u = usersOf(p);
    const a = appsOf(p);
    const kind = isWorkloadPolicy(p) ? 'Workload identities'
      : isAgentPolicy(p) ? 'AI agents'
        : isAgentUserPolicy(p, ctx.agentUserIds) ? 'Agent users'
      : isUserActionPolicy(p) ? 'User action'
        : isAuthContextPolicy(p) ? 'Authentication context' : 'Users and apps';
    const reportOnlyDays = isReportOnly(p) ? daysSince(p.modifiedDateTime || p.createdDateTime, ctx.now) : null;
    return {
      id: p.id,
      name: p.displayName,
      state: p.state,
      stateLabel: STATE_LABEL[p.state] || p.state,
      kind,
      microsoftManaged: isMicrosoftManaged(p),
      users: isAgentPolicy(p) ? describeAgentScope(p) : targetsAllUsers(p) ? 'All users' : describeUserScope(u, ctx),
      apps: describeAppScope(a, ctx),
      conditions: conditionalScope(p),
      controls: describeGrant(gs),
      session: describeSession(ss),
      block: gs.block,
      exclusions: exclusionCount(p),
      reportOnlyDays,
      modified: p.modifiedDateTime || p.createdDateTime || null,
    };
  });
}

function describeAgentScope(p) {
  const c = p.conditions?.clientApplications || {};
  const inc = c.includeAgentIdServicePrincipals || [];
  if (inc.includes('All')) return 'All agent identities';
  if (c.agentIdServicePrincipalFilter && !inc.length) return 'Agents by attribute';
  return `${inc.length} agent${inc.length === 1 ? '' : 's'}`;
}

function describeUserScope(u, ctx) {
  const parts = [];
  if ((u.includeUsers || []).includes('GuestsOrExternalUsers') || u.includeGuestsOrExternalUsers) parts.push('Guests / external');
  const roles = (u.includeRoles || []).length;
  if (roles) parts.push(`${roles} role${roles > 1 ? 's' : ''}`);
  const groups = (u.includeGroups || []).length;
  if (groups) parts.push(`${groups} group${groups > 1 ? 's' : ''}`);
  const users = (u.includeUsers || []).filter((x) => !['All', 'None', 'GuestsOrExternalUsers'].includes(x)).length;
  if (users) parts.push(`${users} user${users > 1 ? 's' : ''}`);
  if ((u.includeUsers || []).includes('None')) parts.push('Nobody');
  return parts.join(', ') || 'Not set';
}

function describeAppScope(a, ctx) {
  if ((a.includeUserActions || []).length) return a.includeUserActions.map((x) => x.replace('urn:user:', '')).join(', ');
  if ((a.includeAuthenticationContextClassReferences || []).length) return 'Auth context ' + a.includeAuthenticationContextClassReferences.join(', ');
  const inc = a.includeApplications || [];
  if (inc.includes('All')) return 'All resources';
  return inc.map((id) => id === 'Office365' ? 'Office 365' : id === 'MicrosoftAdminPortals' ? 'Admin portals'
    : (ctx.spByAppId.get(id)?.displayName || KNOWN_APPS[id]?.name || 'Unknown app')).join(', ') || 'None';
}

function describeSession(ss) {
  const parts = [];
  if (ss.mda) parts.push(ss.mda === 'blockDownloads' ? 'Block downloads (Defender for Cloud Apps)' : ss.mda === 'monitorOnly' ? 'Monitor (Defender for Cloud Apps)' : 'Defender for Cloud Apps policy');
  if (ss.appEnforcedRestrictions) parts.push('App-enforced restrictions');
  if (ss.signInFrequency) parts.push('Sign-in frequency');
  if (ss.persistentBrowser) parts.push(`Persistent browser: ${ss.persistentBrowser}`);
  if (ss.tokenProtection) parts.push('Token protection');
  if (ss.cae === 'strictEnforcement') parts.push('Strict CAE');
  return parts.join(', ');
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

function analyzeExclusions(ctx, crownJewels) {
  const out = [];
  const active = ctx.policies.filter((p) => p.state !== 'disabled');
  const userPolicies = ctx.enabledUserPolicies;

  // Count, per user, how many enabled user policies exclude them. Accounts
  // excluded almost everywhere are emergency-access candidates.
  const userExclusionCount = new Map();
  for (const p of userPolicies) {
    for (const id of usersOf(p).excludeUsers || []) userExclusionCount.set(id, (userExclusionCount.get(id) || 0) + 1);
  }
  const breakGlassThreshold = Math.max(2, Math.ceil(userPolicies.length * 0.75));
  const breakGlass = new Set([...userExclusionCount.entries()]
    .filter(([, n]) => userPolicies.length >= 2 && n >= breakGlassThreshold).map(([id]) => id));
  const breakGlassPlausible = breakGlass.size > 0 && breakGlass.size <= 4;
  const bigGroup = Math.max(50, Math.round((ctx.userCounts.total || 0) * 0.05));

  for (const p of active) {
    const gs = ctx.gs(p);
    const base = { policyId: p.id, policyName: p.displayName, policyState: p.state, policyControls: describeGrant(gs) };
    const u = usersOf(p);
    const a = appsOf(p);

    for (const appId of a.excludeApplications || []) {
      const sp = ctx.spByAppId.get(appId);
      const known = KNOWN_APPS[appId];
      const name = appId === 'Office365' ? 'Office 365 (app group)' : sp?.displayName || known?.name || appId;
      const category = sp ? classifyApp(sp, ctx.tenantId) : known ? 'microsoft' : null;
      const usage = ctx.signIns.get(appId);
      const days = daysSince(usage?.last, ctx.now);
      const unused = ctx.usageKnown && (days === null || days > UNUSED_DAYS);
      let verdict = 'review';
      let reason = 'Exception to the policy. Confirm there is a business owner and a reason on record.';
      let fix = 'Document the owner and reason, or remove the exclusion.';
      if (appId === 'Office365') {
        verdict = 'gap';
        reason = 'The whole Office 365 group is excluded: email, files and Teams are outside this policy.';
        fix = 'Remove the exclusion and handle the specific break with a narrower policy.';
      } else if (!sp && !known) {
        verdict = 'stale';
        reason = 'This app no longer exists in the tenant. The exclusion does nothing but adds noise.';
        fix = 'Remove the exclusion.';
      } else if (crownJewels.has(appId)) {
        verdict = 'gap';
        reason = 'A crown-jewel application is excluded from this policy.';
        fix = 'Remove the exclusion. If the app breaks, create a dedicated policy for it with controls it can meet.';
      } else if (known?.exclusion) {
        verdict = known.exclusion.verdict;
        reason = known.exclusion.why;
        fix = verdict === 'justified' ? 'Keep, with a documented owner and review date.' : 'Remove the exclusion.';
      } else if (unused && category !== 'microsoft') {
        verdict = 'cleanup';
        reason = days === null ? 'No sign-ins recorded for this app. It may not be in use.' : `Not used for ${days} days.`;
        fix = 'Confirm with the app owner. If unused, remove the exclusion (and consider removing the app).';
      } else if (['appProxy', 'saml', 'passwordSso'].includes(category)) {
        verdict = 'gap';
        reason = `${CATEGORY_LABEL[category]} business app excluded. It still signs in through Entra, so excluding it removes control instead of fixing the break.`;
        fix = 'Replace the exclusion with a dedicated policy for this app (for example: compliant or hybrid-joined device, or trusted network plus MFA).';
      } else if (category === 'microsoft') {
        reason = 'Microsoft app excluded. Some are required (for example during device enrollment); check this one is.';
      }
      out.push({ ...base, kind: 'Application', targetId: appId, targetName: name, category: category ? CATEGORY_LABEL[category] : 'Unknown', verdict, reason, fix, lastUsed: usage?.last || null });
    }

    for (const id of u.excludeUsers || []) {
      const o = ctx.dir[id];
      let verdict = 'review';
      let reason = 'Individual user exception. These tend to accumulate and are rarely reviewed.';
      let fix = 'Move exceptions into one named, owned group with an expiry, or remove.';
      if (!o && ctx.dirResolved) {
        verdict = 'stale';
        reason = 'This user no longer exists.';
        fix = 'Remove the exclusion.';
      } else if (breakGlass.has(id) && breakGlassPlausible) {
        verdict = 'justified';
        reason = `Excluded from ${userExclusionCount.get(id)} of ${userPolicies.length} enabled policies: looks like an emergency-access (break-glass) account.`;
        fix = 'Confirm it is an emergency account, protect it with a phishing-resistant method, and alert on every sign-in.';
      }
      out.push({ ...base, kind: 'User', targetId: id, targetName: o ? (o.displayName || o.userPrincipalName) : 'Unknown user', detail: o?.userPrincipalName || '', verdict, reason, fix, size: 1 });
    }

    for (const id of u.excludeGroups || []) {
      const o = ctx.dir[id];
      const size = ctx.groupSizes[id] ?? null;
      let verdict = 'review';
      let reason = 'Group exception. Everyone in the group skips this policy.';
      let fix = 'Confirm the group has an owner, a reason, and a regular access review.';
      if (!o && ctx.dirResolved) {
        verdict = 'stale';
        reason = 'This group no longer exists.';
        fix = 'Remove the exclusion.';
      } else if (/break.?glass|emergency/i.test(o?.displayName || '')) {
        verdict = 'justified';
        reason = 'Named as an emergency-access group.';
        fix = 'Keep it small (2 accounts), phishing-resistant, and monitored.';
      } else if (size !== null && size >= bigGroup && gs.strong) {
        verdict = 'gap';
        reason = `${size.toLocaleString()} people skip this policy through this group.`;
        fix = 'Shrink the group, or give its members a dedicated policy with controls they can meet.';
      }
      out.push({ ...base, kind: 'Group', targetId: id, targetName: o?.displayName || 'Unknown group', verdict, reason, fix, size });
    }

    for (const id of u.excludeRoles || []) {
      const name = ctx.roleNames[id] || 'Directory role';
      let verdict = 'review';
      let reason = 'Everyone holding this role skips the policy.';
      let fix = 'Confirm why the role is excluded.';
      if (id === DIRECTORY_SYNC_ROLE) {
        verdict = 'justified';
        reason = 'The directory sync service account. Excluding it is expected; restrict it by location instead.';
        fix = 'Keep, and limit the sync account to your sync server location.';
      } else if (PRIVILEGED_ROLES[id] && gs.strong) {
        verdict = 'gap';
        reason = `Administrators (${name}) are excluded from a protective policy.`;
        fix = 'Remove the exclusion. Admins should face the strongest controls, not the weakest.';
      }
      out.push({ ...base, kind: 'Role', targetId: id, targetName: name, verdict, reason, fix });
    }

    if (u.excludeGuestsOrExternalUsers) {
      out.push({ ...base, kind: 'Guests', targetId: 'guests', targetName: 'Guests and external users', verdict: 'review', reason: 'External users skip this policy. They can reach shared data.', fix: 'Apply MFA to guests (cross-tenant trust can accept their home MFA).' });
    }

    const loc = p.conditions?.locations;
    for (const id of loc?.excludeLocations || []) {
      const l = ctx.locById.get(id);
      const name = id === 'AllTrusted' ? 'All trusted locations' : l?.displayName || 'Unknown location';
      const trustedBroad = id === 'AllTrusted'
        ? ctx.namedLocations.some((x) => x.isTrusted && ipRangesOf(x).some((r) => r.broad))
        : ipRangesOf(l).some((r) => r.broad);
      let verdict = 'review';
      let reason = 'Sign-ins from this network skip the policy.';
      let fix = 'Confirm the network ranges are tight and owned. Prefer compliant devices over network trust.';
      if (!l && id !== 'AllTrusted' && id !== 'All') {
        verdict = 'stale';
        reason = 'This named location no longer exists.';
        fix = 'Remove the exclusion.';
      } else if (gs.requiresMfa && trustedBroad) {
        verdict = 'gap';
        reason = 'MFA is skipped on a network defined with very broad IP ranges.';
        fix = 'Tighten the IP ranges to your real egress addresses, or stop excluding the location.';
      } else if (gs.requiresMfa) {
        reason = 'MFA is skipped on this network. A stolen password used from inside the network is enough.';
      }
      out.push({ ...base, kind: 'Location', targetId: id, targetName: name, verdict, reason, fix });
    }

    for (const plat of p.conditions?.platforms?.excludePlatforms || []) {
      out.push({ ...base, kind: 'Platform', targetId: plat, targetName: plat, verdict: 'review', reason: 'Device platform is reported by the client and can be spoofed. Platform exclusions are a weak way to avoid breaks.', fix: 'Use a device filter or a dedicated policy for that platform.' });
    }

    const agentCa = p.conditions?.clientApplications || {};
    if ((agentCa.excludeAgentIdServicePrincipals || []).length || (agentCa.agentIdServicePrincipalFilter && (agentCa.includeAgentIdServicePrincipals || []).length)) {
      const riskBased = !!(p.conditions?.agentIdRiskLevels || '').length;
      const allowList = gs.block && !riskBased;
      const agentById = new Map([...(ctx.agentIdentities || []), ...(ctx.agentBlueprints || [])].map((x) => [x.id, x]));
      for (const id of agentCa.excludeAgentIdServicePrincipals || []) {
        const o = agentById.get(id) || ctx.spById.get(id) || ctx.dir[id];
        const known = !!o || !ctx.agentsListed;
        const name = o?.displayName || 'Unknown agent';
        out.push({
          ...base, kind: 'Agent', targetId: id, targetName: name,
          verdict: !known ? 'stale' : allowList ? 'justified' : 'gap',
          reason: !known ? 'This agent or blueprint no longer exists.' : allowList ? 'Approved agent in an allow-list policy (block all other agents). This is the intended pattern.' : riskBased ? 'This agent keeps working even when ID Protection rates it high risk.' : 'This agent skips the agent policy.',
          fix: !known ? 'Remove the exclusion.' : allowList ? 'Keep it documented with the approving sponsor, and review it with the agent\'s access review.' : 'Remove the exclusion so a compromised agent is blocked.',
        });
      }
      if (agentCa.agentIdServicePrincipalFilter && (agentCa.includeAgentIdServicePrincipals || []).length) {
        out.push({ ...base, kind: 'Agent', targetId: 'filter', targetName: 'Agents matching a custom security attribute filter', verdict: allowList ? 'justified' : 'review', reason: allowList ? 'Approved agents are excluded by attribute. Recommended: approval is recorded on the agent.' : 'Agents are selected by a custom security attribute rule.', fix: 'Confirm who can assign the attribute: they decide which agents are approved.' });
      }
    }

    for (const id of p.conditions?.clientApplications?.excludeServicePrincipals || []) {
      const sp = ctx.spById.get(id) || ctx.dir[id];
      out.push({ ...base, kind: 'Workload identity', targetId: id, targetName: sp?.displayName || 'Unknown service principal', verdict: sp ? 'review' : 'stale', reason: sp ? 'This service principal skips the workload identity policy.' : 'This service principal no longer exists.', fix: sp ? 'Confirm why and document it.' : 'Remove the exclusion.' });
    }
  }
  const rank = { gap: 0, review: 1, cleanup: 2, stale: 3, justified: 4 };
  return out.sort((x, y) => rank[x.verdict] - rank[y.verdict]);
}

// ---------------------------------------------------------------------------
// Named locations
// ---------------------------------------------------------------------------

const PRIVATE_V4 = [
  ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
];

function v4ToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function parseCidr(cidr) {
  const [addr, bitsStr] = String(cidr || '').split('/');
  const v6 = addr.includes(':');
  const bits = bitsStr === undefined ? (v6 ? 128 : 32) : Number(bitsStr);
  const r = { cidr, v6, bits, broad: false, veryBroad: false, private: false, addresses: null };
  if (v6) {
    r.broad = bits < 32;
    r.veryBroad = bits < 16;
    r.private = /^f[cd]/i.test(addr) || /^fe80/i.test(addr) || addr === '::1';
    return r;
  }
  const n = v4ToInt(addr);
  r.addresses = 2 ** (32 - bits);
  r.broad = bits <= 16;
  r.veryBroad = bits <= 8;
  if (n !== null) {
    r.private = PRIVATE_V4.some(([net, b]) => {
      const m = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
      return ((n & m) >>> 0) === ((v4ToInt(net) & m) >>> 0) && bits >= b;
    });
  }
  return r;
}

function ipRangesOf(l) {
  if (!l || !Array.isArray(l.ipRanges)) return [];
  return l.ipRanges.map((r) => parseCidr(r.cidrAddress));
}

function locType(l) {
  const t = (l?.['@odata.type'] || '').toLowerCase();
  if (t.includes('country')) return 'country';
  if (t.includes('ip')) return 'ip';
  return Array.isArray(l?.ipRanges) ? 'ip' : Array.isArray(l?.countriesAndRegions) ? 'country' : 'other';
}

function analyzeLocations(ctx) {
  const refs = new Map();
  const note = (id, p, how) => {
    if (!refs.has(id)) refs.set(id, []);
    refs.get(id).push({ id: p.id, name: p.displayName, how, state: p.state });
  };
  for (const p of ctx.policies) {
    if (p.state === 'disabled') continue;
    const loc = p.conditions?.locations || {};
    for (const id of loc.includeLocations || []) note(id, p, 'include');
    for (const id of loc.excludeLocations || []) note(id, p, 'exclude');
  }
  const trustedRefs = refs.get('AllTrusted') || [];
  return ctx.namedLocations.map((l) => {
    const type = locType(l);
    const ranges = ipRangesOf(l);
    const used = [...(refs.get(l.id) || []), ...(l.isTrusted ? trustedRefs.map((r) => ({ ...r, how: r.how + ' (as trusted)' })) : [])];
    const issues = [];
    if (type === 'ip') {
      if (ranges.some((r) => r.veryBroad)) issues.push({ severity: l.isTrusted ? 'critical' : 'high', text: 'Contains a huge IP range (/8 or wider). That covers millions of addresses you do not own.' });
      else if (ranges.some((r) => r.broad)) issues.push({ severity: l.isTrusted ? 'high' : 'medium', text: 'Contains a broad IP range (/16 or wider). Check every address in it is yours.' });
      if (ranges.some((r) => r.private)) issues.push({ severity: 'low', text: 'Contains private IP ranges. Entra only sees your public egress address, so these never match.' });
      if (!ranges.length) issues.push({ severity: 'low', text: 'No IP ranges defined.' });
    }
    if (type === 'country' && l.includeUnknownCountriesAndRegions) {
      issues.push({ severity: 'medium', text: 'Includes unknown countries and regions (for example IPv6 or anonymous addresses that cannot be mapped).' });
    }
    if (!used.length) issues.push({ severity: 'low', text: 'Not used by any active policy.' });
    return {
      id: l.id,
      name: l.displayName,
      type,
      trusted: !!l.isTrusted,
      ranges: ranges.map((r) => r.cidr),
      rangeCount: ranges.length,
      countries: l.countriesAndRegions || [],
      includeUnknown: !!l.includeUnknownCountriesAndRegions,
      lookup: l.countryLookupMethod || null,
      usedBy: used,
      issues,
    };
  });
}

// ---------------------------------------------------------------------------
// Workload identities
// ---------------------------------------------------------------------------

function analyzeWorkload(ctx) {
  const now = ctx.now;
  const apps = ctx.applications.map((app) => {
    const creds = [
      ...(app.passwordCredentials || []).map((c) => ({ ...c, type: 'secret' })),
      ...(app.keyCredentials || []).map((c) => ({ ...c, type: 'certificate' })),
    ];
    const secrets = creds.filter((c) => c.type === 'secret');
    const live = creds.filter((c) => !c.endDateTime || new Date(c.endDateTime) > now);
    const expired = creds.filter((c) => c.endDateTime && new Date(c.endDateTime) <= now);
    const expiring = live.filter((c) => c.endDateTime && (new Date(c.endDateTime) - now) < 30 * DAY);
    const longLived = secrets.filter((c) => c.startDateTime && c.endDateTime &&
      (new Date(c.endDateTime) - new Date(c.startDateTime)) > 366 * DAY && new Date(c.endDateTime) > now);
    const usage = ctx.signIns.get(app.appId);
    const lastAppOnly = usage?.appOnly || null;
    const days = daysSince(usage?.last, now);
    const perm = permissionsForApp(ctx, app.appId);
    return {
      appId: app.appId,
      name: app.displayName,
      agentBlueprint: (ctx.agentBlueprints || []).some((b) => b.appId === app.appId),
      permissions: perm,
      multiTenant: app.signInAudience && app.signInAudience !== 'AzureADMyOrg',
      secrets: secrets.length,
      certificates: creds.length - secrets.length,
      liveCredentials: live.length,
      expired: expired.length,
      expiringSoon: expiring.length,
      longLivedSecrets: longLived.length,
      lastUsed: usage?.last || null,
      lastAppOnlySignIn: lastAppOnly,
      dormant: ctx.usageKnown && live.length > 0 && (days === null || days > UNUSED_DAYS),
    };
  }).filter((a) => a.secrets + a.certificates > 0)
    .sort((a, b) => (b.secrets - a.secrets) || a.name.localeCompare(b.name));

  const policies = ctx.policies.filter(isWorkloadPolicy).map((p) => ({
    id: p.id,
    name: p.displayName,
    state: p.state,
    stateLabel: STATE_LABEL[p.state] || p.state,
    scope: (p.conditions.clientApplications.includeServicePrincipals || []).includes('ServicePrincipalsInMyTenant') ? 'All tenant service principals' : `${(p.conditions.clientApplications.includeServicePrincipals || []).length} service principals`,
    controls: describeGrant(ctx.gs(p)),
    conditions: conditionalScope(p),
  }));

  return {
    apps,
    policies,
    managedIdentities: ctx.sps.filter((s) => s.servicePrincipalType === 'ManagedIdentity').length,
    totals: {
      withSecrets: apps.filter((a) => a.secrets > 0).length,
      withCertsOnly: apps.filter((a) => a.secrets === 0 && a.certificates > 0).length,
      expired: apps.filter((a) => a.expired > 0).length,
      expiringSoon: apps.filter((a) => a.expiringSoon > 0).length,
      longLived: apps.filter((a) => a.longLivedSecrets > 0).length,
      dormant: apps.filter((a) => a.dormant).length,
      multiTenantWithSecrets: apps.filter((a) => a.multiTenant && a.secrets > 0).length,
      highPrivilege: apps.filter((a) => a.permissions.critical.length || a.permissions.roles.length).length,
    },
  };
}

// ---------------------------------------------------------------------------
// Data protection (DLP) controls
// ---------------------------------------------------------------------------

const SPO = '00000003-0000-0ff1-ce00-000000000000';
const EXO = '00000002-0000-0ff1-ce00-000000000000';
const RMS = '00000012-0000-0000-c000-000000000000';

function analyzeDlp(ctx) {
  const on = ctx.enabledUserPolicies;
  const rows = on.map((p) => ({ p, gs: ctx.gs(p), ss: sessionSummary(p) }));
  const coversData = (p) => appInScope(p, SPO) || appInScope(p, EXO);
  const controls = [];

  const mda = rows.filter((r) => r.ss.mda);
  const mdaStrong = mda.filter((r) => r.ss.mda !== 'monitorOnly');
  controls.push({
    id: 'mda',
    title: 'Real-time session control (Defender for Cloud Apps)',
    status: mdaStrong.length ? 'present' : mda.length ? 'partial' : 'missing',
    detail: mda.length ? `${mda.length} polic${mda.length > 1 ? 'ies' : 'y'}: ${mda.map((r) => r.p.displayName).join(', ')}` : 'No policy routes sessions through Defender for Cloud Apps.',
    why: 'Lets you block downloads, apply labels or monitor activity in the browser session. This is how DLP reaches unmanaged devices.',
    ref: DOCS.appControl,
  });

  const aer = rows.filter((r) => r.ss.appEnforcedRestrictions && coversData(r.p));
  controls.push({
    id: 'aer',
    title: 'Limited web access on unmanaged devices (SharePoint and Exchange)',
    status: aer.length ? 'present' : 'missing',
    detail: aer.length ? aer.map((r) => r.p.displayName).join(', ') : 'No policy uses app-enforced restrictions.',
    why: 'Browser-only, no-download access to files and mail from personal devices.',
    ref: DOCS.sessionControls,
  });

  const managed = rows.filter((r) => coversData(r.p) && (r.gs.requiresManagedDevice || r.gs.requiresAppProtection));
  const managedAll = managed.filter((r) => targetsAllUsers(r.p));
  controls.push({
    id: 'managed',
    title: 'Managed device or protected app for Office 365 data',
    status: managedAll.length ? 'present' : managed.length ? 'partial' : 'missing',
    detail: managed.length ? managed.map((r) => r.p.displayName).join(', ') : 'Data can be synced to any device that passes MFA.',
    why: 'DLP policies only apply where Microsoft 365 apps or endpoints are managed. Unmanaged sync clients copy data out of scope.',
    ref: DOCS.caOverview,
  });

  const available = ctx.authContexts.filter((c) => c.isAvailable !== false);
  const usedCtx = new Set();
  for (const p of on) for (const c of appsOf(p).includeAuthenticationContextClassReferences || []) usedCtx.add(c);
  const unusedCtx = available.filter((c) => !usedCtx.has(c.id));
  controls.push({
    id: 'authContext',
    title: 'Step-up for sensitive data (authentication contexts)',
    status: usedCtx.size ? (unusedCtx.length ? 'partial' : 'present') : 'missing',
    detail: available.length
      ? `${available.length} defined, ${usedCtx.size} enforced by a policy${unusedCtx.length ? `. Not enforced: ${unusedCtx.map((c) => c.displayName || c.id).join(', ')}` : ''}.`
      : 'No authentication contexts defined.',
    why: 'Sensitivity labels and SharePoint sites can demand an authentication context. Without a policy behind it, labelled content gets no extra check.',
    ref: DOCS.authContext,
    unused: unusedCtx.map((c) => c.displayName || c.id),
  });

  const insider = rows.filter((r) => (r.p.conditions?.insiderRiskLevels || '').length);
  controls.push({
    id: 'insider',
    title: 'Adaptive Protection (insider risk) in Conditional Access',
    status: insider.length ? 'present' : 'missing',
    detail: insider.length ? insider.map((r) => r.p.displayName).join(', ') : 'No policy uses the insider risk condition.',
    why: 'Purview Adaptive Protection can raise a user\'s risk level; Conditional Access can then block or restrict them automatically.',
    ref: DOCS.insiderRisk,
  });

  const guestRows = rows.filter((r) => {
    const u = usersOf(r.p);
    const incl = (u.includeUsers || []).includes('All') || (u.includeUsers || []).includes('GuestsOrExternalUsers') || !!u.includeGuestsOrExternalUsers;
    return incl && !u.excludeGuestsOrExternalUsers && (r.gs.requiresMfa || r.gs.block) && (targetsAllResources(r.p) || coversData(r.p));
  });
  controls.push({
    id: 'guests',
    title: 'MFA for guests and external users',
    status: guestRows.length ? 'present' : 'missing',
    detail: guestRows.length ? guestRows.map((r) => r.p.displayName).join(', ') : 'No enabled policy requires MFA for guests on data apps.',
    why: 'Guests reach shared files and Teams. Without MFA, a guest\'s stolen password opens your shared data.',
    ref: DOCS.caUsers,
  });

  const tp = rows.filter((r) => r.ss.tokenProtection);
  controls.push({
    id: 'token',
    title: 'Token protection (session binding)',
    status: tp.length ? 'present' : 'missing',
    detail: tp.length ? tp.map((r) => r.p.displayName).join(', ') : 'No policy requires token protection.',
    why: 'Stops a stolen session token from being replayed on another device, a common route for data theft after phishing.',
    ref: DOCS.tokenProtection,
  });

  const sessionLife = rows.filter((r) => r.ss.signInFrequency || r.ss.persistentBrowser === 'never');
  controls.push({
    id: 'lifetime',
    title: 'Session lifetime limits',
    status: sessionLife.length ? 'present' : 'missing',
    detail: sessionLife.length ? sessionLife.map((r) => r.p.displayName).join(', ') : 'Default session lifetime everywhere.',
    why: 'Limits how long an unattended or shared browser keeps access to company data.',
    ref: DOCS.sessionControls,
  });

  const rmsExcluded = ctx.policies.filter((p) => p.state !== 'disabled' && appExcluded(p, RMS));
  return {
    controls,
    enforcedAuthContexts: [...usedCtx],
    rmsExcluded: rmsExcluded.map((p) => p.displayName),
    note: 'This view covers the identity side of DLP: where and how people can reach the data your DLP policies protect. The Purview tab adds sensitivity labels and, from an optional export, the DLP policies themselves.',
  };
}

// ---------------------------------------------------------------------------
// Modern baseline
// ---------------------------------------------------------------------------

function analyzeBaseline(ctx) {
  const on = ctx.enabledUserPolicies;
  const rows = on.map((p) => ({ p, gs: ctx.gs(p), cond: conditionalScope(p) }));
  const checks = [];
  const add = (id, title, status, detail, ref, policies = []) =>
    checks.push({ id, title, status, detail, ref, policies: policies.map((r) => r.p.displayName) });

  const mfaAll = rows.filter((r) => targetsAllUsers(r.p) && targetsAllResources(r.p) && (r.gs.requiresMfa));
  const mfaAllClean = mfaAll.filter((r) => r.cond.length === 0);
  add('mfaAll', 'MFA for all users on all resources',
    mfaAllClean.length ? 'present' : mfaAll.length ? 'partial' : 'missing',
    mfaAllClean.length ? 'A policy requires MFA for everyone, everywhere.' : mfaAll.length ? `MFA for everyone applies only under conditions (${mfaAll[0].cond.join(', ')}).` : 'No enabled policy requires MFA for all users on all resources.',
    DOCS.caOverview, mfaAll);

  const adminRoles = Object.keys(PRIVILEGED_ROLES);
  const adminRows = rows.filter((r) => (usersOf(r.p).includeRoles || []).some((x) => adminRoles.includes(x)) || targetsAllUsers(r.p));
  const adminPr = adminRows.filter((r) => r.gs.requiresPhishingResistant);
  const adminMfa = adminRows.filter((r) => r.gs.requiresMfa);
  add('adminsPr', 'Phishing-resistant MFA for administrators',
    adminPr.length ? 'present' : adminMfa.length ? 'partial' : 'missing',
    adminPr.length ? 'Admins must use a phishing-resistant method.' : adminMfa.length ? 'Admins need MFA, but any method is accepted (phishable).' : 'No policy specifically protects admin roles.',
    DOCS.authStrength, adminPr.length ? adminPr : adminMfa);

  const legacy = rows.filter((r) => r.gs.block && ['exchangeActiveSync', 'other'].every((t) => (r.p.conditions?.clientAppTypes || []).includes(t)));
  add('legacy', 'Legacy authentication blocked', legacy.length ? 'present' : 'missing',
    legacy.length ? 'Old protocols that cannot do MFA are blocked.' : 'Legacy protocols (POP, IMAP, SMTP AUTH, ActiveSync basic) are not blocked by a policy.',
    DOCS.legacyAuth, legacy);

  const dcf = rows.filter((r) => r.gs.block && (r.p.conditions?.authenticationFlows?.transferMethods || '').includes('deviceCodeFlow'));
  add('deviceCode', 'Device code flow restricted', dcf.length ? 'present' : 'missing',
    dcf.length ? 'Device code sign-in is blocked or restricted.' : 'Device code flow is open. It is a common phishing technique.',
    DOCS.authFlows, dcf);

  const sir = rows.filter((r) => (r.p.conditions?.signInRiskLevels || []).length);
  add('signInRisk', 'Sign-in risk policy', sir.length ? 'present' : 'missing',
    sir.length ? 'Risky sign-ins trigger a control.' : 'No policy reacts to risky sign-ins (needs Entra ID P2).', DOCS.caOverview, sir);

  const ur = rows.filter((r) => (r.p.conditions?.userRiskLevels || []).length);
  add('userRisk', 'User risk policy', ur.length ? 'present' : 'missing',
    ur.length ? 'High-risk users must remediate.' : 'No policy reacts to compromised users (needs Entra ID P2).', DOCS.caOverview, ur);

  const regInfo = rows.filter((r) => (appsOf(r.p).includeUserActions || []).includes('urn:user:registersecurityinfo'));
  add('regInfo', 'Security info registration protected', regInfo.length ? 'present' : 'missing',
    regInfo.length ? 'Registering MFA methods is protected.' : 'Anyone with a password can register their own MFA method in some conditions.', DOCS.caOverview, regInfo);

  const wl = ctx.policies.filter((p) => isEnabled(p) && isWorkloadPolicy(p));
  checks.push({ id: 'workload', title: 'Conditional Access for workload identities', status: wl.length ? 'present' : 'missing', detail: wl.length ? 'Apps that sign in on their own are controlled.' : 'Apps that sign in with a secret or certificate are not controlled by any policy (needs Workload Identities Premium).', ref: DOCS.workloadCa, policies: wl.map((p) => p.displayName) });

  const managed = ctx.policies.filter(isMicrosoftManaged);
  checks.push({ id: 'managedPolicies', title: 'Microsoft-managed policies reviewed', status: managed.length === 0 ? 'info' : managed.every((p) => p.state !== 'enabledForReportingButNotEnforced') ? 'present' : 'partial', detail: managed.length ? `${managed.length} Microsoft-managed polic${managed.length > 1 ? 'ies' : 'y'}; ${managed.filter(isReportOnly).length} still in report-only.` : 'No Microsoft-managed policies found.', ref: DOCS.managedPolicies, policies: managed.map((p) => p.displayName) });

  return checks;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function findingsFromBaseline(baseline, ctx, add) {
  const sev = { mfaAll: 'critical', adminsPr: 'high', legacy: 'high', deviceCode: 'medium', signInRisk: 'medium', userRisk: 'medium', regInfo: 'medium', workload: 'medium' };
  for (const c of baseline) {
    if (c.status === 'present' || c.status === 'info') continue;
    if (!sev[c.id]) continue;
    if (c.id === 'workload' && !ctx.applications.some((a) => (a.passwordCredentials || []).length)) continue;
    const severity = c.status === 'partial' ? downgrade(sev[c.id]) : sev[c.id];
    add({
      area: 'access', severity, title: BASELINE_TITLE[c.id][c.status === 'partial' ? 1 : 0],
      detail: c.detail,
      impact: BASELINE_IMPACT[c.id],
      fix: BASELINE_FIX[c.id],
      ref: c.ref,
    });
  }
}

const BASELINE_TITLE = {
  mfaAll: ['No policy requires MFA for everyone on every app', 'MFA for everyone has conditions or gaps'],
  adminsPr: ['Administrators have no dedicated protection', 'Administrators can use phishable MFA methods'],
  legacy: ['Legacy authentication is not blocked', 'Legacy authentication is only partly blocked'],
  deviceCode: ['Device code sign-in is not restricted', 'Device code sign-in is only partly restricted'],
  signInRisk: ['Risky sign-ins are not challenged', 'Risky sign-ins are only partly challenged'],
  userRisk: ['Compromised users are not forced to remediate', 'Compromised users are only partly handled'],
  regInfo: ['MFA method registration is not protected', 'MFA method registration is only partly protected'],
  workload: ['Apps that sign in on their own are not controlled', 'Apps that sign in on their own are only partly controlled'],
};

const BASELINE_IMPACT = {
  mfaAll: 'A stolen password is enough to reach company data for anyone not covered.',
  adminsPr: 'Admin accounts can be phished with real-time proxy kits that bypass ordinary MFA.',
  legacy: 'Attackers use legacy protocols for password spraying because MFA cannot be applied there.',
  deviceCode: 'Device code phishing gives attackers a valid session without touching the user\'s password.',
  signInRisk: 'Suspicious sign-ins (impossible travel, anonymous IPs) succeed without extra checks.',
  userRisk: 'Accounts flagged as compromised keep working.',
  regInfo: 'An attacker with a password can register their own MFA method and lock in access.',
  workload: 'Apps with secrets can be used from anywhere if the secret leaks.',
};
const BASELINE_FIX = {
  mfaAll: 'Create one "All users, All resources, require MFA" policy. Start in report-only, review impact, then enable. Exclude only emergency accounts.',
  adminsPr: 'Require the built-in "Phishing-resistant MFA" authentication strength for privileged roles.',
  legacy: 'Block "Exchange ActiveSync clients" and "Other clients" for all users.',
  deviceCode: 'Block the device code flow except for the few devices that need it (for example meeting room devices).',
  signInRisk: 'Require MFA for medium and high sign-in risk.',
  userRisk: 'Require a secure password change for high user risk.',
  regInfo: 'Protect the "Register security information" user action (trusted location or Temporary Access Pass).',
  workload: 'Use Conditional Access for workload identities to restrict tenant apps to known IP ranges.',
};

function downgrade(s) {
  return SEVERITY_ORDER[Math.min(SEVERITY_ORDER.indexOf(s) + 1, 3)];
}

function findingsFromPolicies(policies, ctx, add) {
  const staleReportOnly = policies.filter((p) => p.state === 'enabledForReportingButNotEnforced' && p.reportOnlyDays !== null && p.reportOnlyDays > 60);
  if (staleReportOnly.length) {
    add({ area: 'access', severity: 'medium', title: `${staleReportOnly.length} report-only polic${staleReportOnly.length > 1 ? 'ies' : 'y'} waiting for a decision for over 60 days`, detail: staleReportOnly.map((p) => p.name).join(', '), impact: 'Protection that was designed is not switched on. The business is carrying the risk without a decision on record.', fix: 'Review the report-only results in the sign-in logs, then enable or delete each policy.', ref: DOCS.reportOnly });
  }
  const disabled = policies.filter((p) => p.state === 'disabled');
  if (disabled.length >= 5) {
    add({ area: 'exceptions', severity: 'low', title: `${disabled.length} disabled policies`, detail: 'Disabled policies make the configuration harder to understand and review.', impact: 'Slower reviews and audits; risk of re-enabling something outdated.', fix: 'Export and delete policies that are no longer needed.', ref: DOCS.caOverview });
  }
  const heavy = policies.filter((p) => p.state === 'enabled' && p.exclusions >= 10);
  if (heavy.length) {
    add({ area: 'exceptions', severity: 'medium', title: `${heavy.length} polic${heavy.length > 1 ? 'ies have' : 'y has'} 10 or more exclusions`, detail: heavy.map((p) => `${p.name} (${p.exclusions})`).join(', '), impact: 'Exception sprawl: each exclusion is a door that no one reviews.', fix: 'Consolidate exceptions into owned groups with expiry, and replace app exclusions with dedicated policies.', ref: DOCS.caUsers });
  }
  // Policies targeting All resources while excluding apps.
  const allWithExcl = ctx.enabledUserPolicies.filter((p) => targetsAllResources(p) && (appsOf(p).excludeApplications || []).length);
  if (allWithExcl.length) {
    add({ area: 'exceptions', severity: 'medium', title: 'Policies on "All resources" with app exclusions: check behaviour change', detail: allWithExcl.map((p) => p.displayName).join(', '), impact: 'Microsoft has changed how these policies apply when an app only asks for basic sign-in permissions: they are now enforced in cases that used to slip through. Apps that relied on that gap can start prompting or failing.', fix: 'Test with report-only and the what-if tool, and replace app exclusions with dedicated policies where possible.', ref: DOCS.caApps, business: true });
  }
}

function findingsFromApps(apps, ctx, add) {
  const business = apps.filter((a) => a.category !== 'microsoft');
  const none = business.filter((a) => a.protection === 'none' && a.enabled !== false);
  if (none.length) {
    const onPrem = none.filter((a) => ['appProxy', 'saml', 'passwordSso'].includes(a.category));
    add({ area: 'access', severity: none.length > 10 ? 'high' : 'medium', title: `${none.length} business app${none.length > 1 ? 's' : ''} with no MFA policy`, detail: `Includes ${onPrem.length} SAML / App Proxy / password-SSO app${onPrem.length === 1 ? '' : 's'}. ${none.slice(0, 8).map((a) => a.name).join(', ')}${none.length > 8 ? ', ...' : ''}`, impact: 'These apps can be reached with a password alone.', fix: 'Bring them under an "All resources" MFA policy, or a dedicated policy if they need special treatment.', ref: DOCS.caApps, business: true });
  }
  const unusedExcluded = apps.filter((a) => a.excludedBy.length && a.unused && a.category !== 'microsoft');
  if (unusedExcluded.length) {
    add({ area: 'exceptions', severity: 'low', title: `${unusedExcluded.length} excluded app${unusedExcluded.length > 1 ? 's' : ''} not used in ${UNUSED_DAYS} days`, detail: unusedExcluded.map((a) => a.name).join(', '), impact: 'Exceptions kept for apps nobody uses.', fix: 'Remove the exclusions and consider retiring the apps.', ref: DOCS.caApps });
  }
}

function findingsFromExclusions(exclusions, ctx, add) {
  const gaps = exclusions.filter((e) => e.verdict === 'gap');
  const byKind = countBy(gaps, 'kind');
  for (const [kind, n] of Object.entries(byKind)) {
    const list = gaps.filter((e) => e.kind === kind);
    const severity = kind === 'Role' || kind === 'Group' ? 'high' : 'medium';
    add({ area: 'exceptions', severity, title: `${plural(n, kind.toLowerCase() + ' exclusion')} that open${n === 1 ? 's' : ''} a security gap`, detail: list.slice(0, 8).map((e) => `${e.targetName} in "${e.policyName}"`).join('; ') + (list.length > 8 ? '; ...' : ''), impact: list[0].reason, fix: list[0].fix, ref: DOCS.caUsers, business: kind === 'Application' });
  }
  const stale = exclusions.filter((e) => e.verdict === 'stale');
  if (stale.length) {
    add({ area: 'exceptions', severity: 'low', title: `${stale.length} exclusion${stale.length > 1 ? 's point' : ' points'} to objects that no longer exist`, detail: stale.slice(0, 8).map((e) => `${e.kind} in "${e.policyName}"`).join('; '), impact: 'Noise that hides the exceptions that matter.', fix: 'Remove them.', ref: DOCS.caUsers });
  }
  const userEx = exclusions.filter((e) => e.kind === 'User' && e.verdict === 'review');
  if (userEx.length >= 5) {
    add({ area: 'exceptions', severity: 'medium', title: `${userEx.length} individual user exceptions`, detail: 'Users excluded one by one, outside emergency accounts.', impact: 'Per-person exceptions are rarely reviewed and outlive their reason.', fix: 'Move them into one exception group with an owner, an expiry and an access review.', ref: DOCS.caUsers });
  }
  const bg = exclusions.filter((e) => e.kind === 'User' && e.verdict === 'justified');
  if (ctx.enabledUserPolicies.length >= 2 && new Set(bg.map((e) => e.targetId)).size === 0) {
    add({ area: 'exceptions', severity: 'low', title: 'No emergency-access account detected', detail: 'No user is excluded from most policies.', impact: 'A Conditional Access mistake can lock every admin out of the tenant.', fix: 'Create two cloud-only emergency accounts with phishing-resistant sign-in, exclude them from policies, and alert on their use.', ref: DOCS.emergencyAccess });
  }
}

function findingsFromLocations(locations, ctx, add) {
  for (const l of locations) {
    for (const i of l.issues) {
      if (i.severity === 'low' && !l.trusted) continue;
      add({ area: 'locations', severity: i.severity, title: `${l.name}: ${i.text.split('.')[0]}`, detail: i.text + (l.trusted ? ' This location is marked trusted.' : ''), impact: l.trusted ? 'Policies that relax controls on trusted networks extend that trust to everyone in the range.' : 'Location conditions may not match what you intended.', fix: 'Use only the public egress ranges you own. Prefer compliant devices over network trust.', ref: DOCS.namedLocations });
    }
  }
  const trustedIp = locations.filter((l) => l.trusted && l.type === 'ip');
  const mfaSkipped = ctx.enabledUserPolicies.filter((p) => ctx.gs(p).requiresMfa && (p.conditions?.locations?.excludeLocations || []).length);
  if (mfaSkipped.length && trustedIp.length) {
    add({ area: 'locations', severity: 'medium', title: 'MFA is skipped on trusted networks', detail: mfaSkipped.map((p) => p.displayName).join(', '), impact: 'Anyone on the office network, including a compromised device or a guest Wi-Fi sharing the egress IP, needs only a password.', fix: 'Keep MFA everywhere and rely on device compliance to reduce prompts.', ref: DOCS.namedLocations });
  }
}

function findingsFromWorkload(w, ctx, add) {
  const t = w.totals;
  if (t.dormant) add({ area: 'workload', severity: 'high', title: `${t.dormant} app${t.dormant > 1 ? 's' : ''} with valid credentials but no recent sign-ins`, detail: w.apps.filter((a) => a.dormant).slice(0, 8).map((a) => a.name).join(', '), impact: 'Dormant credentials are a quiet back door: nobody notices if they are used.', fix: 'Remove the credentials, or the app, after confirming with its owner.', ref: DOCS.workloadCa });
  if (t.longLived) add({ area: 'workload', severity: 'medium', title: `${t.longLived} app${t.longLived > 1 ? 's' : ''} with secrets valid for more than a year`, detail: w.apps.filter((a) => a.longLivedSecrets).slice(0, 8).map((a) => a.name).join(', '), impact: 'Long-lived secrets end up in scripts, wikis and config files.', fix: 'Move to certificates or managed identities; cap secret lifetime with an app management policy.', ref: DOCS.workloadCa });
  if (t.multiTenantWithSecrets) add({ area: 'workload', severity: 'medium', title: `${t.multiTenantWithSecrets} multi-tenant app${t.multiTenantWithSecrets > 1 ? 's' : ''} with client secrets`, detail: w.apps.filter((a) => a.multiTenant && a.secrets).slice(0, 8).map((a) => a.name).join(', '), impact: 'A leaked secret on a multi-tenant app can reach other organisations too.', fix: 'Confirm the app really needs to be multi-tenant; switch to certificates.', ref: DOCS.workloadCa });
  if (t.expired) add({ area: 'workload', severity: 'low', title: `${t.expired} app${t.expired > 1 ? 's' : ''} with expired credentials`, detail: 'Expired secrets and certificates left on app registrations.', impact: 'Clutter that hides which credentials are live.', fix: 'Remove expired credentials.', ref: DOCS.workloadCa });
  if (t.expiringSoon) add({ area: 'workload', severity: 'medium', title: `${t.expiringSoon} app${t.expiringSoon > 1 ? 's' : ''} with credentials expiring within 30 days`, detail: w.apps.filter((a) => a.expiringSoon).slice(0, 8).map((a) => a.name).join(', '), impact: 'Business integrations stop when the credential expires.', fix: 'Rotate now and set reminders with the app owners.', ref: DOCS.workloadCa, business: true });
}

function findingsFromDlp(dlp, add) {
  const sev = { mda: 'high', aer: 'medium', managed: 'high', authContext: 'medium', insider: 'low', guests: 'high', token: 'low', lifetime: 'low' };
  for (const c of dlp.controls) {
    if (c.status === 'present') continue;
    const severity = c.status === 'partial' ? downgrade(sev[c.id]) : sev[c.id];
    add({ area: 'dlp', severity, title: `${c.title}: ${c.status === 'partial' ? 'partial' : 'not in place'}`, detail: c.detail, impact: c.why, fix: DLP_FIX[c.id], ref: c.ref });
  }
  if (dlp.rmsExcluded.length) {
    add({ area: 'dlp', severity: 'info', title: 'Rights Management Services is excluded from a policy', detail: dlp.rmsExcluded.join(', '), impact: 'Affects who can open encrypted, labelled content. This is a DLP decision and should have an owner.', fix: 'Record the decision in the DLP design and review it with the Purview team.', ref: DOCS.purviewDlp });
  }
}

const DLP_FIX = {
  mda: 'Route browser sessions for sensitive apps on unmanaged devices through Defender for Cloud Apps (block download, protect on download).',
  aer: 'Enable app-enforced restrictions for SharePoint and Exchange for unmanaged devices.',
  managed: 'Require a compliant device or an app protection policy for Office 365 on desktop and mobile apps.',
  authContext: 'Create a policy for each authentication context used by sensitivity labels or SharePoint sites.',
  insider: 'If Purview Adaptive Protection is licensed, add a policy that blocks elevated insider risk.',
  guests: 'Require MFA for guests and external users on all resources.',
  token: 'Pilot token protection for Exchange, SharePoint and Teams on Windows.',
  lifetime: 'Set sign-in frequency and no persistent browser for unmanaged devices.',
};

function findingsFromCrownJewels(crown, add) {
  for (const a of crown) {
    if (a.excludedBy.length) {
      add({ area: 'crown', severity: 'critical', title: `Crown jewel "${a.name}" is excluded from ${a.excludedBy.length} polic${a.excludedBy.length > 1 ? 'ies' : 'y'}`, detail: a.excludedBy.map((p) => p.name).join(', '), impact: 'One of the most valuable applications skips protection that the rest of the business has.', fix: 'Remove the exclusion; give the app a dedicated policy if it needs one.', ref: DOCS.caApps, business: true });
    }
    if (a.protection !== 'strong') {
      add({ area: 'crown', severity: a.protection === 'none' ? 'critical' : 'high', title: `Crown jewel "${a.name}": MFA ${a.protection === 'none' ? 'not required' : 'only ' + a.protection}`, detail: a.applying.map((p) => `${p.name}: ${p.controls}`).join('; ') || 'No policy applies.', impact: 'A stolen password may be enough to reach this application.', fix: 'Require MFA for all users on this app, without location exceptions.', ref: DOCS.caApps });
    } else if (!a.phishingResistant) {
      add({ area: 'crown', severity: 'medium', title: `Crown jewel "${a.name}": MFA is not phishing-resistant`, detail: 'Any MFA method is accepted.', impact: 'Real-time phishing kits can capture a normal MFA prompt.', fix: 'Require the "Phishing-resistant MFA" authentication strength for this app.', ref: DOCS.authStrength });
    }
    if (!a.managedDevice && !a.sessionControl) {
      add({ area: 'crown', severity: 'medium', title: `Crown jewel "${a.name}": no device or session control`, detail: 'Data can be reached and downloaded from any device.', impact: 'Data from the most important app can land on unmanaged devices, out of DLP scope.', fix: 'Require a compliant device, or use Defender for Cloud Apps session control on unmanaged devices.', ref: DOCS.appControl });
    }
  }
}

// ---------------------------------------------------------------------------
// Scores and management answers
// ---------------------------------------------------------------------------

function score(findings, applicable) {
  const areas = {};
  for (const [key, a] of Object.entries(AREAS)) {
    const pen = findings.filter((f) => f.area === key).reduce((s, f) => s + PENALTY[f.severity], 0);
    areas[key] = { label: a.label, score: Math.max(0, 100 - pen), weight: a.weight, findings: findings.filter((f) => f.area === key).length };
  }
  if (!applicable.crown) areas.crown.score = null;
  if (!applicable.agents && !areas.agents.findings) areas.agents.score = null;
  const used = Object.values(areas).filter((a) => a.score !== null);
  const w = used.reduce((s, a) => s + a.weight, 0);
  const overall = Math.round(used.reduce((s, a) => s + a.score * a.weight, 0) / w);
  return { overall, rating: rating(overall), areas };
}

export function rating(n) {
  if (n >= 85) return { label: 'Strong', tone: 'good' };
  if (n >= 65) return { label: 'Fair', tone: 'warn' };
  if (n >= 40) return { label: 'Weak', tone: 'danger' };
  return { label: 'At risk', tone: 'danger' };
}

function workforceOutsideMfa(ctx, baseline) {
  const mfa = ctx.enabledUserPolicies.filter((p) => targetsAllUsers(p) && targetsAllResources(p) && ctx.gs(p).requiresMfa);
  if (!mfa.length) return { covered: false, people: ctx.userCounts.total || null, percent: 100 };
  // Use the policy with the fewest excluded people.
  let best = null;
  for (const p of mfa) {
    const u = usersOf(p);
    let n = (u.excludeUsers || []).length;
    let unknown = false;
    for (const g of u.excludeGroups || []) {
      const s = ctx.groupSizes[g];
      if (s == null) unknown = true; else n += s;
    }
    if (!best || n < best.n) best = { n, unknown, policy: p.displayName, guestsExcluded: !!u.excludeGuestsOrExternalUsers, roles: (u.excludeRoles || []).length };
  }
  const total = ctx.userCounts.total || 0;
  return { covered: true, people: best.n, approximate: best.unknown, percent: total ? Math.round((best.n / total) * 1000) / 10 : null, policy: best.policy, guestsExcluded: best.guestsExcluded, rolesExcluded: best.roles };
}

function managementQuestions(r, ctx) {
  const q = [];
  const s = r.summary;
  const base = (id) => r.baseline.find((c) => c.id === id);
  const w = s.workforceOutsideMfa;
  const mfa = base('mfaAll');
  q.push({
    q: 'Is everyone protected by MFA, on every application?',
    status: mfa.status === 'present' && w.people <= 5 ? 'good' : mfa.status === 'missing' ? 'bad' : 'warn',
    a: mfa.status === 'missing'
      ? 'No. There is no policy that requires MFA for all users on all applications.'
      : `${mfa.status === 'present' ? 'Mostly.' : 'Partly.'} The main MFA policy ("${w.policy}") excludes ${w.approximate ? 'at least ' : ''}${(w.people || 0).toLocaleString()} ${w.people === 1 ? 'person' : 'people'}${w.percent !== null ? ` (${w.percent}% of accounts)` : ''}${w.guestsExcluded ? ' plus all guests' : ''}.${mfa.status === 'partial' ? ' It also applies only under certain conditions.' : ''}`,
  });
  const ex = s.exclusions;
  q.push({
    q: 'How many exceptions do we have, and are they justified?',
    status: (ex.gap || 0) === 0 && s.exclusionTotal < 20 ? 'good' : (ex.gap || 0) > 3 ? 'bad' : 'warn',
    a: `${plural(s.exclusionTotal, 'exception')} across active policies (counted once per policy): ${ex.gap || 0} open a gap, ${ex.review || 0} need an owner to confirm, ${ex.cleanup || 0} can likely be removed (unused), ${ex.stale || 0} point to deleted objects, ${ex.justified || 0} look justified.`,
  });
  const appEx = r.exclusions.filter((e) => e.kind === 'Application');
  const onPremEx = appEx.filter((e) => /SAML|App Proxy|Password SSO/.test(e.category));
  q.push({
    q: 'Which business applications are outside protection, and what could break if we tighten?',
    status: s.apps.unprotected === 0 && appEx.length === 0 ? 'good' : s.apps.unprotected > 10 ? 'bad' : 'warn',
    a: `${s.apps.unprotected} of ${s.apps.business} business apps have no MFA policy. ${appEx.length} app exclusion${appEx.length === 1 ? '' : 's'} exist${appEx.length === 1 ? 's' : ''}, ${onPremEx.length} of them for SAML or on-prem (App Proxy) apps. Those apps still sign in through Entra: they are the most likely to be affected when policies tighten, and the best candidates for a dedicated policy instead of an exclusion. Use the What-if tab to test a change before making it.`,
  });
  const cj = r.apps.filter((a) => a.crownJewel);
  q.push({
    q: 'Are our crown-jewel applications protected to the right level?',
    status: !cj.length ? 'unknown' : cj.every((a) => a.protection === 'strong' && !a.excludedBy.length && a.phishingResistant && (a.managedDevice || a.sessionControl)) ? 'good' : cj.some((a) => a.protection === 'none' || a.excludedBy.length) ? 'bad' : 'warn',
    a: !cj.length
      ? 'Not assessed yet. Mark your crown-jewel applications in the Applications tab to get an answer.'
      : `${cj.length} crown jewel${cj.length > 1 ? 's' : ''} tagged. ${cj.filter((a) => a.protection === 'strong').length} always require MFA, ${cj.filter((a) => a.phishingResistant).length} require phishing-resistant MFA, ${cj.filter((a) => a.managedDevice || a.sessionControl).length} have device or session controls, ${cj.filter((a) => a.excludedBy.length).length} excluded from at least one policy.`,
  });
  const trustedBroad = r.locations.filter((l) => l.trusted && l.issues.some((i) => i.severity === 'critical' || i.severity === 'high'));
  const locSkip = r.exclusions.filter((e) => e.kind === 'Location');
  q.push({
    q: 'Do our trusted locations create a way around security?',
    status: trustedBroad.length ? 'bad' : locSkip.length ? 'warn' : 'good',
    a: `${plural(r.locations.length, 'named location')}, ${r.locations.filter((l) => l.trusted).length} trusted. ${plural(trustedBroad.length, 'trusted location has', 'trusted locations have')} overly broad IP ranges. ${locSkip.length} polic${locSkip.length === 1 ? 'y skips' : 'ies skip'} controls based on location.`,
  });
  const wt = r.workload.totals;
  const wlOn = r.workload.policies.filter((p) => p.state === 'enabled').length;
  q.push({
    q: 'Are non-human identities (apps, services, automation) under control?',
    status: base('workload').status === 'present' && !wt.dormant && !wt.highPrivilege ? 'good' : wt.dormant || wt.multiTenantWithSecrets || wt.highPrivilege ? 'bad' : 'warn',
    a: `${plural(r.workload.apps.length, 'app registration')} hold credentials (${wt.withSecrets} with client secrets). ${plural(wt.dormant, 'app has', 'apps have')} valid credentials but no recent use; ${plural(wt.longLived, 'app has', 'apps have')} secrets valid for over a year. ${r.workload.policies.length ? `${plural(r.workload.policies.length, 'workload identity policy', 'workload identity policies')} exist, ${wlOn} enabled.` : 'No Conditional Access policy covers workload identities.'} ${plural(r.workload.managedIdentities, 'managed identity', 'managed identities')} in use (preferred: no secrets to leak).${wt.highPrivilege ? ` ${plural(wt.highPrivilege, 'app', 'apps')} can change tenant security through permissions or admin roles.` : ''}`,
  });
  const dc = r.dlp.controls;
  const present = dc.filter((c) => c.status === 'present').length;
  q.push({
    q: 'Is company data protected on unmanaged and personal devices?',
    status: ['mda', 'managed'].every((id) => dc.find((c) => c.id === id).status === 'present') ? 'good' : present >= 3 ? 'warn' : 'bad',
    a: `${present} of ${dc.length} identity-side data protection controls ${present === 1 ? 'is' : 'are'} in place. ${dc.filter((c) => c.status !== 'present').map((c) => c.title).slice(0, 3).join('; ')}${dc.filter((c) => c.status !== 'present').length ? ' are missing or partial.' : ''}`,
  });
  const adm = base('adminsPr');
  q.push({
    q: 'Are administrators protected against phishing?',
    status: adm.status === 'present' ? 'good' : adm.status === 'partial' ? 'warn' : 'bad',
    a: adm.detail,
  });
  const ag = r.agents;
  const at = ag.totals;
  const agCheck = (id) => ag.checks.find((c) => c.id === id)?.status;
  q.push({
    q: 'Are our AI agents governed, and could one be misused?',
    status: !ag.inUse ? 'unknown'
      : at.riskUnblocked || at.critical || agCheck('agentCa') === 'missing' ? 'bad'
        : agCheck('agentCa') === 'present' && agCheck('agentRisk') === 'present' && !at.highPrivilege && !at.noSponsor ? 'good' : 'warn',
    a: !ag.inUse
      ? 'No AI agents were found (no Entra Agent ID identities or AI-like apps). Re-run when agents are introduced, and set up agent policies before the first one goes live.'
      : `${plural(at.identities, 'agent identity', 'agent identities')}${at.agentUsers ? `, ${plural(at.agentUsers, 'agent user account')}` : ''}${at.candidates ? ` and ${plural(at.candidates, 'AI-like app')} outside Agent ID` : ''}. ${at.governed} of ${at.identities} covered by an enforced Conditional Access policy. ${plural(at.highPrivilege, 'agent holds', 'agents hold')} organisation-wide permissions${at.critical ? `, ${at.critical} of them can change tenant security` : ''}. ${at.atRisk ? `${plural(at.atRisk, 'agent is', 'agents are')} flagged risky${at.riskUnblocked ? ', not blocked' : ''}. ` : ''}${at.noSponsor ? `${plural(at.noSponsor, 'agent has', 'agents have')} no sponsor.` : ''}`.trim(),
  });
  const pv = r.purview;
  const pvc = (id) => pv.checks.find((c) => c.id === id)?.status;
  q.push({
    q: 'Does Purview DLP cover where our data goes, including Copilot and agents?',
    status: !pv.imported ? 'unknown'
      : pvc('dlpCore') === 'present' && pvc('dlpCopilot') === 'present' && ['present', 'unknown'].includes(pvc('dlpEndpoint')) ? 'good'
        : pvc('dlpCore') === 'missing' ? 'bad' : 'warn',
    a: !pv.imported
      ? `${pv.labels.length ? `${plural(pv.labels.length, 'sensitivity label')} found (${pv.totals.encrypting} encrypting). ` : ''}DLP policies are not readable through Graph: load a Purview export in the Purview tab to answer this.`
      : `${plural(pv.totals.dlpPolicies, 'DLP policy', 'DLP policies')} (${pv.totals.enforced} enforced, ${pv.totals.test} in test mode) across ${pv.totals.locationsEnforced} enforced location${pv.totals.locationsEnforced === 1 ? '' : 's'}. Core workloads: ${pvc('dlpCore') === 'present' ? 'covered' : 'gaps'}. Copilot and agents: ${pvc('dlpCopilot') === 'present' ? 'covered' : 'not covered'}. Devices: ${pvc('dlpEndpoint') === 'present' ? 'Endpoint DLP backed by managed-device access' : pvc('dlpEndpoint') === 'partial' ? 'Endpoint DLP without a managed-device requirement' : 'not covered'}.`,
  });
  const top = r.findings.filter((f) => f.severity !== 'info').slice(0, 3);
  q.push({
    q: 'What should we fix first?',
    status: top.length ? (top[0].severity === 'critical' ? 'bad' : 'warn') : 'good',
    a: top.length ? top.map((f, i) => `${i + 1}. ${f.title}`).join(' ') : 'No significant issues found.',
  });
  return q;
}
