// Helpers that describe a single Conditional Access policy.
// Pure functions: no DOM, no Graph. Shared by the analyzer and the what-if engine.

import { KNOWN_APPS, PHISHING_RESISTANT } from './knowledge.js';

export const STATE_LABEL = {
  enabled: 'On',
  disabled: 'Off',
  enabledForReportingButNotEnforced: 'Report-only',
};

export const isEnabled = (p) => p?.state === 'enabled';
export const isReportOnly = (p) => p?.state === 'enabledForReportingButNotEnforced';

export function usersOf(p) {
  return p?.conditions?.users || {};
}

export function appsOf(p) {
  return p?.conditions?.applications || {};
}

// True when the policy is aimed at workload identities (service principals)
// rather than users.
export function isWorkloadPolicy(p) {
  const c = p?.conditions?.clientApplications;
  return !!(c && ((c.includeServicePrincipals || []).length || c.servicePrincipalFilter));
}

// True when the policy targets agent identities (Entra Agent ID, autonomous
// app-only access). Graph beta: clientApplications.includeAgentIdServicePrincipals
// ('All' or agent / blueprint object IDs) or agentIdServicePrincipalFilter.
export function isAgentPolicy(p) {
  const c = p?.conditions?.clientApplications;
  return !!(c && ((c.includeAgentIdServicePrincipals || []).length || c.agentIdServicePrincipalFilter));
}

// True when the policy targets agents' user accounts (agent users, preview).
// The Graph representation is still in preview, so this matches any users
// assignment value that names agent users (for example 'AllAgentIdUsers') or an
// explicit list of known agent user IDs.
export function isAgentUserPolicy(p, agentUserIds = new Set()) {
  const u = p?.conditions?.users || {};
  const inc = u.includeUsers || [];
  if (inc.some((x) => /agent/i.test(x))) return true;
  if (u.includeAgentUsers || u.includeAgentIdUsers) return true;
  return inc.length > 0 && inc.every((x) => agentUserIds.has(x));
}

// Policies that do not apply to human user sign-ins.
export function isNonUserPolicy(p, agentUserIds) {
  return isWorkloadPolicy(p) || isAgentPolicy(p) || isAgentUserPolicy(p, agentUserIds);
}

export function targetsAllUsers(p) {
  return (usersOf(p).includeUsers || []).includes('All');
}

export function targetsAllResources(p) {
  return (appsOf(p).includeApplications || []).includes('All');
}

export function isUserActionPolicy(p) {
  return (appsOf(p).includeUserActions || []).length > 0;
}

export function isAuthContextPolicy(p) {
  return (appsOf(p).includeAuthenticationContextClassReferences || []).length > 0;
}

// Does the policy's *application* assignment cover this appId?
// Ignores users/locations/etc.
export function appInScope(p, appId) {
  const a = appsOf(p);
  const inc = a.includeApplications || [];
  const exc = a.excludeApplications || [];
  if (exc.includes(appId)) return false;
  if (exc.includes('Office365') && KNOWN_APPS[appId]?.o365) return false;
  if (inc.includes('All')) return true;
  if (inc.includes(appId)) return true;
  if (inc.includes('Office365') && KNOWN_APPS[appId]?.o365) return true;
  return false;
}

export function appExcluded(p, appId) {
  const exc = appsOf(p).excludeApplications || [];
  return exc.includes(appId) || (exc.includes('Office365') && !!KNOWN_APPS[appId]?.o365);
}

// Summarise what a policy demands when it applies.
// strengthById: map of authentication strength id -> strength object.
export function grantSummary(p, strengthById = {}) {
  const g = p?.grantControls || {};
  const controls = g.builtInControls || [];
  const operator = (g.operator || 'OR').toUpperCase();
  const strength = g.authenticationStrength
    ? (strengthById[g.authenticationStrength.id] || g.authenticationStrength)
    : null;
  const strengthCombos = strength?.allowedCombinations || [];
  const phishingResistant = !!strength && strengthCombos.length > 0 &&
    strengthCombos.every((c) => c.split(',').every((m) => PHISHING_RESISTANT.has(m.trim())));

  const options = [];
  if (controls.includes('mfa')) options.push('mfa');
  if (strength) options.push(phishingResistant ? 'phishingResistant' : 'authStrength');
  if (controls.includes('compliantDevice')) options.push('compliantDevice');
  if (controls.includes('domainJoinedDevice')) options.push('hybridJoined');
  if (controls.includes('approvedApplication')) options.push('approvedApp');
  if (controls.includes('compliantApplication')) options.push('appProtection');
  if (controls.includes('passwordChange')) options.push('passwordChange');
  if (controls.includes('riskRemediation')) options.push('riskRemediation');
  if ((g.termsOfUse || []).length) options.push('termsOfUse');

  const block = controls.includes('block');
  const mfaish = (o) => o === 'mfa' || o === 'phishingResistant' || o === 'authStrength';
  const deviceish = (o) => o === 'compliantDevice' || o === 'hybridJoined';
  const appish = (o) => o === 'approvedApp' || o === 'appProtection';

  // With OR, a requirement only holds if *every* alternative satisfies it.
  const all = (pred) => options.length > 0 && options.every(pred);
  const any = (pred) => options.some(pred);
  const holds = (pred) => (operator === 'AND' ? any(pred) : all(pred));

  return {
    block,
    operator,
    options,
    strengthName: strength?.displayName || null,
    requiresMfa: holds(mfaish),
    requiresPhishingResistant: holds((o) => o === 'phishingResistant'),
    requiresManagedDevice: holds(deviceish),
    requiresAppProtection: holds(appish),
    // "Strong" = an attacker with only a stolen password is stopped.
    strong: block || holds((o) => mfaish(o) || deviceish(o)),
    mfaOrDevice: block || (options.length > 0 && options.every((o) => mfaish(o) || deviceish(o) || appish(o))),
  };
}

export function sessionSummary(p) {
  const s = p?.sessionControls || {};
  const mda = s.cloudAppSecurity?.isEnabled ? (s.cloudAppSecurity.cloudAppSecurityType || 'mcasConfigured') : null;
  return {
    appEnforcedRestrictions: !!s.applicationEnforcedRestrictions?.isEnabled,
    mda,
    signInFrequency: s.signInFrequency?.isEnabled ? s.signInFrequency : null,
    persistentBrowser: s.persistentBrowser?.isEnabled ? s.persistentBrowser.mode : null,
    cae: s.continuousAccessEvaluation?.mode || null,
    tokenProtection: !!(s.secureSignInSession?.isEnabled),
    resilienceDisabled: !!s.disableResilienceDefaults,
    any: !!(s.applicationEnforcedRestrictions?.isEnabled || s.cloudAppSecurity?.isEnabled ||
      s.signInFrequency?.isEnabled || s.persistentBrowser?.isEnabled || s.secureSignInSession?.isEnabled),
  };
}

// Conditions that make the policy apply only some of the time.
export function conditionalScope(p) {
  const c = p?.conditions || {};
  const parts = [];
  const loc = c.locations;
  if (loc && ((loc.includeLocations || []).some((x) => x !== 'All') || (loc.excludeLocations || []).length)) parts.push('location');
  const plat = c.platforms;
  if (plat && ((plat.includePlatforms || []).some((x) => x !== 'all') || (plat.excludePlatforms || []).length)) parts.push('platform');
  const cat = c.clientAppTypes || [];
  if (cat.length && !cat.includes('all')) parts.push('client app');
  if ((c.signInRiskLevels || []).length) parts.push('sign-in risk');
  if ((c.userRiskLevels || []).length) parts.push('user risk');
  if ((c.insiderRiskLevels || '').length) parts.push('insider risk');
  if ((c.agentIdRiskLevels || '').length) parts.push('agent risk');
  if (c.devices?.deviceFilter) parts.push('device filter');
  if (c.authenticationFlows?.transferMethods) parts.push('authentication flow');
  return parts;
}

export function exclusionCount(p) {
  const u = usersOf(p);
  const a = appsOf(p);
  const c = p?.conditions?.clientApplications || {};
  return (u.excludeUsers || []).length + (u.excludeGroups || []).length + (u.excludeRoles || []).length +
    (u.excludeGuestsOrExternalUsers ? 1 : 0) + (a.excludeApplications || []).length +
    (c.excludeServicePrincipals || []).length + (c.excludeAgentIdServicePrincipals || []).length;
}

export function isMicrosoftManaged(p) {
  return /^microsoft-managed/i.test(p?.displayName || '');
}

// A human description of the controls, for tables and the report.
export function describeGrant(gs) {
  if (gs.block) return 'Block access';
  const label = {
    mfa: 'MFA',
    phishingResistant: 'Phishing-resistant MFA',
    authStrength: 'Authentication strength',
    compliantDevice: 'Compliant device',
    hybridJoined: 'Hybrid-joined device',
    approvedApp: 'Approved client app',
    appProtection: 'App protection policy',
    passwordChange: 'Password change',
    riskRemediation: 'Risk remediation',
    termsOfUse: 'Terms of use',
  };
  if (!gs.options.length) return 'Session controls only';
  return gs.options.map((o) => label[o] || o).join(gs.operator === 'AND' ? ' + ' : ' or ');
}
