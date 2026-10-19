// Simplified Conditional Access what-if evaluator.
//
// Given a sign-in scenario, decides for each policy whether it applies and,
// combining all applying policies, what the user experiences. It follows the
// documented evaluation model: every applying policy must be satisfied; any
// block wins; exclusions beat inclusions.
//
// Simplifications (shown in the UI): device filters, authentication flows,
// insider risk and user actions are reported as "not evaluated" rather than
// guessed. Microsoft's own What If tool in the Entra admin center remains the
// reference for a specific user.

import { KNOWN_APPS } from './knowledge.js';
import { grantSummary, sessionSummary, isWorkloadPolicy, describeGrant, appInScope, STATE_LABEL } from './policy.js';

/**
 * scenario = {
 *   userType: 'member' | 'guest',
 *   userId?: string,            // a specific user referenced by policies
 *   groupIds: string[],         // groups the user belongs to
 *   roleIds: string[],          // directory role template ids the user holds
 *   appId: string,
 *   locationId: string | 'untrusted',   // a named location id
 *   platform: 'windows'|'macOS'|'iOS'|'android'|'linux',
 *   clientApp: 'browser'|'mobileAppsAndDesktopClients'|'exchangeActiveSync'|'other',
 *   device: 'compliant'|'hybrid'|'unmanaged',
 *   signInRisk: 'none'|'low'|'medium'|'high',
 *   userRisk: 'none'|'low'|'medium'|'high',
 * }
 */
export function evaluate(policies, scenario, { strengthById = {}, namedLocations = [] } = {}) {
  const locs = new Map(namedLocations.map((l) => [l.id, l]));
  const results = [];
  for (const p of policies) {
    if (p.state === 'disabled' || isWorkloadPolicy(p)) continue;
    const r = matchPolicy(p, scenario, locs);
    const gs = grantSummary(p, strengthById);
    results.push({
      id: p.id,
      name: p.displayName,
      state: p.state,
      stateLabel: STATE_LABEL[p.state] || p.state,
      applies: r.applies,
      reason: r.reason,
      notEvaluated: r.notEvaluated,
      controls: describeGrant(gs),
      gs,
      session: sessionSummary(p),
    });
  }
  const enforced = results.filter((r) => r.applies && r.state === 'enabled');
  const reportOnly = results.filter((r) => r.applies && r.state === 'enabledForReportingButNotEnforced');
  return {
    results: results.sort((a, b) => (b.applies - a.applies) || a.name.localeCompare(b.name)),
    outcome: combine(enforced, scenario),
    reportOnlyOutcome: reportOnly.length ? combine([...enforced, ...reportOnly], scenario) : null,
  };
}

function matchPolicy(p, s, locs) {
  const c = p.conditions || {};
  const notEvaluated = [];

  // Users
  const u = c.users || {};
  const inUsers = (u.includeUsers || []);
  const isGuest = s.userType === 'guest';
  const userIncluded = inUsers.includes('All') ||
    (isGuest && (inUsers.includes('GuestsOrExternalUsers') || !!u.includeGuestsOrExternalUsers)) ||
    (s.userId && inUsers.includes(s.userId)) ||
    (u.includeGroups || []).some((g) => s.groupIds.includes(g)) ||
    (u.includeRoles || []).some((r) => s.roleIds.includes(r));
  if (!userIncluded) return { applies: false, reason: 'User not in scope', notEvaluated };
  const userExcluded = (s.userId && (u.excludeUsers || []).includes(s.userId)) ||
    (u.excludeGroups || []).some((g) => s.groupIds.includes(g)) ||
    (u.excludeRoles || []).some((r) => s.roleIds.includes(r)) ||
    (isGuest && (!!u.excludeGuestsOrExternalUsers || (u.excludeUsers || []).includes('GuestsOrExternalUsers')));
  if (userExcluded) return { applies: false, reason: 'User excluded', notEvaluated };

  // Applications
  const a = c.applications || {};
  if ((a.includeUserActions || []).length) return { applies: false, reason: 'Applies to a user action, not app sign-in', notEvaluated };
  if ((a.includeAuthenticationContextClassReferences || []).length) return { applies: false, reason: 'Applies when an app requests an authentication context', notEvaluated };
  const inApps = a.includeApplications || [];
  let appMatch = appInScope(p, s.appId);
  if (!appMatch && inApps.includes('MicrosoftAdminPortals') && ADMIN_PORTAL_APPS.has(s.appId)) appMatch = !(a.excludeApplications || []).includes(s.appId);
  if (!appMatch) {
    const excluded = (a.excludeApplications || []).includes(s.appId) || ((a.excludeApplications || []).includes('Office365') && KNOWN_APPS[s.appId]?.o365);
    return { applies: false, reason: excluded ? 'App excluded' : 'App not in scope', notEvaluated };
  }
  if (a.applicationFilter) notEvaluated.push('application filter');

  // Locations
  const l = c.locations;
  if (l && ((l.includeLocations || []).length || (l.excludeLocations || []).length)) {
    const loc = s.locationId === 'untrusted' ? null : locs.get(s.locationId);
    const trusted = !!loc?.isTrusted;
    const inLoc = (id) => id === 'All' || (id === 'AllTrusted' && trusted) || (loc && id === loc.id);
    const inc = l.includeLocations || [];
    if (inc.length && !inc.some(inLoc)) return { applies: false, reason: 'Location not in scope', notEvaluated };
    if ((l.excludeLocations || []).some(inLoc)) return { applies: false, reason: 'Location excluded', notEvaluated };
  }

  // Platforms
  const pl = c.platforms;
  if (pl && ((pl.includePlatforms || []).length)) {
    const inc = pl.includePlatforms.map((x) => x.toLowerCase());
    const plat = s.platform.toLowerCase();
    if (!inc.includes('all') && !inc.includes(plat)) return { applies: false, reason: 'Device platform not in scope', notEvaluated };
    if ((pl.excludePlatforms || []).map((x) => x.toLowerCase()).includes(plat)) return { applies: false, reason: 'Device platform excluded', notEvaluated };
  }

  // Client apps
  const cat = c.clientAppTypes || [];
  if (cat.length && !cat.includes('all') && !cat.includes(s.clientApp)) return { applies: false, reason: 'Client app not in scope', notEvaluated };

  // Risk
  if ((c.signInRiskLevels || []).length && !c.signInRiskLevels.includes(s.signInRisk)) return { applies: false, reason: 'Sign-in risk does not match', notEvaluated };
  if ((c.userRiskLevels || []).length && !c.userRiskLevels.includes(s.userRisk)) return { applies: false, reason: 'User risk does not match', notEvaluated };

  if (c.devices?.deviceFilter) notEvaluated.push('device filter');
  if (c.authenticationFlows?.transferMethods) notEvaluated.push('authentication flows');
  if ((c.insiderRiskLevels || '').length) notEvaluated.push('insider risk');
  if ((c.servicePrincipalRiskLevels || []).length) notEvaluated.push('service principal risk');

  return { applies: true, reason: notEvaluated.length ? 'Applies (some conditions not evaluated)' : 'Applies', notEvaluated };
}

// Admin portals bundle (Azure portal / management API). Conservative subset.
const ADMIN_PORTAL_APPS = new Set(['797f4846-ba00-4fd7-ba43-dac1f8f63013']);

function combine(applying, s) {
  if (!applying.length) {
    return { verdict: 'open', label: 'Allowed with password only', detail: 'No enforced policy applies. The sign-in succeeds with a password alone.', requirements: [], blockedBy: [] };
  }
  const blockedBy = applying.filter((r) => r.gs.block);
  if (blockedBy.length) {
    return { verdict: 'blocked', label: 'Blocked', detail: `Blocked by ${blockedBy.map((r) => `"${r.name}"`).join(', ')}.`, requirements: [], blockedBy: blockedBy.map((r) => r.name) };
  }
  const requirements = [];
  const failing = [];
  for (const r of applying) {
    const gs = r.gs;
    if (!gs.options.length) continue;
    const satisfied = (o) => {
      if (o === 'compliantDevice') return s.device === 'compliant';
      if (o === 'hybridJoined') return s.device === 'hybrid';
      if (o === 'approvedApp' || o === 'appProtection') return s.clientApp === 'mobileAppsAndDesktopClients' && (s.platform === 'iOS' || s.platform === 'android') ? null : false;
      return null; // user-satisfiable (MFA, ToU...) : becomes a prompt
    };
    const states = gs.options.map((o) => ({ o, ok: satisfied(o) }));
    const canPass = gs.operator === 'AND' ? states.every((x) => x.ok !== false) : states.some((x) => x.ok !== false);
    if (!canPass) failing.push(r);
    requirements.push({ policy: r.name, controls: r.controls, met: canPass });
  }
  const session = applying.filter((r) => r.session.any || r.session.mda).map((r) => r.name);
  if (failing.length) {
    return { verdict: 'fails', label: 'Blocked: requirement cannot be met', detail: `The device or app cannot meet ${failing.map((r) => `"${r.name}" (${r.controls})`).join(', ')}. The user sees an access-denied page. This is the classic business break.`, requirements, blockedBy: failing.map((r) => r.name), session };
  }
  const prompts = requirements.filter((r) => /MFA|strength|Terms|Password change/i.test(r.controls));
  return {
    verdict: prompts.length ? 'challenge' : 'allowed',
    label: prompts.length ? 'Allowed after extra checks' : 'Allowed',
    detail: prompts.length ? `The user must complete: ${[...new Set(prompts.map((r) => r.controls))].join('; ')}.` : 'Device requirements are met; no prompt.',
    requirements,
    blockedBy: [],
    session,
  };
}
