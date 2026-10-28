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
import { grantSummary, sessionSummary, isWorkloadPolicy, isAgentPolicy, isAgentUserPolicy, describeGrant, appInScope, STATE_LABEL } from './policy.js';

/**
 * scenario = {
 *   userType: 'member' | 'guest' | 'agent' | 'agentUser',
 *   agentId?: string,           // agent identity object id (userType 'agent')
 *   blueprintIds?: string[],    // its blueprint principal id and blueprint app id
 *   agentUserId?: string,       // agent user object id (userType 'agentUser')
 *   agentRisk?: 'none'|'low'|'medium'|'high',
 *   authFlow?: 'none'|'deviceCodeFlow'|'authenticationTransfer',
 *   insiderRisk?: 'none'|'minor'|'moderate'|'elevated',
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
export function evaluate(policies, scenario, { strengthById = {}, namedLocations = [], agentUserIds = new Set() } = {}) {
  const locs = new Map(namedLocations.map((l) => [l.id, l]));
  const results = [];
  const subject = scenario.userType;
  for (const p of policies) {
    if (p.state === 'disabled' || isWorkloadPolicy(p)) continue;
    const agentPol = isAgentPolicy(p);
    const agentUserPol = !agentPol && isAgentUserPolicy(p, agentUserIds);
    // Each policy type only ever applies to its own kind of token subject.
    if (subject === 'agent' ? !agentPol : subject === 'agentUser' ? !agentUserPol : (agentPol || agentUserPol)) continue;
    const r = subject === 'agent' ? matchAgentPolicy(p, scenario) : matchPolicy(p, scenario, locs);
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

function riskLevels(v) {
  if (!v) return [];
  return (Array.isArray(v) ? v : String(v).split(',')).map((x) => x.trim()).filter(Boolean);
}

// Agent identity acting on its own (autonomous app-only token).
function matchAgentPolicy(p, s) {
  const c = p.conditions || {};
  const ca = c.clientApplications || {};
  const inc = ca.includeAgentIdServicePrincipals || [];
  const exc = ca.excludeAgentIdServicePrincipals || [];
  const ids = [s.agentId, ...(s.blueprintIds || [])].filter(Boolean);
  const notEvaluated = [];
  const included = inc.includes('All') || inc.some((x) => ids.includes(x));
  if (!included && !ca.agentIdServicePrincipalFilter) return { applies: false, reason: 'Agent not in scope', notEvaluated };
  if (!included) notEvaluated.push('agent attribute filter');
  if (exc.some((x) => ids.includes(x))) return { applies: false, reason: 'Agent excluded', notEvaluated };
  if (ca.agentIdServicePrincipalFilter && included) notEvaluated.push('agent attribute filter');
  const a = c.applications || {};
  const inApps = a.includeApplications || [];
  if (!(inApps.includes('All') || inApps.some((x) => /agent/i.test(x)) || appInScope(p, s.appId))) {
    return { applies: false, reason: (a.excludeApplications || []).includes(s.appId) ? 'Resource excluded' : 'Resource not in scope', notEvaluated };
  }
  const levels = riskLevels(c.agentIdRiskLevels);
  if (levels.length && !levels.includes(s.agentRisk || 'none')) return { applies: false, reason: 'Agent risk does not match', notEvaluated };
  return { applies: true, reason: notEvaluated.length ? 'Applies (some conditions not evaluated)' : 'Applies', notEvaluated };
}

function matchPolicy(p, s, locs) {
  const c = p.conditions || {};
  const notEvaluated = [];

  // Users
  const u = c.users || {};
  const inUsers = (u.includeUsers || []);
  const isGuest = s.userType === 'guest';
  if (s.userType === 'agentUser') {
    const inc = inUsers.some((x) => /agent/i.test(x)) || (s.agentUserId && inUsers.includes(s.agentUserId));
    if (!inc) return { applies: false, reason: 'Agent user not in scope', notEvaluated };
    if (s.agentUserId && (u.excludeUsers || []).includes(s.agentUserId)) return { applies: false, reason: 'Agent user excluded', notEvaluated };
    const levels = riskLevels(c.agentIdRiskLevels);
    if (levels.length && !levels.includes(s.agentRisk || 'none')) return { applies: false, reason: 'Agent risk does not match', notEvaluated };
    if (c.agentExecutionEnvironments || c.devices?.deviceFilter) notEvaluated.push('agent execution environment');
  }
  const userIncluded = s.userType === 'agentUser' ||
    inUsers.includes('All') ||
    (isGuest && (inUsers.includes('GuestsOrExternalUsers') || !!u.includeGuestsOrExternalUsers)) ||
    (s.userId && inUsers.includes(s.userId)) ||
    (u.includeGroups || []).some((g) => s.groupIds.includes(g)) ||
    (u.includeRoles || []).some((r) => s.roleIds.includes(r));
  if (!userIncluded) return { applies: false, reason: 'User not in scope', notEvaluated };
  const userExcluded = s.userType !== 'agentUser' && ((s.userId && (u.excludeUsers || []).includes(s.userId)) ||
    (u.excludeGroups || []).some((g) => s.groupIds.includes(g)) ||
    (u.excludeRoles || []).some((r) => s.roleIds.includes(r)) ||
    (isGuest && (!!u.excludeGuestsOrExternalUsers || (u.excludeUsers || []).includes('GuestsOrExternalUsers'))));
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

  // Authentication flows: the policy only applies to those flows.
  const flows = riskLevels(c.authenticationFlows?.transferMethods);
  if (flows.length && !flows.includes(s.authFlow || 'none')) return { applies: false, reason: 'Only applies to device code or authentication transfer', notEvaluated };
  // Insider risk (Purview Adaptive Protection).
  const insider = riskLevels(c.insiderRiskLevels);
  if (insider.length && !insider.includes(s.insiderRisk || 'none')) return { applies: false, reason: 'Insider risk does not match', notEvaluated };

  if (c.devices?.deviceFilter) notEvaluated.push('device filter');
  if ((c.servicePrincipalRiskLevels || []).length) notEvaluated.push('service principal risk');

  return { applies: true, reason: notEvaluated.length ? 'Applies (some conditions not evaluated)' : 'Applies', notEvaluated };
}

// Admin portals bundle (Azure portal / management API). Conservative subset.
const ADMIN_PORTAL_APPS = new Set(['797f4846-ba00-4fd7-ba43-dac1f8f63013']);

function combine(applying, s) {
  const isAgent = s.userType === 'agent' || s.userType === 'agentUser';
  if (!applying.length) {
    return isAgent
      ? { verdict: 'open', label: 'Allowed: no agent policy applies', detail: 'The agent gets a token without any Conditional Access check. Policies for users never apply to agents.', requirements: [], blockedBy: [] }
      : { verdict: 'open', label: 'Allowed with password only', detail: 'No enforced policy applies. The sign-in succeeds with a password alone.', requirements: [], blockedBy: [] };
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
