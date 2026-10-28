// AI agents and application permissions.
//
// Covers Microsoft Entra Agent ID (agent identities, blueprints, agent user
// accounts), Conditional Access for agents, ID Protection agent risk, and the
// application / delegated permissions and directory roles held by agents and
// other non-human identities.
//
// Pure functions of their input. No DOM, no network. Covered by
// test/agents.test.js.

import {
  MICROSOFT_TENANT_IDS, PRIVILEGED_ROLES, PERMISSION_TIERS, BROAD_DELEGATED_SCOPES,
  AGENT_NAME_HINT, DOCS,
} from './knowledge.js';
import { isAgentPolicy, isAgentUserPolicy, describeGrant, STATE_LABEL } from './policy.js';

const TIER_RANK = { critical: 0, high: 1, other: 2 };

export function permissionTier(name) {
  if (PERMISSION_TIERS.critical.has(name)) return 'critical';
  if (PERMISSION_TIERS.high.has(name)) return 'high';
  return 'other';
}

// Indexes the tenant's permission data by principal (service principal object ID).
export function buildPermissionIndex(raw, roleNames = {}) {
  const app = new Map();
  for (const g of raw.appRoleGrants || []) {
    const tier = permissionTier(g.permission);
    if (!app.has(g.principalId)) app.set(g.principalId, []);
    app.get(g.principalId).push({ permission: g.permission, resource: g.resource, tier });
  }
  for (const list of app.values()) list.sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || a.permission.localeCompare(b.permission));

  const delegated = new Map();
  for (const g of raw.delegatedGrants || []) {
    const scopes = String(g.scope || '').split(/\s+/).filter(Boolean);
    if (!delegated.has(g.clientId)) delegated.set(g.clientId, []);
    delegated.get(g.clientId).push({ scopes, allUsers: g.consentType === 'AllPrincipals', broad: scopes.filter((s) => BROAD_DELEGATED_SCOPES.has(s)) });
  }

  const roles = new Map();
  for (const r of raw.roleAssignments || []) {
    const name = roleNames[r.roleDefinitionId] || PRIVILEGED_ROLES[r.roleDefinitionId] || 'Directory role';
    if (!roles.has(r.principalId)) roles.set(r.principalId, []);
    roles.get(r.principalId).push({ id: r.roleDefinitionId, name, privileged: !!PRIVILEGED_ROLES[r.roleDefinitionId], scope: r.directoryScopeId || '/' });
  }
  return { app, delegated, roles };
}

export function summarisePermissions(list = []) {
  return {
    total: list.length,
    critical: list.filter((p) => p.tier === 'critical').map((p) => p.permission),
    high: list.filter((p) => p.tier === 'high').map((p) => p.permission),
  };
}

function publisherOf(ownerTenant, tenantId) {
  if (!ownerTenant) return 'Unknown';
  if (tenantId && ownerTenant === tenantId) return 'This tenant';
  if (MICROSOFT_TENANT_IDS.has(ownerTenant)) return 'Microsoft';
  return 'Third party';
}

// Which agent-identity policies include / exclude an agent.
function agentPolicyMatch(p, agentId, blueprintPrincipalId, blueprintAppId) {
  const c = p.conditions?.clientApplications || {};
  const inc = c.includeAgentIdServicePrincipals || [];
  const exc = c.excludeAgentIdServicePrincipals || [];
  const ids = [agentId, blueprintPrincipalId, blueprintAppId].filter(Boolean);
  const included = inc.includes('All') || inc.some((x) => ids.includes(x)) || (!!c.agentIdServicePrincipalFilter && inc.length === 0 ? 'filter' : false);
  const excluded = exc.some((x) => ids.includes(x));
  return { included, excluded };
}

function riskLevelsOf(p) {
  const v = p.conditions?.agentIdRiskLevels;
  if (!v) return [];
  return (Array.isArray(v) ? v : String(v).split(',')).map((x) => x.trim()).filter(Boolean);
}

const isBlock = (p) => (p.grantControls?.builtInControls || []).includes('block');

export function analyzeAgents(raw, ctx) {
  const tenantId = ctx.tenantId;
  const perms = ctx.perms || buildPermissionIndex(raw, ctx.roleNames);
  const sources = raw.sources || {};
  const agentUsers = raw.agentUsers || [];
  const agentUserIds = new Set(agentUsers.map((u) => u.id));

  // Agent identities: the dedicated beta list, or service principals of type
  // ServiceIdentity when that list is not readable.
  let identities = raw.agentIdentities || [];
  let identitySource = 'agentId';
  if (!identities.length) {
    identities = (raw.servicePrincipals || []).filter((s) => s.servicePrincipalType === 'ServiceIdentity' || /agentIdentity$/i.test(s['@odata.type'] || ''));
    identitySource = identities.length ? 'servicePrincipals' : 'none';
  }
  const blueprints = raw.agentBlueprints || [];
  const bpByAppId = new Map(blueprints.map((b) => [b.appId, b]));
  const risky = new Map();
  for (const r of raw.riskyAgents || []) {
    if (r.isDeleted) continue;
    risky.set(r.id, r);
    if (r.agentDisplayName) risky.set(`name:${r.agentDisplayName.toLowerCase()}`, r);
  }

  const policies = ctx.policies.filter((p) => isAgentPolicy(p) || isAgentUserPolicy(p, agentUserIds));
  const agentIdPolicies = policies.filter(isAgentPolicy);
  const agentUserPolicies = policies.filter((p) => !isAgentPolicy(p));

  const agents = identities.map((a) => {
    const bp = bpByAppId.get(a.agentIdentityBlueprintId);
    const app = [...(perms.app.get(a.id) || []), ...((bp && perms.app.get(bp.id)) || []).map((x) => ({ ...x, inherited: true }))];
    const delegated = [...(perms.delegated.get(a.id) || []), ...((bp && perms.delegated.get(bp.id)) || []).map((x) => ({ ...x, inherited: true }))];
    const roles = perms.roles.get(a.id) || [];
    const riskRec = risky.get(a.id) || risky.get(`name:${(a.displayName || '').toLowerCase()}`) || null;
    const users = agentUsers.filter((u) => u.identityParentId === a.id);
    const sponsors = Array.isArray(a.sponsors) ? a.sponsors.length : null;

    const covered = [];
    const excludedBy = [];
    let riskBlocked = false;
    for (const p of agentIdPolicies) {
      if (p.state === 'disabled') continue;
      const m = agentPolicyMatch(p, a.id, bp?.id, a.agentIdentityBlueprintId);
      if (!m.included) continue;
      if (m.excluded) { excludedBy.push({ id: p.id, name: p.displayName, state: p.state, allowList: isBlock(p) && !riskLevelsOf(p).length }); continue; }
      covered.push({ id: p.id, name: p.displayName, state: p.state, risk: riskLevelsOf(p), block: isBlock(p), viaFilter: m.included === 'filter' });
      if (p.state === 'enabled' && isBlock(p) && riskLevelsOf(p).includes('high')) riskBlocked = true;
    }
    const sum = summarisePermissions(app);
    const atRisk = riskRec && riskRec.riskState === 'atRisk' && ['high', 'medium'].includes(riskRec.riskLevel);
    const issues = [];
    if (a.disabledByMicrosoftStatus && a.disabledByMicrosoftStatus !== 'NotDisabled') issues.push({ severity: 'critical', text: 'Disabled by Microsoft for a terms violation or abuse.' });
    if (atRisk) issues.push({ severity: riskRec.riskLevel === 'high' ? 'critical' : 'high', text: `ID Protection rates this agent ${riskRec.riskLevel} risk${riskBlocked ? ' (a policy blocks it)' : ' and no enforced policy blocks it'}.` });
    if (sum.critical.length) issues.push({ severity: 'critical', text: `Can change tenant security: ${sum.critical.join(', ')}.` });
    if (roles.some((r) => r.privileged)) issues.push({ severity: 'critical', text: `Holds privileged directory role${roles.filter((r) => r.privileged).length > 1 ? 's' : ''}: ${roles.filter((r) => r.privileged).map((r) => r.name).join(', ')}.` });
    if (sum.high.length) issues.push({ severity: 'high', text: `Reads or changes organisation-wide data: ${sum.high.join(', ')}.` });
    const broadDelegated = delegated.filter((d) => d.allUsers && d.broad.length);
    if (broadDelegated.length) issues.push({ severity: 'medium', text: `Tenant-wide consent to act for every user: ${[...new Set(broadDelegated.flatMap((d) => d.broad))].join(', ')}.` });
    if (sponsors === 0) issues.push({ severity: 'medium', text: 'No sponsor: nobody is accountable for this agent.' });
    if (!covered.some((c) => c.state === 'enabled') && a.accountEnabled !== false) issues.push({ severity: 'medium', text: 'No enforced Conditional Access policy covers this agent.' });
    if (excludedBy.some((e) => !e.allowList)) issues.push({ severity: 'medium', text: `Excluded from ${excludedBy.filter((e) => !e.allowList).map((e) => `"${e.name}"`).join(', ')}.` });
    issues.sort((x, y) => SEV.indexOf(x.severity) - SEV.indexOf(y.severity));
    return {
      id: a.id,
      name: a.displayName || 'Unnamed agent',
      blueprintId: a.agentIdentityBlueprintId || null,
      blueprintName: bp?.displayName || null,
      publisher: publisherOf(bp?.appOwnerOrganizationId, tenantId),
      verifiedPublisher: !!bp?.verifiedPublisher?.verifiedPublisherId,
      enabled: a.accountEnabled !== false,
      created: a.createdDateTime || null,
      sponsors,
      sponsorNames: Array.isArray(a.sponsors) ? a.sponsors.map((s) => s.displayName).filter(Boolean) : [],
      risk: riskRec ? { level: riskRec.riskLevel, state: riskRec.riskState, updated: riskRec.riskLastModifiedDateTime } : null,
      atRisk: !!atRisk,
      riskBlocked,
      appPermissions: app,
      permissionSummary: sum,
      delegated,
      roles,
      agentUsers: users.map((u) => ({ id: u.id, name: u.displayName, upn: u.userPrincipalName })),
      coveredBy: covered,
      excludedBy,
      governed: covered.some((c) => c.state === 'enabled'),
      issues,
      severity: issues[0]?.severity || 'none',
    };
  }).sort((x, y) => (SEV_ALL.indexOf(x.severity) - SEV_ALL.indexOf(y.severity)) || x.name.localeCompare(y.name));

  const users = agentUsers.map((u) => {
    const parent = agents.find((a) => a.id === u.identityParentId);
    const covering = agentUserPolicies.filter((p) => p.state !== 'disabled' && !(p.conditions?.users?.excludeUsers || []).includes(u.id));
    return {
      id: u.id, name: u.displayName, upn: u.userPrincipalName, enabled: u.accountEnabled !== false,
      parentName: parent?.name || null,
      coveredBy: covering.map((p) => ({ id: p.id, name: p.displayName, state: p.state })),
      governed: covering.some((p) => p.state === 'enabled'),
    };
  });

  const blueprintRows = blueprints.map((b) => {
    const sum = summarisePermissions(perms.app.get(b.id) || []);
    return {
      id: b.id, appId: b.appId, name: b.displayName, publisher: publisherOf(b.appOwnerOrganizationId, tenantId),
      verifiedPublisher: !!b.verifiedPublisher?.verifiedPublisherId,
      agents: agents.filter((a) => a.blueprintId === b.appId).length,
      permissionSummary: sum,
    };
  }).sort((a, b) => b.agents - a.agents || a.name.localeCompare(b.name));

  // AI-looking apps registered the classic way: Agent ID policies cannot see them.
  const agentIdSet = new Set(agents.map((a) => a.id));
  const candidates = (raw.servicePrincipals || []).filter((s) =>
    !agentIdSet.has(s.id) && s.servicePrincipalType !== 'ManagedIdentity' && s.servicePrincipalType !== 'ServiceIdentity' &&
    !MICROSOFT_TENANT_IDS.has(s.appOwnerOrganizationId) && AGENT_NAME_HINT.test(s.displayName || ''))
    .map((s) => {
      const app = perms.app.get(s.id) || [];
      const reg = (raw.applications || []).find((x) => x.appId === s.appId);
      const delegated = perms.delegated.get(s.id) || [];
      return {
        id: s.id, appId: s.appId, name: s.displayName,
        publisher: publisherOf(s.appOwnerOrganizationId, tenantId),
        permissionSummary: summarisePermissions(app),
        appPermissions: app,
        secrets: (reg?.passwordCredentials || []).length,
        broadDelegated: [...new Set(delegated.filter((d) => d.allUsers).flatMap((d) => d.broad))],
      };
    })
    .sort((a, b) => (b.permissionSummary.critical.length - a.permissionSummary.critical.length) || (b.permissionSummary.high.length - a.permissionSummary.high.length) || a.name.localeCompare(b.name));

  const policyRows = policies.map((p) => {
    const c = p.conditions?.clientApplications || {};
    const agentTarget = isAgentPolicy(p);
    const inc = agentTarget ? (c.includeAgentIdServicePrincipals || []) : (p.conditions?.users?.includeUsers || []);
    const exc = agentTarget ? (c.excludeAgentIdServicePrincipals || []) : (p.conditions?.users?.excludeUsers || []);
    const risk = riskLevelsOf(p);
    return {
      id: p.id, name: p.displayName, state: p.state, stateLabel: STATE_LABEL[p.state] || p.state,
      target: agentTarget ? 'Agent identities' : 'Agent users',
      scope: inc.includes('All') || inc.some((x) => /^All/i.test(x)) ? (agentTarget ? 'All agent identities' : 'All agent users')
        : (agentTarget && c.agentIdServicePrincipalFilter && !inc.length) ? 'Agents matching attributes' : `${inc.length} selected`,
      exclusions: exc.length + (c.agentIdServicePrincipalFilter && inc.length ? 1 : 0),
      risk,
      kind: isBlock(p) ? (risk.length ? 'Risk-based block' : (exc.length || c.agentIdServicePrincipalFilter) ? 'Allow-list (block all others)' : 'Block') : 'Grant',
      controls: isBlock(p) ? 'Block access' : describeGrant(ctx.gs(p)),
    };
  });

  const checks = agentChecks({ agents, users, policyRows, agentIdPolicies, agentUserPolicies, identitySource, sources });
  const totals = {
    identities: agents.length,
    blueprints: blueprintRows.length,
    agentUsers: users.length,
    candidates: candidates.length,
    governed: agents.filter((a) => a.governed).length,
    ungoverned: agents.filter((a) => !a.governed && a.enabled).length,
    critical: agents.filter((a) => a.permissionSummary.critical.length || a.roles.some((r) => r.privileged)).length,
    highPrivilege: agents.filter((a) => a.permissionSummary.critical.length || a.permissionSummary.high.length).length,
    atRisk: agents.filter((a) => a.atRisk).length,
    riskUnblocked: agents.filter((a) => a.atRisk && !a.riskBlocked).length,
    noSponsor: agents.filter((a) => a.sponsors === 0).length,
    thirdParty: agents.filter((a) => a.publisher === 'Third party').length,
    disabledByMicrosoft: agents.filter((a) => a.issues.some((i) => /Disabled by Microsoft/.test(i.text))).length,
    candidatesWithPermissions: candidates.filter((c) => c.permissionSummary.critical.length || c.permissionSummary.high.length).length,
  };
  return {
    agents, users, blueprints: blueprintRows, candidates, policies: policyRows, checks, totals,
    identitySource,
    inUse: agents.length > 0 || users.length > 0 || candidates.length > 0,
    sourceNotes: agentSourceNotes(sources),
  };
}

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_ALL = [...SEV, 'none'];

function agentSourceNotes(sources) {
  const notes = [];
  const s = (k) => sources[k];
  if (s('agentIdentities') && !s('agentIdentities').ok) notes.push('Agent identities could not be read directly. Add the AgentIdentity.Read.All delegated permission (or sign in with an Agent ID role) for blueprints, sponsors and full coverage.');
  if (s('riskyAgents') && !s('riskyAgents').ok) notes.push('Agent risk could not be read. It needs IdentityRiskyAgent.Read.All and an ID Protection licence for agents.');
  if (s('agentUsers') && !s('agentUsers').ok) notes.push('Agent user accounts could not be listed (preview API).');
  return notes;
}

function agentChecks({ agents, users, agentIdPolicies, agentUserPolicies, identitySource }) {
  const checks = [];
  const add = (id, title, status, detail, ref, why) => checks.push({ id, title, status, detail, ref, why });
  const hasAgents = agents.length > 0;
  const on = (list) => list.filter((p) => p.state === 'enabled');
  const ro = (list) => list.filter((p) => p.state === 'enabledForReportingButNotEnforced');
  const allAgents = (p) => (p.conditions?.clientApplications?.includeAgentIdServicePrincipals || []).includes('All');

  const allOn = on(agentIdPolicies).filter(allAgents);
  add('agentCa', 'Conditional Access covers all agent identities',
    !hasAgents && !agentIdPolicies.length ? 'info' : allOn.length ? 'present' : (ro(agentIdPolicies).length || on(agentIdPolicies).length) ? 'partial' : 'missing',
    allOn.length ? `Enforced: ${allOn.map((p) => p.displayName).join(', ')}.`
      : agentIdPolicies.length ? `Agent policies exist but none is enforced for all agents (${agentIdPolicies.map((p) => `${p.displayName}: ${STATE_LABEL[p.state]}`).join('; ')}).`
        : hasAgents ? `${agents.length} agent identit${agents.length > 1 ? 'ies' : 'y'} and no policy targets agents.` : 'No agent identities found.',
    DOCS.agentCa,
    'Policies that target users never apply to an agent acting on its own. Without an agent policy, a compromised agent keeps working.');

  const riskPol = agentIdPolicies.filter((p) => isBlock(p) && riskLevelsOf(p).includes('high'));
  add('agentRisk', 'High-risk agents are blocked',
    !hasAgents && !riskPol.length ? 'info' : on(riskPol).length ? 'present' : riskPol.length ? 'partial' : 'missing',
    on(riskPol).length ? `Enforced: ${on(riskPol).map((p) => p.displayName).join(', ')}.` : riskPol.length ? `Only in report-only: ${riskPol.map((p) => p.displayName).join(', ')}.` : 'No policy reacts to agent risk from ID Protection.',
    DOCS.agentRisk,
    'Microsoft\'s recommended baseline: when ID Protection confirms an agent is compromised, it is blocked automatically.');

  const allow = agentIdPolicies.filter((p) => isBlock(p) && !riskLevelsOf(p).length && allAgents(p));
  add('agentAllowList', 'Only approved agents can reach resources',
    !hasAgents && !allow.length ? 'info' : on(allow).length ? 'present' : allow.length ? 'partial' : 'missing',
    on(allow).length ? `Enforced allow-list: ${on(allow).map((p) => p.displayName).join(', ')}.` : allow.length ? `Allow-list policy in report-only: ${allow.map((p) => p.displayName).join(', ')}.` : 'Any new agent can access resources as soon as it is created.',
    DOCS.agentCaAutonomous,
    'Block all agents except reviewed ones (excluded by blueprint or custom security attribute), so new agents start blocked until approved.');

  const userPolOn = on(agentUserPolicies);
  add('agentUsersCa', 'Agent user accounts are covered',
    !users.length ? 'info' : users.every((u) => u.governed) ? 'present' : userPolOn.length || agentUserPolicies.length ? 'partial' : 'missing',
    !users.length ? 'No agent user accounts found.' : users.every((u) => u.governed) ? 'Every agent user account is covered by an enforced policy.'
      : `${users.filter((u) => !u.governed).length} of ${users.length} agent user account${users.length > 1 ? 's are' : ' is'} not covered. Policies for "All users" do not include agent users.`,
    DOCS.agentCaUsers,
    'Agent users have mailboxes and Teams presence. Policies for "All users" skip them, so they need their own policy.');

  const known = agents.filter((a) => a.sponsors !== null);
  add('agentSponsors', 'Every agent has an accountable sponsor',
    !hasAgents || !known.length ? 'info' : known.every((a) => a.sponsors > 0) ? 'present' : known.some((a) => a.sponsors > 0) ? 'partial' : 'missing',
    !hasAgents ? 'No agent identities found.' : !known.length ? 'Sponsors could not be read.' : `${known.filter((a) => a.sponsors === 0).length} of ${known.length} agents have no sponsor.`,
    DOCS.agentGovernance,
    'Sponsors answer for an agent\'s access in reviews and are contacted when it misbehaves or becomes orphaned.');

  const priv = agents.filter((a) => a.permissionSummary.critical.length || a.roles.some((r) => r.privileged));
  const high = agents.filter((a) => a.permissionSummary.high.length);
  add('agentPrivilege', 'Agents follow least privilege',
    !hasAgents ? 'info' : priv.length ? 'missing' : high.length ? 'partial' : 'present',
    !hasAgents ? 'No agent identities found.' : priv.length ? `${priv.length} agent${priv.length > 1 ? 's' : ''} can change tenant security: ${priv.map((a) => a.name).join(', ')}.`
      : high.length ? `${high.length} agent${high.length > 1 ? 's' : ''} hold organisation-wide data permissions: ${high.map((a) => a.name).join(', ')}.` : 'No agent holds high-impact application permissions or admin roles.',
    DOCS.appPermissions,
    'Agents act at machine speed and can be steered by prompt injection. Their permissions are the real blast radius.');

  if (identitySource === 'servicePrincipals') {
    checks.push({ id: 'agentSource', title: 'Agent ID data read in fallback mode', status: 'info', detail: 'Agents were found among service principals, but blueprints and sponsors could not be read. Add AgentIdentity.Read.All for a full view.', ref: DOCS.agentIdentities });
  }
  return checks;
}

// Findings for the agents area, in the analyzer's finding format.
export function agentFindings(ag, add) {
  const sev = { agentCa: 'high', agentRisk: 'medium', agentAllowList: 'low', agentUsersCa: 'high', agentSponsors: 'medium', agentPrivilege: 'critical' };
  const titles = {
    agentCa: ['No Conditional Access policy covers AI agents', 'AI agents are only partly covered by Conditional Access'],
    agentRisk: ['Compromised agents are not blocked automatically', 'Blocking of high-risk agents is not enforced yet'],
    agentAllowList: ['New AI agents can reach company resources without approval', 'The agent allow-list is not enforced yet'],
    agentUsersCa: ['Agent user accounts are outside Conditional Access', 'Some agent user accounts are outside Conditional Access'],
    agentSponsors: ['AI agents have no sponsor', 'Some AI agents have no sponsor'],
    agentPrivilege: ['AI agents can change tenant security', 'AI agents hold organisation-wide data permissions'],
  };
  const fix = {
    agentCa: 'Create a policy for "All agent identities" on "All resources". Start in report-only, review, then enforce.',
    agentRisk: 'Block "All agent identities" at high agent risk (needs ID Protection for agents). Start in report-only.',
    agentAllowList: 'Block all agent identities except approved blueprints or agents tagged with a custom security attribute.',
    agentUsersCa: 'Target "All agent users" with a risk-based block, and require a compliant device for agents that run on endpoints.',
    agentSponsors: 'Assign a sponsor to every agent identity and include agents in access reviews.',
    agentPrivilege: 'Remove admin roles and tenant-wide application permissions from agents; grant resource-specific, least-privilege access.',
  };
  for (const c of ag.checks) {
    if (!sev[c.id] || c.status === 'present' || c.status === 'info') continue;
    let severity = sev[c.id];
    if (c.id === 'agentPrivilege') severity = c.status === 'missing' ? 'critical' : 'high';
    else if (c.status === 'partial') severity = SEV[Math.min(SEV.indexOf(severity) + 1, 3)];
    add({ area: 'agents', severity, title: titles[c.id][c.id === 'agentPrivilege' ? (c.status === 'missing' ? 0 : 1) : (c.status === 'partial' ? 1 : 0)], detail: c.detail, impact: c.why, fix: fix[c.id], ref: c.ref });
  }
  const t = ag.totals;
  if (t.riskUnblocked) {
    const list = ag.agents.filter((a) => a.atRisk && !a.riskBlocked);
    add({ area: 'agents', severity: list.some((a) => a.risk.level === 'high') ? 'critical' : 'high', title: `${list.length} AI agent${list.length > 1 ? 's are' : ' is'} flagged as risky and still active`, detail: list.map((a) => `${a.name} (${a.risk.level})`).join(', '), impact: 'ID Protection believes these agents may be compromised, and nothing stops them.', fix: 'Investigate now: confirm compromise or dismiss, disable the agent if in doubt, and enforce a risk-based block.', ref: DOCS.agentRisk });
  }
  if (t.disabledByMicrosoft) add({ area: 'agents', severity: 'high', title: `${t.disabledByMicrosoft} agent${t.disabledByMicrosoft > 1 ? 's were' : ' was'} disabled by Microsoft`, detail: ag.agents.filter((a) => a.issues.some((i) => /Disabled by Microsoft/.test(i.text))).map((a) => a.name).join(', '), impact: 'Microsoft disables blueprints for abuse or terms violations. Business processes relying on them have stopped.', fix: 'Find the owner, review what the agent did, and remove it.', ref: DOCS.agentIdentities });
  const thirdHigh = ag.agents.filter((a) => a.publisher === 'Third party' && (a.permissionSummary.critical.length || a.permissionSummary.high.length));
  if (thirdHigh.length) add({ area: 'agents', severity: 'high', title: `${thirdHigh.length} third-party agent${thirdHigh.length > 1 ? 's hold' : ' holds'} organisation-wide permissions`, detail: thirdHigh.map((a) => `${a.name}${a.verifiedPublisher ? '' : ' (unverified publisher)'}`).join(', '), impact: 'A vendor\'s agent can read or change company data across the tenant. A breach at the vendor becomes yours.', fix: 'Confirm the business need and data processing terms, reduce permissions, and cover the agent with a Conditional Access policy.', ref: DOCS.appPermissions, business: true });
  const broad = ag.agents.filter((a) => a.delegated.some((d) => d.allUsers && d.broad.length));
  if (broad.length) add({ area: 'agents', severity: 'medium', title: `${broad.length} agent${broad.length > 1 ? 's have' : ' has'} tenant-wide consent to act for every user`, detail: broad.map((a) => a.name).join(', '), impact: 'On behalf of any user, the agent can reach that user\'s mail or files. User Conditional Access applies, but data access is broad.', fix: 'Replace admin consent for all users with per-user or group-scoped consent; review the scopes.', ref: DOCS.appPermissions });
  if (t.candidatesWithPermissions) {
    const list = ag.candidates.filter((c) => c.permissionSummary.critical.length || c.permissionSummary.high.length);
    add({ area: 'agents', severity: 'medium', title: `${list.length} AI-like app${list.length > 1 ? 's hold' : ' holds'} data permissions outside Agent ID`, detail: list.slice(0, 8).map((c) => c.name).join(', '), impact: 'Agents registered as ordinary apps are invisible to agent policies, agent risk and sponsor governance.', fix: 'Confirm which are AI agents and move them to Entra Agent ID, or cover them with workload identity Conditional Access.', ref: DOCS.agentIdentities });
  }
}

// Permission view for classic workload identities (apps with credentials,
// managed identities). Returns extra findings in the workload area.
export function workloadPermissionFindings(raw, ctx, add) {
  const perms = ctx.perms;
  const agentIds = new Set((raw.agentIdentities || []).map((a) => a.id));
  const blueprintIds = new Set((raw.agentBlueprints || []).map((b) => b.id));
  const sps = (raw.servicePrincipals || []).filter((s) => !agentIds.has(s.id) && !blueprintIds.has(s.id) && s.servicePrincipalType !== 'ServiceIdentity' && !MICROSOFT_TENANT_IDS.has(s.appOwnerOrganizationId));
  const withSecrets = new Set((raw.applications || []).filter((a) => (a.passwordCredentials || []).length).map((a) => a.appId));
  const critical = sps.filter((s) => (perms.app.get(s.id) || []).some((p) => p.tier === 'critical'));
  if (critical.length) {
    const secret = critical.filter((s) => withSecrets.has(s.appId));
    add({ area: 'workload', severity: secret.length ? 'critical' : 'high', title: `${critical.length} app${critical.length > 1 ? 's' : ''} can change tenant security through application permissions`, detail: critical.slice(0, 8).map((s) => `${s.displayName} (${(perms.app.get(s.id) || []).filter((p) => p.tier === 'critical').map((p) => p.permission).join(', ')})${withSecrets.has(s.appId) ? ' [client secret]' : ''}`).join('; '), impact: 'Whoever holds the app\'s credential can grant themselves any access, without a user, MFA or Conditional Access for users.', fix: 'Remove the permission if possible; otherwise switch to certificates or managed identity, and restrict the app with workload identity Conditional Access.', ref: DOCS.appPermissions });
  }
  const privRoles = sps.filter((s) => (perms.roles.get(s.id) || []).some((r) => r.privileged));
  if (privRoles.length) add({ area: 'workload', severity: 'critical', title: `${privRoles.length} app${privRoles.length > 1 ? 's hold' : ' holds'} a privileged directory role`, detail: privRoles.map((s) => `${s.displayName} (${(perms.roles.get(s.id) || []).filter((r) => r.privileged).map((r) => r.name).join(', ')})`).join('; '), impact: 'An app with an admin role is an admin with no MFA.', fix: 'Remove the role, or scope it with an administrative unit and protect the credential.', ref: DOCS.workloadCa });
}

// Per-app permission summary for the workload table.
export function permissionsForApp(ctx, appId) {
  const sp = ctx.spByAppId.get(appId);
  if (!sp) return { total: 0, critical: [], high: [], roles: [] };
  return { ...summarisePermissions(ctx.perms.app.get(sp.id) || []), roles: (ctx.perms.roles.get(sp.id) || []).filter((r) => r.privileged).map((r) => r.name) };
}
