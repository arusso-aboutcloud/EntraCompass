// Collects everything the analyzer needs from Microsoft Graph.
//
// Design rule: bulk calls only. The number of Graph calls grows with the
// number of result pages, not with the number of users or apps, so there is
// no sampling and no cap. The only per-item calls are group member counts,
// and only for groups that Conditional Access policies actually reference.
//
// Every source is recorded in `sources` as ok / failed with a reason, so the
// UI can say exactly what was and wasn't analysed.

import { pool, reasonFor } from './graph.js';
import { PERMISSION_RESOURCES } from './knowledge.js';

const SP_SELECT = [
  'id', 'appId', 'displayName', 'appOwnerOrganizationId', 'servicePrincipalType',
  'preferredSingleSignOnMode', 'tags', 'accountEnabled', 'appRoleAssignmentRequired',
  'signInAudience', 'replyUrls', 'homepage', 'loginUrl', 'passwordCredentials',
  'keyCredentials', 'verifiedPublisher', 'notes',
].join(',');

const APP_SELECT = [
  'id', 'appId', 'displayName', 'signInAudience', 'passwordCredentials',
  'keyCredentials', 'createdDateTime', 'publisherDomain',
].join(',');

export async function collectTenantData(graph, progress = () => {}) {
  const sources = {};
  const data = {};

  // `optional` sources need an extra permission or licence (Agent ID, ID
  // Protection, Purview). When they fail, the UI explains how to enable them
  // instead of warning that the scan is incomplete.
  async function source(key, label, fn, fallback, optional = false) {
    try {
      data[key] = await fn();
      sources[key] = { label, ok: true, optional };
    } catch (err) {
      console.warn(`[collect] ${label} failed`, err);
      data[key] = fallback;
      sources[key] = { label, ok: false, optional, reason: reasonFor(err), status: err?.httpStatus };
    }
  }

  progress('Reading tenant details...');
  await source('organization', 'Organization', async () => {
    const r = await graph.get('/organization?$select=id,displayName,verifiedDomains');
    return r?.value?.[0] || null;
  }, null);

  progress('Reading Conditional Access policies...');
  // The beta endpoint returns the newest conditions and session controls
  // (token protection, insider risk, authentication flows). Fall back to v1.0.
  await source('policies', 'Conditional Access policies', async () => {
    try {
      return await graph.getAll('/identity/conditionalAccess/policies', { beta: true });
    } catch (e) {
      if (e?.httpStatus === 403) throw e;
      return graph.getAll('/identity/conditionalAccess/policies');
    }
  }, []);

  progress('Reading named locations...');
  await source('namedLocations', 'Named locations', () =>
    graph.getAll('/identity/conditionalAccess/namedLocations'), []);

  await source('authContexts', 'Authentication contexts', () =>
    graph.getAll('/identity/conditionalAccess/authenticationContextClassReferences'), []);

  await source('authStrengths', 'Authentication strengths', () =>
    graph.getAll('/policies/authenticationStrengthPolicies?$select=id,displayName,policyType,allowedCombinations'), []);

  await source('roleTemplates', 'Directory role definitions', () =>
    graph.getAll('/directoryRoleTemplates?$select=id,displayName'), []);

  progress('Reading enterprise applications...');
  await source('servicePrincipals', 'Enterprise applications', () =>
    graph.getAll(`/servicePrincipals?$select=${SP_SELECT}&$top=999`, {
      onPage: (n) => progress(`Reading enterprise applications... ${n.toLocaleString()}`),
    }), []);

  progress('Reading app registrations...');
  await source('applications', 'App registrations', () =>
    graph.getAll(`/applications?$select=${APP_SELECT}&$top=999`, {
      onPage: (n) => progress(`Reading app registrations... ${n.toLocaleString()}`),
    }), []);

  progress('Reading application sign-in activity...');
  // Beta report, needs AuditLog.Read.All and Entra ID P1. Optional: when it
  // fails the analysis still runs, just without "last used" dates.
  await source('spSignIns', 'Application sign-in activity', () =>
    graph.getAll('/reports/servicePrincipalSignInActivities?$top=999', { beta: true }), [], true);

  // ---- Agents (Microsoft Entra Agent ID, beta). Optional: needs
  // AgentIdentity.Read.All (or an Agent ID role); falls back to service
  // principals of type ServiceIdentity from the list above.
  progress('Reading agent identities...');
  const AGENT_SELECT = 'id,displayName,agentIdentityBlueprintId,accountEnabled,createdDateTime,createdByAppId,servicePrincipalType,tags,disabledByMicrosoftStatus';
  await source('agentIdentities', 'Agent identities (Entra Agent ID)', async () => {
    try {
      return await graph.getAll(`/servicePrincipals/microsoft.graph.agentIdentity?$select=${AGENT_SELECT}&$expand=sponsors($select=id,displayName)&$top=100`, { beta: true });
    } catch (e) {
      if (e?.httpStatus !== 400) throw e;
      return graph.getAll(`/servicePrincipals/microsoft.graph.agentIdentity?$select=${AGENT_SELECT}&$top=100`, { beta: true });
    }
  }, [], true);
  await source('agentBlueprints', 'Agent identity blueprints', () =>
    graph.getAll('/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$select=id,appId,displayName,appOwnerOrganizationId,accountEnabled,createdDateTime,verifiedPublisher&$top=100', { beta: true }), [], true);
  await source('agentUsers', 'Agent user accounts', () =>
    graph.getAll('/users/microsoft.graph.agentUser?$select=id,displayName,userPrincipalName,accountEnabled,identityParentId,createdDateTime&$top=999', { beta: true }), [], true);
  await source('riskyAgents', 'Risky agents (ID Protection)', () =>
    graph.getAll('/identityProtection/riskyAgents', { beta: true }), [], true);

  // ---- Application permissions granted to apps and agents, read in bulk
  // from the resource side (one paged call per resource API).
  progress('Reading application permissions...');
  await source('appRoleGrants', 'Application permissions', async () => {
    const out = [];
    for (const [resourceAppId, resourceName] of Object.entries(PERMISSION_RESOURCES)) {
      let res;
      try {
        res = await graph.get(`/servicePrincipals(appId='${resourceAppId}')?$select=id,appId,appRoles`);
      } catch (e) {
        if (e?.httpStatus === 404) continue;
        throw e;
      }
      const roles = new Map((res?.appRoles || []).map((r) => [r.id, r.value]));
      const list = await graph.getAll(`/servicePrincipals/${res.id}/appRoleAssignedTo?$top=999`);
      for (const a of list) {
        if (a.principalType !== 'ServicePrincipal') continue;
        out.push({ principalId: a.principalId, principalName: a.principalDisplayName, resource: resourceName, permission: roles.get(a.appRoleId) || a.appRoleId });
      }
    }
    return out;
  }, []);

  await source('delegatedGrants', 'Delegated permission grants', () =>
    graph.getAll('/oauth2PermissionGrants?$top=999'), []);

  await source('roleAssignments', 'Directory role assignments', () =>
    graph.getAll('/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId'), []);

  // ---- Purview: sensitivity labels available to the signed-in admin.
  // Needs InformationProtectionPolicy.Read (delegated, no admin consent).
  progress('Reading sensitivity labels...');
  await source('sensitivityLabels', 'Sensitivity labels (Purview)', () =>
    graph.getAll('/me/security/informationProtection/sensitivityLabels', { beta: true }), [], true);

  progress('Counting users...');
  const countHeaders = { ConsistencyLevel: 'eventual' };
  await source('userCounts', 'User counts', async () => {
    const [all, guests] = await Promise.all([
      graph.get('/users/$count', { headers: countHeaders }),
      graph.get("/users/$count?$filter=userType eq 'Guest'", { headers: countHeaders }),
    ]);
    return { total: Number(all) || 0, guests: Number(guests) || 0 };
  }, { total: 0, guests: 0 });

  // Resolve every user / group / service principal ID referenced by policies.
  progress('Resolving users and groups referenced by policies...');
  const refs = collectDirectoryRefs(data.policies);
  await source('directoryObjects', 'Users and groups in policies', async () => {
    const out = {};
    const ids = [...refs.userIds, ...refs.groupIds, ...refs.spIds];
    for (let i = 0; i < ids.length; i += 1000) {
      const r = await graph.post('/directoryObjects/getByIds', {
        ids: ids.slice(i, i + 1000),
        types: ['user', 'group', 'servicePrincipal'],
      });
      for (const o of r?.value || []) out[o.id] = o;
    }
    return out;
  }, {});

  progress('Sizing groups used in policies...');
  await source('groupSizes', 'Group member counts', async () => {
    const sizes = {};
    const groupIds = [...refs.groupIds].filter((id) => data.directoryObjects?.[id]);
    await pool(groupIds, 4, async (id) => {
      try {
        const n = await graph.get(`/groups/${encodeURIComponent(id)}/transitiveMembers/$count`, { headers: countHeaders });
        sizes[id] = Number(n);
      } catch {
        sizes[id] = null;
      }
    });
    return sizes;
  }, {});

  return { ...data, sources, scannedAt: new Date().toISOString() };
}

// Only object IDs go to getByIds: special values ('All', 'None',
// 'GuestsOrExternalUsers', preview agent values...) would fail the whole call.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function collectDirectoryRefs(policies = []) {
  const userIds = new Set();
  const groupIds = new Set();
  const spIds = new Set();
  for (const p of policies) {
    const u = p?.conditions?.users || {};
    for (const id of [...(u.includeUsers || []), ...(u.excludeUsers || [])]) {
      if (GUID.test(id)) userIds.add(id);
    }
    for (const id of [...(u.includeGroups || []), ...(u.excludeGroups || [])]) if (GUID.test(id)) groupIds.add(id);
    const c = p?.conditions?.clientApplications || {};
    for (const id of [...(c.includeServicePrincipals || []), ...(c.excludeServicePrincipals || []),
      ...(c.includeAgentIdServicePrincipals || []), ...(c.excludeAgentIdServicePrincipals || [])]) {
      if (GUID.test(id)) spIds.add(id);
    }
  }
  return { userIds, groupIds, spIds };
}
