import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/analyzer.js';
import { analyzeAgents, buildPermissionIndex, permissionTier } from '../src/agents.js';
import { isAgentPolicy, isAgentUserPolicy } from '../src/policy.js';
import { fixture, IDS } from '../src/demo-data.js';

const NOW = '2026-10-28T12:00:00Z';
const r = analyze(fixture, { now: NOW });
const ag = r.agents;

test('agent policies are recognised from the Graph beta schema', () => {
  const p10 = fixture.policies.find((p) => p.id === 'p10');
  assert.equal(isAgentPolicy(p10), true);
  assert.equal(isAgentPolicy(fixture.policies.find((p) => p.id === 'p1')), false);
  assert.equal(isAgentUserPolicy({ conditions: { users: { includeUsers: ['AllAgentIdUsers'] } } }), true);
  assert.equal(isAgentUserPolicy({ conditions: { users: { includeUsers: ['All'] } } }), false);
});

test('inventory: identities, blueprints, agent users and AI-like apps', () => {
  assert.equal(ag.totals.identities, 4);
  assert.equal(ag.totals.blueprints, 3);
  assert.equal(ag.totals.agentUsers, 1);
  assert.deepEqual(ag.candidates.map((c) => c.name).sort(), ['Meeting Notes AI', 'OpenAI SharePoint Connector']);
  assert.equal(ag.users[0].parentName, 'IT Helpdesk Agent');
});

test('permissions: direct, inherited from blueprint, admin roles', () => {
  const invoice = ag.agents.find((a) => a.id === IDS.invoiceAgent);
  assert.deepEqual(invoice.permissionSummary.high.sort(), ['Files.ReadWrite.All', 'Mail.Read']);
  assert.ok(invoice.appPermissions.some((p) => p.permission === 'User.Read.All' && p.inherited));
  const helpdesk = ag.agents.find((a) => a.id === IDS.helpdeskAgent);
  assert.ok(helpdesk.roles.some((x) => x.privileged && x.name === 'Helpdesk Administrator'));
  assert.equal(helpdesk.severity, 'critical');
});

test('risk: risky agent with only a report-only block is flagged critical', () => {
  const invoice = ag.agents.find((a) => a.id === IDS.invoiceAgent);
  assert.equal(invoice.atRisk, true);
  assert.equal(invoice.riskBlocked, false);
  assert.ok(r.findings.some((f) => f.area === 'agents' && f.severity === 'critical' && /risky/.test(f.title)));
});

test('checks: report-only agent policies are partial; agent users uncovered; sponsors partial', () => {
  const st = Object.fromEntries(ag.checks.map((c) => [c.id, c.status]));
  assert.equal(st.agentCa, 'partial');
  assert.equal(st.agentRisk, 'partial');
  assert.equal(st.agentAllowList, 'partial');
  assert.equal(st.agentUsersCa, 'missing');
  assert.equal(st.agentSponsors, 'partial');
  assert.equal(st.agentPrivilege, 'missing');
});

test('enforcing the agent policies makes coverage present', () => {
  const policies = fixture.policies.map((p) => (['p10', 'p11'].includes(p.id) ? { ...p, state: 'enabled' } : p));
  const r2 = analyze({ ...fixture, policies }, { now: NOW });
  const st = Object.fromEntries(r2.agents.checks.map((c) => [c.id, c.status]));
  assert.equal(st.agentCa, 'present');
  assert.equal(st.agentRisk, 'present');
  const invoice = r2.agents.agents.find((a) => a.id === IDS.invoiceAgent);
  assert.equal(invoice.riskBlocked, true);
  assert.equal(r2.agents.totals.riskUnblocked, 0);
});

test('no agents: agent area is not scored and checks are informational', () => {
  const bare = { ...fixture, agentIdentities: [], agentBlueprints: [], agentUsers: [], riskyAgents: [], servicePrincipals: fixture.servicePrincipals.filter((s) => !/AI|OpenAI/.test(s.displayName)), policies: fixture.policies.filter((p) => !isAgentPolicy(p)) };
  const r3 = analyze(bare, { now: NOW });
  assert.equal(r3.agents.inUse, false);
  assert.equal(r3.scores.areas.agents.score, null);
  assert.ok(r3.agents.checks.every((c) => c.status === 'info'));
});

test('fallback: agents found among service principals when the Agent ID list is unavailable', () => {
  const raw = { ...fixture, agentIdentities: [], sources: { ...fixture.sources, agentIdentities: { ok: false, optional: true, reason: 'permission_denied' } }, servicePrincipals: [...fixture.servicePrincipals, { id: 'x1', appId: 'x1', displayName: 'Shadow agent', servicePrincipalType: 'ServiceIdentity' }] };
  const res = analyzeAgents(raw, { tenantId: fixture.organization.id, policies: raw.policies, gs: () => ({ options: [] }), perms: buildPermissionIndex(raw) });
  assert.equal(res.identitySource, 'servicePrincipals');
  assert.equal(res.agents.length, 1);
  assert.ok(res.sourceNotes.length >= 1);
});

test('workload: app with a secret and a critical permission is a critical finding', () => {
  assert.equal(permissionTier('Directory.ReadWrite.All'), 'critical');
  assert.ok(r.findings.some((f) => f.area === 'workload' && f.severity === 'critical' && /Nightly batch/.test(f.detail)));
  const batch = r.workload.apps.find((a) => a.name === 'Nightly batch');
  assert.deepEqual(batch.permissions.critical, ['Directory.ReadWrite.All']);
});
