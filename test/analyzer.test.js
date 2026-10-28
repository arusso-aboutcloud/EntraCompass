import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, parseCidr, classifyApp } from '../src/analyzer.js';
import { evaluate } from '../src/whatif.js';
import { grantSummary } from '../src/policy.js';
import { fixture, IDS } from '../src/demo-data.js';

const NOW = '2026-10-19T12:00:00Z';
const r = analyze(fixture, { now: NOW, crownJewels: [IDS.sapApp] });

test('summary counts policies by state', () => {
  assert.equal(r.summary.policyCounts.total, 12);
  assert.equal(r.summary.policyCounts.enabled, 7);
  assert.equal(r.summary.policyCounts.reportOnly, 4);
  assert.equal(r.summary.policyCounts.workload, 1);
  assert.equal(r.summary.policyCounts.agents, 2);
});

test('emergency accounts are recognised, other user exclusions need review', () => {
  const users = r.exclusions.filter((e) => e.kind === 'User');
  const bg = users.filter((e) => e.verdict === 'justified').map((e) => e.targetId);
  assert.ok(bg.includes(IDS.bg1) && bg.includes(IDS.bg2));
  assert.equal(users.find((e) => e.targetId === IDS.contractor).verdict, 'review');
  assert.equal(users.find((e) => e.targetId === IDS.deletedUser).verdict, 'stale');
});

test('app exclusions: crown jewel is a gap, deleted app is stale, Intune justified', () => {
  const apps = r.exclusions.filter((e) => e.kind === 'Application');
  assert.equal(apps.find((e) => e.targetId === IDS.sapApp).verdict, 'gap');
  assert.equal(apps.find((e) => e.targetId === IDS.deletedApp).verdict, 'stale');
  assert.equal(apps.find((e) => e.targetId === '0000000a-0000-0000-c000-000000000000').verdict, 'justified');
});

test('a large exception group is flagged as a gap', () => {
  const g = r.exclusions.find((e) => e.kind === 'Group');
  assert.equal(g.size, 140);
  assert.equal(g.verdict, 'gap');
});

test('trusted location with /8 range is critical, private ranges noted', () => {
  const office = r.locations.find((l) => l.id === IDS.officeLoc);
  assert.ok(office.issues.some((i) => i.severity === 'critical'));
  assert.ok(office.issues.some((i) => /private/i.test(i.text)));
  const old = r.locations.find((l) => l.name === 'Old datacenter');
  assert.ok(old.issues.some((i) => /Not used/.test(i.text)));
});

test('MFA policy skipped on trusted network -> conditional coverage', () => {
  const mfa = r.baseline.find((c) => c.id === 'mfaAll');
  assert.equal(mfa.status, 'partial');
  const intranet = r.apps.find((a) => a.appId === IDS.intranetApp);
  assert.equal(intranet.protection, 'conditional');
  assert.equal(intranet.categoryLabel, 'On-prem (App Proxy)');
});

test('crown jewel excluded produces a critical finding', () => {
  assert.ok(r.findings.some((f) => f.area === 'crown' && f.severity === 'critical'));
});

test('workforce outside MFA counts excluded users and group members', () => {
  assert.equal(r.summary.workforceOutsideMfa.people, 4 + 140);
});

test('workload identities: long-lived, multi-tenant, expired, expiring', () => {
  const t = r.workload.totals;
  assert.equal(t.withSecrets, 3);
  assert.equal(t.longLived, 2); // Nightly batch and the AI connector
  assert.equal(t.multiTenantWithSecrets, 1);
  assert.equal(t.expired, 1);
  assert.equal(t.expiringSoon, 1); // Old integration expires 2026-11-01
  assert.equal(t.dormant, 1); // Old integration has no sign-ins
  assert.equal(r.workload.managedIdentities, 1);
});

test('DLP: MDA monitor-only is partial; auth context defined but unused', () => {
  const mda = r.dlp.controls.find((c) => c.id === 'mda');
  assert.equal(mda.status, 'partial');
  const ac = r.dlp.controls.find((c) => c.id === 'authContext');
  assert.equal(ac.status, 'missing');
  assert.deepEqual(ac.unused, ['Highly confidential']);
});

test('scores are within range and management questions are answered', () => {
  assert.ok(r.scores.overall >= 0 && r.scores.overall <= 100);
  assert.equal(r.questions.length, 11);
  for (const q of r.questions) assert.ok(q.a.length > 10);
});

test('parseCidr', () => {
  assert.equal(parseCidr('10.1.0.0/16').private, true);
  assert.equal(parseCidr('52.0.0.0/8').veryBroad, true);
  assert.equal(parseCidr('203.0.113.0/24').broad, false);
  assert.equal(parseCidr('2001:db8::/16').broad, true);
});

test('classifyApp', () => {
  assert.equal(classifyApp({ tags: ['WindowsAzureActiveDirectoryOnPremApp'] }, 'x'), 'appProxy');
  assert.equal(classifyApp({ preferredSingleSignOnMode: 'saml' }, 'x'), 'saml');
  assert.equal(classifyApp({ appOwnerOrganizationId: 'x', servicePrincipalType: 'Application' }, 'x'), 'tenantApp');
});

test('grantSummary: OR of MFA and compliant device does not "require MFA"', () => {
  const gs = grantSummary({ grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } });
  assert.equal(gs.requiresMfa, false);
  assert.equal(gs.strong, true);
});

const base = { userType: 'member', groupIds: [], roleIds: [], platform: 'windows', clientApp: 'browser', device: 'unmanaged', signInRisk: 'none', userRisk: 'none' };
const opts = { namedLocations: fixture.namedLocations };

test('what-if: member from untrusted network to intranet gets MFA', () => {
  const w = evaluate(fixture.policies, { ...base, appId: IDS.intranetApp, locationId: 'untrusted' }, opts);
  assert.equal(w.outcome.verdict, 'challenge');
});

test('what-if: from the trusted office, SAP is password-only (excluded app + trusted network)', () => {
  const w = evaluate(fixture.policies, { ...base, appId: IDS.sapApp, locationId: IDS.officeLoc }, opts);
  assert.equal(w.outcome.verdict, 'open');
});

test('what-if: blocked country', () => {
  const w = evaluate(fixture.policies, { ...base, appId: IDS.intranetApp, locationId: IDS.blockedCountries }, opts);
  assert.equal(w.outcome.verdict, 'blocked');
});

test('what-if: legacy client blocked; emergency account not', () => {
  const w = evaluate(fixture.policies, { ...base, appId: IDS.intranetApp, locationId: 'untrusted', clientApp: 'exchangeActiveSync' }, opts);
  assert.equal(w.outcome.verdict, 'blocked');
  const bg = evaluate(fixture.policies, { ...base, userId: IDS.bg1, appId: IDS.intranetApp, locationId: 'untrusted', clientApp: 'exchangeActiveSync' }, opts);
  assert.equal(bg.outcome.verdict, 'open');
});

test('what-if: report-only compliant-device policy would break unmanaged desktop Outlook', () => {
  const w = evaluate(fixture.policies, { ...base, appId: '00000002-0000-0ff1-ce00-000000000000', locationId: 'untrusted', clientApp: 'mobileAppsAndDesktopClients' }, opts);
  assert.equal(w.outcome.verdict, 'challenge');
  assert.equal(w.reportOnlyOutcome.verdict, 'fails');
});

test('policies scoped to device code or insider risk do not apply to a normal sign-in', () => {
  const w = evaluate(fixture.policies, { ...base, appId: IDS.intranetApp, locationId: 'untrusted' }, opts);
  const dc = w.results.find((x) => x.id === 'p9');
  assert.equal(dc.applies, false);
  const dcFlow = evaluate(fixture.policies, { ...base, appId: IDS.intranetApp, locationId: 'untrusted', authFlow: 'deviceCodeFlow' }, opts);
  assert.equal(dcFlow.outcome.verdict, 'blocked');
  const ir = evaluate(fixture.policies, { ...base, appId: '00000002-0000-0ff1-ce00-000000000000', locationId: 'untrusted', insiderRisk: 'elevated' }, opts);
  assert.equal(ir.reportOnlyOutcome.verdict, 'blocked');
});

test('what-if: user policies never apply to an agent; agent policies never apply to people', () => {
  const agent = evaluate(fixture.policies, { ...base, userType: 'agent', agentId: IDS.salesAgent, blueprintIds: [IDS.bpVendor, IDS.bpVendorApp], appId: '00000003-0000-0000-c000-000000000000', agentRisk: 'none' }, opts);
  assert.equal(agent.outcome.verdict, 'open');
  assert.ok(agent.results.every((x) => ['p10', 'p11'].includes(x.id)));
  // Not in the allow-list: report-only policy would block it.
  assert.equal(agent.reportOnlyOutcome.verdict, 'blocked');
  const approved = evaluate(fixture.policies, { ...base, userType: 'agent', agentId: IDS.hrAgent, blueprintIds: [IDS.bpCopilotStudio, IDS.bpCopilotStudioApp], appId: '00000003-0000-0000-c000-000000000000', agentRisk: 'none' }, opts);
  assert.equal(approved.reportOnlyOutcome?.verdict ?? approved.outcome.verdict, 'open');
  const human = evaluate(fixture.policies, { ...base, appId: IDS.intranetApp, locationId: 'untrusted' }, opts);
  assert.ok(!human.results.some((x) => ['p10', 'p11'].includes(x.id)));
});

test('agent and workload-identity policies are not counted as user policies', () => {
  assert.equal(r.summary.workforceOutsideMfa.people, 4 + 140);
  assert.equal(r.policies.find((p) => p.id === 'p10').kind, 'AI agents');
  assert.equal(r.policies.find((p) => p.id === 'p10').users, 'All agent identities');
});

test('agent exclusions from an allow-list are justified', () => {
  const ex = r.exclusions.filter((e) => e.kind === 'Agent');
  assert.equal(ex.length, 2);
  assert.ok(ex.every((e) => e.verdict === 'justified'));
});

test('a conditional block policy does not count as MFA coverage', () => {
  const sap = r.apps.find((a) => a.appId === IDS.sapApp);
  assert.equal(sap.protection, 'partial'); // only the admin MFA policy applies
});
