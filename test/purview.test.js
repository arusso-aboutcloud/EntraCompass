import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/analyzer.js';
import { parsePurviewExport } from '../src/purview.js';
import { fixture, purviewExport } from '../src/demo-data.js';

const NOW = '2026-10-28T12:00:00Z';
const pv = parsePurviewExport(JSON.stringify(purviewExport), { fileName: 'purview.json' });

test('parser: policies, modes, locations, rules and labels', () => {
  assert.equal(pv.dlpPolicies.length, 4);
  const fin = pv.dlpPolicies.find((p) => p.name.startsWith('Financial'));
  assert.equal(fin.mode, 'enforce');
  assert.deepEqual(fin.locations.sort(), ['exchange', 'oneDrive', 'sharePoint']);
  assert.equal(fin.blockingRules, 2);
  assert.equal(pv.dlpPolicies.find((p) => p.name.startsWith('Personal')).mode, 'test');
  const hc = pv.labels.find((l) => l.name === 'Highly Confidential');
  assert.equal(hc.encryption, true);
  assert.equal(hc.authContext, 'c1');
});

test('parser: accepts a bare Get-DlpCompliancePolicy array and a Copilot location', () => {
  const p = parsePurviewExport(JSON.stringify([{ Name: 'Copilot: exclude HC', Mode: 'Enable', Locations: '[{"Workload":"Applications","Location":"470f2276-e011-4e9d-a6ec-20768be3a4b0"}]' }]));
  assert.deepEqual(p.dlpPolicies[0].locations, ['copilot']);
});

test('parser: rejects junk with a readable error', () => {
  assert.throws(() => parsePurviewExport('not json'), /not valid JSON/);
  assert.throws(() => parsePurviewExport('{"foo":1}'), /No DLP policies/);
  assert.throws(() => parsePurviewExport(''), /empty/);
});

test('cross-checks against Conditional Access', () => {
  const r = analyze(fixture, { now: NOW, purview: pv });
  const st = Object.fromEntries(r.purview.checks.map((c) => [c.id, c.status]));
  assert.equal(st.dlpCore, 'present');
  assert.equal(st.dlpEndpoint, 'partial'); // only in test mode
  assert.equal(st.dlpMdca, 'partial'); // CA session control is monitor-only
  assert.equal(st.dlpCopilot, 'missing');
  assert.equal(st.dlpTestMode, 'missing'); // unchanged for over 60 days
  assert.equal(st.labelAuthContext, 'missing'); // c1 has no CA policy
  assert.ok(r.findings.some((f) => f.purview && f.severity === 'high' && /Copilot/.test(f.title)));
});

test('without an export: labels from Graph, DLP checks unknown and unscored', () => {
  const r = analyze(fixture, { now: NOW });
  const st = Object.fromEntries(r.purview.checks.map((c) => [c.id, c.status]));
  assert.equal(st.labels, 'present');
  assert.equal(st.labelsProtected, 'present');
  assert.equal(st.dlpCore, 'unknown');
  assert.ok(!r.findings.some((f) => f.purview));
  assert.equal(r.questions.find((q) => /Purview/.test(q.q)).status, 'unknown');
});

test('executive report renders agents and Purview sections, with and without an export', async () => {
  const { buildReportHtml } = await import('../src/report.js');
  const withPv = buildReportHtml(analyze(fixture, { now: NOW, purview: pv }));
  assert.match(withPv, /<h2>AI agents <span class="pv">Preview<\/span><\/h2>/);
  assert.match(withPv, /preview at Microsoft/);
  assert.match(withPv, /DLP coverage by location/);
  assert.match(withPv, /Invoice Triage Agent/);
  const without = buildReportHtml(analyze(fixture, { now: NOW }));
  assert.match(without, /no Purview export was loaded/);
  // Untrusted names are escaped.
  const evil = { ...fixture, organization: { ...fixture.organization, displayName: '<img src=x onerror=alert(1)>' } };
  assert.ok(!buildReportHtml(analyze(evil, { now: NOW })).includes('<img src=x'));
});
