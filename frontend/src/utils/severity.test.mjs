import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import tailwindConfig from '../../tailwind.config.js';
import { RISK_COLORS, RISK_LEVELS, SEVERITY_LEVELS } from './constants.js';
import { getRiskColor, getSeverityClass } from './helpers.js';
import {
  SEVERITY_CONTRACT_VERSION,
  SEVERITY_DEFINITIONS,
  SEVERITY_IDS,
  normalizeRisk,
  normalizeSeverity,
  severityRank,
  severityWeight,
} from './severity.js';
import {
  buildCategoryScores,
  buildFindingsDistribution,
  buildResourceGroupGroups,
  buildTrend,
  countBySeverity,
} from './monitoring.js';

const findings = [
  { severity: 'critical', category: 'Supply Chain', resourceGroup: 'production' },
  { severity: 'HIGH', category: 'Supply Chain', resourceGroup: 'production' },
  { severity: 'INFORMATIONAL', category: 'Inventory', resourceGroup: 'shared' },
];

test('contract v1 ranks and weights CRITICAL above every other severity', () => {
  assert.equal(SEVERITY_CONTRACT_VERSION, '1.0.0');
  assert.deepEqual(SEVERITY_IDS, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  assert.equal(severityRank('CRITICAL'), Math.max(...SEVERITY_DEFINITIONS.map((level) => level.rank)));
  assert.equal(severityWeight('CRITICAL'), 20);
  assert.equal(normalizeSeverity(' informational '), 'INFO');
  assert.equal(normalizeRisk('none'), 'NONE');
  assert.throws(() => normalizeSeverity('urgent'), RangeError);
});

test('frontend options, classes, and Tailwind colors include every contract level', () => {
  assert.deepEqual(Object.keys(SEVERITY_LEVELS), SEVERITY_IDS);
  assert.deepEqual(Object.keys(RISK_LEVELS), [...SEVERITY_IDS, 'NONE']);
  assert.deepEqual(Object.keys(RISK_COLORS), [...SEVERITY_IDS, 'NONE']);
  assert.match(getSeverityClass('CRITICAL'), /red-950/);
  assert.equal(getRiskColor('CRITICAL'), '#b91c1c');
  assert.equal(
    tailwindConfig.theme.extend.colors['severity-critical'],
    SEVERITY_DEFINITIONS[0].color,
  );
});

test('monitoring counts, charts, and category scores use the same contract', () => {
  const counts = countBySeverity(findings);
  assert.deepEqual(counts, { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 1 });

  const distribution = buildFindingsDistribution(counts);
  assert.deepEqual(distribution.map((entry) => entry.name), [
    'Critical', 'High', 'Medium', 'Low', 'Info',
  ]);
  assert.equal(distribution[0].value, 1);

  const groups = buildResourceGroupGroups(findings);
  assert.deepEqual(groups[0], {
    group: 'production', CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0,
  });

  const categoryScores = buildCategoryScores(findings);
  assert.deepEqual(categoryScores, [
    { category: 'Supply Chain', score: 70 },
    { category: 'Inventory', score: 100 },
  ]);
});

test('monitoring trends never invent scores for incomplete or legacy scans', () => {
  const trend = buildTrend([
    {
      status: 'completed', score: 80, severity_contract_version: '1.0.0',
      started_at: '2026-08-21T00:00:00Z',
    },
    {
      status: 'failed', score: null, severity_contract_version: '1.0.0',
      started_at: '2026-08-20T00:00:00Z', total_findings: 0,
    },
    {
      status: 'pending', score: null, severity_contract_version: '1.0.0',
      started_at: '2026-08-19T00:00:00Z', total_findings: 0,
    },
    {
      status: 'completed', score: 100, severity_contract_version: null,
      started_at: '2026-08-18T00:00:00Z',
    },
  ]);

  assert.equal(trend.length, 1);
  assert.equal(trend[0].score, 80);
});

test('every severity-facing React consumer stays wired to contract-backed helpers', async () => {
  const consumers = new Map([
    ['../components/shared/SeverityBadge.jsx', ['severityDefinition']],
    ['../components/shared/RiskBadge.jsx', ['normalizeRisk', 'severityDefinition']],
    ['../components/prioritization/PriorityFilters.jsx', ['SEVERITY_IDS']],
    ['../components/drift/DriftFilters.jsx', ['SEVERITY_IDS']],
    ['../components/discovery/ResourceFilter.jsx', ['SEVERITY_DEFINITIONS']],
    ['../components/prioritization/PriorityMatrix.jsx', ['SEVERITY_DEFINITIONS', 'severityColor']],
    ['../components/compliance/ComplianceTable.jsx', ['SeverityBadge', 'c.severity ?']],
    ['../components/monitoring/StatCards.jsx', ['criticalIssues', 'severity-critical']],
    ['../components/monitoring/ResourceGroupChart.jsx', ['SEVERITY_DEFINITIONS']],
    ['../pages/Monitoring.jsx', ['buildTrend', 'countBySeverity']],
  ]);

  for (const [relativePath, requiredTokens] of consumers) {
    const source = await readFile(new URL(relativePath, import.meta.url), 'utf8');
    for (const token of requiredTokens) {
      assert.ok(source.includes(token), `${relativePath} must use ${token}`);
    }
  }
});
