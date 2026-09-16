import {
  SEVERITY_CONTRACT_VERSION,
  SEVERITY_BY_ID,
  SEVERITY_DEFINITIONS,
  normalizeSeverity,
  severityWeight,
} from './severity.js';

export function buildTrend(scans) {
  return scans
    .filter((scan) => (
      String(scan.status || '').toLowerCase() === 'completed'
      && Number.isFinite(scan.score)
      && (scan.severity_contract_version || scan.severityContractVersion)
        === SEVERITY_CONTRACT_VERSION
    ))
    .slice(0, 8)
    .reverse()
    .map((scan) => ({
      month: new Date(scan.started_at || scan.startedAt).toLocaleDateString(undefined, {
        month: 'short', day: 'numeric',
      }),
      score: scan.score,
    }));
}

export function countBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITY_DEFINITIONS.map((level) => [level.id, 0]));
  findings.forEach((finding) => {
    counts[normalizeSeverity(finding.severity)] += 1;
  });
  return counts;
}

export function buildResourceGroupGroups(findings) {
  const groups = {};
  findings.forEach((finding) => {
    const group = finding.resourceGroup || 'unknown';
    if (!groups[group]) {
      groups[group] = {
        group,
        ...Object.fromEntries(SEVERITY_DEFINITIONS.map((level) => [level.id, 0])),
      };
    }
    groups[group][normalizeSeverity(finding.severity)] += 1;
  });
  return Object.values(groups).sort((left, right) => {
    const total = (item) => SEVERITY_DEFINITIONS.reduce((sum, level) => sum + item[level.id], 0);
    return total(right) - total(left);
  });
}

export function buildCategoryScores(findings) {
  const categories = {};
  findings.forEach((finding) => {
    const category = finding.category || 'Other';
    if (!categories[category]) categories[category] = [];
    categories[category].push(finding);
  });
  return Object.entries(categories)
    .map(([category, categoryFindings]) => ({
      category,
      score: Math.max(
        0,
        100 - categoryFindings.reduce(
          (deduction, finding) => deduction + severityWeight(finding.severity),
          0,
        ),
      ),
    }))
    .sort((left, right) => left.score - right.score);
}

export function buildFindingsDistribution(counts) {
  return SEVERITY_DEFINITIONS.map((level) => ({
    name: level.label,
    value: counts[level.id],
    color: SEVERITY_BY_ID[level.id].color,
  }));
}
