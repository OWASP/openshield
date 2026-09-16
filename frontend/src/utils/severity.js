import severityContract from '../generated/severity.v1.json' with { type: 'json' };

function validateContract(contract) {
  const supportedTones = new Set(['critical', 'danger', 'warning', 'success', 'neutral']);
  if (
    contract.contract !== 'openshield.finding-severity'
    || typeof contract.version !== 'string'
    || !/^[1-9][0-9]*\.[0-9]+\.[0-9]+$/.test(contract.version)
  ) {
    throw new Error('Invalid OpenShield severity contract metadata');
  }
  if (!Array.isArray(contract.levels) || contract.levels.length === 0) {
    throw new Error('OpenShield severity contract has no levels');
  }
  const ids = contract.levels.map((level) => level.id);
  const ranks = contract.levels.map((level) => level.rank);
  if (ids.some((id) => typeof id !== 'string' || id !== id.trim().toUpperCase())) {
    throw new Error('OpenShield severity IDs must be canonical uppercase values');
  }
  if (new Set(ids).size !== ids.length || new Set(ranks).size !== ranks.length) {
    throw new Error('OpenShield severity IDs and ranks must be unique');
  }
  if (contract.levels.some((level) => (
    !Number.isInteger(level.rank)
    || !Number.isInteger(level.score_weight)
    || !Number.isInteger(level.risk_score)
  ))) {
    throw new Error('OpenShield severity ranks, weights, and risk scores must be integers');
  }
  if (contract.levels.some((level) => level.score_weight < 0 || level.risk_score < 0)) {
    throw new Error('OpenShield severity weights and risk scores cannot be negative');
  }
  if (contract.levels.some((level) => (
    typeof level.label !== 'string'
    || level.label.trim() === ''
    || typeof level.color !== 'string'
    || !/^#[0-9a-f]{6}$/i.test(level.color)
    || !supportedTones.has(level.tone)
  ))) {
    throw new Error('OpenShield severity labels, colors, and tones must be supported');
  }
  const ordered = [...contract.levels].sort((left, right) => left.rank - right.rank);
  for (let index = 1; index < ordered.length; index += 1) {
    const lower = ordered[index - 1];
    const higher = ordered[index];
    if (lower.score_weight > higher.score_weight || lower.risk_score > higher.risk_score) {
      throw new Error('OpenShield severity weights and risk scores must increase with rank');
    }
  }
  const critical = contract.levels.find((level) => level.id === 'CRITICAL');
  if (!critical || critical.rank !== Math.max(...ranks)) {
    throw new Error('CRITICAL must be the highest OpenShield severity');
  }
  for (const [source, target] of Object.entries(contract.aliases || {})) {
    if (source !== source.trim().toUpperCase() || ids.includes(source) || !ids.includes(target)) {
      throw new Error('OpenShield severity aliases must map to canonical IDs');
    }
  }
}

validateContract(severityContract);

export const SEVERITY_CONTRACT_VERSION = severityContract.version;
export const SEVERITY_DEFINITIONS = Object.freeze(
  severityContract.levels.map((level) => Object.freeze({ ...level })),
);
export const SEVERITY_IDS = Object.freeze(SEVERITY_DEFINITIONS.map((level) => level.id));
export const SEVERITY_BY_ID = Object.freeze(
  Object.fromEntries(SEVERITY_DEFINITIONS.map((level) => [level.id, level])),
);
export const SEVERITY_ALIASES = Object.freeze({ ...severityContract.aliases });

export function normalizeSeverity(value, { nullable = false } = {}) {
  if (value == null && nullable) return null;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError('severity must be a non-empty string');
  }
  const candidate = value.trim().toUpperCase();
  const canonical = SEVERITY_ALIASES[candidate] || candidate;
  if (!SEVERITY_BY_ID[canonical]) {
    throw new RangeError(`Unsupported severity: ${value}`);
  }
  return canonical;
}

export function severityDefinition(value) {
  return SEVERITY_BY_ID[normalizeSeverity(value)];
}

export function severityWeight(value) {
  return severityDefinition(value).score_weight;
}

export function severityRank(value) {
  return severityDefinition(value).rank;
}

export function severityColor(value) {
  return severityDefinition(value).color;
}

export function normalizeRisk(value) {
  if (typeof value === 'string' && value.trim().toUpperCase() === 'NONE') return 'NONE';
  return normalizeSeverity(value);
}
