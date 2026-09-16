import { SEVERITY_DEFINITIONS, SEVERITY_IDS } from './severity.js';

export const SEVERITY_LEVELS = Object.freeze(Object.fromEntries(SEVERITY_IDS.map((id) => [id, id])));

export const RISK_LEVELS = Object.freeze({ ...SEVERITY_LEVELS, NONE: 'NONE' });

export const CATEGORIES = [
  'Storage',
  'Compute',
  'Network',
  'Identity',
  'Database',
  'KeyVault',
  'Monitoring',
];

export const FRAMEWORKS = ['CIS', 'NIST', 'ISO27001', 'SOC2'];

export const DRIFT_TYPES = {
  ADDED: 'ADDED',
  REMOVED: 'REMOVED',
  MODIFIED: 'MODIFIED',
};

const RISK_TONE_CLASSES = {
  critical: 'text-severity-critical bg-red-100 dark:bg-red-950/40',
  danger: 'text-severity-high bg-red-50 dark:bg-red-900/20',
  warning: 'text-severity-medium bg-orange-50 dark:bg-orange-900/20',
  success: 'text-severity-low bg-green-50 dark:bg-green-900/20',
  neutral: 'text-severity-info bg-gray-50 dark:bg-gray-900/20',
};

export const RISK_COLORS = Object.freeze({
  ...Object.fromEntries(
    SEVERITY_DEFINITIONS.map((level) => [level.id, RISK_TONE_CLASSES[level.tone]]),
  ),
  NONE: 'text-text-secondary bg-bg-secondary dark:bg-bg-dark-tertiary',
});

export const NAV_ITEMS = [
  { path: '/monitoring', label: 'Monitor', icon: 'FiActivity' },
  { path: '/discovery', label: 'Discover', icon: 'FiSearch' },
  { path: '/prioritization', label: 'Prioritize', icon: 'FiTarget' },
  { path: '/scan', label: 'Scan', icon: 'FiZap' },
  { path: '/compliance', label: 'Comply', icon: 'FiShield' },
  { path: '/drift', label: 'Drift', icon: 'FiGitBranch' },
  { path: '/ai', label: 'AI', icon: 'FiCpu' },
];
