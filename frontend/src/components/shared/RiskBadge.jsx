
import { normalizeRisk, severityDefinition } from '../../utils/severity';

const styles = {
  critical: 'bg-red-200 text-red-900 dark:bg-red-950/50 dark:text-red-300',
  danger: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  warning: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  success: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  neutral: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
  NONE: 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
};

export default function RiskBadge({ risk }) {
  const normalized = normalizeRisk(risk || 'NONE');
  const style = normalized === 'NONE'
    ? styles.NONE
    : styles[severityDefinition(normalized).tone];
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-semibold uppercase tracking-wider ${style}`}>
      {normalized}
    </span>
  );
}
