
import { SEVERITY_IDS } from '../../utils/severity';

const TYPES = ['All', 'ADDED', 'REMOVED', 'MODIFIED'];
const SEVERITIES = ['All', ...SEVERITY_IDS];

export default function DriftFilters({ filters, onChange }) {
  const set = (key, val) => onChange({ ...filters, [key]: val });

  return (
    <div className="flex flex-wrap gap-3">
      <div className="flex gap-1">
        <span className="text-xs font-medium text-text-secondary dark:text-text-dark-tertiary self-center mr-1">Type:</span>
        {TYPES.map((t) => (
          <button
            key={t}
            onClick={() => set('type', t)}
            className={`px-3 py-1 text-xs rounded-lg font-medium transition-all duration-200 ${
              filters.type === t
                ? 'bg-brand-primary text-white'
                : 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary border border-border-light dark:border-border-dark'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="flex gap-1">
        <span className="text-xs font-medium text-text-secondary dark:text-text-dark-tertiary self-center mr-1">Severity:</span>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => set('severity', s)}
            className={`px-3 py-1 text-xs rounded-lg font-medium transition-all duration-200 ${
              filters.severity === s
                ? 'bg-brand-primary text-white'
                : 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary border border-border-light dark:border-border-dark'
            }`}
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}
