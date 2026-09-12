import { FiShield, FiCheckCircle, FiXCircle } from 'react-icons/fi';

export default function FrameworkCards({ frameworks, selected, onSelect }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {frameworks.map((fw) => {
        // A null score means no evidence to report - either no completed
        // scan exists yet, or every mapped control is excluded from the
        // denominator. Both are distinct facts from a real, evaluated 0%,
        // and must never render as one.
        const hasScore = typeof fw.score === 'number';
        const pct = hasScore ? fw.score : 0;
        const notAssessedLabel = fw.status === 'NO_IN_SCOPE_CONTROLS' ? 'No in-scope controls' : 'Not assessed';
        const isSelected = selected?.id === fw.id;
        return (
          <button
            key={fw.id}
            onClick={() => onSelect(fw)}
            className={`p-4 rounded-2xl border text-left transition-all duration-200 ${
              isSelected
                ? 'border-brand-primary bg-brand-primary/5 dark:bg-brand-primary/10'
                : 'border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary hover:border-brand-primary/40'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: fw.color + '20' }}>
                <FiShield size={16} style={{ color: fw.color }} />
              </div>
              <span className="text-lg font-bold text-text-primary dark:text-text-dark-primary">
                {hasScore ? `${pct}%` : notAssessedLabel}
              </span>
            </div>
            <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary">{fw.name}</p>
            <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary mb-3">{fw.version}</p>

            <div className="w-full bg-bg-secondary dark:bg-bg-dark-tertiary rounded-full h-1.5 mb-3">
              <div
                className="h-1.5 rounded-full transition-all duration-700"
                style={{ width: hasScore ? `${pct}%` : '0%', background: hasScore ? fw.color : '#9ca3af' }}
              />
            </div>

            <div className="flex items-center justify-between text-xs text-text-secondary dark:text-text-dark-tertiary">
              <span className="flex items-center gap-1 text-brand-primary">
                <FiCheckCircle size={11} /> {fw.passing} pass
              </span>
              <span className="flex items-center gap-1 text-severity-high">
                <FiXCircle size={11} /> {fw.failing} fail
              </span>
            </div>
          </button>
        );
      })}
    </div>
  );
}
