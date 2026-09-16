import { FiDatabase, FiServer, FiWifi, FiUser, FiHardDrive, FiKey, FiEye, FiZap } from 'react-icons/fi';
import Card from '../shared/Card';

const CATEGORY_ICONS = {
  Storage:     FiHardDrive,
  Compute:     FiServer,
  Network:     FiWifi,
  Identity:    FiUser,
  Database:    FiDatabase,
  KeyVault:    FiKey,
  Monitoring:  FiEye,
  PostQuantum: FiZap,
};

export default function ResourceSummary({ summary, activeCategory, onCategoryClick }) {
  if (!summary) return null;

  const stats = [
    { label: 'Total Resources', value: summary.total,                    sub: 'across all categories' },
    { label: 'Critical Risk',   value: summary.byRiskLevel?.CRITICAL || 0, sub: 'require immediate action', color: 'text-severity-critical' },
    { label: 'High Risk',       value: summary.byRiskLevel?.HIGH   || 0, sub: 'require immediate action', color: 'text-severity-high' },
    { label: 'Medium Risk',     value: summary.byRiskLevel?.MEDIUM || 0, sub: 'need attention',           color: 'text-severity-medium' },
    { label: 'Clean',           value: summary.byRiskLevel?.NONE   || 0, sub: 'no issues found',          color: 'text-brand-primary' },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {stats.map(({ label, value, sub, color }) => (
          <Card key={label} className="p-4">
            <p className="text-xs font-semibold uppercase tracking-wider text-text-secondary dark:text-text-dark-tertiary mb-2">{label}</p>
            <p className={`text-3xl font-bold ${color || 'text-text-primary dark:text-text-dark-primary'}`}>{value}</p>
            <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary mt-1">{sub}</p>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {Object.entries(summary.byCategory || {}).map(([cat, count]) => {
          const Icon = CATEGORY_ICONS[cat] || FiDatabase;
          const isActive = activeCategory === cat;
          return (
            <button
              key={cat}
              onClick={() => onCategoryClick?.(isActive ? 'All' : cat)}
              className={`p-4 rounded-2xl border flex flex-col items-center text-center gap-2 transition-all duration-200 ${
                isActive
                  ? 'border-brand-primary bg-brand-primary/5 dark:bg-brand-primary/10 shadow-soft-lg'
                  : 'border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary hover:border-brand-primary/40 hover:shadow-soft-lg'
              }`}
            >
              <div className={`w-9 h-9 rounded-lg flex items-center justify-center transition-colors ${isActive ? 'bg-brand-primary' : 'bg-brand-primary/10'}`}>
                <Icon size={16} className={isActive ? 'text-white' : 'text-brand-primary'} />
              </div>
              <p className="text-xl font-bold text-text-primary dark:text-text-dark-primary">{count}</p>
              <p className="text-xs text-text-secondary dark:text-text-dark-tertiary leading-tight">{cat}</p>
            </button>
          );
        })}
      </div>
    </div>
  );
}
