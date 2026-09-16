
import { SEVERITY_IDS } from '../../utils/severity';

const CATEGORIES = ['All', 'Storage', 'Compute', 'Network', 'Identity', 'Database', 'KeyVault'];
const SEVERITIES = ['All', ...SEVERITY_IDS];

export default function PriorityFilters({ filters, onChange }) {
  const set = (key, val) => onChange({ ...filters, [key]: val });

  return (
    <div className="flex flex-wrap gap-3">
      <select
        value={filters.category || 'All'}
        onChange={(e) => set('category', e.target.value)}
        className="px-3 py-2 text-sm rounded-lg border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary focus:outline-none focus:ring-1 focus:ring-brand-primary"
      >
        {CATEGORIES.map((c) => <option key={c} value={c}>{c === 'All' ? 'All Categories' : c}</option>)}
      </select>

      <select
        value={filters.severity || 'All'}
        onChange={(e) => set('severity', e.target.value)}
        className="px-3 py-2 text-sm rounded-lg border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary focus:outline-none focus:ring-1 focus:ring-brand-primary"
      >
        {SEVERITIES.map((s) => <option key={s} value={s}>{s === 'All' ? 'All Severities' : s}</option>)}
      </select>
    </div>
  );
}
