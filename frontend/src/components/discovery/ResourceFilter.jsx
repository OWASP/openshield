import { FiSearch, FiX, FiLayers, FiList } from 'react-icons/fi';
import { SEVERITY_DEFINITIONS } from '../../utils/severity';

const RISK_TEXT_STYLES = {
  critical: 'text-severity-critical',
  danger: 'text-severity-high',
  warning: 'text-severity-medium',
  success: 'text-severity-low',
  neutral: 'text-severity-info',
};

const RISK_ACTIVE_TONE_STYLES = {
  critical: 'bg-severity-critical text-white',
  danger: 'bg-severity-high text-white',
  warning: 'bg-severity-medium text-white',
  success: 'bg-severity-low text-white',
  neutral: 'bg-severity-info text-white',
};

const RISK_PILLS = [
  { value: 'ACTIVE', label: 'Active Issues', color: 'text-text-primary dark:text-text-dark-primary' },
  ...SEVERITY_DEFINITIONS.map((level) => ({
    value: level.id,
    label: level.id,
    color: RISK_TEXT_STYLES[level.tone],
  })),
  { value: 'CLEAN',  label: 'Clean Only',     color: 'text-brand-primary' },
];

const RISK_ACTIVE_STYLES = {
  ACTIVE: 'bg-text-primary dark:bg-text-dark-primary text-bg-primary dark:text-bg-dark-primary',
  ...Object.fromEntries(
    SEVERITY_DEFINITIONS.map((level) => [level.id, RISK_ACTIVE_TONE_STYLES[level.tone]]),
  ),
  CLEAN:  'bg-brand-primary text-white',
};

const RESOURCE_GROUPS = ['All', 'rg-prod', 'rg-staging', 'rg-dev'];
const LOCATIONS = ['All', 'eastus', 'westus2', 'centralus', 'global'];

export default function ResourceFilter({ filters, onChange }) {
  const set = (key, val) => onChange({ ...filters, [key]: val });

  return (
    <div className="space-y-3">
      {/* Search */}
      <div className="relative">
        <FiSearch size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-tertiary dark:text-text-dark-tertiary" />
        <input
          type="text"
          placeholder="Search by name or resource type..."
          value={filters.search || ''}
          onChange={(e) => set('search', e.target.value)}
          className="w-full pl-9 pr-9 py-2 text-sm rounded-lg border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary placeholder:text-text-tertiary dark:placeholder:text-text-dark-tertiary focus:outline-none focus:ring-1 focus:ring-brand-primary"
        />
        {filters.search && (
          <button onClick={() => set('search', '')} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary dark:text-text-dark-tertiary hover:text-text-primary dark:hover:text-text-dark-primary">
            <FiX size={14} />
          </button>
        )}
      </div>

      {/* Risk pills */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-text-secondary dark:text-text-dark-tertiary mr-1">Risk:</span>
        {RISK_PILLS.map(({ value, label, color }) => {
          const isActive = filters.risk === value;
          return (
            <button
              key={value}
              onClick={() => set('risk', value)}
              className={`px-3 py-1 text-xs font-medium rounded-lg border transition-all duration-150 ${
                isActive
                  ? `${RISK_ACTIVE_STYLES[value]} border-transparent`
                  : `border-border-light dark:border-border-dark ${color} bg-bg-primary dark:bg-bg-dark-secondary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary`
              }`}
            >
              {label}
            </button>
          );
        })}
      </div>

      {/* Resource group buttons + location + groupBy */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-medium text-text-secondary dark:text-text-dark-tertiary">Group:</span>
          {RESOURCE_GROUPS.map((rg) => {
            const isActive = filters.resourceGroup === rg;
            return (
              <button
                key={rg}
                onClick={() => set('resourceGroup', rg)}
                className={`px-3 py-1 text-xs font-medium rounded-lg border transition-all duration-150 ${
                  isActive
                    ? 'bg-brand-primary border-brand-primary text-white'
                    : 'border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary bg-bg-primary dark:bg-bg-dark-secondary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary'
                }`}
              >
                {rg === 'All' ? 'All Groups' : rg}
              </button>
            );
          })}
        </div>

        <div className="sm:ml-auto flex flex-wrap items-center gap-3">
          <select
            value={filters.location || 'All'}
            onChange={(e) => set('location', e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary focus:outline-none focus:ring-1 focus:ring-brand-primary"
          >
            {LOCATIONS.map((l) => <option key={l} value={l}>{l === 'All' ? 'All Locations' : l}</option>)}
          </select>

          <button
            onClick={() => set('groupByCategory', !filters.groupByCategory)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border transition-all duration-150 ${
              filters.groupByCategory
                ? 'bg-brand-primary border-brand-primary text-white'
                : 'border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary'
            }`}
          >
            {filters.groupByCategory ? <FiLayers size={12} /> : <FiList size={12} />}
            {filters.groupByCategory ? 'Grouped' : 'Group by Category'}
          </button>
        </div>
      </div>
    </div>
  );
}
