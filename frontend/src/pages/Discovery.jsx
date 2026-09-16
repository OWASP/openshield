import { useCallback, useState } from 'react';
import { api } from '../utils/api';
import ResourceSummary from '../components/discovery/ResourceSummary';
import ResourceFilter from '../components/discovery/ResourceFilter';
import ResourceTable from '../components/discovery/ResourceTable';
import Loader from '../components/shared/Loader';
import EmptyState from '../components/shared/EmptyState';
import ErrorState from '../components/shared/ErrorState';
import usePageData from '../hooks/usePageData';

const DEFAULT_FILTERS = {
  search: '',
  risk: 'ACTIVE',
  category: 'All',
  resourceGroup: 'All',
  location: 'All',
  groupByCategory: false,
};

function applyFilters(resources, filters) {
  return resources.filter((r) => {
    const s = filters.search.toLowerCase();
    if (s && !r.name.toLowerCase().includes(s) && !r.type.toLowerCase().includes(s)) return false;
    if (filters.category !== 'All' && r.category !== filters.category) return false;
    if (filters.location !== 'All' && r.location !== filters.location) return false;
    if (filters.resourceGroup !== 'All' && r.resourceGroup !== filters.resourceGroup) return false;
    if (filters.risk === 'ACTIVE') return r.risk !== 'NONE';
    if (filters.risk === 'CLEAN')  return r.risk === 'NONE';
    if (filters.risk !== 'All')    return r.risk === filters.risk;
    return true;
  });
}

// Merge findings + prioritization matrix, deduplicate by (ruleId, resourceName).
function buildIssueCounts(findings, matrix) {
  const seen = new Set();
  const counts = {};
  const add = (ruleId, name) => {
    if (!ruleId || !name) return;
    const key = `${ruleId}:${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    counts[name] = (counts[name] || 0) + 1;
  };
  findings.forEach((f) => add(f.ruleId, f.resourceName));
  matrix.forEach((m) => add(m.ruleId, m.resource));
  return counts;
}

export default function Discovery() {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const loadDiscovery = useCallback(async () => {
    const [resourceData, findings, prio] = await Promise.all([
      api.getResources(),
      api.getFindings(),
      api.getPrioritization(),
    ]);
    return {
      resourceData,
      issueCounts: buildIssueCounts(findings, prio.matrix),
    };
  }, []);
  const { status, data, retry } = usePageData(loadDiscovery);

  if (status === 'loading') return <Loader rows={8} />;
  if (status === 'error') return (
    <ErrorState
      title="Could not load discovery data"
      description="Resources and their security findings are unavailable right now."
      onRetry={retry}
    />
  );

  const { resourceData, issueCounts } = data;
  if (resourceData.resources.length === 0) return (
    <EmptyState
      title="No resources discovered"
      description="Run a scan to populate your cloud resource inventory."
    />
  );

  const filtered = applyFilters(resourceData.resources, filters);

  return (
    <div className="space-y-6">
      <ResourceSummary
        summary={resourceData.summary}
        activeCategory={filters.category}
        onCategoryClick={(cat) => setFilters((p) => ({ ...p, category: cat }))}
      />

      <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary overflow-hidden">
        <div className="p-4 border-b border-border-light dark:border-border-dark">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary">
              Resources
              <span className="ml-2 text-sm font-normal text-text-tertiary dark:text-text-dark-tertiary">
                {filtered.length} of {resourceData.resources.length} shown
              </span>
            </h2>
            <div className="flex items-center gap-2 flex-wrap justify-end">
              {filters.category !== 'All' && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-lg bg-brand-primary/10 text-brand-primary">
                  {filters.category}
                  <button onClick={() => setFilters((p) => ({ ...p, category: 'All' }))} className="hover:text-brand-secondary ml-0.5">×</button>
                </span>
              )}
              {filters.resourceGroup !== 'All' && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-lg bg-brand-primary/10 text-brand-primary font-mono">
                  {filters.resourceGroup}
                  <button onClick={() => setFilters((p) => ({ ...p, resourceGroup: 'All' }))} className="hover:text-brand-secondary ml-0.5">×</button>
                </span>
              )}
            </div>
          </div>
          <ResourceFilter filters={filters} onChange={setFilters} />
        </div>

        <div className="p-4">
          <ResourceTable
            resources={filtered}
            issueCounts={issueCounts}
            groupByCategory={filters.groupByCategory}
          />
        </div>
      </div>
    </div>
  );
}
