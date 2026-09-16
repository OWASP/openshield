import { useCallback, useState } from 'react';
import { FiX } from 'react-icons/fi';
import { api } from '../utils/api';
import PriorityMatrix from '../components/prioritization/PriorityMatrix';
import RiskRanking from '../components/prioritization/RiskRanking';
import ActionItems from '../components/prioritization/ActionItems';
import PriorityFilters from '../components/prioritization/PriorityFilters';
import QuickRemediation from '../components/prioritization/QuickRemediation';
import Card from '../components/shared/Card';
import Loader from '../components/shared/Loader';
import EmptyState from '../components/shared/EmptyState';
import ErrorState from '../components/shared/ErrorState';
import usePageData from '../hooks/usePageData';

export default function Prioritization() {
  const [filters, setFilters] = useState({ category: 'All', severity: 'All' });
  const [selectedId, setSelectedId] = useState(null);
  const loadPrioritization = useCallback(async () => {
    const [data, findings] = await Promise.all([api.getPrioritization(), api.getFindings()]);
    return { data, findings };
  }, []);
  const { status, data: loaded, retry } = usePageData(loadPrioritization);

  if (status === 'loading') return <Loader rows={8} />;
  if (status === 'error') return (
    <ErrorState
      title="Could not load prioritization data"
      description="Risk rankings and action items are unavailable right now."
      onRetry={retry}
    />
  );

  const { data, findings } = loaded;
  if (data.matrix.length === 0 && data.rankings.length === 0 && data.actionItems.length === 0) return (
    <EmptyState
      title="No issues to prioritize"
      description="Prioritization results will appear after a scan finds security issues."
    />
  );

  const filteredMatrix = data.matrix.filter((item) => {
    if (filters.category !== 'All' && item.category !== filters.category) return false;
    if (filters.severity !== 'All' && item.severity !== filters.severity) return false;
    return true;
  });

  const filteredRankings = data.rankings.filter((item) => {
    if (filters.category !== 'All' && item.category !== filters.category) return false;
    if (filters.severity !== 'All' && item.severity !== filters.severity) return false;
    return true;
  });

  const selectedItem = selectedId ? data.rankings.find((r) => r.ruleId === selectedId) : null;
  // Match the ruleId to a finding for portal/CLI steps from the live API
  const selectedFinding = selectedId ? findings.find((f) => f.ruleId === selectedId) : null;

  const handleSelect = (ruleId) => setSelectedId(ruleId);
  const clearSelection = () => setSelectedId(null);

  return (
    <div className="space-y-6">
      {/* Filters + selection banner */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-text-secondary dark:text-text-dark-tertiary uppercase tracking-wider">
            Filter
          </h2>
          <PriorityFilters filters={filters} onChange={(f) => { setFilters(f); clearSelection(); }} />
        </div>

        {selectedItem ? (
          <div className="flex items-center gap-2 px-3 py-2 rounded-xl border border-brand-primary bg-brand-primary/5 dark:bg-brand-primary/10 text-sm max-w-md">
            <span className="text-text-secondary dark:text-text-dark-tertiary shrink-0">Showing:</span>
            <span className="font-semibold text-brand-primary truncate">{selectedItem.name}</span>
            <button
              onClick={clearSelection}
              className="ml-1 flex items-center gap-1 text-xs text-text-secondary dark:text-text-dark-tertiary hover:text-severity-high transition-colors shrink-0"
            >
              <FiX size={13} /> View All {filteredRankings.length}
            </button>
          </div>
        ) : (
          <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary">
            Showing all{' '}
            <strong className="text-text-primary dark:text-text-dark-primary">{filteredRankings.length}</strong>{' '}
            issues — click any to focus
          </p>
        )}
      </div>

      {/* Matrix + Rankings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">
            Risk vs. Effort Matrix
          </h2>
          <PriorityMatrix items={filteredMatrix} selectedId={selectedId} onSelect={handleSelect} />
        </Card>

        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">
            Risk Rankings{' '}
            <span className="text-sm font-normal text-text-tertiary dark:text-text-dark-tertiary">
              ({filteredRankings.length} issues)
            </span>
          </h2>
          <RiskRanking rankings={filteredRankings} selectedId={selectedId} onSelect={handleSelect} />
        </Card>
      </div>

      {/* Quick Remediation — appears when an issue is selected */}
      {selectedItem && (
        <div key={selectedId} className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Remediation panel — takes 3/5 */}
          <div className="lg:col-span-3">
            <QuickRemediation ranking={selectedItem} finding={selectedFinding} />
          </div>

          {/* Single action item — takes 2/5 */}
          <div className="lg:col-span-2">
            <Card className="h-full">
              <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary mb-4">
                Action Item
              </p>
              {/* no onSelect here — item is already selected, clicking does nothing */}
              <ActionItems rankings={[selectedItem]} selectedId={selectedId} />
            </Card>
          </div>
        </div>
      )}

      {/* All Action Items */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary">
              Action Items
            </h2>
            <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5">
              {selectedItem
                ? `Filtered to: ${selectedItem.name}`
                : `All ${filteredRankings.length} issues ranked by priority`}
            </p>
          </div>
          {selectedId && (
            <button
              onClick={clearSelection}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors"
            >
              <FiX size={12} /> Show All
            </button>
          )}
        </div>
        <ActionItems rankings={filteredRankings} selectedId={selectedId} onSelect={handleSelect} />
      </Card>
    </div>
  );
}
