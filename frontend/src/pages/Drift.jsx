import { useCallback, useState } from 'react';
import { api } from '../utils/api';
import DriftSummary from '../components/drift/DriftSummary';
import DriftTimeline from '../components/drift/DriftTimeline';
import DriftFilters from '../components/drift/DriftFilters';
import Loader from '../components/shared/Loader';
import ErrorState from '../components/shared/ErrorState';
import usePageData from '../hooks/usePageData';
import { formatDateTime } from '../utils/helpers';

export default function Drift() {
  const [filters, setFilters] = useState({ type: 'All', severity: 'All' });
  const loadDrift = useCallback(() => api.getDrift(), []);
  const { status, data, retry } = usePageData(loadDrift);

  if (status === 'loading') return <Loader rows={6} />;
  if (status === 'error') return (
    <ErrorState
      title="Could not load drift data"
      description="Configuration change history is unavailable right now."
      onRetry={retry}
    />
  );

  const filtered = data.events.filter((e) => {
    if (filters.type !== 'All' && e.type !== filters.type) return false;
    if (filters.severity !== 'All' && e.severity !== filters.severity) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <DriftSummary summary={data.summary} />

      <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary overflow-hidden">
        <div className="p-4 border-b border-border-light dark:border-border-dark">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary">
              Change Timeline <span className="text-text-tertiary font-normal text-sm">({filtered.length})</span>
            </h2>
            <span className="text-xs text-text-tertiary dark:text-text-dark-tertiary">
              Last checked: {formatDateTime(data.summary.lastChecked)}
            </span>
          </div>
          <DriftFilters filters={filters} onChange={setFilters} />
        </div>
        <div className="p-4">
          <DriftTimeline events={filtered} />
        </div>
      </div>
    </div>
  );
}
