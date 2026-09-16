import { useCallback, useState } from 'react';
import { api } from '../utils/api';
import FrameworkCards from '../components/compliance/FrameworkCards';
import ComplianceTable from '../components/compliance/ComplianceTable';
import ComparisonChart from '../components/compliance/ComparisonChart';
import ExportButton from '../components/compliance/ExportButton';
import Card from '../components/shared/Card';
import Loader from '../components/shared/Loader';
import EmptyState from '../components/shared/EmptyState';
import ErrorState from '../components/shared/ErrorState';
import usePageData from '../hooks/usePageData';

export default function Compliance() {
  const [selectedFw, setSelectedFw] = useState(null);
  const [statusFilter, setStatusFilter] = useState('All');
  const loadCompliance = useCallback(() => api.getCompliance(), []);
  const { status, data, retry } = usePageData(loadCompliance);

  if (status === 'loading') return <Loader rows={8} />;
  if (status === 'error') return (
    <ErrorState
      title="Could not load compliance data"
      description="Compliance frameworks and controls are unavailable right now."
      onRetry={retry}
    />
  );
  if (data.frameworks.length === 0 && data.controls.length === 0) return (
    <EmptyState
      title="No compliance results"
      description="Run a scan to assess resources against compliance frameworks."
    />
  );

  const activeFramework = data.frameworks.find((framework) => framework.name === selectedFw?.name)
    ?? data.frameworks[0]
    ?? null;

  const filteredControls = data.controls.filter((c) => {
    if (activeFramework && c.framework !== activeFramework.name) return false;
    if (statusFilter !== 'All' && c.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <FrameworkCards
        frameworks={data.frameworks}
        selected={activeFramework}
        onSelect={setSelectedFw}
      />

      <Card>
        <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">Framework Score Trends</h2>
        <ComparisonChart trend={data.trend} />
      </Card>

      <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary overflow-hidden">
        <div className="p-4 flex items-center justify-between border-b border-border-light dark:border-border-dark">
          <div className="flex items-center gap-4">
            <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary">
              Controls <span className="text-text-tertiary font-normal text-sm">({filteredControls.length})</span>
            </h2>
            <div className="flex gap-1">
              {['All', 'PASS', 'FAIL'].map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-3 py-1 text-xs rounded-lg font-medium transition-all duration-200 ${
                    statusFilter === s
                      ? 'bg-brand-primary text-white'
                      : 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <ExportButton controls={filteredControls} framework={selectedFw} />
        </div>
        <ComplianceTable controls={filteredControls} />
      </div>
    </div>
  );
}
