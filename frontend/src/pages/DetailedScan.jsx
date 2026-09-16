import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { FiArrowLeft, FiX, FiAlertTriangle } from 'react-icons/fi';
import { api } from '../utils/api';
import FindingHeader from '../components/scan/FindingHeader';
import PlaybookTabs from '../components/scan/PlaybookTabs';
import AskAIButton from '../components/scan/AskAIButton';
import SeverityBadge from '../components/shared/SeverityBadge';
import Card from '../components/shared/Card';
import Loader from '../components/shared/Loader';
import EmptyState from '../components/shared/EmptyState';
import ErrorState from '../components/shared/ErrorState';
import usePageData from '../hooks/usePageData';

const IMPACT_COLORS = {
  CRITICAL: 'text-red-600 dark:text-red-400',
  HIGH:     'text-orange-500 dark:text-orange-400',
  MEDIUM:   'text-yellow-600 dark:text-yellow-400',
  LOW:      'text-green-600 dark:text-green-400',
};

const EMPTY_PLAYBOOK = {
  portalSteps: [],
  cliCommands: [],
  validationSteps: [],
  references: [],
};

function FromPrioritizationBanner({ state, finding, onDismiss }) {
  const navigate = useNavigate();
  const issueName = state.issueName || finding?.ruleName || 'Selected finding';
  const resource  = state.resource  || finding?.resourceName || '';
  const category  = state.category  || finding?.category || '';
  const impact    = state.impact;
  const rank      = state.rank;

  return (
    <div className="flex flex-wrap items-start gap-3 px-4 py-3 rounded-2xl border border-brand-primary/30 bg-brand-primary/5 dark:bg-brand-primary/10 mb-2">
      {/* Back button */}
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1.5 text-xs font-semibold text-brand-primary hover:text-brand-secondary transition-colors shrink-0 mt-0.5"
      >
        <FiArrowLeft size={13} />
        Prioritization
      </button>

      <div className="w-px self-stretch bg-border-light dark:bg-border-dark" />

      {/* Context pill */}
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-1">
          {rank && (
            <span className="px-2 py-0.5 text-[10px] font-bold rounded-md bg-brand-primary text-white uppercase tracking-wider">
              Rank #{rank}
            </span>
          )}
          {impact && (
            <span className={`text-[10px] font-semibold uppercase tracking-wider flex items-center gap-1 ${IMPACT_COLORS[impact] ?? ''}`}>
              <FiAlertTriangle size={10} />
              {impact} impact
            </span>
          )}
          {finding && <SeverityBadge severity={finding.severity} />}
        </div>
        <p className="text-sm font-bold text-text-primary dark:text-text-dark-primary leading-snug truncate">
          {issueName}
        </p>
        {(resource || category) && (
          <p className="text-xs font-mono text-text-secondary dark:text-text-dark-tertiary mt-0.5">
            {resource}{category ? ` · ${category}` : ''}
          </p>
        )}
      </div>

      {/* Dismiss */}
      <button
        onClick={onDismiss}
        className="p-1 rounded-lg text-text-tertiary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors shrink-0"
        aria-label="Dismiss banner"
      >
        <FiX size={14} />
      </button>
    </div>
  );
}

export default function DetailedScan() {
  const location = useLocation();
  const [selectedId, setSelectedId] = useState(null);
  const [playbookState, setPlaybookState] = useState({ findingId: null, data: null });
  const [showBanner, setShowBanner] = useState(!!location.state?.fromPrioritization);
  const preSelectRuleId = location.state?.ruleId;
  const loadFindings = useCallback(() => api.getFindings(), []);
  const { status, data: findings, retry } = usePageData(loadFindings);

  const preselected = preSelectRuleId
    ? findings?.find((finding) => finding.ruleId === preSelectRuleId)
    : null;
  const selected = findings?.find((finding) => finding.id === selectedId)
    ?? preselected
    ?? findings?.[0]
    ?? null;
  const playbook = playbookState.findingId === selected?.id ? playbookState.data : null;

  // Fetch the playbook for the derived initial finding or a user selection.
  useEffect(() => {
    if (!selected?.id) return undefined;
    let active = true;
    api.getPlaybook(selected.id).then((data) => {
      if (active) setPlaybookState({ findingId: selected.id, data });
    }).catch(() => {
      if (active) setPlaybookState({ findingId: selected.id, data: EMPTY_PLAYBOOK });
    });
    return () => { active = false; };
  }, [selected?.id]);

  // Merge playbook data into the selected finding for rendering
  const enriched = selected ? { ...selected, ...(playbook || {}) } : null;

  if (status === 'loading') return <Loader rows={6} />;
  if (status === 'error') return (
    <ErrorState
      title="Could not load scan findings"
      description="Detailed findings are unavailable right now."
      onRetry={retry}
    />
  );
  if (findings.length === 0) return (
    <EmptyState
      title="No findings detected"
      description="The latest scan completed without reporting security findings."
    />
  );

  const fromState = location.state?.fromPrioritization ? location.state : null;

  return (
    <div className="space-y-4">
      {/* From-Prioritization banner */}
      {showBanner && fromState && (
        <FromPrioritizationBanner
          state={fromState}
          finding={selected}
          onDismiss={() => setShowBanner(false)}
        />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Finding list */}
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-text-secondary dark:text-text-dark-tertiary">
            Findings ({findings.length})
          </h2>
          <div className="h-64 lg:h-[calc(100vh-14rem)] overflow-y-auto flex flex-col gap-2 pr-1 custom-scrollbar">
            {findings.map((f) => {
              const isActive = selected?.id === f.id;
              const isPreSelected = fromState?.ruleId === f.ruleId;
              return (
                <button
                  key={f.id}
                  onClick={() => setSelectedId(f.id)}
                  className={`w-full text-left p-4 rounded-2xl border transition-all duration-200 ${
                    isActive
                      ? 'border-brand-primary bg-brand-primary/5 dark:bg-brand-primary/10 shadow-soft'
                      : 'border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary hover:border-brand-primary/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-mono text-text-tertiary dark:text-text-dark-tertiary">{f.ruleId}</span>
                    <div className="flex items-center gap-1.5">
                      {isPreSelected && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-brand-primary text-white uppercase tracking-wider">
                          From Prioritization
                        </span>
                      )}
                      <SeverityBadge severity={f.severity} />
                    </div>
                  </div>
                  <p className="text-sm font-medium text-text-primary dark:text-text-dark-primary leading-snug">{f.ruleName}</p>
                  <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-1">{f.resourceName}</p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Finding detail */}
        <div className="lg:col-span-2 space-y-6">
          {enriched && (
            <>
              <Card>
                <FindingHeader finding={enriched} />
              </Card>

              <Card>
                <div className="flex items-center justify-between mb-1">
                  <h3 className="text-base font-semibold text-text-primary dark:text-text-dark-primary">
                    Remediation Playbook
                  </h3>
                  {/* Show a loading indicator while playbook is being fetched */}
                  {!playbook && (
                    <span className="text-xs text-text-tertiary dark:text-text-dark-tertiary animate-pulse">
                      Loading playbook…
                    </span>
                  )}
                </div>
                <p className="text-sm text-text-secondary dark:text-text-dark-tertiary mb-4">{enriched.remediation}</p>
                <PlaybookTabs finding={enriched} />
              </Card>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card>
                  <AskAIButton finding={enriched} />
                </Card>
                <Card>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-dark-primary mb-2">References</h3>
                  <div className="space-y-1">
                    {(enriched.references || []).map((ref, i) => (
                      <p key={i} className="text-xs text-text-secondary dark:text-text-dark-tertiary">{ref}</p>
                    ))}
                  </div>
                </Card>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
