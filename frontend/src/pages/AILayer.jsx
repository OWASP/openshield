import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router';
import { FiCpu, FiX, FiAlertCircle, FiKey, FiCheckCircle } from 'react-icons/fi';
import { api } from '../utils/api';
import { aiApi, aiSettings } from '../utils/aiApi';
import ChatPanel from '../components/ai/ChatPanel';
import ExecutiveSummary from '../components/ai/ExecutiveSummary';
import CVEAnalysis from '../components/ai/CVEAnalysis';
import SeverityBadge from '../components/shared/SeverityBadge';

const PROVIDERS = [
  { value: 'anthropic', label: 'Anthropic (Claude)' },
  { value: 'groq',      label: 'Groq (Llama)' },
  { value: 'gemini',    label: 'Google Gemini' },
];

// ── AI Settings card ────────────────────────────────────────────────────────
function AISettingsCard({ onSaved }) {
  const [provider, setProvider]   = useState(aiSettings.getProvider());
  const [apiKey,   setApiKey]     = useState(aiSettings.getApiKey());
  const [saved,    setSaved]      = useState(false);
  const configured = aiSettings.isConfigured();

  const handleSave = () => {
    aiSettings.save({ provider, apiKey });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
    onSaved?.();
  };

  return (
    <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary flex items-center gap-1.5">
          <FiKey size={11} /> AI Provider
        </p>
        {configured && (
          <span className="flex items-center gap-1 text-[10px] text-brand-primary font-semibold">
            <FiCheckCircle size={11} /> Configured
          </span>
        )}
      </div>

      <select
        value={provider}
        onChange={(e) => setProvider(e.target.value)}
        className="w-full px-3 py-1.5 text-xs rounded-lg border border-border-light dark:border-border-dark bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary focus:outline-none focus:ring-1 focus:ring-brand-primary"
      >
        {PROVIDERS.map((p) => (
          <option key={p.value} value={p.value}>{p.label}</option>
        ))}
      </select>

      <input
        type="password"
        placeholder="Paste your API key..."
        value={apiKey}
        onChange={(e) => setApiKey(e.target.value)}
        className="w-full px-3 py-1.5 text-xs rounded-lg border border-border-light dark:border-border-dark bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary placeholder:text-text-tertiary dark:placeholder:text-text-dark-tertiary focus:outline-none focus:ring-1 focus:ring-brand-primary"
      />

      <div className="flex gap-2">
        <button
          onClick={handleSave}
          disabled={!apiKey.trim()}
          className="flex-1 py-1.5 text-xs font-semibold rounded-lg bg-brand-primary hover:bg-brand-secondary disabled:opacity-50 text-white transition-colors"
        >
          {saved ? '✓ Saved' : 'Save'}
        </button>
        {configured && (
          <button
            onClick={() => { aiSettings.clear(); setApiKey(''); onSaved?.(); }}
            className="px-3 py-1.5 text-xs rounded-lg border border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      <p className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary">
        Key stored locally in your browser. Never sent to our servers.
      </p>
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────
export default function AILayer() {
  const location = useLocation();
  const chatRef  = useRef(null);

  const [initialMessages] = useState([]);
  const [suggestions] = useState([]);
  const [findings,        setFindings]        = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [summary,         setSummary]         = useState(null);
  const [summaryLoading,  setSummaryLoading]  = useState(true);
  const [cveData,         setCveData]         = useState(null);
  const [cveLoading,      setCveLoading]      = useState(true);
  const [settingsKey,     setSettingsKey]     = useState(0); // force re-render on settings save
  const initialFinding = location.state?.finding;

  useEffect(() => {
    api.getFindings()
      .then((scans) => {
        setFindings(scans);
        if (initialFinding) setSelectedFinding(initialFinding);
        aiApi.getSummary().then(setSummary).finally(() => setSummaryLoading(false));
      })
      .catch(() => {
        setFindings(null);
        aiApi.getSummary().then(setSummary).finally(() => setSummaryLoading(false));
      });
    aiApi.getCVEAnalysis().then(setCveData).finally(() => setCveLoading(false));
  }, [initialFinding]);

  const handleFindingSelect = (f) =>
    setSelectedFinding((prev) => (prev?.id === f.id ? null : f));

  const refreshSummary = () => {
    setSummaryLoading(true);
    aiApi.getSummary().then(setSummary).finally(() => setSummaryLoading(false));
  };

  return (
    <div className="flex flex-col lg:flex-row gap-4 lg:h-[calc(100vh-9.5rem)]">

      {/* ══ LEFT COLUMN: Chat ════════════════════════════════════════════ */}
      <div className="flex-1 min-w-0 flex flex-col gap-4 min-h-0">
        <div className="flex-1 min-h-[440px] lg:min-h-0 rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary flex flex-col overflow-hidden">

          {/* Chat header */}
          <div className="px-4 py-3 border-b border-border-light dark:border-border-dark flex items-center gap-3 flex-shrink-0">
            <div className="w-8 h-8 rounded-lg bg-brand-primary flex items-center justify-center flex-shrink-0">
              <FiCpu size={15} className="text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary">AI Security Chat</p>
              <p className="text-xs text-text-secondary dark:text-text-dark-tertiary">
                {aiSettings.isConfigured()
                  ? `${aiSettings.getProvider()} · live AI responses`
                  : 'Configure a provider to enable AI responses'}
              </p>
            </div>

            {selectedFinding && (
              <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-brand-primary/10 border border-brand-primary/30 min-w-0 max-w-[220px]">
                <FiAlertCircle size={12} className="text-brand-primary flex-shrink-0" />
                <span className="text-xs font-semibold text-brand-primary truncate">{selectedFinding.ruleId}</span>
                <button onClick={() => setSelectedFinding(null)} className="text-brand-primary/60 hover:text-brand-primary flex-shrink-0">
                  <FiX size={12} />
                </button>
              </div>
            )}

            <div className="flex items-center gap-1.5 flex-shrink-0">
              <span className="w-2 h-2 rounded-full bg-brand-primary animate-pulse" />
              <span className="text-xs text-brand-primary font-medium">Online</span>
            </div>
          </div>

          {/* Messages + input */}
          <div className="flex-1 min-h-0 overflow-hidden">
            <ChatPanel
              ref={chatRef}
              initialMessages={initialMessages}
              contextFinding={selectedFinding}
              suggestions={suggestions}
            />
          </div>
        </div>
      </div>

      {/* ══ RIGHT COLUMN: Findings + Settings + Summary + CVE ═══════════ */}
      <div className="lg:w-80 xl:w-96 flex-shrink-0 flex flex-col gap-4 overflow-y-auto custom-scrollbar pb-1">

        {/* Findings picker */}
        <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary overflow-hidden flex-shrink-0">
          <div className="px-4 py-3 border-b border-border-light dark:border-border-dark flex items-center justify-between">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary">Findings</p>
              <p className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary mt-0.5">Select to focus AI on a finding</p>
            </div>
            {selectedFinding && (
              <button onClick={() => setSelectedFinding(null)} className="text-xs text-text-tertiary dark:text-text-dark-tertiary hover:text-severity-high transition-colors flex items-center gap-1">
                <FiX size={12} /> Clear
              </button>
            )}
          </div>
          <div className="overflow-y-auto max-h-64 custom-scrollbar divide-y divide-border-light dark:divide-border-dark">
            {findings === null
              ? <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary px-4 py-6 text-center">Could not load findings — backend may be waking up.</p>
              : findings.length === 0
              ? <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary px-4 py-6 text-center">No findings yet. Run a scan first.</p>
              : findings.map((f) => {
                  const isActive = selectedFinding?.id === f.id;
                  return (
                    <button key={f.id} onClick={() => handleFindingSelect(f)}
                      className={`w-full text-left px-4 py-3 transition-colors duration-150 ${isActive ? 'bg-brand-primary/10 dark:bg-brand-primary/15' : 'hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary'}`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="text-[10px] font-mono text-text-tertiary dark:text-text-dark-tertiary truncate">{f.ruleId}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      <p className={`text-xs font-medium leading-snug ${isActive ? 'text-brand-primary' : 'text-text-primary dark:text-text-dark-secondary'}`}>{f.ruleName}</p>
                      <p className="text-[10px] font-mono text-text-tertiary dark:text-text-dark-tertiary mt-0.5 truncate">{f.resourceName}</p>
                    </button>
                  );
                })
            }
          </div>
        </div>

        {/* AI provider settings */}
        <AISettingsCard key={settingsKey} onSaved={() => setSettingsKey((k) => k + 1)} />

        {/* Executive summary */}
        <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary p-4">
          <ExecutiveSummary summary={summary} loading={summaryLoading} onRefresh={refreshSummary} />
        </div>

        {/* CVE analysis */}
        <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary p-4">
          <CVEAnalysis data={cveData} loading={cveLoading} />
        </div>
      </div>
    </div>
  );
}
