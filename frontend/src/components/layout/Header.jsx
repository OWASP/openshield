import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router';
import {
  FiMenu, FiAlertTriangle, FiX,
  FiLoader, FiZap, FiCheckCircle, FiAlertCircle, FiClock,
} from 'react-icons/fi';
import { api } from '../../utils/api';
import { pollScan } from '../../utils/scanPolling';
import { useI18n } from '../../i18n/I18nState';

const PAGE_KEYS = {
  '/monitoring': 'monitoring', '/discovery': 'discovery', '/prioritization': 'prioritization',
  '/scan': 'scan', '/compliance': 'compliance', '/drift': 'drift', '/ai': 'ai',
};

// ── Connection-error popup ─────────────────────────────────────────────────
function ConnectionErrorPopup({ apiBase, onClose }) {
  return (
    <>
      <button type="button" aria-label="Close connection error" className="fixed inset-0 bg-black/30 z-[90]" onClick={onClose} />
      <div role="dialog" aria-modal="true" aria-labelledby="connection-error-title" className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[100] w-full max-w-sm px-4">
        <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary shadow-soft-lg overflow-hidden">
          <div className="px-5 py-4 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-100 dark:border-amber-900/40 flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-amber-100 dark:bg-amber-900/40 flex items-center justify-center flex-shrink-0">
                <FiAlertTriangle size={18} className="text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <p id="connection-error-title" className="text-sm font-bold text-text-primary dark:text-text-dark-primary">Unable to connect</p>
                <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5">Backend API unreachable</p>
              </div>
            </div>
            <button aria-label="Close connection error" onClick={onClose} className="p-1 rounded-lg text-text-tertiary hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors">
              <FiX size={16} />
            </button>
          </div>
          <div className="px-5 py-4 space-y-3">
            <p className="text-sm text-text-secondary dark:text-text-dark-secondary leading-relaxed">Could not reach the backend at:</p>
            <code className="block text-xs font-mono bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary px-3 py-2 rounded-lg">
              {apiBase}/health
            </code>
            <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary">
              Make sure the backend is running and{' '}
              <code className="px-1 rounded bg-bg-secondary dark:bg-bg-dark-tertiary">VITE_API_URL</code> is set correctly.
            </p>
          </div>
          <div className="px-5 pb-5">
            <button onClick={onClose} className="w-full py-2.5 rounded-xl bg-brand-primary hover:bg-brand-secondary text-white text-sm font-semibold transition-colors">
              Dismiss
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Scan result toast ──────────────────────────────────────────────────────
function ScanToast({ result, error, onClose }) {
  useEffect(() => {
    const t = setTimeout(onClose, 6000);
    return () => clearTimeout(t);
  }, [onClose]);

  const isSuccess = !!result;

  return (
    <div role="status" aria-live="polite" className="fixed bottom-6 right-6 z-[100] w-full max-w-xs">
      <div className={`rounded-2xl border shadow-soft-lg overflow-hidden ${
        isSuccess
          ? 'bg-bg-primary dark:bg-bg-dark-secondary border-green-200 dark:border-green-900/50'
          : 'bg-bg-primary dark:bg-bg-dark-secondary border-red-200 dark:border-red-900/50'
      }`}>
        <div className={`px-4 py-3 flex items-center justify-between gap-3 ${
          isSuccess ? 'bg-green-50 dark:bg-green-900/20' : 'bg-red-50 dark:bg-red-900/20'
        }`}>
          <div className="flex items-center gap-2">
            {isSuccess
              ? <FiCheckCircle size={16} className="text-brand-primary flex-shrink-0" />
              : <FiAlertCircle size={16} className="text-severity-high flex-shrink-0" />
            }
            <p className="text-sm font-bold text-text-primary dark:text-text-dark-primary">
              {isSuccess ? 'Scan complete' : 'Scan failed'}
            </p>
          </div>
          <button aria-label="Dismiss scan status" onClick={onClose} className="text-text-tertiary hover:text-text-primary transition-colors">
            <FiX size={14} />
          </button>
        </div>
        <div className="px-4 py-3 space-y-1.5 text-xs text-text-secondary dark:text-text-dark-tertiary">
          {isSuccess ? (
            <>
              <div className="flex justify-between">
                <span>Scan ID</span>
                <span className="font-mono text-text-primary dark:text-text-dark-primary truncate max-w-[160px]">{result.scan_id}</span>
              </div>
              <div className="flex justify-between">
                <span>Findings detected</span>
                <span className={`font-bold ${result.total_findings > 0 ? 'text-severity-high' : 'text-brand-primary'}`}>
                  {result.total_findings}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Status</span>
                <span className="text-brand-primary font-semibold capitalize">{result.status}</span>
              </div>
            </>
          ) : (
            <p className="text-severity-high">{error || 'Could not reach the backend.'}</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Scan input popover (live mode only) ────────────────────────────────────
function ScanInputPopover({ onConfirm, onCancel }) {
  const [subId, setSubId] = useState('');
  const inputRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  return (
    <>
      <button type="button" aria-label="Cancel scan" className="fixed inset-0 z-[80]" onClick={onCancel} />
      <div role="dialog" aria-modal="true" aria-labelledby="scan-dialog-title" className="absolute top-full right-0 mt-2 z-[90] w-72 rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary shadow-soft-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border-light dark:border-border-dark">
          <p id="scan-dialog-title" className="text-sm font-semibold text-text-primary dark:text-text-dark-primary">Run Azure Scan</p>
          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5">
            Leave blank to use the subscription configured on the backend.
          </p>
        </div>
        <div className="px-4 py-3 space-y-3">
          <div>
            <label className="text-xs font-medium text-text-secondary dark:text-text-dark-tertiary block mb-1">
              Subscription ID <span className="text-text-tertiary">(optional)</span>
            </label>
            <input
              ref={inputRef}
              type="text"
              value={subId}
              onChange={(e) => setSubId(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') onConfirm(subId || undefined); if (e.key === 'Escape') onCancel(); }}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-border-light dark:border-border-dark bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary placeholder:text-text-tertiary dark:placeholder:text-text-dark-tertiary focus:outline-none focus:ring-1 focus:ring-brand-primary"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => onConfirm(subId || undefined)}
              className="flex-1 py-2 text-xs font-semibold rounded-lg bg-brand-primary hover:bg-brand-secondary text-white transition-colors"
            >
              Start Scan
            </button>
            <button
              onClick={onCancel}
              className="px-3 py-2 text-xs rounded-lg border border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Main Header ────────────────────────────────────────────────────────────
export default function Header({ onMenuToggle }) {
  const { pathname } = useLocation();
  const { locale, locales, setLocale, t, formatDate } = useI18n();
  const pageKey = PAGE_KEYS[pathname];
  const page = pageKey
    ? { title: t(`page.${pageKey}.title`), subtitle: t(`page.${pageKey}.subtitle`) }
    : { title: 'OpenShield', subtitle: '' };

  const [showConnErr, setConnErr]   = useState(false);
  const [scanning, setScanning]     = useState(false);
  const [elapsed, setElapsed]       = useState(0);
  const [scanToast, setScanToast]   = useState(null);
  const [showScanInput, setShowScanInput] = useState(false);
  const [lastScanAt, setLastScanAt] = useState(null);
  const [isLive, setIsLive]         = useState(false);
  const scanBtnRef = useRef(null);

  useEffect(() => {
    // Probe the backend to set the live indicator accurately
    api.testConnection().then((ok) => setIsLive(ok));
  }, []);

  useEffect(() => {
    if (!isLive) return;
    api.getScans().then((data) => {
      const latest = data?.scans?.[0];
      const raw = latest?.started_at || latest?.startedAt;
      if (raw) {
        setLastScanAt(formatDate(raw, {
          month: 'short', day: 'numeric', year: 'numeric',
          hour: 'numeric', minute: '2-digit',
        }));
      }
    }).catch(() => {});
  }, [formatDate, isLive]);

  const closeConnErr = () => setConnErr(false);

  const handleScanClick = () => setShowScanInput(true);

  // ── Execute scan (after optional subscription ID is provided) ─────────────
  const executeScan = async (subscriptionId) => {
    setShowScanInput(false);
    setScanning(true);
    setElapsed(0);
    setScanToast(null);

    const ticker = setInterval(() => setElapsed((s) => s + 1), 1000);

    try {
      const trigger = await api.triggerScan(subscriptionId);

      if (trigger.status === 'completed' || trigger.status === 'failed') {
        setScanToast(trigger.status === 'completed' ? { result: trigger } : { error: 'Scan failed on the backend.' });
        return;
      }

      // Poll until done (max 5 min, every 4s). Individual transport failures
      // are transient; only a backend terminal status ends the scan.
      const scanId = trigger.scan_id;
      const scan = await pollScan({ scanId, getScan: api.getScan });
      if (scan?.status === 'completed') { setScanToast({ result: scan }); return; }
      if (scan?.status === 'failed')    { setScanToast({ error: `Scan ${scanId} failed.` }); return; }
      setScanToast({ error: 'Scan timed out after 5 minutes. Check backend logs.' });
    } catch (err) {
      setScanToast({ error: err?.message || 'Scan failed. Is the backend running?' });
    } finally {
      clearInterval(ticker);
      setScanning(false);
      setElapsed(0);
    }
  };

  return (
    <>
      <header className="h-14 md:h-16 flex items-center justify-between px-4 md:px-6 bg-bg-primary dark:bg-bg-dark-secondary border-b border-border-light dark:border-border-dark flex-shrink-0">

        {/* Left: hamburger + title */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={onMenuToggle}
            className="lg:hidden w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all flex-shrink-0"
            aria-label={t('menu.open')}
          >
            <FiMenu size={18} />
          </button>
          <div className="min-w-0">
            <h1 className="text-base md:text-lg font-bold text-text-primary dark:text-text-dark-primary leading-tight truncate">
              {page.title}
            </h1>
            {page.subtitle && (
              <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5 hidden sm:block truncate">
                {page.subtitle}
              </p>
            )}
          </div>
        </div>

        {/* Right: controls */}
        <div className="flex items-center gap-2 md:gap-2.5 flex-shrink-0">
          <label className="sr-only" htmlFor="locale-select">{t('language.label')}</label>
          <select
            id="locale-select"
            value={locale}
            onChange={(event) => setLocale(event.target.value)}
            className="rounded-lg border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-tertiary px-2 py-1.5 text-xs text-text-primary dark:text-text-dark-primary"
          >
            {locales.map((item) => <option key={item} value={item}>{t(`language.${item}`)}</option>)}
          </select>

          {/* Run Scan button + popover wrapper */}
          <div className="relative" ref={scanBtnRef}>
            <button
              onClick={handleScanClick}
              disabled={scanning}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-primary hover:bg-brand-secondary disabled:opacity-60 disabled:cursor-wait text-white transition-all duration-200"
              title="Trigger an Azure scan"
            >
              {scanning
                ? <FiLoader size={12} className="animate-spin" />
                : <FiZap size={12} />
              }
              <span className="hidden sm:inline">
                {scanning ? t('scan.scanning', { seconds: elapsed }) : t('scan.run')}
              </span>
            </button>

            {showScanInput && (
              <ScanInputPopover
                onConfirm={executeScan}
                onCancel={() => setShowScanInput(false)}
              />
            )}
          </div>

          {/* Last scanned — only shown when live data confirmed */}
          {lastScanAt && isLive && (
            <div className="hidden sm:flex items-center gap-1.5 text-xs text-text-tertiary dark:text-text-dark-tertiary">
              <FiClock size={13} />
              <span>{t('scan.last', { date: lastScanAt })}</span>
            </div>
          )}

          {/* Live / Reconnecting status dot */}
          <div
            role="status"
            aria-live="polite"
            title={isLive ? 'Connected to live API' : 'Reconnecting to backend…'}
            className="hidden sm:flex items-center gap-1.5 cursor-default select-none"
          >
            {isLive ? (
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
              </span>
            ) : (
              <span className="h-2 w-2 rounded-full bg-amber-400" />
            )}
            <span className={`text-xs font-medium ${isLive ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400'}`}>
              {isLive ? t('status.live') : t('status.reconnecting')}
            </span>
          </div>
        </div>
      </header>

      {showConnErr && <ConnectionErrorPopup apiBase={api.getApiBase()} onClose={closeConnErr} />}
      {scanToast && (
        <ScanToast
          result={scanToast.result}
          error={scanToast.error}
          onClose={() => setScanToast(null)}
        />
      )}
    </>
  );
}
