import { FiAlertCircle, FiRefreshCw } from 'react-icons/fi';
import Button from './Button';

export default function ErrorState({
  title = 'Unable to load this page',
  description = 'Check your connection and try again.',
  onRetry,
}) {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className="flex flex-col items-center justify-center py-16 px-6 text-center rounded-2xl border border-severity-high/30 bg-bg-primary dark:bg-bg-dark-secondary"
    >
      <div className="w-14 h-14 rounded-2xl bg-severity-high/10 flex items-center justify-center mb-4">
        <FiAlertCircle size={24} className="text-severity-high" aria-hidden="true" />
      </div>
      <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">
        {title}
      </h2>
      <p className="text-sm text-text-secondary dark:text-text-dark-tertiary max-w-md mb-5">
        {description}
      </p>
      <Button onClick={onRetry}>
        <FiRefreshCw size={14} aria-hidden="true" />
        Try again
      </Button>
    </div>
  );
}
