import { useNavigate } from 'react-router';
import { FiCheckCircle, FiXCircle, FiMinusCircle, FiArrowRight } from 'react-icons/fi';
import SeverityBadge from '../shared/SeverityBadge';

function StatusIcon({ status }) {
  if (status === 'PASS') return <FiCheckCircle size={16} className="text-brand-primary" />;
  if (status === 'FAIL') return <FiXCircle size={16} className="text-severity-high" />;
  return <FiMinusCircle size={16} className="text-text-tertiary dark:text-text-dark-tertiary" />;
}

export default function ComplianceTable({ controls }) {
  const navigate = useNavigate();

  return (
    <div className="overflow-x-auto custom-scrollbar">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-bg-secondary dark:bg-bg-dark-tertiary">
            {['Control ID', 'Name', 'Severity', 'Category', 'Status', ''].map((h) => (
              <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-text-secondary dark:text-text-dark-tertiary whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border-light dark:divide-border-dark">
          {controls.map((c) => (
            <tr key={c.id} className="group hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors duration-150">
              <td className="px-4 py-3 font-mono text-xs text-text-secondary dark:text-text-dark-tertiary whitespace-nowrap">{c.id}</td>
              <td className="px-4 py-3 text-text-primary dark:text-text-dark-secondary max-w-xs">{c.name}</td>
              <td className="px-4 py-3">
                {c.severity ? <SeverityBadge severity={c.severity} /> : <span className="text-text-tertiary">—</span>}
              </td>
              <td className="px-4 py-3 text-text-secondary dark:text-text-dark-tertiary text-xs">{c.category}</td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1.5">
                  <StatusIcon status={c.status} />
                  <span className={`text-xs font-medium ${c.status === 'PASS' ? 'text-brand-primary' : c.status === 'FAIL' ? 'text-severity-high' : 'text-text-tertiary'}`}>
                    {c.status}
                  </span>
                </div>
              </td>
              <td className="px-4 py-3">
                {c.ruleId && c.status === 'FAIL' && (
                  <button
                    onClick={() => navigate('/scan', { state: { ruleId: c.ruleId } })}
                    className="opacity-0 group-hover:opacity-100 transition-opacity inline-flex items-center gap-1 text-xs font-semibold text-brand-primary hover:text-brand-secondary whitespace-nowrap"
                    title={`View finding for ${c.ruleId}`}
                  >
                    View finding <FiArrowRight size={11} />
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
