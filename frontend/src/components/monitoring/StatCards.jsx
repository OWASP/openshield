import { FiAlertCircle, FiAlertTriangle, FiInfo, FiLayers } from 'react-icons/fi';
import Card from '../shared/Card';

export default function StatCards({ stats }) {
  const cards = [
    { label: 'Total Findings', value: stats.totalFindings, Icon: FiLayers, color: 'text-status-info', bg: 'bg-blue-50 dark:bg-blue-900/20' },
    { label: 'Critical Issues', value: stats.criticalIssues, Icon: FiAlertCircle, color: 'text-severity-critical', bg: 'bg-red-100 dark:bg-red-950/40' },
    { label: 'High Risk', value: stats.highRisk, Icon: FiAlertCircle, color: 'text-severity-high', bg: 'bg-red-50 dark:bg-red-900/20' },
    { label: 'Medium Risk', value: stats.mediumRisk, Icon: FiAlertTriangle, color: 'text-severity-medium', bg: 'bg-orange-50 dark:bg-orange-900/20' },
    { label: 'Low Priority', value: stats.lowPriority, Icon: FiInfo, color: 'text-severity-low', bg: 'bg-green-50 dark:bg-green-900/20' },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
      {cards.map(({ label, value, Icon, color, bg }) => (
        <Card key={label} className="p-4 flex items-center gap-4">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${bg}`}>
            <Icon size={18} className={color} />
          </div>
          <div>
            <p className="text-2xl font-bold text-text-primary dark:text-text-dark-primary">{value}</p>
            <p className="text-xs text-text-secondary dark:text-text-dark-tertiary">{label}</p>
          </div>
        </Card>
      ))}
    </div>
  );
}
