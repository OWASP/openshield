import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

import { SEVERITY_DEFINITIONS } from '../../utils/severity';

const DISPLAY_LEVELS = SEVERITY_DEFINITIONS.filter((level) => level.score_weight > 0);

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + p.value, 0);
  return (
    <div className="bg-bg-primary/95 dark:bg-bg-dark-tertiary/95 backdrop-blur-md border border-border-light dark:border-border-dark rounded-xl p-3 shadow-soft-lg text-xs">
      <p className="font-semibold text-text-primary dark:text-text-dark-primary mb-2">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex justify-between gap-6" style={{ color: p.fill }}>
          <span>{p.name}</span>
          <span className="font-bold">{p.value}</span>
        </p>
      ))}
      <p className="border-t border-border-light dark:border-border-dark mt-1.5 pt-1.5 text-text-secondary dark:text-text-dark-tertiary flex justify-between">
        <span>Total</span><span className="font-bold text-text-primary dark:text-text-dark-primary">{total}</span>
      </p>
    </div>
  );
};

export default function ResourceGroupChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 5, right: 5, bottom: 0, left: -10 }} barCategoryGap="35%">
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
        <XAxis dataKey="group" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} />
        {DISPLAY_LEVELS.map((level, index) => (
          <Bar
            key={level.id}
            dataKey={level.id}
            name={level.label}
            stackId="a"
            fill={level.color}
            radius={index === DISPLAY_LEVELS.length - 1 ? [4, 4, 0, 0] : [0, 0, 0, 0]}
            animationDuration={800}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}
