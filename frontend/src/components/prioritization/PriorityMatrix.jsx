import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine, ReferenceArea,
} from 'recharts';

import { SEVERITY_DEFINITIONS, severityColor } from '../../utils/severity';

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-bg-primary/95 dark:bg-bg-dark-tertiary/95 backdrop-blur-md border border-border-light dark:border-border-dark rounded-xl p-3 shadow-soft-lg text-xs space-y-1">
      <p className="font-semibold text-text-primary dark:text-text-dark-primary">{d.name}</p>
      <p className="text-text-secondary dark:text-text-dark-tertiary font-mono text-[10px]">{d.resource}</p>
      <div className="flex gap-3 pt-1">
        <span className="text-text-secondary dark:text-text-dark-tertiary">Risk: <strong>{d.risk}/10</strong></span>
        <span className="text-text-secondary dark:text-text-dark-tertiary">Effort: <strong>{d.effort}/10</strong></span>
      </div>
    </div>
  );
};

export default function PriorityMatrix({ items, selectedId, onSelect }) {
  const hasSelection = !!selectedId;

  return (
    <div>
      <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mb-3">
        Top-left = fix first (high risk, low effort)
        {hasSelection && <span className="ml-2 text-brand-primary font-medium">• 1 item highlighted</span>}
      </p>

      <ResponsiveContainer width="100%" height={300}>
        <ScatterChart margin={{ top: 16, right: 16, bottom: 24, left: 0 }}>

          {/* Quadrant background shading */}
          <ReferenceArea x1={0} x2={5} y1={5} y2={10} fill="#ef4444" fillOpacity={0.04}
            label={{ value: 'Fix First ↗', position: 'insideTopLeft', fill: '#ef444460', fontSize: 9, fontWeight: 600 }} />
          <ReferenceArea x1={5} x2={10} y1={5} y2={10} fill="#f97316" fillOpacity={0.03}
            label={{ value: 'Plan It', position: 'insideTopRight', fill: '#f9731660', fontSize: 9, fontWeight: 600 }} />
          <ReferenceArea x1={0} x2={5} y1={0} y2={5} fill="#10b981" fillOpacity={0.04}
            label={{ value: 'Quick Win', position: 'insideBottomLeft', fill: '#10b98160', fontSize: 9, fontWeight: 600 }} />
          <ReferenceArea x1={5} x2={10} y1={0} y2={5} fill="#6b7280" fillOpacity={0.03}
            label={{ value: 'Deprioritize', position: 'insideBottomRight', fill: '#6b728060', fontSize: 9, fontWeight: 600 }} />

          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
          <XAxis
            type="number" dataKey="effort" name="Effort" domain={[0, 10]}
            tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false}
            label={{ value: 'Effort →', position: 'insideBottomRight', fill: '#9ca3af', fontSize: 10, dy: 20 }}
          />
          <YAxis
            type="number" dataKey="risk" name="Risk" domain={[0, 10]}
            tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false}
            label={{ value: '↑ Risk', angle: -90, position: 'insideTopLeft', fill: '#9ca3af', fontSize: 10, dx: -4 }}
          />
          <Tooltip content={<CustomTooltip />} />

          <ReferenceLine x={5} stroke="#e5e7eb" strokeDasharray="4 4" strokeOpacity={0.6} />
          <ReferenceLine y={5} stroke="#e5e7eb" strokeDasharray="4 4" strokeOpacity={0.6} />

          <Scatter
            data={items}
            animationDuration={600}
            onClick={(data) => onSelect?.(data.ruleId === selectedId ? null : data.ruleId)}
            style={{ cursor: 'pointer' }}
            shape={(props) => {
              const { cx, cy, payload } = props;
              const isSelected = payload.ruleId === selectedId;
              const isDimmed = hasSelection && !isSelected;
              const color = severityColor(payload.severity);
              return (
                <g>
                  {isSelected && (
                    <circle cx={cx} cy={cy} r={16} fill={color} fillOpacity={0.15} />
                  )}
                  <circle
                    cx={cx} cy={cy}
                    r={isSelected ? 10 : isDimmed ? 5 : 8}
                    fill={color}
                    fillOpacity={isDimmed ? 0.2 : isSelected ? 1 : 0.85}
                    stroke={isSelected ? 'white' : isDimmed ? 'none' : 'white'}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                    style={{ transition: 'all 0.2s' }}
                  />
                </g>
              );
            }}
          />
        </ScatterChart>
      </ResponsiveContainer>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs text-text-secondary dark:text-text-dark-tertiary mt-2">
        {SEVERITY_DEFINITIONS.map((level) => (
          <span key={level.id} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: level.color }} />{level.id}
          </span>
        ))}
        <span className="ml-auto text-[10px] text-text-tertiary dark:text-text-dark-tertiary">
          Click a dot to select
        </span>
      </div>
    </div>
  );
}
