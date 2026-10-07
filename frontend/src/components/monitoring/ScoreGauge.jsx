import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

function getScoreColor(score) {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  return '#ef4444';
}

function getScoreLabel(score) {
  if (score >= 80) return 'Good';
  if (score >= 60) return 'Fair';
  return 'Poor';
}

export default function ScoreGauge({ score, maxScore = 100 }) {
  // A null score (no completed scan yet) is a distinct fact from a real,
  // evaluated 0 - it must render as "no data", never as a gauge, a
  // percentage, or the "Poor" label a confirmed worst-case score would get.
  if (score === null || score === undefined) {
    return (
      <div className="flex flex-col items-center">
        <div className="relative w-48 h-48 flex items-center justify-center">
          <div className="w-[156px] h-[156px] rounded-full border-8 border-bg-secondary dark:border-bg-dark-tertiary flex flex-col items-center justify-center">
            <span className="text-2xl font-bold text-text-tertiary dark:text-text-dark-tertiary">—</span>
            <span className="text-xs text-text-secondary dark:text-text-dark-tertiary font-medium">Not assessed</span>
          </div>
        </div>
        <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary mt-2">Security Score</p>
        <p className="text-xs text-text-secondary dark:text-text-dark-tertiary">No completed scan yet</p>
      </div>
    );
  }

  const pct = Math.round((score / maxScore) * 100);
  const color = getScoreColor(pct);
  const remaining = 100 - pct;

  const data = [
    { value: pct },
    { value: remaining },
  ];

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={78}
              startAngle={90}
              endAngle={-270}
              dataKey="value"
              animationBegin={0}
              animationDuration={800}
            >
              <Cell fill={color} />
              <Cell fill="#e5e7eb" className="dark:fill-bg-dark-tertiary" />
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold" style={{ color }}>{pct}</span>
          <span className="text-xs text-text-secondary dark:text-text-dark-tertiary font-medium">{getScoreLabel(pct)}</span>
        </div>
      </div>
      <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary mt-2">Security Score</p>
      <p className="text-xs text-text-secondary dark:text-text-dark-tertiary">{score} / {maxScore} points</p>
    </div>
  );
}
