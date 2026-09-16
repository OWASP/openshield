import { useCallback } from 'react';
import { api } from '../utils/api';
import ScoreGauge from '../components/monitoring/ScoreGauge';
import TrendChart from '../components/monitoring/TrendChart';
import StatCards from '../components/monitoring/StatCards';
import FindingsDistribution from '../components/monitoring/FindingsDistribution';
import ResourceGroupChart from '../components/monitoring/ResourceGroupChart';
import Card from '../components/shared/Card';
import Loader, { CardLoader } from '../components/shared/Loader';
import ErrorState from '../components/shared/ErrorState';
import usePageData from '../hooks/usePageData';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import {
  buildCategoryScores,
  buildFindingsDistribution,
  buildResourceGroupGroups,
  buildTrend,
  countBySeverity,
} from '../utils/monitoring';

export default function Monitoring() {
  const loadMonitoring = useCallback(async () => {
    const [scoreData, findings, scansData] = await Promise.all([
      api.getScore(),
      api.getFindings(),
      api.getScans(),
    ]);
    const scans  = scansData.scans || [];
    const counts = countBySeverity(findings);

    return {
      score:    scoreData.score    ?? scoreData,
      maxScore: scoreData.max_score ?? 100,
      stats: {
        totalFindings:  findings.length,
        criticalIssues: counts.CRITICAL,
        highRisk:       counts.HIGH,
        mediumRisk:     counts.MEDIUM,
        lowPriority:    counts.LOW,
      },
      findingsDistribution:    buildFindingsDistribution(counts),
      categoryScores:          buildCategoryScores(findings),
      trend:                   buildTrend(scans),
      findingsByResourceGroup: buildResourceGroupGroups(findings),
    };
  }, []);
  const { status, data, retry } = usePageData(loadMonitoring);

  if (status === 'error') return (
    <ErrorState
      title="Could not load monitoring data"
      description="The backend may still be starting. Wait a moment and try again."
      onRetry={retry}
    />
  );

  if (status === 'loading') return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {[...Array(5)].map((_, i) => <CardLoader key={i} />)}
      </div>
      <Loader rows={6} />
    </div>
  );

  const categoryColors = ['#10b981', '#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#f97316', '#06b6d4'];

  return (
    <div className="space-y-6">
      <StatCards stats={data.stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="flex items-center justify-center">
          <ScoreGauge score={data.score} maxScore={data.maxScore} />
        </Card>

        <Card className="lg:col-span-2">
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">
            Score Trend
          </h2>
          {data.trend.length > 1
            ? <TrendChart trend={data.trend} />
            : <p className="text-sm text-text-tertiary dark:text-text-dark-tertiary py-8 text-center">
                Trend available after multiple scans.
              </p>
          }
        </Card>
      </div>

      {data.categoryScores.length > 0 && (
        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">
            Security Score by Category
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data.categoryScores} margin={{ top: 0, right: 0, bottom: 0, left: -10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
              <XAxis dataKey="category" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip
                contentStyle={{ background: 'rgba(255,255,255,0.95)', border: '1px solid #e5e7eb', borderRadius: 12, fontSize: 12 }}
                formatter={(v) => [`${v}%`, 'Score']}
              />
              <Bar dataKey="score" radius={[4, 4, 0, 0]} animationDuration={800}>
                {data.categoryScores.map((_, i) => <Cell key={i} fill={categoryColors[i % categoryColors.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">Findings Distribution</h2>
          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mb-2">Breakdown by severity across all resources</p>
          <FindingsDistribution data={data.findingsDistribution} />
        </Card>

        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">Issues by Resource Group</h2>
          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mb-4">Count and severity of findings per resource group</p>
          <ResourceGroupChart data={data.findingsByResourceGroup} />
        </Card>
      </div>
    </div>
  );
}
