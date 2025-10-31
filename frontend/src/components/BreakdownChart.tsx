import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ScoreBreakdownItem } from '../types';

interface BreakdownChartProps {
  breakdown: ScoreBreakdownItem[];
}

export const BreakdownChart = ({ breakdown }: BreakdownChartProps) => {
  const data = breakdown.map((item) => ({
    check: item.check,
    impact: item.passed ? 0 : item.impact,
    status: item.passed ? 'Passed' : 'Failed',
  }));

  return (
    <div className="card">
      <div className="section-heading">
        <h2>Score Breakdown</h2>
        <span className="badge">Lower impact is better</span>
      </div>
      <div className="breakdown-chart">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 16, right: 16, bottom: 16, left: 120 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis type="number" domain={[0, 'dataMax']} tick={{ fill: '#475569' }} />
            <YAxis dataKey="check" type="category" width={120} tick={{ fill: '#475569' }} />
            <Tooltip formatter={(value: number) => [`-${value} pts`, 'Impact']} labelStyle={{ fontWeight: 600 }} />
            <Bar dataKey="impact" fill="#f87171" radius={[6, 6, 6, 6]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
