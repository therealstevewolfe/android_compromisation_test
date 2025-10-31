import { RadialBar, RadialBarChart, PolarAngleAxis } from 'recharts';

interface ScoreGaugeProps {
  score: number;
  breakdownCount: number;
}

export const ScoreGauge = ({ score, breakdownCount }: ScoreGaugeProps) => {
  const clampedScore = Math.max(0, Math.min(100, score));
  const data = [
    { name: 'Score', value: clampedScore, fill: clampedScore >= 80 ? '#22c55e' : clampedScore >= 50 ? '#f59e0b' : '#ef4444' },
  ];

  return (
    <div className="card score-gauge">
      <div>
        <h2>Security Score</h2>
        <p>The weighted score derived from all automated checks.</p>
        <ul>
          <li>Score is capped between 0 and 100.</li>
          <li>{breakdownCount} controls contribute to the total.</li>
        </ul>
      </div>
      <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="100%" barSize={18} data={data} startAngle={90} endAngle={-270}>
        <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
        <RadialBar minAngle={15} clockWise dataKey="value" cornerRadius={18} />
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle" style={{ fontSize: '2.5rem', fontWeight: 700 }}>
          {clampedScore}
        </text>
        <text x="50%" y="65%" textAnchor="middle" dominantBaseline="middle" style={{ fontSize: '0.95rem', fill: '#64748b' }}>
          out of 100
        </text>
      </RadialBarChart>
    </div>
  );
};
