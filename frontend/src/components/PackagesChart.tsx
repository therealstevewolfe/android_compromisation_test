import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

interface PackagesChartProps {
  total?: number;
  thirdParty?: number;
}

export const PackagesChart = ({ total = 0, thirdParty = 0 }: PackagesChartProps) => {
  const safeThirdParty = Math.min(thirdParty, total);
  const systemApps = Math.max(total - safeThirdParty, 0);
  const data = [
    { name: 'System', value: systemApps, fill: '#3b82f6' },
    { name: 'Third-party', value: safeThirdParty, fill: '#f97316' },
  ];

  return (
    <div className="card">
      <div className="section-heading">
        <h2>Application Mix</h2>
        <span className="badge">{total} total apps</span>
      </div>
      <ResponsiveContainer width="100%" height={280}>
        <PieChart>
          <Pie dataKey="value" data={data} innerRadius={60} outerRadius={100} paddingAngle={4}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.fill} />
            ))}
          </Pie>
          <Tooltip formatter={(value: number, name: string) => [`${value}`, name]} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};
