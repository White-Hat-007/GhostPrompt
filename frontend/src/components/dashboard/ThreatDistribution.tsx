'use client';

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

interface ThreatDistributionProps {
  data: Record<string, number>;
}

const THREAT_COLORS: Record<string, string> = {
  safe: '#10b981',
  low: '#3b82f6',
  medium: '#f59e0b',
  high: '#ef4444',
  critical: '#dc2626',
};

export default function ThreatDistribution({ data }: ThreatDistributionProps) {
  const chartData = Object.entries(data).map(([level, count]) => ({
    name: level,
    value: count,
    color: THREAT_COLORS[level] || '#6b7280',
  }));

  const total = chartData.reduce((sum, item) => sum + item.value, 0);

  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.[0]) return null;
    const item = payload[0].payload;
    const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : "0.0";
    return (
      <div className="glass-card p-3 border border-white/10 shadow-2xl">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-xl" style={{ backgroundColor: item.color }} />
          <span className="text-xs font-semibold text-white capitalize">{item.name}</span>
        </div>
        <p className="text-xs text-gray-400 mt-1">{item.value.toLocaleString('en-US')} scans ({pct}%)</p>
      </div>
    );
  };

  return (
    <div className="glass-card p-6 h-full">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-white">Threat Distribution</h3>
        <p className="text-xs text-gray-500 mt-0.5">Scan results by threat level</p>
      </div>

      <div className="h-[200px] mb-4">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={85}
              paddingAngle={3}
              dataKey="value"
              strokeWidth={0}
            >
              {chartData.map((entry, index) => (
                <Cell key={index} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Legend */}
      <div className="space-y-2">
        {chartData.map((item) => {
          const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : "0.0";
          return (
            <div key={item.name} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-xl" style={{ backgroundColor: item.color }} />
                <span className="text-xs text-gray-400 capitalize">{item.name}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500">{pct}%</span>
                <span className="text-xs font-semibold text-white w-16 text-right">{item.value.toLocaleString('en-US')}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
