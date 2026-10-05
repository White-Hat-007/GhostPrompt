'use client';

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface TopCategoriesProps {
  data: Array<{
    category: string;
    count: number;
    percentage: number;
  }>;
}

export default function TopCategories({ data }: TopCategoriesProps) {
  // Take top 10 and format names
  const chartData = data.slice(0, 10).map(d => ({
    name: d.category.replace('injection.', '').replace('jailbreak.', '').replace('encoded.', '').replace('oracle.', '').replace('sponge.', '').replace('intent.', '').replace('memorization.', '').replace('tokenizer.', '').replace('external.', '').replace(/_/g, ' '),
    count: d.count,
    percentage: d.percentage
  }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.[0]) return null;
    const item = payload[0].payload;
    return (
      <div className="glass-card p-3 border border-white/10 shadow-2xl">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-white capitalize">{item.name}</span>
        </div>
        <p className="text-xs text-gray-400 mt-1">{item.count.toLocaleString('en-US')} events ({item.percentage}%)</p>
      </div>
    );
  };

  return (
    <div className="glass-card p-6 h-full">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-white">Top 10 Attack Vectors</h3>
        <p className="text-xs text-gray-500 mt-0.5">Most triggered signatures</p>
      </div>

      {chartData.length > 0 ? (
        <div className="h-[250px] mb-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart layout="vertical" data={chartData} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis 
                dataKey="name" 
                type="category" 
                axisLine={false} 
                tickLine={false} 
                tick={{ fill: '#9ca3af', fontSize: 11, style: { textTransform: 'capitalize' } }} 
                width={120} 
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="h-[250px] flex items-center justify-center border border-white/5 border-dashed rounded-xl">
          <span className="text-sm text-gray-500">No attack data yet</span>
        </div>
      )}
    </div>
  );
}
