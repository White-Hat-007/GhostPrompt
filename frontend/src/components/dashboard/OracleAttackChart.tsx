"use client";

import { Activity } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

interface ScanEvent {
  created_at: string;
  category?: string;
  detections?: Array<{ category: string; description?: string }>;
  threat_score: number;
}

interface Props {
  scans?: ScanEvent[];
}

export default function OracleAttackChart({ scans = [] }: Props) {
  // We want to count occurrences of oracle attack signatures
  const counts = {
    clustering: 0,
    fishing: 0,
    velocity: 0,
  };

  scans.forEach(s => {
    const cats = [
      s.category?.toLowerCase() || "", 
      ...(s.detections || []).map(d => `${d.category || ""} ${d.description || ""}`.toLowerCase())
    ];
    const joined = cats.join(" ");
    if (joined.includes("oracle")) {
      if (joined.includes("clustering")) counts.clustering++;
      else if (joined.includes("fishing")) counts.fishing++;
      else if (joined.includes("velocity")) counts.velocity++;
      else counts.clustering++;
    }
  });

  const data = [
    { name: "Semantic Clustering", count: counts.clustering, color: "#8b5cf6" },
    { name: "Logprob Fishing", count: counts.fishing, color: "#a855f7" },
    { name: "Query Velocity", count: counts.velocity, color: "#d946ef" },
  ];

  const total = data.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="glass-card p-6 h-full group overflow-hidden xl:col-span-1">
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <Activity className="w-4 h-4 text-purple-400" />
          API Oracle Attacks
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Model Inversion & Weight Stealing</p>
      </div>
      <div className="pt-2">
        {total > 0 ? (
          <div className="h-[200px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} layout="vertical" margin={{ top: 0, right: 10, left: 10, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} width={110} />
                <Tooltip
                  cursor={{ fill: '#27272a', opacity: 0.4 }}
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '8px', color: '#fff' }}
                  itemStyle={{ color: '#f4f4f5' }}
                  labelStyle={{ color: '#d1d5db', fontWeight: 600 }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[200px] flex items-center justify-center">
            <p className="text-xs text-gray-500">No oracle attacks detected</p>
          </div>
        )}
      </div>
    </div>
  );
}
