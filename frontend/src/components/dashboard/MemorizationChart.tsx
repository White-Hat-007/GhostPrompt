"use client";

import { Lock } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

interface ScanEvent {
  category?: string;
  detections?: Array<{ category: string; description?: string }>;
}

interface Props {
  scans?: ScanEvent[];
}

export default function MemorizationChart({ scans = [] }: Props) {
  const counts = { code: 0, trigger: 0, copyright: 0 };

  scans.forEach((s) => {
    const cats = [
      s.category?.toLowerCase() || "", 
      ...(s.detections || []).map(d => `${d.category || ""} ${d.description || ""}`.toLowerCase())
    ];
    const joined = cats.join(" ");
    if (joined.includes("memorization")) {
      if (joined.includes("code")) counts.code++;
      else if (joined.includes("trigger")) counts.trigger++;
      else if (joined.includes("copyright")) counts.copyright++;
      else counts.trigger++;
    }
  });

  const data = [
    { name: "Code Leaks", value: counts.code, color: "#ef4444" },
    { name: "Repetition Triggers", value: counts.trigger, color: "#f97316" },
    { name: "Copyright Extraction", value: counts.copyright, color: "#f59e0b" },
  ].filter(d => d.value > 0);

  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div className="glass-card p-6 h-full xl:col-span-1">
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <Lock className="w-4 h-4 text-red-400" />
          Data Memorization
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Training Data Exfiltration</p>
      </div>
      <div className="pt-2">
        {total > 0 ? (
          <div className="h-[200px] w-full relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '8px', color: '#fff' }}
                  itemStyle={{ color: '#f4f4f5' }}
                  labelStyle={{ color: '#d1d5db', fontWeight: 600 }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold text-white">{total}</span>
              <span className="text-[10px] text-gray-500 uppercase tracking-wider">Leaks</span>
            </div>
          </div>
        ) : (
          <div className="h-[200px] flex items-center justify-center">
            <p className="text-xs text-gray-500">No memorization leaks detected</p>
          </div>
        )}
      </div>
    </div>
  );
}
