"use client";

import { Link as LinkIcon } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface ScanEvent {
  created_at: string;
  category?: string;
  detections?: Array<{ category: string; description?: string }>;
  threat_score: number;
}

interface Props {
  scans?: ScanEvent[];
}

export default function IndirectInjectionChart({ scans = [] }: Props) {
  // Group by 4-hour buckets
  const buckets: Record<string, { severity: number; count: number }> = {};
  const labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"];

  labels.forEach((l) => {
    buckets[l] = { severity: 0, count: 0 };
  });

  scans.forEach((s) => {
    const cats = [
      s.category?.toLowerCase() || "", 
      ...(s.detections || []).map(d => `${d.category || ""} ${d.description || ""}`.toLowerCase())
    ];
    const joined = cats.join(" ");
    const isExternal = joined.includes("external");

    const scanTime = new Date(s.created_at);
    const hour = scanTime.getUTCHours();
    const bucketIdx = Math.floor(hour / 4);
    const label = labels[bucketIdx] || labels[0];

    if (isExternal) {
      buckets[label].severity += Math.round(s.threat_score * 100);
      buckets[label].count++;
    } else {
      buckets[label].severity += Math.round(s.threat_score * 5); // Base line
      buckets[label].count++;
    }
  });

  const data = labels.map((time) => ({
    time,
    intensity: buckets[time].count > 0
      ? Math.round(buckets[time].severity / Math.max(buckets[time].count, 1))
      : 0,
  }));

  const hasData = data.some((d) => d.intensity > 0);

  return (
    <div className="glass-card p-6 h-full group overflow-hidden xl:col-span-1">
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <LinkIcon className="w-4 h-4 text-pink-400" />
          Indirect Injection
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Out-of-Band Prompt Injection</p>
      </div>
      <div className="pt-2">
        {hasData ? (
          <div className="h-[200px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorExternal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f472b6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f472b6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '8px' }}
                  itemStyle={{ color: '#f4f4f5' }}
                />
                <Area type="monotone" dataKey="intensity" stroke="#f472b6" strokeWidth={2} fillOpacity={1} fill="url(#colorExternal)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[200px] flex items-center justify-center">
            <p className="text-xs text-gray-500">No out-of-band threats detected</p>
          </div>
        )}
      </div>
    </div>
  );
}
