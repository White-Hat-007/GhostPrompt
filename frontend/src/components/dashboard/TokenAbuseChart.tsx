"use client";

import { ZapOff } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface ScanEvent {
  created_at: string;
  category?: string;
  detections?: Array<{ category: string }>;
  scan_duration_ms?: number;
  threat_score: number;
}

interface TokenAbuseChartProps {
  scans?: ScanEvent[];
}

const SPONGE_MATCH = ["sponge", "dos", "token", "complexity", "compute", "budget", "repetition"];

function buildTimeSeriesFromScans(scans: ScanEvent[]) {
  // Group by 4-hour buckets over the last 24h
  const buckets: Record<string, { complexity: number; count: number }> = {};
  const now = Date.now();
  const labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"];

  labels.forEach((l) => {
    buckets[l] = { complexity: 0, count: 0 };
  });

  scans.forEach((s) => {
    const allCats: string[] = [];
    if (s.category) allCats.push(s.category.toLowerCase());
    (s.detections || []).forEach((d) => {
      if (d.category) allCats.push(d.category.toLowerCase());
    });
    const joined = allCats.join(" ");
    const isSponge = SPONGE_MATCH.some((m) => joined.includes(m));

    const scanTime = new Date(s.created_at);
    const hour = scanTime.getUTCHours();
    const bucketIdx = Math.floor(hour / 4);
    const label = labels[bucketIdx] || labels[0];

    if (isSponge) {
      buckets[label].complexity += Math.round(s.threat_score * 100);
      buckets[label].count++;
    } else {
      // Add a baseline for non-sponge scans
      buckets[label].complexity += Math.round(s.threat_score * 10);
      buckets[label].count++;
    }
  });

  return labels.map((time) => ({
    time,
    complexity: buckets[time].count > 0
      ? Math.round(buckets[time].complexity / Math.max(buckets[time].count, 1))
      : 0,
  }));
}

export default function TokenAbuseChart({ scans = [] }: TokenAbuseChartProps) {
  const data = buildTimeSeriesFromScans(scans);
  const hasData = data.some((d) => d.complexity > 0);

  return (
    <div className="glass-card p-6 h-full group overflow-hidden">
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <ZapOff className="w-4 h-4 text-yellow-400" />
          DoS & Token Complexity
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Computational abuse prevention</p>
      </div>
      <div className="pt-2">
        {hasData ? (
          <div className="h-[200px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorComplexity" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#eab308" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#eab308" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '8px', color: '#fff' }}
                  itemStyle={{ color: '#f4f4f5' }}
                  labelStyle={{ color: '#d1d5db', fontWeight: 600 }}
                />
                <Area type="monotone" dataKey="complexity" stroke="#eab308" strokeWidth={2} fillOpacity={1} fill="url(#colorComplexity)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[200px] flex items-center justify-center">
            <p className="text-xs text-gray-500">No DoS / token abuse data yet</p>
          </div>
        )}
      </div>
    </div>
  );
}
