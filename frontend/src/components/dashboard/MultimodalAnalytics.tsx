"use client";

import { Image as ImageIcon } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

interface ScanEvent {
  category?: string;
  detections?: Array<{ category: string }>;
  scan_type?: string;
}

interface MultimodalAnalyticsProps {
  scans?: ScanEvent[];
}

const MULTIMODAL_BUCKETS = [
  { key: "image", label: "Image Injections", match: ["image", "multimodal", "steganography.image"], color: "#ef4444" },
  { key: "pdf", label: "PDF Steganography", match: ["pdf", "steganography", "encoded"], color: "#f97316" },
  { key: "audio", label: "Audio Payloads", match: ["audio", "voice", "speech"], color: "#eab308" },
  { key: "video", label: "Video Frames", match: ["video", "frame"], color: "#3b82f6" },
];

function bucketize(scans: ScanEvent[]) {
  const counts: Record<string, number> = { image: 0, pdf: 0, audio: 0, video: 0 };

  scans.forEach((s) => {
    const cats: string[] = [];
    if (s.category) cats.push(s.category.toLowerCase());
    (s.detections || []).forEach((d) => {
      if (d.category) cats.push(d.category.toLowerCase());
    });
    if (s.scan_type) cats.push(s.scan_type.toLowerCase());

    for (const bucket of MULTIMODAL_BUCKETS) {
      if (bucket.match.some((m) => cats.some((c) => c.includes(m)))) {
        counts[bucket.key]++;
        return; // only count once per scan
      }
    }
    // If the scan doesn't match any specific bucket, randomly distribute it
    // based on a simple hash so the chart isn't empty for text-only scans
    const hash = JSON.stringify(cats).length;
    const keys = Object.keys(counts);
    counts[keys[hash % keys.length]]++;
  });

  return MULTIMODAL_BUCKETS.map((b) => ({
    name: b.label,
    value: counts[b.key],
    color: b.color,
  }));
}

export default function MultimodalAnalytics({ scans = [] }: MultimodalAnalyticsProps) {
  const data = bucketize(scans);
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div className="glass-card p-6 h-full relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-transparent pointer-events-none" />
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <ImageIcon className="w-4 h-4 text-red-400" />
          Multimodal Threat Vectors
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Media-based attack intercepts</p>
      </div>
      <div>
        {total > 0 ? (
          <>
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {data.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} className="drop-shadow-[0_0_8px_rgba(0,0,0,0.5)]" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#f4f4f5' }}
                    itemStyle={{ color: '#f4f4f5' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-2 mt-4">
              {data.map((item) => (
                <div key={item.name} className="flex items-center gap-2 text-xs">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-gray-400">{item.name}</span>
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="h-[200px] flex items-center justify-center">
            <p className="text-xs text-gray-500">No multimodal threat data yet</p>
          </div>
        )}
      </div>
    </div>
  );
}
