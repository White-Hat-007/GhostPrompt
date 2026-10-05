'use client';

import { motion } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface ThreatChartProps {
  data: Array<{
    hour: string;
    scans: number;
    blocked: number;
    flagged: number;
  }>;
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload) return null;
  return (
    <div className="glass-card p-3.5 border border-white/10 shadow-2xl backdrop-blur-xl" style={{ background: 'rgba(8, 12, 24, 0.95)' }}>
      <p className="text-[10px] font-mono font-bold text-ghost-400 mb-2 uppercase tracking-wider">{label}</p>
      {payload.map((entry: any, i: number) => (
        <div key={i} className="flex items-center gap-2.5 text-xs py-0.5">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color, boxShadow: `0 0 6px ${entry.color}40` }} />
          <span className="text-gray-500 capitalize font-mono">{entry.name}:</span>
          <span className="text-white font-bold font-mono tabular-nums">{entry.value.toLocaleString('en-US')}</span>
        </div>
      ))}
    </div>
  );
};

export default function ThreatChart({ data }: ThreatChartProps) {
  return (
    <motion.div
      className="glass-card p-6 relative overflow-hidden"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
    >
      {/* Subtle gradient accent line at top */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-ghost-500/20 to-transparent" />

      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-sm font-semibold text-white">AI Traffic & Threats</h3>
          <p className="text-xs text-gray-500 mt-0.5 font-mono">Last 24 hours — scan volume and blocked attacks</p>
        </div>
        <div className="flex items-center gap-4">
          {[
            { color: '#3b82f6', label: 'Scans', glow: 'rgba(59,130,246,0.3)' },
            { color: '#ef4444', label: 'Blocked', glow: 'rgba(239,68,68,0.3)' },
            { color: '#f59e0b', label: 'Flagged', glow: 'rgba(245,158,11,0.3)' },
          ].map((item, i) => (
            <div key={i} className="flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: item.color, boxShadow: `0 0 6px ${item.glow}` }}
              />
              <span className="text-[10px] text-gray-500">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="flaggedGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.25} />
                <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
              </linearGradient>
              {/* Glow filters */}
              <filter id="scanGlow">
                <feGaussianBlur stdDeviation="2" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
            <XAxis
              dataKey="hour"
              tick={{ fontSize: 10, fill: '#4b5563', fontFamily: 'JetBrains Mono, monospace' }}
              axisLine={{ stroke: 'rgba(255,255,255,0.04)' }}
              tickLine={false}
              interval={2}
            />
            <YAxis
              tick={{ fontSize: 10, fill: '#4b5563', fontFamily: 'JetBrains Mono, monospace' }}
              axisLine={false}
              tickLine={false}
              width={45}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(59, 130, 246, 0.15)', strokeWidth: 1 }} />
            <Area
              type="monotone"
              dataKey="scans"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#scanGradient)"
              name="scans"
              dot={false}
              activeDot={{ r: 4, stroke: '#3b82f6', strokeWidth: 2, fill: '#0a1020' }}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke="#ef4444"
              strokeWidth={2}
              fill="url(#blockedGradient)"
              name="blocked"
              dot={false}
              activeDot={{ r: 4, stroke: '#ef4444', strokeWidth: 2, fill: '#0a1020' }}
            />
            <Area
              type="monotone"
              dataKey="flagged"
              stroke="#f59e0b"
              strokeWidth={1.5}
              fill="url(#flaggedGradient)"
              name="flagged"
              dot={false}
              activeDot={{ r: 3, stroke: '#f59e0b', strokeWidth: 2, fill: '#0a1020' }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}
