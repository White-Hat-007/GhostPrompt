'use client';

import { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface ScanEvent {
  model: string;
  action: string;
  threat_level: string;
}

interface ModelActivityProps {
  fullView?: boolean;
  scans?: ScanEvent[];
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload) return null;
  return (
    <div className="glass-card p-3 border border-white/10 shadow-2xl">
      <p className="text-xs font-semibold text-white mb-2">{label}</p>
      {payload.map((entry: any, i: number) => (
        <div key={i} className="flex items-center gap-2 text-xs">
          <span className="w-2 h-2 rounded-xl" style={{ backgroundColor: entry.color }} />
          <span className="text-gray-400">{entry.name}:</span>
          <span className="text-white font-semibold">{entry.value.toLocaleString('en-US')}</span>
        </div>
      ))}
    </div>
  );
};

export default function ModelActivity({ fullView, scans = [] }: ModelActivityProps) {
  const modelData = useMemo(() => {
    if (scans.length === 0) {
      return [];
    }

    const byModel: Record<string, { scans: number; blocked: number; flagged: number }> = {};
    scans.forEach((s) => {
      const model = s.model || 'unknown';
      if (!byModel[model]) byModel[model] = { scans: 0, blocked: 0, flagged: 0 };
      byModel[model].scans++;
      if (s.action === 'blocked') byModel[model].blocked++;
      if (s.action === 'flagged') byModel[model].flagged++;
    });

    return Object.entries(byModel)
      .map(([model, data]) => ({
        model,
        ...data,
        safe_rate: data.scans > 0
          ? Math.round(((data.scans - data.blocked) / data.scans) * 1000) / 10
          : 100,
      }))
      .sort((a, b) => b.scans - a.scans);
  }, [scans]);

  const isEmpty = modelData.length === 0;

  return (
    <div className="glass-card p-6">
      <div className="mb-5">
        <h3 className="text-sm font-semibold text-white">Model Activity</h3>
        <p className="text-xs text-gray-500 mt-0.5">
          {isEmpty ? 'Run scans to see model activity data' : `Scan volume by AI model — ${scans.length} total scans`}
        </p>
      </div>

      {isEmpty ? (
        <div className="h-[250px] flex items-center justify-center">
          <div className="text-center">
            <div className="w-12 h-12 rounded-xl bg-surface-2 flex items-center justify-center mx-auto mb-3">
              <svg className="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <p className="text-xs text-gray-500">No scan data yet</p>
            <p className="text-[10px] text-gray-600 mt-1">Use the Live Scanner to run scans</p>
          </div>
        </div>
      ) : (
        <div className="h-[250px] mb-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={modelData} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis
                dataKey="model"
                tick={{ fontSize: 10, fill: '#6b7280' }}
                axisLine={{ stroke: 'rgba(255,255,255,0.05)' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: '#6b7280' }}
                axisLine={false}
                tickLine={false}
                width={40}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="scans" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Scans" />
              <Bar dataKey="blocked" fill="#ef4444" radius={[4, 4, 0, 0]} name="Blocked" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Model table */}
      {fullView && modelData.length > 0 && (
        <div className="mt-6 space-y-2">
          <div className="grid grid-cols-5 gap-4 px-3 py-2 text-[10px] uppercase tracking-wider text-gray-600 font-semibold">
            <span>Model</span>
            <span className="text-right">Scans</span>
            <span className="text-right">Blocked</span>
            <span className="text-right">Flagged</span>
            <span className="text-right">Safe Rate</span>
          </div>
          {modelData.map((model) => (
            <div key={model.model} className="grid grid-cols-5 gap-4 px-3 py-2.5 rounded-xl bg-surface-2/30 hover:bg-surface-2/60 transition-colors">
              <span className="text-xs font-medium text-white">{model.model}</span>
              <span className="text-xs text-gray-400 text-right">{model.scans.toLocaleString('en-US')}</span>
              <span className="text-xs text-red-400 text-right">{model.blocked}</span>
              <span className="text-xs text-amber-400 text-right">{model.flagged}</span>
              <span className="text-xs text-white text-right font-semibold">{model.safe_rate}%</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
