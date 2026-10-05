'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Calendar, TrendingUp, TrendingDown, Download, Filter,
  Shield, AlertTriangle, BarChart3, Activity, Clock,
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

// ── Date range presets ──
const PRESETS = [
  { value: 'today', label: 'Today' },
  { value: 'yesterday', label: 'Yesterday' },
  { value: '7d', label: '7 Days' },
  { value: '30d', label: '30 Days' },
  { value: 'mtd', label: 'MTD' },
  { value: 'qtd', label: 'QTD' },
  { value: 'ytd', label: 'YTD' },
  { value: '1y', label: '1 Year' },
];

const GRANULARITY = [
  { value: 'auto', label: 'Auto' },
  { value: 'hour', label: 'Hour' },
  { value: 'day', label: 'Day' },
  { value: 'week', label: 'Week' },
  { value: 'month', label: 'Month' },
];

const SEVERITY_COLORS = {
  safe: '#10b981',
  low: '#3b82f6',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
};

interface AnalyticsData {
  summary: {
    total_scans: number;
    total_blocked: number;
    total_flagged: number;
    total_allowed: number;
    avg_threat_score: number;
    avg_latency_ms: number;
    block_rate: number;
    scans_delta?: { current: number; previous: number; delta: number; delta_pct: number };
    blocked_delta?: { current: number; previous: number; delta: number; delta_pct: number };
  };
  time_series: Array<{ timestamp: string; scans: number; blocked: number; flagged: number; allowed: number }>;
  severity_trend: Array<{ timestamp: string; safe: number; low: number; medium: number; high: number; critical: number }>;
  top_techniques: Array<{ name: string; count: number; percentage: number }>;
  top_categories: Array<{ name: string; count: number; percentage: number }>;
}

function DeltaBadge({ delta, pct }: { delta: number; pct: number }) {
  const isUp = delta >= 0;
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] font-mono font-bold px-1.5 py-0.5 rounded ${
      isUp ? 'text-red-400 bg-red-500/10' : 'text-emerald-400 bg-emerald-500/10'
    }`}>
      {isUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {isUp ? '+' : ''}{pct.toFixed(1)}%
    </span>
  );
}

export default function AnalyticsDashboard() {
  const [preset, setPreset] = useState('7d');
  const [granularity, setGranularity] = useState('auto');
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [drilldown, setDrilldown] = useState<{ category: string; events: any[] } | null>(null);
  const [drillLoading, setDrillLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(
        `${API}/api/v1/analytics?preset=${preset}&granularity=${granularity}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (res.ok) {
        setData(await res.json());
      }
    } catch (e) {
      console.error('Analytics fetch failed:', e);
    }
    setLoading(false);
  }, [preset, granularity]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleDrilldown = useCallback(async (category: string) => {
    setDrillLoading(true);
    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(
        `${API}/api/v1/analytics/drilldown?category=${encodeURIComponent(category)}&preset=${preset}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (res.ok) {
        const result = await res.json();
        setDrilldown({ category, events: result.events || [] });
      }
    } catch (e) {
      console.error('Drilldown failed:', e);
    }
    setDrillLoading(false);
  }, [preset]);

  // Format timestamp for chart labels
  const formatLabel = (ts: string) => {
    if (!ts) return '';
    const d = new Date(ts);
    if (granularity === 'hour' || preset === 'today') return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };

  const chartData = useMemo(() =>
    (data?.time_series || []).map(d => ({ ...d, label: formatLabel(d.timestamp) })),
    [data, granularity, preset]
  );

  const severityData = useMemo(() =>
    (data?.severity_trend || []).map(d => ({ ...d, label: formatLabel(d.timestamp) })),
    [data, granularity, preset]
  );

  const s = data?.summary;

  const handleExport = async (format: 'csv' | 'json') => {
    const token = localStorage.getItem('access_token');
    const res = await fetch(
      `${API}/api/v1/analytics/export?format=${format}&preset=${preset}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!res.ok) return;

    if (format === 'csv') {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `ghostprompt_analytics.csv`; a.click();
      URL.revokeObjectURL(url);
    } else {
      const json = await res.json();
      const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `ghostprompt_analytics.json`; a.click();
      URL.revokeObjectURL(url);
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* ── Header + Controls ── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-ghost-400" />
            Analytics
          </h2>
          <p className="text-xs text-gray-500 font-mono mt-1">DATEWISE THREAT INTELLIGENCE</p>
        </div>

        <div className="flex items-center gap-3">
          {/* Date presets */}
          <div className="flex bg-surface-1 rounded-lg border border-white/[0.06] p-0.5">
            {PRESETS.map(p => (
              <button
                key={p.value}
                onClick={() => setPreset(p.value)}
                className={`px-2.5 py-1.5 text-[11px] font-medium rounded-md transition-all ${
                  preset === p.value
                    ? 'bg-ghost-600/20 text-ghost-400 shadow-sm'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Granularity */}
          <select
            value={granularity}
            onChange={e => setGranularity(e.target.value)}
            className="bg-surface-1 border border-white/[0.06] rounded-lg px-3 py-1.5 text-[11px] text-gray-400 outline-none"
          >
            {GRANULARITY.map(g => (
              <option key={g.value} value={g.value}>{g.label}</option>
            ))}
          </select>

          {/* Export */}
          <div className="flex gap-1">
            <button onClick={() => handleExport('csv')} className="btn-ghost text-[11px] gap-1.5">
              <Download className="w-3 h-3" /> CSV
            </button>
            <button onClick={() => handleExport('json')} className="btn-ghost text-[11px] gap-1.5">
              <Download className="w-3 h-3" /> JSON
            </button>
            <button
              onClick={async () => {
                const token = localStorage.getItem('access_token');
                const res = await fetch(
                  `${API}/api/v1/analytics/export/pdf?preset=${preset}`,
                  { headers: { Authorization: `Bearer ${token}` } }
                );
                if (!res.ok) return;
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `ghostprompt_analytics_${preset}.pdf`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              }}
              className="btn-ghost text-[11px] gap-1.5 text-cyan-400 border-cyan-500/20 hover:border-cyan-500/40"
            >
              <Download className="w-3 h-3" /> PDF
            </button>
          </div>
        </div>
      </div>

      {/* ── Summary Cards — ELITE ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3" style={{ perspective: '1200px' }}>
        {[
          { label: 'Total Scans', value: s?.total_scans || 0, delta: s?.scans_delta, icon: Activity, color: 'text-ghost-400', accent: '#3b82f6' },
          { label: 'Blocked', value: s?.total_blocked || 0, delta: s?.blocked_delta, icon: Shield, color: 'text-red-400', accent: '#ef4444' },
          { label: 'Flagged', value: s?.total_flagged || 0, icon: AlertTriangle, color: 'text-amber-400', accent: '#f59e0b' },
          { label: 'Allowed', value: s?.total_allowed || 0, icon: Shield, color: 'text-emerald-400', accent: '#10b981' },
          { label: 'Block Rate', value: `${s?.block_rate || 0}%`, icon: Shield, color: 'text-orange-400', accent: '#f97316' },
          { label: 'Avg Latency', value: `${s?.avg_latency_ms?.toFixed(0) || 0}ms`, icon: Clock, color: 'text-cyan-400', accent: '#06b6d4' },
        ].map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 16, filter: 'blur(4px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            transition={{ delay: i * 0.06, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            whileHover={{ y: -2, transition: { duration: 0.2 } }}
            className="stat-card relative overflow-hidden group"
          >
            {/* Top accent line */}
            <div
              className="absolute top-0 left-0 right-0 h-[2px] opacity-50 group-hover:opacity-100 transition-opacity"
              style={{ background: `linear-gradient(90deg, transparent, ${card.accent}, transparent)` }}
            />
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono text-gray-600 uppercase tracking-wider">{card.label}</span>
              <card.icon className={`w-3.5 h-3.5 ${card.color} group-hover:scale-110 transition-transform`} />
            </div>
            <div className="text-xl font-bold text-white font-mono tabular-nums">
              {typeof card.value === 'number' ? card.value.toLocaleString() : card.value}
            </div>
            {card.delta && (
              <div className="mt-1.5">
                <DeltaBadge delta={card.delta.delta} pct={card.delta.delta_pct} />
                <span className="text-[9px] text-gray-700 ml-1">vs prev period</span>
              </div>
            )}
            {/* Hover glow */}
            <div
              className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
              style={{ boxShadow: `inset 0 0 0 1px ${card.accent}20, 0 0 15px ${card.accent}10` }}
            />
          </motion.div>
        ))}
      </div>

      {/* ── Main Charts Row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Scan Volume Over Time */}
        <div className="lg:col-span-2 glass-card p-4">
          <h3 className="text-sm font-bold text-white mb-3">Scan Volume</h3>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
              <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#6b7280' }} />
              <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} />
              <Tooltip
                contentStyle={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#9ca3af' }}
              />
              <Area type="monotone" dataKey="scans" stroke="#3b82f6" fill="url(#scanGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#blockedGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="flagged" stroke="#f59e0b" fill="transparent" strokeWidth={1.5} strokeDasharray="4 4" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Top Techniques */}
        <div className="glass-card p-4">
          <h3 className="text-sm font-bold text-white mb-3">Top Techniques <span className="text-[10px] text-gray-600 font-normal">(click to drill down)</span></h3>
          <div className="space-y-2">
            {(data?.top_techniques || []).slice(0, 8).map((t, i) => (
              <div key={t.name} className="flex items-center gap-2 cursor-pointer hover:bg-white/[0.02] rounded-lg px-1 py-0.5 transition-colors" onClick={() => handleDrilldown(t.name)}>
                <span className="text-[10px] font-mono text-gray-600 w-4">{i + 1}</span>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[11px] text-gray-300 truncate max-w-[140px] hover:text-ghost-400 transition-colors">{t.name}</span>
                    <span className="text-[10px] font-mono text-gray-500">{t.count}</span>
                  </div>
                  <div className="h-1 bg-surface-2 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${t.percentage}%` }}
                      transition={{ duration: 0.6, delay: i * 0.05 }}
                      className="h-full bg-gradient-to-r from-ghost-500 to-cyan-500 rounded-full"
                    />
                  </div>
                </div>
              </div>
            ))}
            {(!data?.top_techniques || data.top_techniques.length === 0) && (
              <p className="text-xs text-gray-700 text-center py-4">No data for selected period</p>
            )}
          </div>
        </div>
      </div>

      {/* ── Severity Trend ── */}
      <div className="glass-card p-4">
        <h3 className="text-sm font-bold text-white mb-3">Severity Distribution Over Time</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={severityData}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#6b7280' }} />
            <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} />
            <Tooltip
              contentStyle={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }}
            />
            <Bar dataKey="safe" stackId="a" fill={SEVERITY_COLORS.safe} radius={[0, 0, 0, 0]} />
            <Bar dataKey="low" stackId="a" fill={SEVERITY_COLORS.low} />
            <Bar dataKey="medium" stackId="a" fill={SEVERITY_COLORS.medium} />
            <Bar dataKey="high" stackId="a" fill={SEVERITY_COLORS.high} />
            <Bar dataKey="critical" stackId="a" fill={SEVERITY_COLORS.critical} radius={[2, 2, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      {/* ── Drilldown Panel ── */}
      {drilldown && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-4 border-ghost-500/20"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white">Drill-Down: <span className="text-ghost-400">{drilldown.category}</span></h3>
              <p className="text-[10px] text-gray-500">{drilldown.events.length} events found</p>
            </div>
            <button onClick={() => setDrilldown(null)} className="text-xs text-gray-500 hover:text-white px-2 py-1 rounded bg-surface-2 hover:bg-surface-1 transition-colors">Close</button>
          </div>
          {drilldown.events.length > 0 ? (
            <div className="max-h-[300px] overflow-y-auto space-y-1">
              {drilldown.events.map((e: any, i: number) => (
                <div key={e.id || i} className="flex items-center gap-3 p-2 rounded-lg bg-surface-0/50 border border-white/[0.03] hover:border-white/[0.06] transition-colors">
                  <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                    e.threat_level === 'critical' ? 'bg-red-500/10 text-red-400' :
                    e.threat_level === 'high' ? 'bg-orange-500/10 text-orange-400' :
                    e.threat_level === 'medium' ? 'bg-amber-500/10 text-amber-400' :
                    'bg-blue-500/10 text-blue-400'
                  }`}>{e.threat_level}</span>
                  <span className="text-[11px] text-gray-300 flex-1 truncate">{e.prompt_preview || e.request_id}</span>
                  <span className="text-[10px] font-mono text-gray-600">{e.action}</span>
                  <span className="text-[10px] font-mono text-gray-600">{e.threat_score?.toFixed(2)}</span>
                  <span className="text-[10px] text-gray-700">{e.timestamp ? new Date(e.timestamp).toLocaleString() : ''}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-600 text-center py-4">No events found for this category in the selected period.</p>
          )}
        </motion.div>
      )}
    </div>
  );
}
