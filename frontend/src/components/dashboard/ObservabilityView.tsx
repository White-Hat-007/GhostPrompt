'use client';
import { useState, useEffect, useCallback } from 'react';
import { Eye, RefreshCw, IndianRupee, Clock, Users, BarChart3 } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function ObservabilityView({ token }: { token: string }) {
  const [analytics, setAnalytics] = useState<any>(null);
  const [traces, setTraces] = useState<any[]>([]);
  const [period, setPeriod] = useState('day');
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [aRes, tRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/observability/analytics`, { headers }),
        fetch(`${API}/api/v1/platform/observability/traces?limit=20`, { headers }),
      ]);
      if (aRes.ok) setAnalytics(await aRes.json());
      if (tRes.ok) { const d = await tRes.json(); setTraces(d.traces || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const costData = analytics?.cost_today || {};
  const modelPerf = analytics?.model_performance || {};
  const topUsers = analytics?.top_users || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><Eye className="w-6 h-6 text-cyan-400" /> Observability Platform</h2>
          <p className="text-sm text-gray-400 mt-1">Request tracing, cost tracking, and performance analytics</p>
        </div>
        <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition flex items-center gap-2"><RefreshCw className="w-3 h-3" /> Refresh</button>
      </div>

      {/* Cost Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Cost Today', value: `₹${costData.total_cost_usd?.toFixed(4) || '0.00'}`, color: 'text-green-400', icon: IndianRupee },
          { label: 'Total Requests', value: costData.total_requests?.toLocaleString() || '0', color: 'text-cyan-400', icon: BarChart3 },
          { label: 'Input Tokens', value: (costData.total_input_tokens || 0).toLocaleString(), color: 'text-blue-400', icon: Clock },
          { label: 'Output Tokens', value: (costData.total_output_tokens || 0).toLocaleString(), color: 'text-purple-400', icon: Clock },
        ].map((card, i) => (
          <div key={i} className="glass-card p-4">
            <div className="flex items-center gap-2 mb-2"><card.icon className={`w-4 h-4 ${card.color}`} /><p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">{card.label}</p></div>
            <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* Cost by Model */}
      {costData.by_model && Object.keys(costData.by_model).length > 0 && (
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3">Cost Breakdown by Model</h3>
          <div className="space-y-2">{Object.entries(costData.by_model).map(([model, data]: [string, any]) => (
            <div key={model} className="flex items-center gap-3 text-xs p-2 rounded bg-white/[0.02]">
              <span className="font-mono text-white w-40">{model}</span>
              <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 rounded-full" style={{ width: `${Math.min(100, (data.cost_usd / Math.max(costData.total_cost_usd, 0.001)) * 100)}%` }} /></div>
              <span className="text-green-400 font-mono w-24 text-right">₹{data.cost_usd.toFixed(4)}</span>
              <span className="text-gray-400 w-20 text-right">{data.requests} req</span>
            </div>
          ))}</div>
        </div>
      )}

      {/* Model Performance */}
      {Object.keys(modelPerf).length > 0 && (
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3">Model Latency Percentiles</h3>
          <table className="w-full text-xs">
            <thead><tr className="text-gray-500 border-b border-white/5">
              <th className="text-left py-2 px-3">Model</th><th className="text-right py-2 px-3">P50</th><th className="text-right py-2 px-3">P95</th><th className="text-right py-2 px-3">P99</th><th className="text-right py-2 px-3">Requests</th><th className="text-right py-2 px-3">Errors</th>
            </tr></thead>
            <tbody>{Object.entries(modelPerf).map(([model, data]: [string, any]) => (
              <tr key={model} className="border-b border-white/5">
                <td className="py-2 px-3 text-white font-mono">{model}</td>
                <td className="py-2 px-3 text-right text-green-400">{data.p50}ms</td>
                <td className="py-2 px-3 text-right text-amber-400">{data.p95}ms</td>
                <td className="py-2 px-3 text-right text-red-400">{data.p99}ms</td>
                <td className="py-2 px-3 text-right text-gray-300">{data.count}</td>
                <td className="py-2 px-3 text-right text-red-400">{data.error_count}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}

      {/* Top Users */}
      {topUsers.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Users className="w-4 h-4 text-purple-400" /> Top Users by Token Consumption</h3>
          <div className="space-y-2">{topUsers.map((u: any, i: number) => (
            <div key={i} className="flex justify-between text-xs p-2 rounded bg-white/[0.02]">
              <span className="text-gray-300 font-mono">{u.user_id}</span>
              <span className="text-cyan-400">{u.tokens.toLocaleString()} tokens</span>
              <span className="text-green-400">₹{u.cost.toFixed(4)}</span>
            </div>
          ))}</div>
        </div>
      )}

      {/* Recent Traces */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3">Recent Traces</h3>
        {traces.length === 0 ? (
          <p className="text-xs text-gray-500">No traces recorded yet. Traces appear as requests flow through the gateway.</p>
        ) : (
          <div className="space-y-2">{traces.map((t: any, i: number) => (
            <div key={i} className="flex items-center gap-3 text-xs p-2 rounded bg-white/[0.02] hover:bg-white/[0.04] transition cursor-pointer">
              <span className="font-mono text-cyan-400 w-48 truncate">{t.trace_id}</span>
              <span className="text-gray-400">{t.spans?.length || 0} spans</span>
              <span className="text-amber-400">{t.total_duration_ms}ms</span>
              <span className="text-gray-500 ml-auto">{new Date(t.created_at * 1000).toLocaleTimeString()}</span>
            </div>
          ))}</div>
        )}
      </div>
    </div>
  );
}
