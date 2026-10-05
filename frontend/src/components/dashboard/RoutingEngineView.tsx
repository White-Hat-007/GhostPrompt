'use client';
import { useState, useEffect, useCallback } from 'react';
import { Route, Zap, Shield, AlertTriangle, Activity, RefreshCw, GitBranch, Server } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function RoutingEngineView({ token }: { token: string }) {
  const [config, setConfig] = useState<any>(null);
  const [health, setHealth] = useState<any[]>([]);
  const [pricing, setPricing] = useState<any>({});
  const [loading, setLoading] = useState(true);

  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [cfgRes, healthRes, priceRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/routing/config`, { headers }),
        fetch(`${API}/api/v1/platform/routing/health`, { headers }),
        fetch(`${API}/api/v1/platform/routing/pricing`, { headers }),
      ]);
      if (cfgRes.ok) setConfig(await cfgRes.json());
      if (healthRes.ok) { const d = await healthRes.json(); setHealth(d.providers || []); }
      if (priceRes.ok) { const d = await priceRes.json(); setPricing(d.pricing || {}); }
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const strategies = ['semantic', 'cost', 'latency', 'round_robin', 'weighted'];

  const updateStrategy = async (strategy: string) => {
    await fetch(`${API}/api/v1/platform/routing/config`, { method: 'PUT', headers, body: JSON.stringify({ strategy }) });
    fetchData();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3">
            <Route className="w-6 h-6 text-cyan-400" /> Intelligent Routing Engine
          </h2>
          <p className="text-sm text-gray-400 mt-1">Semantic, cost-based, latency-based routing with automatic failover</p>
        </div>
        <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition flex items-center gap-2"><RefreshCw className="w-3 h-3" /> Refresh</button>
      </div>

      {/* Strategy Selector */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3">Active Routing Strategy</h3>
        <div className="flex gap-2 flex-wrap">
          {strategies.map(s => (
            <button key={s} onClick={() => updateStrategy(s)} className={`px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all ${config?.strategy === s ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-[0_0_12px_rgba(0,212,255,0.15)]' : 'bg-white/5 text-gray-400 border border-white/10 hover:border-white/20'}`}>
              {s.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Budget & Failover */}
      {config && (
        <div className="grid grid-cols-3 gap-4">
          <div className="glass-card p-4">
            <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Monthly Budget</p>
            <p className="text-2xl font-bold text-white mt-1">₹{config.monthly_budget_usd?.toLocaleString()}</p>
            <div className="mt-2 h-1.5 bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 to-green-500 rounded-full" style={{ width: `${Math.min(100, 100 - (config.budget_remaining_pct || 100))}%` }} />
            </div>
          </div>
          <div className="glass-card p-4">
            <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Current Spend</p>
            <p className="text-2xl font-bold text-green-400 mt-1">₹{config.current_spend_usd?.toFixed(4)}</p>
          </div>
          <div className="glass-card p-4">
            <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Failover Chain</p>
            <div className="flex gap-1 mt-2 flex-wrap">{(config.failover_chain || []).map((p: string, i: number) => (
              <span key={p} className="text-[10px] px-2 py-1 rounded bg-white/5 text-gray-300 font-mono">{i > 0 && '→ '}{p}</span>
            ))}</div>
          </div>
        </div>
      )}

      {/* Model Pricing Table */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3">Model Pricing (per 1M tokens)</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead><tr className="text-gray-500 border-b border-white/5">
              <th className="text-left py-2 px-3 font-semibold">Model</th>
              <th className="text-right py-2 px-3 font-semibold">Input</th>
              <th className="text-right py-2 px-3 font-semibold">Output</th>
            </tr></thead>
            <tbody>{Object.entries(pricing).map(([model, prices]: [string, any]) => (
              <tr key={model} className="border-b border-white/5 hover:bg-white/[0.02]">
                <td className="py-2 px-3 text-white font-mono">{model}</td>
                <td className="py-2 px-3 text-right text-green-400">₹{prices.input}</td>
                <td className="py-2 px-3 text-right text-amber-400">₹{prices.output}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>

      {/* Provider Health */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Activity className="w-4 h-4 text-green-400" /> Provider Health</h3>
        {health.length === 0 ? (
          <p className="text-xs text-gray-500">No provider metrics yet. Health data populates as requests flow through the routing engine.</p>
        ) : (
          <div className="grid grid-cols-2 gap-3">{health.map((h: any, i: number) => (
            <div key={i} className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <div className="flex justify-between items-center">
                <span className="text-xs font-mono text-white">{h.model}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${h.circuit_state === 'closed' ? 'bg-green-500/15 text-green-400' : h.circuit_state === 'open' ? 'bg-red-500/15 text-red-400' : 'bg-amber-500/15 text-amber-400'}`}>{h.circuit_state}</span>
              </div>
              <div className="flex gap-4 mt-2 text-[10px] text-gray-400">
                <span>P95: {h.latency_p95_ms}ms</span>
                <span>Err: {(h.error_rate * 100).toFixed(1)}%</span>
                <span>Conn: {h.active_connections}</span>
              </div>
            </div>
          ))}</div>
        )}
      </div>
    </div>
  );
}
