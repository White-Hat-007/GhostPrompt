'use client';
import { useState, useEffect, useCallback } from 'react';
import { Database, RefreshCw, Trash2, Zap } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function CacheAnalyticsView({ token }: { token: string }) {
  const [analytics, setAnalytics] = useState<any>(null);
  const [cacheSize, setCacheSize] = useState<any>(null);
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [aRes, sRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/cache/analytics`, { headers }),
        fetch(`${API}/api/v1/platform/cache/size`, { headers }),
      ]);
      if (aRes.ok) setAnalytics(await aRes.json());
      if (sRes.ok) setCacheSize(await sRes.json());
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const flushCache = async () => {
    await fetch(`${API}/api/v1/platform/cache/flush`, { method: 'POST', headers });
    fetchData();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><Database className="w-6 h-6 text-cyan-400" /> Cache Analytics</h2>
          <p className="text-sm text-gray-400 mt-1">Exact + Semantic caching performance and cost savings</p>
        </div>
        <div className="flex gap-2">
          <button onClick={flushCache} className="glass-card px-3 py-2 text-xs text-red-400 hover:text-red-300 transition flex items-center gap-2"><Trash2 className="w-3 h-3" /> Flush</button>
          <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition flex items-center gap-2"><RefreshCw className="w-3 h-3" /> Refresh</button>
        </div>
      </div>

      {analytics && (
        <>
          <div className="grid grid-cols-4 gap-4">
            <div className="glass-card p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Exact Hit Rate</p>
              <p className="text-3xl font-bold text-cyan-400 mt-1">{(analytics.exact_hit_rate * 100).toFixed(1)}%</p>
              <div className="mt-2 h-1.5 bg-white/5 rounded-full overflow-hidden"><div className="h-full bg-cyan-500 rounded-full transition-all" style={{ width: `${analytics.exact_hit_rate * 100}%` }} /></div>
            </div>
            <div className="glass-card p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Semantic Hit Rate</p>
              <p className="text-3xl font-bold text-purple-400 mt-1">{(analytics.semantic_hit_rate * 100).toFixed(1)}%</p>
              <div className="mt-2 h-1.5 bg-white/5 rounded-full overflow-hidden"><div className="h-full bg-purple-500 rounded-full transition-all" style={{ width: `${analytics.semantic_hit_rate * 100}%` }} /></div>
            </div>
            <div className="glass-card p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Tokens Saved</p>
              <p className="text-3xl font-bold text-green-400 mt-1">{(analytics.total_tokens_saved || 0).toLocaleString()}</p>
            </div>
            <div className="glass-card p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Cost Saved</p>
              <p className="text-3xl font-bold text-amber-400 mt-1">₹{analytics.total_cost_saved_usd?.toFixed(4)}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Hit/Miss Breakdown</h3>
              <div className="space-y-3">
                <div className="flex justify-between text-xs"><span className="text-gray-400">Exact Hits</span><span className="text-cyan-400 font-mono">{analytics.exact_hits}</span></div>
                <div className="flex justify-between text-xs"><span className="text-gray-400">Exact Misses</span><span className="text-gray-300 font-mono">{analytics.exact_misses}</span></div>
                <div className="flex justify-between text-xs"><span className="text-gray-400">Semantic Hits</span><span className="text-purple-400 font-mono">{analytics.semantic_hits}</span></div>
                <div className="flex justify-between text-xs"><span className="text-gray-400">Semantic Misses</span><span className="text-gray-300 font-mono">{analytics.semantic_misses}</span></div>
              </div>
            </div>
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Cache Size</h3>
              {cacheSize && (
                <div className="space-y-3">
                  <div className="flex justify-between text-xs"><span className="text-gray-400">Exact Entries</span><span className="text-white font-mono">{cacheSize.exact_entries}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-gray-400">Semantic Tenants</span><span className="text-white font-mono">{cacheSize.semantic_tenants}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-gray-400">Semantic Entries</span><span className="text-white font-mono">{cacheSize.semantic_total_entries}</span></div>
                </div>
              )}
            </div>
          </div>

          {analytics.top_cached_queries?.length > 0 && (
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Top Cached Queries</h3>
              <div className="space-y-2">{analytics.top_cached_queries.map((q: any, i: number) => (
                <div key={i} className="flex justify-between items-center text-xs p-2 rounded bg-white/[0.02]">
                  <span className="text-gray-300 font-mono truncate max-w-[70%]">{q.query}</span>
                  <span className="text-cyan-400 font-bold">{q.hits} hits</span>
                </div>
              ))}</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
