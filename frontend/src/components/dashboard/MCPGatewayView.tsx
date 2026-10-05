'use client';
import { useState, useEffect, useCallback } from 'react';
import { Server, Plus, RefreshCw, Shield, Activity } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function MCPGatewayView({ token }: { token: string }) {
  const [servers, setServers] = useState<any[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  const [showRegister, setShowRegister] = useState(false);
  const [form, setForm] = useState({ name: '', url: '', auth_method: 'api_key' });
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [sRes, lRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/mcp/servers`, { headers }),
        fetch(`${API}/api/v1/platform/mcp/logs?limit=30`, { headers }),
      ]);
      if (sRes.ok) { const d = await sRes.json(); setServers(d.servers || []); }
      if (lRes.ok) { const d = await lRes.json(); setLogs(d.logs || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const registerServer = async () => {
    await fetch(`${API}/api/v1/platform/mcp/servers`, { method: 'POST', headers, body: JSON.stringify(form) });
    setShowRegister(false); setForm({ name: '', url: '', auth_method: 'api_key' }); fetchData();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><Server className="w-6 h-6 text-cyan-400" /> MCP Gateway</h2>
          <p className="text-sm text-gray-400 mt-1">Centralized control plane for Model Context Protocol servers</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowRegister(!showRegister)} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-bold flex items-center gap-2 hover:bg-cyan-500/30 transition"><Plus className="w-3 h-3" /> Register Server</button>
          <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition"><RefreshCw className="w-3 h-3" /></button>
        </div>
      </div>

      {showRegister && (
        <div className="glass-card p-5 border border-cyan-500/20">
          <h3 className="text-sm font-semibold text-white mb-4">Register MCP Server</h3>
          <div className="grid grid-cols-3 gap-4">
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Server Name</label>
              <input value={form.name} onChange={e => setForm({...form, name: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" placeholder="GitHub MCP" /></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">URL</label>
              <input value={form.url} onChange={e => setForm({...form, url: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono" placeholder="https://mcp.example.com" /></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Auth Method</label>
              <select value={form.auth_method} onChange={e => setForm({...form, auth_method: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                <option value="api_key">API Key</option><option value="oauth">OAuth</option><option value="none">None</option>
              </select></div>
          </div>
          <button onClick={registerServer} className="mt-4 px-6 py-2 bg-cyan-500 text-black rounded-lg text-xs font-bold hover:bg-cyan-400 transition">Register</button>
        </div>
      )}

      {/* Server List */}
      <div className="grid grid-cols-2 gap-4">
        {servers.map((s: any, i: number) => (
          <div key={i} className="glass-card p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Server className={`w-5 h-5 ${s.is_active ? 'text-green-400' : 'text-red-400'}`} />
                <h4 className="text-sm font-semibold text-white">{s.name}</h4>
              </div>
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${s.is_active ? 'bg-green-500/15 text-green-400' : 'bg-red-500/15 text-red-400'}`}>{s.is_active ? 'ACTIVE' : 'INACTIVE'}</span>
            </div>
            <p className="text-xs text-gray-500 font-mono truncate">{s.url}</p>
            <div className="flex gap-4 mt-3 text-[10px] text-gray-400">
              <span>{s.tool_count} tools</span>
              <span>{s.total_calls} calls</span>
              <span>{s.total_errors} errors</span>
              <span className="text-purple-400">{s.auth_method}</span>
            </div>
            {s.tools?.length > 0 && (
              <div className="mt-3 flex gap-1 flex-wrap">{s.tools.map((t: any, j: number) => (
                <span key={j} className="text-[10px] px-2 py-0.5 rounded bg-white/5 text-gray-300">{t.name}</span>
              ))}</div>
            )}
          </div>
        ))}
        {servers.length === 0 && <div className="col-span-2 glass-card p-8 text-center"><p className="text-gray-500 text-sm">No MCP servers registered. Register one to begin routing tool calls through GhostPrompt.</p></div>}
      </div>

      {/* Call Logs */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400" /> Real-Time Tool Call Feed</h3>
        {logs.length === 0 ? (
          <p className="text-xs text-gray-500">No tool calls yet. Tool call logs appear as MCP requests flow through the gateway.</p>
        ) : (
          <div className="space-y-2">{logs.map((l: any, i: number) => (
            <div key={i} className={`flex items-center gap-3 text-xs p-2 rounded ${l.blocked ? 'bg-red-500/5 border border-red-500/20' : 'bg-white/[0.02]'}`}>
              <span className={`w-2 h-2 rounded-full ${l.blocked ? 'bg-red-400' : 'bg-green-400'}`} />
              <span className="font-mono text-white w-32 truncate">{l.tool_name}</span>
              <span className="text-gray-400 w-24 truncate">{l.server_id?.slice(0, 12)}</span>
              <span className="text-amber-400">{l.latency_ms}ms</span>
              {l.blocked && <span className="text-red-400 ml-auto">{l.block_reason}</span>}
            </div>
          ))}</div>
        )}
      </div>
    </div>
  );
}
