'use client';
import { useState, useEffect, useCallback } from 'react';
import { Network, RefreshCw, Shield, Ban, Globe2, AlertTriangle } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function NetworkGuardsView({ token }: { token: string }) {
  const [config, setConfig] = useState<any>(null);
  const [blocked, setBlocked] = useState<any[]>([]);
  const [ipInput, setIpInput] = useState('');
  const [listType, setListType] = useState<'allow' | 'deny'>('deny');
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [cRes, bRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/network/config`, { headers }),
        fetch(`${API}/api/v1/platform/network/blocked?limit=30`, { headers }),
      ]);
      if (cRes.ok) setConfig(await cRes.json());
      if (bRes.ok) { const d = await bRes.json(); setBlocked(d.blocked || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const updateConfig = async (updates: any) => {
    await fetch(`${API}/api/v1/platform/network/config`, { method: 'PUT', headers, body: JSON.stringify(updates) });
    fetchData();
  };

  const addIp = () => {
    if (!ipInput.trim()) return;
    const key = listType === 'allow' ? 'ip_allowlist' : 'ip_denylist';
    const current = config?.[key] || [];
    updateConfig({ [key]: [...current, ipInput.trim()] });
    setIpInput('');
  };

  const removeIp = (ip: string, type: 'allow' | 'deny') => {
    const key = type === 'allow' ? 'ip_allowlist' : 'ip_denylist';
    const current = config?.[key] || [];
    updateConfig({ [key]: current.filter((i: string) => i !== ip) });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><Network className="w-6 h-6 text-cyan-400" /> Network Guardrails</h2>
          <p className="text-sm text-gray-400 mt-1">IP controls, geo-blocking, request validation, outbound content inspection</p>
        </div>
        <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition flex items-center gap-2"><RefreshCw className="w-3 h-3" /> Refresh</button>
      </div>

      {config && (
        <>
          {/* Feature Toggles */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { key: 'block_tor', label: 'Block Tor', icon: Ban, color: 'red' },
              { key: 'profanity_filter', label: 'Profanity Filter', icon: Shield, color: 'amber' },
              { key: 'block_malicious_urls', label: 'Block Malicious URLs', icon: AlertTriangle, color: 'red' },
              { key: 'block_vpn', label: 'Block VPN', icon: Globe2, color: 'purple' },
            ].map(toggle => (
              <div key={toggle.key} className="glass-card p-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <toggle.icon className={`w-4 h-4 text-${toggle.color}-400`} />
                  <span className="text-xs text-gray-300">{toggle.label}</span>
                </div>
                <button onClick={() => updateConfig({ [toggle.key]: !config[toggle.key] })} className={`w-10 h-5 rounded-full transition-all relative ${config[toggle.key] ? 'bg-cyan-500/40' : 'bg-white/10'}`}>
                  <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${config[toggle.key] ? 'left-5 bg-white' : 'left-0.5 bg-gray-500'}`} />
                </button>
              </div>
            ))}
          </div>

          {/* IP Management */}
          <div className="grid grid-cols-2 gap-4">
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Shield className="w-4 h-4 text-green-400" /> IP Allowlist</h3>
              <div className="space-y-2">{(config.ip_allowlist || []).map((ip: string, i: number) => (
                <div key={i} className="flex justify-between items-center text-xs p-2 rounded bg-green-500/5 border border-green-500/20">
                  <span className="text-green-400 font-mono">{ip}</span>
                  <button onClick={() => removeIp(ip, 'allow')} className="text-gray-500 hover:text-red-400">✕</button>
                </div>
              ))}{(config.ip_allowlist || []).length === 0 && <p className="text-[10px] text-gray-500">No IPs allowlisted (all IPs permitted)</p>}</div>
            </div>
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /> IP Denylist</h3>
              <div className="space-y-2">{(config.ip_denylist || []).map((ip: string, i: number) => (
                <div key={i} className="flex justify-between items-center text-xs p-2 rounded bg-red-500/5 border border-red-500/20">
                  <span className="text-red-400 font-mono">{ip}</span>
                  <button onClick={() => removeIp(ip, 'deny')} className="text-gray-500 hover:text-red-400">✕</button>
                </div>
              ))}{(config.ip_denylist || []).length === 0 && <p className="text-[10px] text-gray-500">No IPs denied</p>}</div>
            </div>
          </div>

          {/* Add IP */}
          <div className="glass-card p-4 flex items-center gap-3">
            <select value={listType} onChange={e => setListType(e.target.value as any)} className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white">
              <option value="deny">Denylist</option><option value="allow">Allowlist</option>
            </select>
            <input value={ipInput} onChange={e => setIpInput(e.target.value)} className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white font-mono" placeholder="192.168.1.0/24 or single IP" />
            <button onClick={addIp} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-bold hover:bg-cyan-500/30 transition">Add</button>
          </div>

          {/* Geo Controls */}
          <div className="glass-card p-5">
            <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2"><Globe2 className="w-4 h-4 text-purple-400" /> Geo Restrictions</h3>
            <p className="text-xs text-gray-500">Country allowlist: {(config.country_allowlist || []).join(', ') || 'None (all countries allowed)'}</p>
            <p className="text-xs text-gray-500 mt-1">Country denylist: {(config.country_denylist || []).join(', ') || 'None'}</p>
            <p className="text-xs text-gray-500 mt-1">Max request size: {(config.max_request_size_bytes / 1024 / 1024).toFixed(1)} MB</p>
          </div>
        </>
      )}

      {/* Blocked Requests */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /> Blocked Requests</h3>
        {blocked.length === 0 ? (
          <p className="text-xs text-gray-500">No blocked requests. Network guardrails will log blocks here.</p>
        ) : (
          <div className="space-y-2">{blocked.map((b: any, i: number) => (
            <div key={i} className="flex items-center gap-3 text-xs p-2 rounded bg-red-500/5 border border-red-500/10">
              <Ban className="w-3 h-3 text-red-400" />
              <span className="text-red-300 font-mono">{b.ip}</span>
              <span className="text-gray-400 flex-1">{b.reason}</span>
              <span className="text-gray-600">{new Date(b.timestamp * 1000).toLocaleTimeString()}</span>
            </div>
          ))}</div>
        )}
      </div>
    </div>
  );
}
