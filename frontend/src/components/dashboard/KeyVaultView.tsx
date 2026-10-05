'use client';
import { useState, useEffect, useCallback } from 'react';
import { KeyRound, Plus, RefreshCw, Trash2, RotateCw, Shield } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function KeyVaultView({ token }: { token: string }) {
  const [keys, setKeys] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ provider: 'openai', real_api_key: '', name: '', scope: 'write', monthly_cap: 0 });
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchKeys = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/platform/vault/keys`, { headers });
      if (res.ok) { const d = await res.json(); setKeys(d.keys || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchKeys(); }, [fetchKeys]);

  const createKey = async () => {
    await fetch(`${API}/api/v1/platform/vault/keys`, { method: 'POST', headers, body: JSON.stringify(form) });
    setShowCreate(false); setForm({ provider: 'openai', real_api_key: '', name: '', scope: 'write', monthly_cap: 0 }); fetchKeys();
  };

  const revokeKey = async (vk: string) => {
    await fetch(`${API}/api/v1/platform/vault/keys/${vk}`, { method: 'DELETE', headers }); fetchKeys();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><KeyRound className="w-6 h-6 text-cyan-400" /> Virtual Key Vault</h2>
          <p className="text-sm text-gray-400 mt-1">AES-256 encrypted key management — customers never see real API keys</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-bold flex items-center gap-2 hover:bg-cyan-500/30 transition"><Plus className="w-3 h-3" /> Create Key</button>
          <button onClick={fetchKeys} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition"><RefreshCw className="w-3 h-3" /></button>
        </div>
      </div>

      {showCreate && (
        <div className="glass-card p-5 border border-cyan-500/20">
          <h3 className="text-sm font-semibold text-white mb-4">Create Virtual Key</h3>
          <div className="grid grid-cols-2 gap-4">
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Provider</label>
              <select value={form.provider} onChange={e => setForm({...form, provider: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                {['openai','anthropic','google','mistral','cohere','groq','deepseek','together','perplexity','xai'].map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Name</label>
              <input value={form.name} onChange={e => setForm({...form, name: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" placeholder="Production Key" />
            </div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Real API Key</label>
              <input value={form.real_api_key} onChange={e => setForm({...form, real_api_key: e.target.value})} type="password" className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono" placeholder="sk-..." />
            </div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Scope</label>
              <select value={form.scope} onChange={e => setForm({...form, scope: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                <option value="read">Read Only</option><option value="write">Full Access</option><option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <button onClick={createKey} className="mt-4 px-6 py-2 bg-cyan-500 text-black rounded-lg text-xs font-bold hover:bg-cyan-400 transition">Create Virtual Key</button>
        </div>
      )}

      <div className="space-y-3">
        {keys.length === 0 ? (
          <div className="glass-card p-8 text-center"><p className="text-gray-500 text-sm">No virtual keys created yet. Create one to get started.</p></div>
        ) : keys.map((k: any, i: number) => (
          <div key={i} className="glass-card p-4 flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${k.is_active ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
              <KeyRound className={`w-5 h-5 ${k.is_active ? 'text-green-400' : 'text-red-400'}`} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-white">{k.name}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-white/5 text-gray-400 font-mono">{k.provider}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${k.scope === 'admin' ? 'bg-red-500/15 text-red-400' : k.scope === 'write' ? 'bg-cyan-500/15 text-cyan-400' : 'bg-gray-500/15 text-gray-400'}`}>{k.scope}</span>
              </div>
              <p className="text-xs text-gray-500 font-mono mt-1">{k.virtual_key?.slice(0, 20)}...</p>
            </div>
            <div className="text-right">
              <p className="text-xs text-gray-400">{k.usage?.request_count || 0} requests</p>
              <p className="text-xs text-green-400">₹{(k.usage?.cost_usd || 0).toFixed(4)}</p>
            </div>
            <button onClick={() => revokeKey(k.virtual_key)} className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition"><Trash2 className="w-4 h-4" /></button>
          </div>
        ))}
      </div>
    </div>
  );
}
