'use client';
import { useState, useEffect, useCallback } from 'react';
import { FileCheck, RefreshCw, Shield, Download, Trash2, Globe2, Clock, Key } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function DataControlsView({ token }: { token: string }) {
  const [config, setConfig] = useState<any>(null);
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [cRes, aRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/compliance/config`, { headers }),
        fetch(`${API}/api/v1/platform/compliance/audit?limit=30`, { headers }),
      ]);
      if (cRes.ok) setConfig(await cRes.json());
      if (aRes.ok) { const d = await aRes.json(); setAuditLog(d.entries || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const updateConfig = async (updates: any) => {
    await fetch(`${API}/api/v1/platform/compliance/config`, { method: 'PUT', headers, body: JSON.stringify(updates) });
    fetchData();
  };

  const exportData = async () => {
    const res = await fetch(`${API}/api/v1/platform/compliance/export?format=json`, { method: 'POST', headers });
    if (res.ok) { const data = await res.json(); const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'ghostprompt-data-export.json'; a.click(); }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><FileCheck className="w-6 h-6 text-cyan-400" /> Compliance & Data Controls</h2>
          <p className="text-sm text-gray-400 mt-1">Data residency, retention, GDPR compliance, BAA, and BYOK encryption</p>
        </div>
        <div className="flex gap-2">
          <button onClick={exportData} className="px-4 py-2 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-xs font-bold flex items-center gap-2 hover:bg-green-500/30 transition"><Download className="w-3 h-3" /> Export Data</button>
          <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition"><RefreshCw className="w-3 h-3" /></button>
        </div>
      </div>

      {config && (
        <div className="grid grid-cols-3 gap-4">
          {/* Data Region */}
          <div className="glass-card p-4">
            <div className="flex items-center gap-2 mb-3"><Globe2 className="w-4 h-4 text-cyan-400" /><p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Data Region</p></div>
            <div className="flex gap-2">{['global', 'us', 'eu', 'apac'].map(r => (
              <button key={r} onClick={() => updateConfig({ data_region: r })} className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase ${config.data_region === r ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' : 'bg-white/5 text-gray-400 border border-white/10'}`}>{r}</button>
            ))}</div>
          </div>
          {/* Retention */}
          <div className="glass-card p-4">
            <div className="flex items-center gap-2 mb-3"><Clock className="w-4 h-4 text-amber-400" /><p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Log Retention</p></div>
            <div className="flex gap-2">{[30, 90, 365].map(d => (
              <button key={d} onClick={() => updateConfig({ log_retention_days: d })} className={`px-3 py-1.5 rounded-lg text-xs font-bold ${config.log_retention_days === d ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' : 'bg-white/5 text-gray-400 border border-white/10'}`}>{d}d</button>
            ))}</div>
          </div>
          {/* Toggles */}
          <div className="glass-card p-4 space-y-3">
            {[
              { key: 'baa_enabled', label: 'BAA (HIPAA)', color: 'red' },
              { key: 'gdpr_enabled', label: 'GDPR Mode', color: 'blue' },
              { key: 'byok_enabled', label: 'BYOK Encryption', color: 'purple' },
            ].map(toggle => (
              <div key={toggle.key} className="flex items-center justify-between">
                <span className="text-xs text-gray-300">{toggle.label}</span>
                <button onClick={() => updateConfig({ [toggle.key]: !config[toggle.key] })} className={`w-10 h-5 rounded-full transition-all relative ${config[toggle.key] ? `bg-${toggle.color}-500/40` : 'bg-white/10'}`}>
                  <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${config[toggle.key] ? 'left-5 bg-white' : 'left-0.5 bg-gray-500'}`} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Audit Log */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Shield className="w-4 h-4 text-green-400" /> Immutable Audit Log (HMAC-Signed)</h3>
        {auditLog.length === 0 ? (
          <p className="text-xs text-gray-500">No audit entries yet. Actions are logged as compliance settings change.</p>
        ) : (
          <div className="space-y-2">{auditLog.map((e: any, i: number) => (
            <div key={i} className="flex items-center gap-3 text-xs p-2 rounded bg-white/[0.02]">
              <span className="w-2 h-2 rounded-full bg-green-400" />
              <span className="text-white font-mono w-32 truncate">{e.action}</span>
              <span className="text-gray-400">{e.resource_type}</span>
              <span className="text-gray-500">{e.actor_email || e.actor_id}</span>
              <span className="text-gray-600 ml-auto font-mono text-[10px]">{e.hmac_signature}</span>
            </div>
          ))}</div>
        )}
      </div>
    </div>
  );
}
