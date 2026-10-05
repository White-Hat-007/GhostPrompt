'use client';
import { useState, useEffect, useCallback } from 'react';
import { IndianRupee, RefreshCw, TrendingUp, AlertTriangle, Plus } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function BudgetControlsView({ token }: { token: string }) {
  const [budgets, setBudgets] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ entity_id: '', entity_type: 'tenant', monthly_cap: 100, tpm_limit: 100000, rpm_limit: 60 });
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [bRes, aRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/budget/all`, { headers }),
        fetch(`${API}/api/v1/platform/budget/alerts`, { headers }),
      ]);
      if (bRes.ok) { const d = await bRes.json(); setBudgets(d.budgets || []); }
      if (aRes.ok) { const d = await aRes.json(); setAlerts(d.alerts || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const createBudget = async () => {
    await fetch(`${API}/api/v1/platform/budget`, { method: 'POST', headers, body: JSON.stringify(form) });
    setShowCreate(false); fetchData();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><IndianRupee className="w-6 h-6 text-green-400" /> Budget & Cost Controls</h2>
          <p className="text-sm text-gray-400 mt-1">Hard spend limits, token rate limiting, spend forecasting</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-xs font-bold flex items-center gap-2 hover:bg-green-500/30 transition"><Plus className="w-3 h-3" /> Set Budget</button>
          <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition"><RefreshCw className="w-3 h-3" /></button>
        </div>
      </div>

      {showCreate && (
        <div className="glass-card p-5 border border-green-500/20">
          <h3 className="text-sm font-semibold text-white mb-4">Configure Budget</h3>
          <div className="grid grid-cols-2 gap-4">
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Entity ID</label>
              <input value={form.entity_id} onChange={e => setForm({...form, entity_id: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" placeholder="org-id or user-id" /></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Entity Type</label>
              <select value={form.entity_type} onChange={e => setForm({...form, entity_type: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                <option value="tenant">Tenant</option><option value="workspace">Workspace</option><option value="user">User</option><option value="key">API Key</option>
              </select></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Monthly Cap (INR)</label>
              <input type="number" value={form.monthly_cap} onChange={e => setForm({...form, monthly_cap: +e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" /></div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">TPM Limit</label>
              <input type="number" value={form.tpm_limit} onChange={e => setForm({...form, tpm_limit: +e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" /></div>
          </div>
          <button onClick={createBudget} className="mt-4 px-6 py-2 bg-green-500 text-black rounded-lg text-xs font-bold hover:bg-green-400 transition">Set Budget</button>
        </div>
      )}

      {/* Budget Cards */}
      <div className="grid grid-cols-2 gap-4">
        {budgets.map((b: any, i: number) => {
          const utilPct = b.utilization_pct || 0;
          const barColor = utilPct > 90 ? 'from-red-500 to-red-400' : utilPct > 75 ? 'from-amber-500 to-amber-400' : 'from-green-500 to-green-400';
          return (
            <div key={i} className="glass-card p-4">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-semibold text-white">{b.entity_type}: {b.entity_id?.slice(0, 12)}</span>
                <span className={`text-xs font-bold ${utilPct > 90 ? 'text-red-400' : utilPct > 75 ? 'text-amber-400' : 'text-green-400'}`}>{utilPct.toFixed(1)}%</span>
              </div>
              <div className="h-2 bg-white/5 rounded-full overflow-hidden mb-2"><div className={`h-full bg-gradient-to-r ${barColor} rounded-full transition-all`} style={{ width: `${Math.min(100, utilPct)}%` }} /></div>
              <div className="flex justify-between text-[10px] text-gray-400">
                <span>₹{b.current_spend_usd?.toFixed(4)} / ₹{b.monthly_cap_usd}</span>
                <span>TPM: {b.tpm_limit || '∞'} | RPM: {b.rpm_limit || '∞'}</span>
              </div>
            </div>
          );
        })}
        {budgets.length === 0 && <div className="col-span-2 glass-card p-8 text-center"><p className="text-gray-500 text-sm">No budgets configured. Set spend limits per tenant, workspace, user, or API key.</p></div>}
      </div>

      {/* Alerts */}
      {alerts.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-amber-400" /> Budget Alerts</h3>
          <div className="space-y-2">{alerts.map((a: any, i: number) => (
            <div key={i} className="flex items-center gap-3 text-xs p-2 rounded bg-amber-500/5 border border-amber-500/20">
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              <span className="text-amber-300">{a.entity_type}:{a.entity_id?.slice(0, 12)} hit {a.threshold_pct}% — ₹{a.current_spend?.toFixed(4)} / ₹{a.monthly_cap}</span>
            </div>
          ))}</div>
        </div>
      )}
    </div>
  );
}
