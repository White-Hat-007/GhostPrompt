'use client';
import { useState, useEffect, useCallback } from 'react';
import { Pen, Plus, RefreshCw, Check, AlertTriangle, Shield, Beaker } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function PromptStudioView({ token }: { token: string }) {
  const [prompts, setPrompts] = useState<any[]>([]);
  const [experiments, setExperiments] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [form, setForm] = useState({ name: '', content: '', description: '', template_type: 'system' });
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const fetchData = useCallback(async () => {
    try {
      const [pRes, eRes] = await Promise.all([
        fetch(`${API}/api/v1/platform/studio/prompts`, { headers }),
        fetch(`${API}/api/v1/platform/studio/experiments`, { headers }),
      ]);
      if (pRes.ok) { const d = await pRes.json(); setPrompts(d.prompts || []); }
      if (eRes.ok) { const d = await eRes.json(); setExperiments(d.experiments || []); }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const createPrompt = async () => {
    await fetch(`${API}/api/v1/platform/studio/prompts`, { method: 'POST', headers, body: JSON.stringify(form) });
    setShowCreate(false); setForm({ name: '', content: '', description: '', template_type: 'system' }); fetchData();
  };

  const viewPrompt = async (id: string) => {
    const res = await fetch(`${API}/api/v1/platform/studio/prompts/${id}`, { headers });
    if (res.ok) setSelected(await res.json());
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-3"><Pen className="w-6 h-6 text-cyan-400" /> Prompt Studio</h2>
          <p className="text-sm text-gray-400 mt-1">Version-controlled prompt registry with A/B testing and security scanning</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowCreate(!showCreate)} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-bold flex items-center gap-2 hover:bg-cyan-500/30 transition"><Plus className="w-3 h-3" /> New Prompt</button>
          <button onClick={fetchData} className="glass-card px-3 py-2 text-xs text-gray-400 hover:text-white transition"><RefreshCw className="w-3 h-3" /></button>
        </div>
      </div>

      {showCreate && (
        <div className="glass-card p-5 border border-cyan-500/20">
          <h3 className="text-sm font-semibold text-white mb-4">Create System Prompt</h3>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Name</label>
                <input value={form.name} onChange={e => setForm({...form, name: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" placeholder="Customer Support Agent" /></div>
              <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Type</label>
                <select value={form.template_type} onChange={e => setForm({...form, template_type: e.target.value})} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                  <option value="system">System Prompt</option><option value="user">User Template</option><option value="few_shot">Few-Shot</option>
                </select></div>
            </div>
            <div><label className="text-[10px] uppercase text-gray-500 font-semibold">Content (supports &#123;&#123;variables&#125;&#125;)</label>
              <textarea value={form.content} onChange={e => setForm({...form, content: e.target.value})} rows={6} className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono" placeholder="You are a helpful assistant for {{company_name}}..." /></div>
            <button onClick={createPrompt} className="px-6 py-2 bg-cyan-500 text-black rounded-lg text-xs font-bold hover:bg-cyan-400 transition">Create & Scan</button>
          </div>
        </div>
      )}

      {/* Prompt List */}
      <div className="grid grid-cols-2 gap-4">
        {prompts.map((p: any, i: number) => (
          <div key={i} className="glass-card p-4 cursor-pointer hover:border-cyan-500/30 hover:border transition-all" onClick={() => viewPrompt(p.prompt_id)}>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-semibold text-white">{p.name}</h4>
              <span className="text-[10px] px-2 py-0.5 rounded bg-white/5 text-gray-400">{p.template_type}</span>
            </div>
            <p className="text-xs text-gray-500 font-mono truncate">{p.active_content?.slice(0, 80)}...</p>
            <div className="flex gap-3 mt-3 text-[10px] text-gray-400">
              <span>v{p.active_version}</span>
              <span>{p.total_versions} versions</span>
              <span>{p.usage_count} uses</span>
              {p.variables?.length > 0 && <span className="text-purple-400">{p.variables.length} vars</span>}
              {p.security_scan?.passed === false && <span className="text-red-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Issues</span>}
              {p.security_scan?.passed === true && <span className="text-green-400 flex items-center gap-1"><Check className="w-3 h-3" /> Secure</span>}
            </div>
          </div>
        ))}
        {prompts.length === 0 && <div className="col-span-2 glass-card p-8 text-center"><p className="text-gray-500 text-sm">No prompts yet. Create your first system prompt to get started.</p></div>}
      </div>

      {/* Selected Prompt Detail */}
      {selected && (
        <div className="glass-card p-5 border border-white/10">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-white">{selected.name} — Version History</h3>
            <button onClick={() => setSelected(null)} className="text-xs text-gray-400 hover:text-white">✕ Close</button>
          </div>
          <div className="space-y-3">{(selected.versions || []).map((v: any, i: number) => (
            <div key={i} className="p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-bold text-white">Version {v.version_number}</span>
                <div className="flex gap-2">
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${v.status === 'production' ? 'bg-green-500/15 text-green-400' : v.status === 'staging' ? 'bg-amber-500/15 text-amber-400' : 'bg-gray-500/15 text-gray-400'}`}>{v.status}</span>
                  {v.security_scan?.risk_level && <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${v.security_scan.risk_level === 'safe' ? 'bg-green-500/15 text-green-400' : 'bg-red-500/15 text-red-400'}`}>{v.security_scan.risk_level}</span>}
                </div>
              </div>
              <p className="text-xs text-gray-400 font-mono whitespace-pre-wrap max-h-20 overflow-hidden">{v.content}</p>
            </div>
          ))}</div>
        </div>
      )}

      {/* A/B Experiments */}
      {experiments.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2"><Beaker className="w-4 h-4 text-purple-400" /> A/B Experiments</h3>
          {experiments.map((e: any, i: number) => (
            <div key={i} className="p-3 rounded-lg bg-white/[0.02] mb-2">
              <div className="flex justify-between text-xs"><span className="text-white font-mono">{e.experiment_id}</span><span className={e.is_active ? 'text-green-400' : 'text-gray-400'}>{e.is_active ? 'Running' : 'Completed'}</span></div>
              {e.winner && <span className="text-xs text-amber-400 font-bold mt-1">Winner: Variant {e.winner}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
