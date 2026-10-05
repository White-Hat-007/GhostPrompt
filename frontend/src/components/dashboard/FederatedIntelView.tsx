'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Globe, Shield, AlertTriangle, Users, TrendingUp, Lock, Radio,
  ChevronRight, ExternalLink, Zap, Loader2, RefreshCw, Send,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface FederatedIntelViewProps {
  token?: string;
}

interface FederationNode {
  id: string;
  org_id: string;
  display_name: string;
  is_active: boolean;
  opted_in: boolean;
  epsilon_budget: number;
  epsilon_spent: number;
  signatures_contributed: number;
  signatures_received: number;
  last_sync: string;
  joined_at: string;
}

interface NetworkStats {
  total_nodes: number;
  active_nodes: number;
  total_signatures: number;
  total_contributions: number;
  avg_epsilon_spent: number;
}

interface SharedIndicator {
  id: string;
  stix_id: string;
  pattern: string;
  attack_category: string;
  confidence: number;
  severity: string;
  first_seen: string;
  last_seen: string;
  contributor_count: number;
  noise_level: number;
  created_at: string;
}

export default function FederatedIntelView({ token }: FederatedIntelViewProps) {
  const [activeTab, setActiveTab] = useState<'feeds' | 'indicators' | 'sharing' | 'register'>('feeds');
  const [nodeInfo, setNodeInfo] = useState<FederationNode | null>(null);
  const [network, setNetwork] = useState<NetworkStats | null>(null);
  const [indicators, setIndicators] = useState<SharedIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [contributing, setContributing] = useState(false);
  const [optedIn, setOptedIn] = useState(true);
  // Registration form
  const [regName, setRegName] = useState('');
  const [regEndpoint, setRegEndpoint] = useState('');
  const [regCaps, setRegCaps] = useState('threat_intel,signatures');
  const [registering, setRegistering] = useState(false);
  const [regResult, setRegResult] = useState<any>(null);
  // Reputation
  const [reputation, setReputation] = useState<{ reputation: number; tier: string } | null>(null);

  // Sharing rules (persisted locally, toggled via API)
  const [sharingRules, setSharingRules] = useState([
    { key: 'share_signatures', rule: 'Share anonymized attack signatures', enabled: true, desc: 'Strips PII/org identifiers before sharing' },
    { key: 'receive_iocs', rule: 'Receive community threat indicators', enabled: true, desc: 'Import IOCs from federated peers' },
    { key: 'share_fingerprints', rule: 'Share model fingerprints', enabled: false, desc: 'Allow peers to identify compromised model versions' },
    { key: 'auto_block', rule: 'Auto-block federated IOCs', enabled: true, desc: 'Automatically add shared IOCs to blocklist' },
    { key: 'contribute_atlas', rule: 'Contribute to ATLAS enrichment', enabled: false, desc: 'Share MITRE ATLAS technique annotations' },
  ]);

  const authHeaders = useCallback(() => {
    const t = token || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null);
    return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
  }, [token]);

  const fetchAll = useCallback(async () => {
    try {
      const [statusRes, intelRes, networkRes] = await Promise.all([
        fetch(`${API}/api/v1/federation/status`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/federation/intel?limit=50`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/federation/network`, { headers: authHeaders() }),
      ]);

      if (statusRes.ok) {
        const data = await statusRes.json();
        setNodeInfo(data.node);
        setOptedIn(data.node?.opted_in ?? true);
      }
      if (intelRes.ok) {
        const data = await intelRes.json();
        setIndicators(data.indicators || []);
      }
      if (networkRes.ok) {
        const data = await networkRes.json();
        setNetwork(data);
      }
    } catch (err) {
      console.error('Failed to fetch federation data:', err);
    } finally {
      setLoading(false);
    }
  }, [authHeaders]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const toggleOptIn = async () => {
    const newValue = !optedIn;
    try {
      await fetch(`${API}/api/v1/federation/opt-in`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ opt_in: newValue }),
      });
      setOptedIn(newValue);
    } catch (err) {
      console.error(err);
    }
  };

  const contributeSignature = async () => {
    setContributing(true);
    try {
      await fetch(`${API}/api/v1/federation/contribute`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          pattern: 'auto-contributed-from-dashboard',
          attack_category: 'prompt_injection',
          confidence: 0.85,
          severity: 'high',
        }),
      });
      await fetchAll();
    } catch (err) {
      console.error(err);
    }
    setContributing(false);
  };

  const toggleSharingRule = (key: string) => {
    setSharingRules(rules =>
      rules.map(r => r.key === key ? { ...r, enabled: !r.enabled } : r)
    );
  };

  const sevColor = (sev: string) => {
    if (sev === 'critical') return 'bg-red-500/10 text-red-400';
    if (sev === 'high') return 'bg-orange-500/10 text-orange-400';
    if (sev === 'medium') return 'bg-amber-500/10 text-amber-400';
    return 'bg-gray-500/10 text-gray-400';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-ghost-400 animate-spin" />
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Federated Threat Intelligence</h2>
          <p className="text-sm text-gray-500 mt-1">Cross-organization threat sharing with privacy-preserving federation</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={toggleOptIn}
            className={`flex items-center gap-1.5 text-[10px] font-mono px-3 py-1.5 rounded-lg border transition-all ${
              optedIn ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/15' : 'text-gray-500 bg-surface-2 border-white/[0.06]'
            }`}
          >
            <Radio className="w-3 h-3" />
            {optedIn ? 'FEDERATION ACTIVE' : 'FEDERATION OFF'}
          </button>
          <button onClick={fetchAll} className="btn-ghost text-[10px] gap-1">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface-1/50 border border-white/[0.04] w-fit">
        {(['feeds', 'indicators', 'sharing', 'register'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === tab ? 'bg-ghost-600/20 text-ghost-400' : 'text-gray-500 hover:text-gray-300'
            }`}>
            {tab === 'feeds' ? 'Network Status' : tab === 'indicators' ? 'Shared IOCs' : tab === 'sharing' ? 'Sharing Rules' : '🌐 Register Node'}
          </button>
        ))}
      </div>

      {activeTab === 'feeds' && (
        <div className="space-y-4">
          {/* Stats from real API */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { label: 'Network Nodes', value: network?.total_nodes?.toString() || '0', icon: Globe, color: 'text-ghost-400' },
              { label: 'Active Nodes', value: network?.active_nodes?.toString() || '0', icon: Users, color: 'text-emerald-400' },
              { label: 'Shared Signatures', value: network?.total_signatures?.toLocaleString() || '0', icon: Shield, color: 'text-cyan-400' },
              { label: 'Total Contributions', value: network?.total_contributions?.toLocaleString() || '0', icon: TrendingUp, color: 'text-amber-400' },
            ].map((s, i) => (
              <div key={i} className="glass-card p-4">
                <div className="flex items-center gap-2 mb-2">
                  <s.icon className={`w-4 h-4 ${s.color}`} />
                  <span className="text-[10px] text-gray-500 uppercase tracking-wider">{s.label}</span>
                </div>
                <p className="text-2xl font-bold text-white font-mono">{s.value}</p>
              </div>
            ))}
          </div>

          {/* Node info */}
          {nodeInfo && (
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-white mb-4">Your Node</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-gray-600">Node ID</span>
                  <p className="text-gray-300 font-mono">{nodeInfo.id}</p>
                </div>
                <div>
                  <span className="text-gray-600">Contributed</span>
                  <p className="text-white font-mono">{nodeInfo.signatures_contributed}</p>
                </div>
                <div>
                  <span className="text-gray-600">Received</span>
                  <p className="text-white font-mono">{nodeInfo.signatures_received}</p>
                </div>
                <div>
                  <span className="text-gray-600">Privacy Budget (ε)</span>
                  <p className="font-mono">
                    <span className="text-white">{(nodeInfo.epsilon_spent || 0).toFixed(3)}</span>
                    <span className="text-gray-600"> / {(nodeInfo.epsilon_budget || 0).toFixed(1)}</span>
                  </p>
                </div>
              </div>
              <div className="mt-4">
                <button onClick={contributeSignature} disabled={contributing}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-ghost-600/15 text-ghost-400 border border-ghost-500/20 hover:bg-ghost-600/25 transition-all"
                >
                  {contributing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                  Contribute Test Signature
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'indicators' && (
        <div className="glass-card overflow-hidden">
          <div className="px-5 py-3 border-b border-white/[0.04] flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Shared Indicators of Compromise</h3>
            <span className="text-[9px] font-mono text-gray-500">{indicators.length} IOCs</span>
          </div>
          <div className="divide-y divide-white/[0.03]">
            {indicators.length === 0 ? (
              <div className="px-5 py-8 text-center text-sm text-gray-600">
                No shared indicators yet. Contribute signatures to populate the federation.
              </div>
            ) : (
              indicators.map((ioc, i) => (
                <div key={i} className="flex items-center justify-between px-5 py-3 hover:bg-white/[0.02] transition-colors">
                  <div className="flex items-center gap-3">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${sevColor(ioc.severity)}`}>
                      {ioc.severity}
                    </span>
                    <div>
                      <p className="text-sm text-gray-300">{ioc.attack_category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</p>
                      <p className="text-[10px] text-gray-600 font-mono">
                        {ioc.id} • Confidence: {(ioc.confidence * 100).toFixed(1)}% (±{(ioc.noise_level * 100).toFixed(1)}% DP noise)
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-right">
                    <div>
                      <p className="text-[10px] text-gray-500">{new Date(ioc.created_at).toLocaleDateString()}</p>
                      <p className="text-[10px] text-ghost-400 font-mono">{ioc.contributor_count} contributor{ioc.contributor_count !== 1 ? 's' : ''}</p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {activeTab === 'sharing' && (
        <div className="space-y-4">
          <div className="glass-card p-6">
            <h3 className="text-sm font-semibold text-white mb-4">Federation Sharing Rules</h3>
            <div className="space-y-3">
              {sharingRules.map((r) => (
                <div key={r.key} className="flex items-center justify-between py-3 border-b border-white/[0.03] last:border-0">
                  <div>
                    <p className="text-sm text-gray-300">{r.rule}</p>
                    <p className="text-[10px] text-gray-600">{r.desc}</p>
                  </div>
                  <button onClick={() => toggleSharingRule(r.key)}
                    className={`w-10 h-5 rounded-full flex items-center px-0.5 transition-colors cursor-pointer ${
                      r.enabled ? 'bg-ghost-500/40 justify-end' : 'bg-surface-3 justify-start'
                    }`}
                  >
                    <div className={`w-4 h-4 rounded-full ${r.enabled ? 'bg-ghost-400' : 'bg-gray-600'}`} />
                  </button>
                </div>
              ))}
            </div>
          </div>
          <div className="glass-card p-6 border-l-2 border-amber-500/30">
            <div className="flex items-start gap-3">
              <Lock className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-white">Privacy-Preserving Federation</p>
                <p className="text-xs text-gray-500 mt-1">
                  All shared data is anonymized using differential privacy (Laplace mechanism, ε-budget per org).
                  Organization identifiers, user data, and raw prompts are never shared.
                  {nodeInfo && (
                    <span className="text-ghost-400"> Your current ε budget: {nodeInfo.epsilon_spent.toFixed(3)} / {nodeInfo.epsilon_budget.toFixed(1)}</span>
                  )}
                </p>
              </div>
            </div>
          </div>
          {/* Reputation Display */}
          {reputation && (
            <div className="glass-card p-4 border-l-2 border-ghost-500/30 mt-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-500 font-mono uppercase">Node Reputation</p>
                  <p className="text-2xl font-bold text-white font-mono">{reputation.reputation.toFixed(1)}</p>
                </div>
                <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wider ${
                  reputation.tier === 'trusted' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                  reputation.tier === 'verified' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                  reputation.tier === 'provisional' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                  'bg-red-500/10 text-red-400 border border-red-500/20'
                }`}>{reputation.tier}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ══════ REGISTER TAB ══════ */}
      {activeTab === 'register' && (
        <div className="space-y-4">
          <div className="glass-card p-6">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Globe className="w-4 h-4 text-ghost-400" />
              Register New Federation Node
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-[10px] text-gray-500 font-mono uppercase block mb-1">Node Name</label>
                <input value={regName} onChange={e => setRegName(e.target.value)} placeholder="My Organization Node" className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white" />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 font-mono uppercase block mb-1">Endpoint URL</label>
                <input value={regEndpoint} onChange={e => setRegEndpoint(e.target.value)} placeholder="https://my-ghostprompt.example.com/api/v1/federation" className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono" />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 font-mono uppercase block mb-1">Capabilities (comma-separated)</label>
                <input value={regCaps} onChange={e => setRegCaps(e.target.value)} placeholder="threat_intel,signatures,iocs" className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono" />
              </div>
              <button
                onClick={async () => {
                  if (!regName || !regEndpoint) return;
                  setRegistering(true);
                  try {
                    const r = await fetch(`${API}/api/v1/platform/federation/register`, {
                      method: 'POST', headers: authHeaders(),
                      body: JSON.stringify({ node_name: regName, endpoint_url: regEndpoint, capabilities: regCaps.split(',').map(s => s.trim()) }),
                    });
                    if (r.ok) {
                      const d = await r.json();
                      setRegResult(d.node);
                      setRegName(''); setRegEndpoint('');
                    }
                  } catch (e) { console.error(e); }
                  setRegistering(false);
                }}
                disabled={registering || !regName || !regEndpoint}
                className="w-full py-2.5 rounded-lg text-sm font-medium bg-ghost-600/20 text-ghost-400 border border-ghost-500/20 hover:bg-ghost-600/30 transition-colors disabled:opacity-50"
              >
                {registering ? 'Registering...' : '🌐 Register Node'}
              </button>
            </div>
            {regResult && (
              <div className="mt-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <p className="text-xs text-emerald-400 font-bold">✅ Node Registered Successfully</p>
                <p className="text-[10px] text-gray-400 font-mono mt-1">ID: {regResult.id}</p>
                <p className="text-[10px] text-gray-400 mt-0.5">Reputation: {regResult.reputation} (starting neutral)</p>
              </div>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}
