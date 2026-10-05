'use client';

import { useState, useEffect, useCallback, Fragment } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, Users, Building2, Trash2, Check, X, Activity,
  Loader2, Flag, Heart, Cpu, Database, Wifi, Shield, Zap,
  ToggleLeft, ToggleRight, Copy, Eye, ChevronRight, Server,
  Crown, UserCog, DollarSign, TrendingUp, Megaphone, Send,
  BarChart3, ChevronDown, ChevronUp,
} from 'lucide-react';
import Link from 'next/link';
import GhostLogo from '@/components/ui/GhostLogo';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

type Tab = 'overview' | 'analytics' | 'users' | 'orgs' | 'broadcasts' | 'flags' | 'health';

export default function SuperAdminDashboard() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [users, setUsers] = useState<any[]>([]);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [overview, setOverview] = useState<any>(null);
  const [flags, setFlags] = useState<Record<string, any>>({});
  const [health, setHealth] = useState<any>(null);
  const [analytics, setAnalytics] = useState<any>(null);
  const [broadcasts, setBroadcasts] = useState<any[]>([]);
  const [expandedOrg, setExpandedOrg] = useState<string|null>(null);
  const [orgDetails, setOrgDetails] = useState<any>(null);
  const [broadcastTitle, setBroadcastTitle] = useState('');
  const [broadcastMsg, setBroadcastMsg] = useState('');
  const [broadcastSeverity, setBroadcastSeverity] = useState('info');
  const [error, setError] = useState('');

  const headers = useCallback(() => {
    const token = localStorage.getItem('access_token');
    return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  }, []);

  const fetchAll = useCallback(async () => {
    try {
      const h = headers();
      const [ov, u, o, f, hc, an, bc] = await Promise.allSettled([
        fetch(`${API}/api/v1/super-admin/overview`, { headers: h }).then(r => r.ok ? r.json() : null),
        fetch(`${API}/api/v1/super-admin/users`, { headers: h }).then(r => r.ok ? r.json() : []),
        fetch(`${API}/api/v1/super-admin/organizations`, { headers: h }).then(r => r.ok ? r.json() : []),
        fetch(`${API}/api/v1/super-admin/feature-flags`, { headers: h }).then(r => r.ok ? r.json() : {}),
        fetch(`${API}/api/v1/super-admin/health-deep`, { headers: h }).then(r => r.ok ? r.json() : null),
        fetch(`${API}/api/v1/super-admin/analytics`, { headers: h }).then(r => r.ok ? r.json() : null),
        fetch(`${API}/api/v1/super-admin/broadcasts`, { headers: h }).then(r => r.ok ? r.json() : []),
      ]);
      if (ov.status === 'fulfilled') setOverview(ov.value);
      if (u.status === 'fulfilled') setUsers(u.value || []);
      if (o.status === 'fulfilled') setOrgs(o.value || []);
      if (f.status === 'fulfilled') setFlags(f.value || {});
      if (hc.status === 'fulfilled') setHealth(hc.value);
      if (an.status === 'fulfilled') setAnalytics(an.value);
      if (bc.status === 'fulfilled') setBroadcasts(bc.value || []);
    } catch (err: any) {
      setError(err.message);
    }
    setLoading(false);
  }, [headers]);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) { router.push('/auth/login'); return; }
    fetchAll();
  }, [fetchAll, router]);

  const toggleFlag = async (name: string, current: boolean) => {
    await fetch(`${API}/api/v1/super-admin/feature-flags`, {
      method: 'PUT',
      headers: headers(),
      body: JSON.stringify({ name, enabled: !current }),
    });
    setFlags(prev => ({ ...prev, [name]: { ...prev[name], enabled: !current } }));
  };

  const deleteUser = async (id: string) => {
    if (!confirm('Permanently delete this user?')) return;
    await fetch(`${API}/api/v1/superadmin/users/${id}`, { method: 'DELETE', headers: headers() });
    setUsers(prev => prev.filter(u => u.id !== id));
  };

  const deleteOrg = async (id: string) => {
    if (!confirm('WARNING: Delete this org and ALL users?')) return;
    await fetch(`${API}/api/v1/superadmin/organizations/${id}`, { method: 'DELETE', headers: headers() });
    setOrgs(prev => prev.filter(o => o.id !== id));
    fetchAll();
  };

  const impersonate = async (userId: string) => {
    const res = await fetch(`${API}/api/v1/super-admin/users/${userId}/impersonate`, {
      method: 'POST', headers: headers(),
    });
    if (res.ok) {
      const data = await res.json();
      navigator.clipboard.writeText(data.impersonation_token);
      alert(`Impersonation token copied! Target: ${data.target_email}\nExpires in ${data.expires_in_minutes} min.`);
    }
  };

  const fetchOrgDetails = async (orgId: string) => {
    if (expandedOrg === orgId) { setExpandedOrg(null); setOrgDetails(null); return; }
    setExpandedOrg(orgId);
    try {
      const res = await fetch(`${API}/api/v1/super-admin/organizations/${orgId}/details`, { headers: headers() });
      if (res.ok) setOrgDetails(await res.json());
    } catch { setOrgDetails(null); }
  };

  const sendBroadcast = async () => {
    if (!broadcastTitle || !broadcastMsg) return;
    const res = await fetch(`${API}/api/v1/super-admin/broadcasts`, {
      method: 'POST', headers: headers(),
      body: JSON.stringify({ title: broadcastTitle, message: broadcastMsg, severity: broadcastSeverity }),
    });
    if (res.ok) {
      const bc = await res.json();
      setBroadcasts(prev => [bc, ...prev]);
      setBroadcastTitle(''); setBroadcastMsg('');
    }
  };

  const deleteBroadcast = async (id: string) => {
    await fetch(`${API}/api/v1/super-admin/broadcasts/${id}`, { method: 'DELETE', headers: headers() });
    setBroadcasts(prev => prev.filter(b => b.id !== id));
  };

  const TABS: { id: Tab; label: string; icon: any }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
    { id: 'users', label: `Users (${users.length})`, icon: Users },
    { id: 'orgs', label: `Orgs (${orgs.length})`, icon: Building2 },
    { id: 'broadcasts', label: 'Broadcasts', icon: Megaphone },
    { id: 'flags', label: 'Feature Flags', icon: Flag },
    { id: 'health', label: 'Health', icon: Heart },
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center relative">
        <div className="fixed inset-0 pointer-events-none z-0" style={{ backgroundImage: 'url(/bg/hacker.jpg)', backgroundSize: 'cover', backgroundPosition: 'center' }} />
        <Loader2 className="w-8 h-8 text-red-400 animate-spin relative z-10" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white font-sans relative">
      <div 
        className="fixed inset-0 pointer-events-none z-0" 
        style={{ backgroundImage: 'url(/bg/hacker.jpg)', backgroundSize: 'cover', backgroundPosition: 'center' }}
      />
      {/* Navbar */}
      <nav className="relative z-50 border-b border-red-500/10 bg-black/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 flex justify-between items-center h-14">
          <div className="flex items-center gap-4">
            <GhostLogo className="text-xl" />
            <div className="h-6 w-px bg-white/10" />
            <span className="text-sm font-bold tracking-wider text-red-400 uppercase font-mono flex items-center gap-1.5">
              <Crown className="w-3.5 h-3.5" /> Founder Console
            </span>
          </div>
          <Link href="/dashboard" className="text-xs text-gray-500 hover:text-white transition-colors flex items-center gap-1.5">
            <ChevronRight className="w-3 h-3" /> Back to Dashboard
          </Link>
        </div>
      </nav>

      <div className="relative z-10 max-w-7xl mx-auto px-6 py-6">
        {/* Tabs */}
        <div className="flex gap-1 bg-surface-0/50 border border-white/5 p-1 rounded-xl mb-6 overflow-x-auto">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                activeTab === t.id
                  ? 'bg-red-500/15 text-red-400 shadow-sm border border-red-500/20'
                  : 'text-gray-500 hover:text-gray-300'
              }`}>
              <t.icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm">{error}</div>
        )}

        <AnimatePresence mode="wait">
          <motion.div key={activeTab} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }}>

            {/* ── Overview ── */}
            {activeTab === 'overview' && overview && (
              <div className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    { label: 'Total Orgs', value: overview.stats?.total_organizations, icon: Building2, color: 'text-blue-400' },
                    { label: 'Total Users', value: overview.stats?.total_users, icon: Users, color: 'text-emerald-400' },
                    { label: 'Firewall Mode', value: overview.config?.firewall_mode, icon: Shield, color: 'text-amber-400' },
                    { label: 'GPU', value: overview.config?.gpu_available ? 'Active' : 'None', icon: Cpu, color: 'text-purple-400' },
                  ].map(c => (
                    <div key={c.label} className="glass-card p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <c.icon className={`w-4 h-4 ${c.color}`} />
                        <span className="text-[11px] text-gray-500 uppercase tracking-wider">{c.label}</span>
                      </div>
                      <p className="text-2xl font-bold text-white">{c.value ?? 0}</p>
                    </div>
                  ))}
                </div>

                <div className="glass-card p-6">
                  <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                    <Server className="w-4 h-4 text-red-400" /> Platform Info
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div><span className="text-gray-500">Version</span><p className="text-white font-mono">{overview.platform?.version}</p></div>
                    <div><span className="text-gray-500">Environment</span><p className="text-white font-mono">{overview.platform?.env}</p></div>
                    <div><span className="text-gray-500">Threat Threshold</span><p className="text-white font-mono">{overview.config?.threat_threshold}</p></div>
                    <div><span className="text-gray-500">Max Prompt</span><p className="text-white font-mono">{overview.config?.max_prompt_length?.toLocaleString()}</p></div>
                  </div>
                </div>

                {overview.stats?.plan_distribution && (
                  <div className="glass-card p-6">
                    <h3 className="text-sm font-bold text-white mb-4">Plan Distribution</h3>
                    <div className="flex gap-4">
                      {Object.entries(overview.stats.plan_distribution).map(([plan, count]: any) => (
                        <div key={plan} className="flex-1 bg-surface-0/50 rounded-lg p-4 text-center border border-white/5">
                          <p className="text-2xl font-bold text-white">{count}</p>
                          <p className="text-[10px] text-ghost-400 uppercase tracking-wider font-bold mt-1">{plan}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Analytics ── */}
            {activeTab === 'analytics' && analytics && (
              <div className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    { label: 'MRR', value: analytics.revenue?.mrr_formatted, icon: DollarSign, color: 'text-emerald-400' },
                    { label: 'ARR', value: analytics.revenue?.arr_formatted, icon: TrendingUp, color: 'text-cyan-400' },
                    { label: 'Active Orgs', value: analytics.organizations?.active, icon: Building2, color: 'text-blue-400' },
                    { label: 'Churn Rate', value: `${analytics.organizations?.churn_rate}%`, icon: Activity, color: 'text-red-400' },
                  ].map(c => (
                    <div key={c.label} className="glass-card p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <c.icon className={`w-4 h-4 ${c.color}`} />
                        <span className="text-[11px] text-gray-500 uppercase tracking-wider">{c.label}</span>
                      </div>
                      <p className="text-2xl font-bold text-white">{c.value ?? 0}</p>
                    </div>
                  ))}
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="glass-card p-6">
                    <h4 className="text-sm font-bold text-white mb-4">Plan Breakdown</h4>
                    <div className="space-y-2">
                      {Object.entries(analytics.organizations?.plan_breakdown || {}).map(([plan, count]: any) => (
                        <div key={plan} className="flex items-center justify-between p-3 bg-surface-0/50 rounded-lg">
                          <span className="text-sm text-ghost-400 font-bold uppercase">{plan}</span>
                          <span className="text-lg font-bold text-white">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="glass-card p-6">
                    <h4 className="text-sm font-bold text-white mb-4">Threat Stats</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between p-3 bg-surface-0/50 rounded-lg">
                        <span className="text-sm text-gray-400">Total Scans</span>
                        <span className="text-lg font-bold text-white">{analytics.threats?.total_scans?.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between p-3 bg-surface-0/50 rounded-lg">
                        <span className="text-sm text-gray-400">Total Blocked</span>
                        <span className="text-lg font-bold text-red-400">{analytics.threats?.total_blocked?.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between p-3 bg-surface-0/50 rounded-lg">
                        <span className="text-sm text-gray-400">Total Users</span>
                        <span className="text-lg font-bold text-white">{analytics.users?.total}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ── Users ── */}
            {activeTab === 'users' && (
              <div className="glass-card overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="text-[10px] uppercase bg-surface-1/50 text-gray-500 border-b border-white/5">
                    <tr>
                      <th className="px-5 py-3">User</th>
                      <th className="px-5 py-3">Role</th>
                      <th className="px-5 py-3">Status</th>
                      <th className="px-5 py-3">Joined</th>
                      <th className="px-5 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {users.map(u => (
                      <tr key={u.id} className="hover:bg-surface-0/30 transition-colors text-gray-400">
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-ghost-500/20 to-cyber-500/20 flex items-center justify-center border border-white/5 text-[10px] font-bold text-white">
                              {(u.full_name || u.email)?.charAt(0)?.toUpperCase()}
                            </div>
                            <div>
                              <span className="text-white text-sm font-medium flex items-center gap-1.5">
                                {u.full_name || u.email.split('@')[0]}
                                {u.email === (process.env.NEXT_PUBLIC_SUPERADMIN_EMAIL || '') && <Crown className="w-3 h-3 text-amber-400" />}
                              </span>
                              <p className="text-[11px] text-gray-600 font-mono">{u.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <span className={`text-[10px] font-bold uppercase tracking-wider ${
                            u.role === 'super_admin' ? 'text-red-400' :
                            u.role === 'admin' ? 'text-amber-400' : 'text-gray-500'
                          }`}>{u.role}</span>
                        </td>
                        <td className="px-5 py-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                            u.is_active ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
                          }`}>{u.is_active ? 'Active' : 'Disabled'}</span>
                        </td>
                        <td className="px-5 py-3 text-[11px] font-mono text-gray-600">
                          {u.created_at ? new Date(u.created_at).toLocaleDateString() : '-'}
                        </td>
                        <td className="px-5 py-3 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <button onClick={() => impersonate(u.id)} title="Impersonate"
                              className="p-1.5 text-gray-600 hover:text-amber-400 hover:bg-amber-500/10 rounded-lg transition-colors">
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button onClick={() => deleteUser(u.id)} disabled={u.email === (process.env.NEXT_PUBLIC_SUPERADMIN_EMAIL || '')}
                              className="p-1.5 text-gray-600 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-20">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── Orgs with Drill-Down ── */}
            {activeTab === 'orgs' && (
              <div className="glass-card overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="text-[10px] uppercase bg-surface-1/50 text-gray-500 border-b border-white/5">
                    <tr>
                      <th className="px-5 py-3">Organization</th>
                      <th className="px-5 py-3">Slug</th>
                      <th className="px-5 py-3">Plan</th>
                      <th className="px-5 py-3">Users</th>
                      <th className="px-5 py-3">Created</th>
                      <th className="px-5 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {orgs.map(o => (
                      <Fragment key={o.id}>
                        <tr key={o.id} className="hover:bg-surface-0/30 transition-colors text-gray-400 cursor-pointer" onClick={() => fetchOrgDetails(o.id)}>
                          <td className="px-5 py-3">
                            <div className="flex items-center gap-3">
                              <div className="w-7 h-7 rounded-lg bg-surface-1 flex items-center justify-center border border-white/5">
                                <Building2 className="w-3.5 h-3.5 text-gray-500" />
                              </div>
                              <span className="text-white font-medium">{o.name}</span>
                              {expandedOrg === o.id ? <ChevronUp className="w-3 h-3 text-gray-500" /> : <ChevronDown className="w-3 h-3 text-gray-500" />}
                            </div>
                          </td>
                          <td className="px-5 py-3 font-mono text-[11px] text-gray-600">{o.slug}</td>
                          <td className="px-5 py-3">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-ghost-400">{o.plan}</span>
                          </td>
                          <td className="px-5 py-3 text-sm text-white font-medium">{o.user_count || 0}</td>
                          <td className="px-5 py-3 text-[11px] font-mono text-gray-600">
                            {o.created_at ? new Date(o.created_at).toLocaleDateString() : '-'}
                          </td>
                          <td className="px-5 py-3 text-right" onClick={e => e.stopPropagation()}>
                            <button onClick={() => deleteOrg(o.id)}
                              className="p-1.5 text-gray-600 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                        {/* Drill-down panel */}
                        {expandedOrg === o.id && orgDetails && (
                          <tr>
                            <td colSpan={6} className="px-5 py-4 bg-surface-0/30">
                              <div className="grid grid-cols-3 gap-4 mb-4">
                                <div className="p-3 bg-surface-0/50 rounded-lg border border-white/5">
                                  <span className="text-[10px] text-gray-500 uppercase">MRR</span>
                                  <p className="text-lg font-bold text-emerald-400">${orgDetails.billing?.mrr}</p>
                                </div>
                                <div className="p-3 bg-surface-0/50 rounded-lg border border-white/5">
                                  <span className="text-[10px] text-gray-500 uppercase">Total Scans</span>
                                  <p className="text-lg font-bold text-white">{orgDetails.usage?.total_scans}</p>
                                </div>
                                <div className="p-3 bg-surface-0/50 rounded-lg border border-white/5">
                                  <span className="text-[10px] text-gray-500 uppercase">API Keys</span>
                                  <p className="text-lg font-bold text-white">{orgDetails.usage?.api_key_count}</p>
                                </div>
                              </div>
                              <h5 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Members</h5>
                              <div className="space-y-1">
                                {(orgDetails.members || []).map((m: any) => (
                                  <div key={m.id} className="flex items-center justify-between p-2 bg-surface-0/30 rounded-lg">
                                    <div className="flex items-center gap-2">
                                      <span className="text-sm text-white">{m.full_name || m.email}</span>
                                      <span className="text-[10px] text-gray-600 font-mono">{m.email}</span>
                                    </div>
                                    <span className={`text-[10px] font-bold uppercase ${m.role === 'admin' ? 'text-amber-400' : 'text-gray-500'}`}>{m.role}</span>
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── Broadcasts ── */}
            {activeTab === 'broadcasts' && (
              <div className="space-y-6">
                <div className="glass-card p-6">
                  <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                    <Send className="w-4 h-4 text-cyan-400" /> Compose Announcement
                  </h3>
                  <div className="space-y-3">
                    <input value={broadcastTitle} onChange={e => setBroadcastTitle(e.target.value)} placeholder="Announcement title..."
                      className="w-full bg-surface-0 border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-ghost-500" />
                    <textarea rows={3} value={broadcastMsg} onChange={e => setBroadcastMsg(e.target.value)} placeholder="Message body..."
                      className="w-full bg-surface-0 border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-ghost-500 resize-none" />
                    <div className="flex items-center gap-3">
                      <select value={broadcastSeverity} onChange={e => setBroadcastSeverity(e.target.value)}
                        className="bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                        <option value="info">Info</option>
                        <option value="warning">Warning</option>
                        <option value="critical">Critical</option>
                      </select>
                      <button onClick={sendBroadcast} disabled={!broadcastTitle || !broadcastMsg}
                        className="btn-primary text-xs py-2 px-4 flex items-center gap-2 disabled:opacity-40">
                        <Send className="w-3.5 h-3.5" /> Send Broadcast
                      </button>
                    </div>
                  </div>
                </div>
                <div className="glass-card p-6">
                  <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                    <Megaphone className="w-4 h-4 text-amber-400" /> Active Announcements ({broadcasts.length})
                  </h3>
                  {broadcasts.length === 0 ? (
                    <p className="text-sm text-gray-600 text-center py-6">No active announcements.</p>
                  ) : (
                    <div className="space-y-3">
                      {broadcasts.map((b: any) => (
                        <div key={b.id} className={`p-4 rounded-xl border ${
                          b.severity === 'critical' ? 'border-red-500/20 bg-red-500/5' :
                          b.severity === 'warning' ? 'border-amber-500/20 bg-amber-500/5' :
                          'border-white/5 bg-surface-0/50'
                        }`}>
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="text-sm font-bold text-white">{b.title}</h4>
                            <div className="flex items-center gap-2">
                              <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                                b.severity === 'critical' ? 'bg-red-500/10 text-red-400' :
                                b.severity === 'warning' ? 'bg-amber-500/10 text-amber-400' :
                                'bg-cyan-500/10 text-cyan-400'
                              }`}>{b.severity}</span>
                              <button onClick={() => deleteBroadcast(b.id)} className="text-gray-600 hover:text-red-400">
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                          <p className="text-xs text-gray-400">{b.message}</p>
                          <p className="text-[10px] text-gray-600 mt-2 font-mono">
                            By {b.created_by} · {b.created_at ? new Date(b.created_at).toLocaleString() : ''}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ── Feature Flags ── */}
            {activeTab === 'flags' && (
              <div className="glass-card p-6">
                <h3 className="text-sm font-bold text-white mb-5 flex items-center gap-2">
                  <Flag className="w-4 h-4 text-amber-400" /> Feature Flags
                </h3>
                <div className="space-y-3">
                  {Object.entries(flags).map(([name, flag]: any) => (
                    <div key={name} className="flex items-center justify-between p-4 bg-surface-0/50 border border-white/[0.04] rounded-xl hover:border-white/10 transition-colors">
                      <div>
                        <p className="text-sm text-white font-medium font-mono">{name}</p>
                        <p className="text-[11px] text-gray-500 mt-0.5">{flag.description}</p>
                      </div>
                      <div className="flex items-center gap-4">
                        {flag.rollout_pct !== undefined && (
                          <span className="text-[10px] font-mono text-gray-600">{flag.rollout_pct}% rollout</span>
                        )}
                        <button onClick={() => toggleFlag(name, flag.enabled)}
                          className={`transition-colors ${flag.enabled ? 'text-emerald-400' : 'text-gray-600'}`}>
                          {flag.enabled ? <ToggleRight className="w-7 h-7" /> : <ToggleLeft className="w-7 h-7" />}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Deep Health ── */}
            {activeTab === 'health' && health && (
              <div className="space-y-4">
                <div className="glass-card p-6">
                  <div className="flex items-center justify-between mb-5">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Heart className="w-4 h-4 text-red-400" /> System Health
                    </h3>
                    <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                      health.overall === 'healthy'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>{health.overall}</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {Object.entries(health.services || {}).map(([name, svc]: any) => {
                      const isOk = svc.status === 'healthy' || svc.status === 'active';
                      const Icon = name === 'database' ? Database : name === 'redis' ? Wifi : name === 'gpu' ? Cpu : Shield;
                      return (
                        <div key={name} className={`p-4 rounded-xl border ${isOk ? 'border-emerald-500/10 bg-emerald-500/[0.03]' : 'border-amber-500/10 bg-amber-500/[0.03]'}`}>
                          <div className="flex items-center gap-2 mb-3">
                            <Icon className={`w-4 h-4 ${isOk ? 'text-emerald-400' : 'text-amber-400'}`} />
                            <span className="text-xs font-bold text-white uppercase">{name}</span>
                          </div>
                          <p className={`text-[10px] font-bold uppercase tracking-wider ${isOk ? 'text-emerald-400' : 'text-amber-400'}`}>
                            {svc.status}
                          </p>
                          {svc.device && <p className="text-[11px] text-gray-500 mt-1 font-mono">{svc.device}</p>}
                          {svc.memory_total_gb && <p className="text-[11px] text-gray-500 font-mono">{svc.memory_total_gb} GB VRAM</p>}
                          {svc.type && <p className="text-[11px] text-gray-500 font-mono">{svc.type}</p>}
                          {svc.mode && <p className="text-[11px] text-gray-500 font-mono">Mode: {svc.mode}</p>}
                          {svc.error && <p className="text-[11px] text-red-400 font-mono mt-1">{svc.error}</p>}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="glass-card p-4 text-center">
                  <p className="text-[11px] text-gray-600 font-mono">
                    Last checked: {health.timestamp ? new Date(health.timestamp).toLocaleString() : 'N/A'}
                  </p>
                </div>
              </div>
            )}

          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
