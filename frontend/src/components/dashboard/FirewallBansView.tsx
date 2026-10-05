import React, { useState, useEffect, useRef } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export default function FirewallBansView() {
  const [bans, setBans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [banIp, setBanIp] = useState('');
  const [banning, setBanning] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);
  const toastTimer = useRef<any>(null);

  const getHeaders = () => {
    const token = localStorage.getItem('access_token');
    return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } as Record<string, string>;
  };

  const showToast = (msg: string, type: 'success' | 'error' = 'success') => {
    setToast({ msg, type });
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 4000);
  };

  const fetchBans = async () => {
    try {
      const r = await fetch(`${API}/api/v1/platform/bans`, { headers: getHeaders() });
      if (r.ok) { const d = await r.json(); setBans(d.bans || []); }
    } catch {} finally { setLoading(false); }
  };

  useEffect(() => { fetchBans(); const iv = setInterval(fetchBans, 15000); return () => clearInterval(iv); }, []);

  const handleBan = async () => {
    const ip = banIp.trim();
    if (!ip) return;
    setBanning(true);
    try {
      const r = await fetch(`${API}/api/v1/platform/bans/${ip}/ban`, { method: 'POST', headers: getHeaders() });
      if (r.ok) {
        const data = await r.json();
        // Optimistic UI: add to table immediately
        setBans(prev => [...prev, {
          ip,
          ban_id: data.ban_id || `ban-${ip}-${Date.now()}`,
          reason: 'Manual ban by analyst',
          severity: 'high',
          offense_count: 1,
          ban_duration_seconds: 300,
          banned_at: new Date().toISOString(),
          expires_at: data.expires_at || new Date(Date.now() + 300000).toISOString(),
          ban_method: 'netsh',
          auto_banned: false,
        }]);
        setBanIp('');
        showToast(`🚫 Banned ${ip} — expires in 5 minutes`, 'success');
        // Then refresh from server
        setTimeout(fetchBans, 500);
      } else {
        showToast(`❌ Failed to ban ${ip} — server error`, 'error');
      }
    } catch {
      showToast(`❌ Failed to ban ${ip} — network error`, 'error');
    } finally { setBanning(false); }
  };

  const handleUnban = async (ip: string) => {
    try {
      const r = await fetch(`${API}/api/v1/platform/bans/${ip}/unban`, { method: 'POST', headers: getHeaders() });
      if (r.ok) {
        setBans(prev => prev.filter(b => b.ip !== ip));
        showToast(`✅ Unbanned ${ip}`, 'success');
        setTimeout(fetchBans, 500);
      }
    } catch {}
  };

  const formatDuration = (s: number) => {
    if (s >= 86400) return `${(s / 86400).toFixed(1)}d`;
    if (s >= 3600) return `${(s / 3600).toFixed(1)}h`;
    if (s >= 60) return `${Math.round(s / 60)}m`;
    return `${s}s`;
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: 960, margin: '0 auto', overflowY: 'auto', height: '100%', position: 'relative' }}>
      {/* Toast notification */}
      {toast && (
        <div style={{
          position: 'fixed', top: 80, left: '50%', transform: 'translateX(-50%)', zIndex: 1000,
          padding: '12px 24px', borderRadius: 10,
          background: toast.type === 'success' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
          border: `1px solid ${toast.type === 'success' ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
          backdropFilter: 'blur(12px)',
          color: toast.type === 'success' ? '#10B981' : '#EF4444',
          fontSize: 13, fontWeight: 600, fontFamily: 'JetBrains Mono, monospace',
          boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
          animation: 'fadeIn 0.3s ease', whiteSpace: 'nowrap',
        }}>
          {toast.msg}
        </div>
      )}
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: '#F1F5F9', margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            🛡️ Firewall Bans
          </h2>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
            Infrastructure-level IP enforcement via {typeof window !== 'undefined' && navigator.platform?.includes('Win') ? 'Windows Firewall (netsh)' : 'Fail2Ban / iptables'}
          </div>
        </div>
        <button onClick={fetchBans} style={{ padding: '8px 16px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8, color: '#00D4FF', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>
          🔄 Refresh
        </button>
      </div>

      {/* Manual ban input */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
        <input
          value={banIp}
          onChange={e => setBanIp(e.target.value)}
          placeholder="Enter IP address to ban..."
          onKeyDown={e => e.key === 'Enter' && handleBan()}
          style={{ flex: 1, padding: '10px 14px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, color: '#F1F5F9', fontSize: 13, outline: 'none', fontFamily: 'JetBrains Mono, monospace' }}
        />
        <button
          onClick={handleBan}
          disabled={banning || !banIp.trim()}
          style={{ padding: '10px 20px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, color: '#EF4444', fontSize: 12, cursor: 'pointer', fontWeight: 700, opacity: banning || !banIp.trim() ? 0.4 : 1, fontFamily: 'JetBrains Mono, monospace' }}
        >
          {banning ? '⏳ Banning...' : '🚫 BAN IP'}
        </button>
      </div>

      {/* Stats bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 24 }}>
        <div style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.1)', borderRadius: 10, padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#EF4444', fontFamily: 'JetBrains Mono, monospace' }}>{bans.length}</div>
          <div style={{ fontSize: 10, color: '#94A3B8', marginTop: 2 }}>Active Bans</div>
        </div>
        <div style={{ background: 'rgba(245,158,11,0.04)', border: '1px solid rgba(245,158,11,0.1)', borderRadius: 10, padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#F59E0B', fontFamily: 'JetBrains Mono, monospace' }}>{bans.filter(b => b.auto_banned).length}</div>
          <div style={{ fontSize: 10, color: '#94A3B8', marginTop: 2 }}>Auto-Banned</div>
        </div>
        <div style={{ background: 'rgba(168,85,247,0.04)', border: '1px solid rgba(168,85,247,0.1)', borderRadius: 10, padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#A855F7', fontFamily: 'JetBrains Mono, monospace' }}>{bans.filter(b => (b.offense_count || 0) > 1).length}</div>
          <div style={{ fontSize: 10, color: '#94A3B8', marginTop: 2 }}>Repeat Offenders</div>
        </div>
      </div>

      {/* Bans table */}
      <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['IP Address', 'Severity', 'Offenses', 'Duration', 'Method', 'Banned At', 'Expires', 'Actions'].map(h => (
                <th key={h} style={{ padding: '12px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#64748B', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {bans.length === 0 && (
              <tr><td colSpan={8} style={{ padding: 40, textAlign: 'center', color: '#64748B', fontSize: 13 }}>
                {loading ? '⏳ Loading...' : '✅ No active bans — network is clean'}
              </td></tr>
            )}
            {bans.map((ban: any) => {
              const severityColors: Record<string, string> = { critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6' };
              return (
                <tr key={ban.ban_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                  <td style={{ padding: '10px 14px', fontSize: 13, color: '#F1F5F9', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>{ban.ip}</td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: `${severityColors[ban.severity] || '#64748B'}18`, color: severityColors[ban.severity] || '#64748B', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>{ban.severity}</span>
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 12, color: ban.offense_count > 1 ? '#EF4444' : '#94A3B8', fontFamily: 'JetBrains Mono, monospace', fontWeight: ban.offense_count > 1 ? 700 : 400 }}>
                    {ban.offense_count}x {ban.offense_count > 2 ? '🔥' : ''}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 11, color: '#CBD5E1', fontFamily: 'JetBrains Mono, monospace' }}>{formatDuration(ban.ban_duration_seconds)}</td>
                  <td style={{ padding: '10px 14px', fontSize: 10, color: '#64748B', fontFamily: 'JetBrains Mono, monospace' }}>{ban.ban_method}</td>
                  <td style={{ padding: '10px 14px', fontSize: 10, color: '#94A3B8' }}>{ban.banned_at ? new Date(ban.banned_at).toLocaleTimeString() : '—'}</td>
                  <td style={{ padding: '10px 14px', fontSize: 10, color: '#F59E0B' }}>{ban.expires_at ? new Date(ban.expires_at).toLocaleTimeString() : '—'}</td>
                  <td style={{ padding: '10px 14px' }}>
                    <button
                      onClick={() => handleUnban(ban.ip)}
                      style={{ padding: '4px 12px', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 6, color: '#10B981', fontSize: 10, cursor: 'pointer', fontWeight: 600 }}
                    >
                      Unban
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Info banner */}
      <div style={{ marginTop: 20, padding: 16, background: 'rgba(59,130,246,0.04)', border: '1px solid rgba(59,130,246,0.1)', borderRadius: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: '#3B82F6', marginBottom: 6 }}>ℹ️ Ban Escalation Policy</div>
        <div style={{ fontSize: 11, color: '#94A3B8', lineHeight: 1.6 }}>
          Repeat offenses escalate ban duration exponentially (5min → 15min → 45min → 2.25h → 6.75h → max 24h).
          Bans are applied at the OS firewall level and auto-expire. Actor cluster attribution ensures IP rotation doesn't evade enforcement.
        </div>
      </div>
    </div>
  );
}
