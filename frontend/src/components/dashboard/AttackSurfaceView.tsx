import React, { useState, useEffect } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export default function AttackSurfaceView() {
  const [scan, setScan] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const token = localStorage.getItem('access_token');
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => { runScan(); }, []);

  const runScan = async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/v1/platform/attack-surface`, { headers });
      if (r.ok) setScan(await r.json());
    } catch {} finally { setLoading(false); }
  };

  const RiskBadge = ({ level }: { level: string }) => {
    const colors: Record<string, string> = { safe: '#10B981', low: '#3B82F6', medium: '#F59E0B', high: '#F97316', critical: '#EF4444', unknown: '#64748B' };
    return (
      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: `${colors[level] || colors.unknown}18`, color: colors[level] || colors.unknown, textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>
        {level}
      </span>
    );
  };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#64748B' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>🔍</div>
        <div style={{ fontSize: 13 }}>Scanning attack surface...</div>
      </div>
    </div>
  );

  const summary = scan?.summary || {};
  const endpoints = scan?.endpoints || [];
  const recommendations = scan?.recommendations || [];

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1060, margin: '0 auto', overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: '#F1F5F9', margin: 0 }}>🎯 AI Attack Surface</h2>
          <div style={{ fontSize: 11, color: '#64748B', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
            Scanned {new Date(scan?.scan_timestamp).toLocaleString()}
          </div>
        </div>
        <button onClick={runScan} style={{ padding: '8px 16px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8, color: '#00D4FF', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>
          🔄 Re-Scan
        </button>
      </div>

      {/* Coverage KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Total Endpoints', value: summary.total_endpoints, icon: '🌐', color: '#3B82F6' },
          { label: 'Protected', value: summary.protected, icon: '🛡️', color: '#10B981' },
          { label: 'Unprotected', value: summary.unprotected, icon: '⚠️', color: '#EF4444' },
          { label: 'Coverage', value: `${summary.coverage_pct}%`, icon: '📊', color: summary.coverage_pct >= 90 ? '#10B981' : '#F59E0B' },
        ].map((kpi, i) => (
          <div key={i} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: 16, textAlign: 'center' }}>
            <div style={{ fontSize: 20, marginBottom: 4 }}>{kpi.icon}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: kpi.color, fontFamily: 'JetBrains Mono, monospace' }}>{kpi.value}</div>
            <div style={{ fontSize: 10, color: '#64748B', marginTop: 2 }}>{kpi.label}</div>
          </div>
        ))}
      </div>

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          {recommendations.map((rec: any, i: number) => (
            <div key={i} style={{ background: rec.severity === 'critical' ? 'rgba(239,68,68,0.04)' : 'rgba(245,158,11,0.04)', border: `1px solid ${rec.severity === 'critical' ? 'rgba(239,68,68,0.12)' : 'rgba(245,158,11,0.12)'}`, borderRadius: 10, padding: 16, marginBottom: 10 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: rec.severity === 'critical' ? '#EF4444' : '#F59E0B', marginBottom: 6 }}>
                {rec.severity === 'critical' ? '🚨' : '⚠️'} {rec.title}
              </div>
              <div style={{ fontSize: 12, color: '#94A3B8', lineHeight: 1.5 }}>{rec.description}</div>
            </div>
          ))}
        </div>
      )}

      {/* Endpoint Table */}
      <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#F1F5F9' }}>Discovered Endpoints</span>
          <span style={{ fontSize: 11, color: '#64748B' }}>{endpoints.length} endpoints</span>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['Name', 'Type', 'Provider', 'Protected', 'Risk', 'Method'].map(h => (
                <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#64748B', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {endpoints.map((ep: any) => (
              <tr key={ep.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                <td style={{ padding: '10px 16px', fontSize: 12, color: '#CBD5E1', fontWeight: 500 }}>{ep.name}</td>
                <td style={{ padding: '10px 16px', fontSize: 11, color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>{ep.endpoint_type}</td>
                <td style={{ padding: '10px 16px', fontSize: 12, color: '#94A3B8', textTransform: 'capitalize' }}>{ep.provider || '—'}</td>
                <td style={{ padding: '10px 16px' }}>
                  <span style={{ fontSize: 11, color: ep.is_protected ? '#10B981' : '#EF4444' }}>
                    {ep.is_protected ? '✓ Protected' : '✗ Exposed'}
                  </span>
                </td>
                <td style={{ padding: '10px 16px' }}><RiskBadge level={ep.risk_level} /></td>
                <td style={{ padding: '10px 16px', fontSize: 10, color: '#64748B', fontFamily: 'JetBrains Mono, monospace' }}>{ep.protection_method || 'none'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
