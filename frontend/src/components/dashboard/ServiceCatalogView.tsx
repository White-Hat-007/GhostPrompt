import React, { useState, useEffect } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export default function ServiceCatalogView() {
  const [services, setServices] = useState<any[]>([]);
  const [scorecard, setScorecard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedService, setSelectedService] = useState<any>(null);

  const token = localStorage.getItem('access_token');
  const headers: Record<string, string> = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  useEffect(() => { discover(); }, []);

  const discover = async () => {
    setLoading(true);
    try {
      await fetch(`${API}/api/v1/platform/service-catalog/discover`, { method: 'POST', headers });
      const [svcR, scR] = await Promise.all([
        fetch(`${API}/api/v1/platform/service-catalog`, { headers }),
        fetch(`${API}/api/v1/platform/service-catalog-scorecard`, { headers }),
      ]);
      if (svcR.ok) setServices(await svcR.json());
      if (scR.ok) setScorecard(await scR.json());
    } catch {} finally { setLoading(false); }
  };

  const GradeBadge = ({ grade, score }: { grade: string; score: number }) => {
    const colors: Record<string, string> = { A: '#10B981', B: '#3B82F6', C: '#F59E0B', D: '#F97316', F: '#EF4444', 'N/A': '#64748B' };
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ width: 44, height: 44, borderRadius: 10, background: `${colors[grade] || colors['N/A']}18`, border: `2px solid ${colors[grade] || colors['N/A']}40`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, fontWeight: 800, color: colors[grade], fontFamily: 'JetBrains Mono, monospace' }}>
          {grade}
        </div>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#F1F5F9', fontFamily: 'JetBrains Mono, monospace' }}>{score}/100</div>
          <div style={{ fontSize: 10, color: '#64748B' }}>Readiness Score</div>
        </div>
      </div>
    );
  };

  const ReadinessBar = ({ label, met, weight }: { label: string; met: boolean; weight: number }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0' }}>
      <span style={{ fontSize: 14, width: 20, textAlign: 'center' }}>{met ? '✅' : '❌'}</span>
      <span style={{ flex: 1, fontSize: 12, color: met ? '#CBD5E1' : '#64748B', textTransform: 'capitalize' }}>{label.replace(/_/g, ' ')}</span>
      <span style={{ fontSize: 10, color: met ? '#10B981' : '#EF4444', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{met ? `+${weight}` : '0'}/{weight}</span>
    </div>
  );

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#64748B' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>📂</div>
        <div style={{ fontSize: 13 }}>Discovering AI services...</div>
      </div>
    </div>
  );

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1060, margin: '0 auto', overflowY: 'auto', height: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: '#F1F5F9', margin: 0 }}>📂 AI Service Catalog</h2>
        <button onClick={discover} style={{ padding: '8px 16px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8, color: '#00D4FF', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>
          🔄 Rediscover
        </button>
      </div>

      {/* Org-wide scorecard */}
      {scorecard && (
        <div style={{ background: 'linear-gradient(135deg, rgba(0,212,255,0.04), rgba(168,85,247,0.04))', border: '1px solid rgba(0,212,255,0.1)', borderRadius: 12, padding: 20, marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#F1F5F9', marginBottom: 4 }}>Organization Readiness</div>
            <div style={{ fontSize: 11, color: '#64748B' }}>{scorecard.total_services} services cataloged</div>
          </div>
          <GradeBadge grade={scorecard.grade} score={Math.round(scorecard.avg_score)} />
        </div>
      )}

      {/* Service Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 14 }}>
        {services.map((svc: any) => (
          <div
            key={svc.id}
            onClick={() => setSelectedService(selectedService?.id === svc.id ? null : svc)}
            style={{
              background: selectedService?.id === svc.id ? 'rgba(0,212,255,0.04)' : 'rgba(255,255,255,0.02)',
              border: `1px solid ${selectedService?.id === svc.id ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.06)'}`,
              borderRadius: 12, padding: 18, cursor: 'pointer', transition: 'all 0.15s',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#F1F5F9' }}>{svc.name}</div>
                <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>{svc.description}</div>
              </div>
              <GradeBadge grade={svc.readiness?.grade} score={svc.readiness?.score} />
            </div>

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, background: 'rgba(59,130,246,0.1)', color: '#3B82F6', fontFamily: 'JetBrains Mono, monospace' }}>{svc.service_type}</span>
              <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, background: 'rgba(168,85,247,0.1)', color: '#A855F7', fontFamily: 'JetBrains Mono, monospace' }}>{svc.provider}</span>
              {svc.tags?.map((t: string) => (
                <span key={t} style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, background: 'rgba(255,255,255,0.04)', color: '#64748B' }}>{t}</span>
              ))}
            </div>

            {/* Expanded readiness breakdown */}
            {selectedService?.id === svc.id && svc.readiness?.breakdown && (
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 12, marginTop: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#94A3B8', marginBottom: 8, fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1 }}>READINESS BREAKDOWN</div>
                {Object.entries(svc.readiness.breakdown).map(([key, val]: [string, any]) => (
                  <ReadinessBar key={key} label={key} met={val.met} weight={val.weight} />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {services.length === 0 && (
        <div style={{ textAlign: 'center', padding: 60, color: '#64748B' }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>📂</div>
          <div style={{ fontSize: 14 }}>No services discovered. Configure AI providers to populate the catalog.</div>
        </div>
      )}
    </div>
  );
}
