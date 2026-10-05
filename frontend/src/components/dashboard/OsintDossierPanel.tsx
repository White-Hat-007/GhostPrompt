import React, { useState, useEffect } from 'react';

interface OsintDossierPanelProps {
  ip: string;
  domain?: string;
  isOpen?: boolean;
}

export default function OsintDossierPanel({ ip, domain, isOpen = true }: OsintDossierPanelProps) {
  const [dossier, setDossier] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen && ip) fetchOsint();
  }, [ip, isOpen]);

  const fetchOsint = async () => {
    setLoading(true);
    setError('');
    try {
      // Always read fresh token from localStorage
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('Not authenticated — please log in again');
        setLoading(false);
        return;
      }
      const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
      const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
      const params = domain ? `?domain=${encodeURIComponent(domain)}` : '';
      const r = await fetch(`${API}/api/v1/platform/osint/${encodeURIComponent(ip)}${params}`, { headers });
      if (r.ok) {
        setDossier(await r.json());
      } else if (r.status === 401) {
        // Try refreshing token from localStorage in case it was updated by another component
        const freshToken = localStorage.getItem('access_token');
        if (freshToken && freshToken !== token) {
          const retry = await fetch(`${API}/api/v1/platform/osint/${encodeURIComponent(ip)}${params}`, {
            headers: { Authorization: `Bearer ${freshToken}` },
          });
          if (retry.ok) {
            setDossier(await retry.json());
            return;
          }
        }
        setError('Authentication expired — please log in again');
      } else {
        setError(`Enrichment failed (${r.status})`);
      }
    } catch (e: any) {
      setError(e.message || 'Network error');
    } finally {
      setLoading(false);
    }
  };

  const sectionIcons: Record<string, string> = {
    dns: '🌐', whois: '📋', cert_transparency: '🔐', bgp: '🛰️', exposed_services: '🔍',
    breach_check: '💀', infostealer_check: '🕵️', sanctions: '⚖️', mac_oui: '📡', cve: '🐛',
    geolocation: '📍', reverse_dns: '🔄', threat_feeds: '🎯',
  };

  const sectionLabels: Record<string, string> = {
    dns: 'DNS Resolution', whois: 'WHOIS Registrar', cert_transparency: 'Certificate Transparency',
    bgp: 'BGP / ASN / Prefix', exposed_services: 'Exposed Services', breach_check: 'Breach Corpus',
    infostealer_check: 'Infostealer Check', sanctions: 'Sanctions Lists', mac_oui: 'MAC/OUI Vendor',
    cve: 'CVE Cross-Reference', geolocation: 'Geolocation', reverse_dns: 'Reverse DNS', threat_feeds: 'Threat Feeds',
  };

  if (!isOpen) return null;

  return (
    <div style={{ background: 'rgba(0,212,255,0.02)', border: '1px solid rgba(0,212,255,0.08)', borderRadius: 10, overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 16 }}>🕵️</span>
          <span style={{ fontSize: 13, fontWeight: 700, color: '#F1F5F9' }}>OSINT Dossier</span>
          <span style={{ fontSize: 10, color: '#64748B', fontFamily: 'JetBrains Mono, monospace' }}>{ip}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {dossier && (
            <span style={{ fontSize: 10, color: '#64748B' }}>
              {dossier.total_lookups} lookups • {dossier.duration_ms?.toFixed(0)}ms
            </span>
          )}
          {!loading && (
            <button onClick={fetchOsint} style={{ fontSize: 10, color: '#00D4FF', cursor: 'pointer', background: 'none', border: 'none', fontWeight: 600 }}>
              ↻ Refresh
            </button>
          )}
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div style={{ padding: 24, textAlign: 'center', color: '#64748B', fontSize: 12 }}>
          <div style={{ marginBottom: 8 }}>🔍 Running enrichment...</div>
          <div style={{ fontSize: 10 }}>DNS • WHOIS • CertTransparency • BGP • Shodan • Breach • Sanctions</div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 11, color: '#EF4444', marginBottom: 8 }}>⚠️ {error}</div>
          <button onClick={fetchOsint} style={{ padding: '6px 14px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, color: '#00D4FF', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
            🔍 Retry Enrichment
          </button>
        </div>
      )}

      {/* Rate Limited */}
      {dossier?.rate_limited && (
        <div style={{ padding: 16, textAlign: 'center', color: '#F59E0B', fontSize: 12 }}>
          ⚠️ Rate limited — try again in 60 seconds
        </div>
      )}

      {/* ALL Sections — expanded inline by default, no collapse */}
      {dossier?.sections && !dossier.rate_limited && (
        <div style={{ maxHeight: 500, overflowY: 'auto' }}>
          {Object.entries(dossier.sections).map(([key, data]: [string, any]) => (
            <div key={key} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              {/* Section header */}
              <div style={{ padding: '8px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.01)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 14 }}>{sectionIcons[key] || '📄'}</span>
                  <span style={{ fontSize: 11, fontWeight: 600, color: '#CBD5E1' }}>{sectionLabels[key] || key}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  {data?.status === 'found' && <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(16,185,129,0.12)', color: '#10B981', fontWeight: 600 }}>FOUND</span>}
                  {data?.status === 'not_found' && <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(100,116,139,0.12)', color: '#64748B' }}>N/A</span>}
                  {data?.status === 'error' && <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(239,68,68,0.12)', color: '#EF4444' }}>ERR</span>}
                </div>
              </div>

              {/* Content — ALWAYS visible, full text, no truncation */}
              <div style={{ padding: '0 16px 10px 42px' }}>
                {typeof data === 'object' && data !== null ? (
                  Object.entries(data).filter(([k]) => k !== 'status' && k !== 'source').map(([k, v]: [string, any]) => (
                    <div key={k} style={{ padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                      <div style={{ fontSize: 10, color: '#64748B', fontFamily: 'JetBrains Mono, monospace', textTransform: 'capitalize', marginBottom: 2, fontWeight: 600 }}>
                        {k.replace(/_/g, ' ')}
                      </div>
                      {typeof v === 'object' && v !== null ? (
                        Array.isArray(v) ? (
                          v.length === 0 ? (
                            <span style={{ fontSize: 10, color: '#475569', fontStyle: 'italic' }}>none</span>
                          ) : (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                              {v.map((item: any, i: number) => (
                                <span key={i} style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.1)', color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace' }}>
                                  {typeof item === 'object' ? Object.entries(item).map(([ik,iv]) => `${ik}:${iv}`).join(' · ') : String(item)}
                                </span>
                              ))}
                            </div>
                          )
                        ) : (
                          <div style={{ marginTop: 2 }}>
                            {Object.entries(v).map(([sk, sv]: [string, any]) => (
                              <div key={sk} style={{ display: 'flex', gap: 8, padding: '2px 0' }}>
                                <span style={{ fontSize: 9, color: '#475569', fontFamily: 'JetBrains Mono, monospace', minWidth: 60, textTransform: 'capitalize' }}>{sk.replace(/_/g, ' ')}</span>
                                <span style={{ fontSize: 9, color: '#94A3B8', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>
                                  {typeof sv === 'object' ? JSON.stringify(sv) : String(sv)}
                                </span>
                              </div>
                            ))}
                          </div>
                        )
                      ) : (
                        <div style={{ fontSize: 10, color: '#CBD5E1', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                          {String(v)}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div style={{ fontSize: 10, color: '#94A3B8', wordBreak: 'break-all' }}>{String(data)}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && !dossier && !error && (
        <div style={{ padding: 20, textAlign: 'center' }}>
          <button onClick={fetchOsint} style={{ padding: '8px 16px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, color: '#00D4FF', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
            🔍 Run OSINT Enrichment
          </button>
        </div>
      )}
    </div>
  );
}
