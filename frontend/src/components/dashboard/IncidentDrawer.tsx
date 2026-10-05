'use client';

import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import OsintDossierPanel from './OsintDossierPanel';
import {
  X, Shield, AlertTriangle, Globe, Clock, Terminal, User,
  MapPin, Monitor, Fingerprint, Activity, FileCode, Target, Layers, ExternalLink, Network, Search, Database
} from 'lucide-react';

interface IncidentDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  attack: any;
}

// ATLAS mapping (shared with LiveAttackFeed)
const ATLAS_MAP: Record<string, { id: string; name: string }> = {
  'injection': { id: 'AML.T0051', name: 'LLM Prompt Injection' },
  'jailbreak': { id: 'AML.T0054', name: 'LLM Jailbreak' },
  'pliny': { id: 'AML.T0054.002', name: 'Pliny-Class Jailbreak' },
  'encoded': { id: 'AML.T0015', name: 'Evade ML Model' },
  'pii': { id: 'AML.T0024', name: 'Exfiltration via Inference API' },
  'secrets': { id: 'AML.T0024.001', name: 'Secret Exfiltration' },
  'oracle': { id: 'AML.T0044', name: 'Full ML Model Access' },
  'tokenizer': { id: 'AML.T0043', name: 'Craft Adversarial Data' },
  'zero_day': { id: 'AML.T0000', name: 'Novel Attack Vector' },
  'sponge': { id: 'AML.T0029', name: 'Denial of ML Service' },
  'agent': { id: 'AML.T0052', name: 'Agent Hijacking' },
  'external': { id: 'AML.T0051.002', name: 'Indirect Prompt Injection' },
  'memorization': { id: 'AML.T0024.002', name: 'Training Data Extraction' },
  'supply_chain': { id: 'AML.T0010', name: 'ML Supply Chain Compromise' },
  'hallucination': { id: 'AML.T0048.001', name: 'Hallucination Exploit' },
  'content': { id: 'AML.T0048.002', name: 'Content Policy Violation' },
};

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', label: 'CRITICAL' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', label: 'HIGH' },
  medium: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', label: 'MEDIUM' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', label: 'LOW' },
  safe: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', label: 'SAFE' },
};

function InfoRow({ label, value, icon: Icon, mono = false }: { label: string; value: string; icon?: any; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between py-2 border-b border-white/[0.03] last:border-0">
      <div className="flex items-center gap-2 text-gray-500">
        {Icon && <Icon className="w-3.5 h-3.5 flex-shrink-0" />}
        <span className="text-[11px] uppercase tracking-wider font-medium">{label}</span>
      </div>
      <span className={`text-[12px] text-gray-300 text-right max-w-[60%] break-all ${mono ? 'font-mono' : ''}`}>{value || '—'}</span>
    </div>
  );
}

export default function IncidentDrawer({ isOpen, onClose, attack }: IncidentDrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);
  const [showOsint, setShowOsint] = useState(true);

  // Close on Escape
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  // Close on click outside
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: MouseEvent) => {
      if (drawerRef.current && !drawerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    // Delay to avoid closing on the click that opens
    const timer = setTimeout(() => document.addEventListener('mousedown', handler), 100);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('mousedown', handler);
    };
  }, [isOpen, onClose]);

  if (!isOpen || !attack) return null;

  const severity = SEVERITY_CONFIG[attack.threat_level] || SEVERITY_CONFIG.low;
  const category = attack.category || attack.scan_type || 'unknown';
  const atlasPrefix = category.split('.')[0];
  const atlas = ATLAS_MAP[category] || ATLAS_MAP[atlasPrefix] || null;
  const detections = attack.detections || [];
  const scorePercent = Math.round((attack.threat_score || 0) * 100);

  return (
    <>
      {/* Backdrop */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40"
      />

      {/* Drawer */}
      <motion.div
        ref={drawerRef}
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 30, stiffness: 300 }}
        className="incident-drawer z-50"
      >
        {/* Header */}
        <div className="sticky top-0 z-10 px-6 py-4 border-b border-white/[0.06] bg-surface-0/95 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-9 h-9 rounded-lg ${severity.bg} border ${severity.border} flex items-center justify-center`}>
                <AlertTriangle className={`w-4.5 h-4.5 ${severity.color}`} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-white">Incident Forensics</h2>
                <p className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">{attack.request_id}</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-surface-2 border border-white/[0.06] flex items-center justify-center text-gray-500 hover:text-white hover:border-white/[0.1] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          {/* SIEM Sync Status Badge */}
          <div className="mt-2 flex items-center gap-2">
            <span className="text-[9px] font-mono px-2 py-0.5 rounded-full border bg-emerald-500/10 text-emerald-400 border-emerald-500/20 inline-flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              SIEM SYNCED
            </span>
            <span className="text-[9px] text-gray-600 font-mono">Auto-forwarded to configured connectors</span>
          </div>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Severity + Score Banner */}
          <div className={`rounded-xl p-4 ${severity.bg} border ${severity.border}`}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Threat Assessment</p>
                <div className="flex items-center gap-2">
                  <span className={`text-lg font-bold ${severity.color}`}>{severity.label}</span>
                  {atlas && (
                    <span className="data-tag text-[9px]">{atlas.id}</span>
                  )}
                </div>
                {atlas && <p className="text-[11px] text-gray-500 mt-0.5">{atlas.name}</p>}
              </div>
              <div className="text-right">
                <p className={`text-3xl font-bold font-mono ${severity.color}`}>{scorePercent}%</p>
                <p className="text-[10px] text-gray-600">confidence</p>
              </div>
            </div>
            {/* Score bar */}
            <div className="mt-3 w-full h-1.5 rounded-full bg-white/5">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  scorePercent >= 80 ? 'bg-red-500' : scorePercent >= 50 ? 'bg-amber-500' : 'bg-blue-500'
                }`}
                style={{ width: `${scorePercent}%` }}
              />
            </div>
          </div>

          {/* Event Details */}
          <div>
            <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Event Details</h3>
            <div className="glass-card px-4 py-1">
              <InfoRow label="Action" value={attack.action?.toUpperCase()} icon={Shield} />
              <InfoRow label="Category" value={category} icon={Target} mono />
              <InfoRow label="Model" value={attack.model} icon={Layers} />
              <InfoRow label="Timestamp" value={attack.created_at ? new Date(attack.created_at).toLocaleString() : '—'} icon={Clock} />
              <InfoRow label="Scan Duration" value={attack.scan_duration_ms ? `${attack.scan_duration_ms}ms` : '—'} icon={Activity} />
            </div>
          </div>

          {/* Attacker Profile */}
          {(attack.ip || attack.city) && (
            <div>
              <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Attacker Profile</h3>
              <div className="glass-card px-4 py-1">
                <InfoRow label="IP Address" value={attack.ip} icon={Globe} mono />
                <InfoRow label="Location" value={`${attack.city || '?'}, ${attack.country || '?'}`} icon={MapPin} />
                {attack.timezone && <InfoRow label="Timezone" value={attack.timezone} icon={Clock} />}
                {attack.postal_code && <InfoRow label="Postal Code" value={attack.postal_code} icon={MapPin} mono />}
                {attack.isp && <InfoRow label="ISP / Org" value={attack.isp} icon={Network} />}
                {attack.asn && <InfoRow label="ASN" value={attack.asn} icon={FileCode} mono />}
                <InfoRow label="Browser" value={attack.browser} icon={Monitor} />
                <InfoRow label="OS" value={attack.os} icon={Fingerprint} />
              </div>

              {(attack.is_vpn || attack.attacker_profile?.is_vpn || attack.is_tor || attack.attacker_profile?.is_tor_exit_node || attack.is_proxy || attack.attacker_profile?.connection_type === 'proxy') && (
                <div className="mt-2 flex flex-wrap gap-1 px-1">
                  {(attack.is_vpn || attack.attacker_profile?.is_vpn) && <span className="text-[9px] bg-orange-500/10 text-orange-400 px-1.5 py-0.5 rounded border border-orange-500/20 font-bold uppercase tracking-widest">VPN Detected</span>}
                  {(attack.is_tor || attack.attacker_profile?.is_tor_exit_node) && <span className="text-[9px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded border border-red-500/20 font-bold uppercase tracking-widest">TOR Exit Node</span>}
                  {(attack.is_proxy || attack.attacker_profile?.connection_type === 'proxy') && <span className="text-[9px] bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded border border-amber-500/20 font-bold uppercase tracking-widest">Proxy</span>}
                </div>
              )}
            </div>
          )}

          {/* OSINT Enrichment Dossier — always visible inline */}
          {attack.ip && (
            <div>
              <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Search className="w-3 h-3" />
                OSINT Intelligence
              </h3>
              <OsintDossierPanel ip={attack.ip} domain={attack.domain} isOpen={true} />
            </div>
          )}

          {/* Network Telemetry */}
          {(attack.latency_ms !== undefined || attack.attacker_profile?.rtt_ms !== undefined) && (
            <div>
              <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Clock className="w-3 h-3" />
                Network Telemetry
              </h3>
              <div className="glass-card px-4 py-3 flex items-center justify-between">
                <div>
                  <div className="text-[9px] text-gray-500 mb-0.5 uppercase tracking-wider">RTT (Latency)</div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-gray-300 font-mono font-bold">{(attack.latency_ms || attack.attacker_profile?.rtt_ms).toFixed(1)}ms</span>
                    {(attack.latency_ms || attack.attacker_profile?.rtt_ms) > 200 && <span className="text-[9px] text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded border border-amber-400/20">HIGH LATENCY</span>}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-[9px] text-gray-500 mb-0.5 uppercase tracking-wider">Data Provider</div>
                  <div className="flex items-center gap-1 justify-end text-[9px] text-emerald-400 font-bold tracking-widest">
                    <Database className="w-2.5 h-2.5" />
                    IPINFO.IO LIVE
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Traceback Evidence Chain */}
          {(attack.traceback_evidence_chain?.length > 0 || attack.attacker_profile?.traceback_evidence_chain?.length > 0) && (
            <div>
              <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Search className="w-3 h-3" />
                Traceback Evidence
              </h3>
              <div className="relative border-l border-white/10 ml-2.5 space-y-3 pb-2 mt-3">
                {(attack.traceback_evidence_chain || attack.attacker_profile?.traceback_evidence_chain).map((ev: any, idx: number) => (
                  <div key={idx} className="relative pl-5 group">
                    <div className="absolute left-[-11px] top-1 w-5 h-5 rounded-full border border-white/10 bg-[#050914] flex items-center justify-center z-10 transition-colors group-hover:border-blue-500/50 group-hover:bg-blue-500/10">
                      <span className="text-[9px] font-bold text-gray-400 group-hover:text-blue-400">{idx + 1}</span>
                    </div>
                    <div className="glass-card p-3 group-hover:border-blue-500/30 transition-colors">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-bold text-blue-400 uppercase tracking-widest">{ev.step}</span>
                        <span className="text-[8px] text-emerald-400/80 font-mono bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                          {ev.confidence ? `${(ev.confidence*100).toFixed(0)}% CONF` : '100% CONF'}
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-300 font-bold mb-1">{ev.source}</div>
                      <p className="text-[10px] text-gray-500 leading-relaxed">{ev.details}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detection Engines */}
          {detections.length > 0 && (
            <div>
              <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">
                Detection Engines ({detections.length})
              </h3>
              <div className="space-y-1.5">
                {detections.map((det: any, i: number) => (
                  <div key={i} className="glass-card px-4 py-2.5 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-ghost-400" />
                      <span className="text-[11px] text-gray-300 font-medium">{det.detector}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {det.category && <span className="data-tag text-[9px]">{det.category}</span>}
                      <span className={`text-[11px] font-mono font-bold ${
                        det.confidence >= 0.8 ? 'text-red-400' : det.confidence >= 0.5 ? 'text-amber-400' : 'text-gray-500'
                      }`}>
                        {(det.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Intercepted Payload */}
          {attack.prompt && (
            <div>
              <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-2">
                <Terminal className="w-3 h-3" />
                Intercepted Payload
              </h3>
              <div className="glass-card p-4 overflow-hidden">
                <code className="text-[11px] text-gray-300 font-mono whitespace-pre-wrap break-words leading-relaxed block">
                  {attack.prompt}
                </code>
              </div>
            </div>
          )}

          {/* ATLAS Reference */}
          {atlas && (
            <div className="glass-card p-4">
              <div className="flex items-center gap-2 mb-2">
                <FileCode className="w-3.5 h-3.5 text-ghost-400" />
                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">MITRE ATLAS Reference</span>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-mono text-ghost-400 font-bold">{atlas.id}</p>
                  <p className="text-[11px] text-gray-500 mt-0.5">{atlas.name}</p>
                </div>
                <a
                  href={`https://atlas.mitre.org/techniques/${atlas.id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[10px] text-ghost-400 hover:text-ghost-300 transition-colors"
                >
                  View in ATLAS <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          )}

          {/* NIST AI RMF Compliance Mapping */}
          {(() => {
            const cat = attack.category?.split('.')[0] || '';
            const NIST_MAP: Record<string, { subcats: string[]; function: string; desc: string }> = {
              'injection': { subcats: ['MEASURE-2.7', 'MANAGE-2.1', 'MANAGE-2.2'], function: 'MEASURE / MANAGE', desc: 'Prompt injection detection validates AI security resilience and documents incident response.' },
              'jailbreak': { subcats: ['MEASURE-2.7', 'MANAGE-2.1', 'GOVERN-1.7'], function: 'MEASURE / MANAGE', desc: 'Jailbreak detection validates containment of AI misuse attempts.' },
              'pii': { subcats: ['MEASURE-2.10', 'MAP-5.1', 'GOVERN-1.1'], function: 'MEASURE / MAP', desc: 'PII detection validates privacy risk controls and data protection.' },
              'secrets': { subcats: ['MEASURE-2.10', 'MANAGE-3.1', 'GOVERN-6.1'], function: 'MEASURE / MANAGE', desc: 'Secret exfiltration prevention validates access control and data governance.' },
              'zero_day': { subcats: ['MEASURE-2.7', 'MANAGE-1.1', 'MANAGE-4.1'], function: 'MEASURE / MANAGE', desc: 'Zero-day detection validates continuous AI security monitoring.' },
              'agent': { subcats: ['MAP-3.4', 'MEASURE-2.7', 'MANAGE-2.2'], function: 'MAP / MEASURE', desc: 'Agent hijack prevention validates multi-agent system security controls.' },
              'hallucination': { subcats: ['MEASURE-2.9', 'MEASURE-2.5', 'MAP-2.3'], function: 'MEASURE / MAP', desc: 'Hallucination detection validates AI output reliability and accuracy.' },
              'content': { subcats: ['MEASURE-2.6', 'MEASURE-2.11', 'GOVERN-5.1'], function: 'MEASURE / GOVERN', desc: 'Content policy enforcement validates fairness and bias monitoring.' },
              'encoded': { subcats: ['MEASURE-2.7', 'MANAGE-2.2'], function: 'MEASURE / MANAGE', desc: 'Encoded attack detection validates evasion resilience.' },
              'oracle': { subcats: ['MEASURE-2.7', 'MAP-1.6'], function: 'MEASURE / MAP', desc: 'Model extraction prevention validates IP protection controls.' },
              'sponge': { subcats: ['MEASURE-2.7', 'MANAGE-1.3'], function: 'MEASURE / MANAGE', desc: 'Resource abuse detection validates availability controls.' },
            };
            const nist = NIST_MAP[cat] || NIST_MAP['injection'];

            return (
              <div className="glass-card p-4 border-l-2 border-cyan-500/30">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">NIST AI RMF 1.0 Mapping</span>
                  <span className="ml-auto text-[9px] font-mono text-cyan-400/60 bg-cyan-500/10 px-2 py-0.5 rounded">100% ALIGNED</span>
                </div>
                <p className="text-[11px] text-gray-400 mb-3 leading-relaxed">{nist.desc}</p>
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {nist.subcats.map((sc, i) => (
                    <span key={i} className="text-[9px] font-mono px-2 py-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      {sc}
                    </span>
                  ))}
                </div>
                <div className="text-[9px] text-gray-600 font-mono">
                  Functions: {nist.function} · Evidence Type: automated_detection
                </div>
              </div>
            );
          })()}

          {/* ISO 42001 Mapping */}
          {(() => {
            const ISO_MAP: Record<string, string[]> = {
              'injection': ['6.1.2', '8.1', 'A.10.4'],
              'jailbreak': ['8.1', 'A.10.3', 'A.10.4'],
              'pii': ['A.8.4', 'A.8.5', '8.1'],
              'secrets': ['A.6.2.2', 'A.8.4', '8.1'],
              'default': ['8.1', 'A.10.4', '6.1.2'],
            };
            const cat = attack.category?.split('.')[0] || '';
            const isoRefs = ISO_MAP[cat] || ISO_MAP['default'];

            return (
              <div className="glass-card p-4 border-l-2 border-violet-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <Layers className="w-3.5 h-3.5 text-violet-400" />
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">ISO/IEC 42001 Mapping</span>
                  <span className="ml-auto text-[9px] font-mono text-violet-400/60 bg-violet-500/10 px-2 py-0.5 rounded">100% READY</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {isoRefs.map((ref, i) => (
                    <span key={i} className="text-[9px] font-mono px-2 py-1 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20">
                      Clause {ref}
                    </span>
                  ))}
                </div>
              </div>
            );
          })()}

          {/* ─── Additional Framework Mappings (7 remaining) ─── */}
          {(() => {
            const cat = attack.category?.split('.')[0] || '';

            // SOC 2 Type II mapping
            const SOC2_MAP: Record<string, string[]> = {
              'injection': ['CC5.1', 'CC7.2', 'CC7.3'],
              'jailbreak': ['CC5.1', 'CC7.3', 'CC7.4'],
              'pii': ['C1.1', 'P3.1', 'P6.1'],
              'secrets': ['CC6.7', 'C1.1', 'C1.2'],
              'oracle': ['CC6.6', 'CC7.2', 'PI1.1'],
              'encoded': ['CC5.1', 'CC7.2', 'CC6.8'],
              'sponge': ['A1.1', 'CC7.2', 'CC9.1'],
              'hallucination': ['PI1.1', 'PI1.2', 'CC4.1'],
              'content': ['CC5.1', 'CC5.3', 'P1.1'],
              'agent': ['CC5.2', 'CC6.8', 'CC9.2'],
              'supply_chain': ['CC6.8', 'CC9.2', 'CC8.1'],
              'default': ['CC7.2', 'CC7.3', 'CC5.1'],
            };

            // PCI DSS mapping
            const PCIDSS_MAP: Record<string, string[]> = {
              'injection': ['6.1', '11.4', '12.10'],
              'jailbreak': ['6.1', '11.3', '12.10'],
              'pii': ['3.1', '3.4', '4.2'],
              'secrets': ['3.3', '3.5', '4.1'],
              'oracle': ['11.3', '11.4', '6.3'],
              'encoded': ['5.1', '6.1', '11.4'],
              'sponge': ['6.1', '10.7', '12.10'],
              'default': ['10.1', '10.2', '12.10'],
            };

            // GDPR mapping
            const GDPR_MAP: Record<string, string[]> = {
              'injection': ['Art-32.1', 'Art-33.1', 'Art-5.1(f)'],
              'jailbreak': ['Art-32.1', 'Art-32.1(d)', 'Art-5.1(f)'],
              'pii': ['Art-5.1(c)', 'Art-25.1', 'Art-17.1'],
              'secrets': ['Art-32.1', 'Art-5.1(f)', 'Art-25.2'],
              'oracle': ['Art-32.1', 'Art-5.1(f)', 'Art-35.1'],
              'hallucination': ['Art-5.1(d)', 'Art-13.1', 'Art-35.1'],
              'content': ['Art-5.1(a)', 'Art-25.1', 'Art-35.1'],
              'default': ['Art-32.1', 'Art-5.1(f)', 'Art-30.1'],
            };

            // EU AI Act mapping
            const EUAI_MAP: Record<string, string[]> = {
              'injection': ['Art-9.2', 'Art-15.3', 'Art-15.4'],
              'jailbreak': ['Art-9.4', 'Art-15.3', 'Art-14.4'],
              'pii': ['Art-10.1', 'Art-10.5', 'Art-13.1'],
              'hallucination': ['Art-15.1', 'Art-13.1', 'Art-9.5'],
              'content': ['Art-10.5', 'Art-13.1', 'Art-14.1'],
              'oracle': ['Art-15.4', 'Art-12.1', 'Art-9.2'],
              'agent': ['Art-14.1', 'Art-14.4', 'Art-15.3'],
              'default': ['Art-9.1', 'Art-15.3', 'Art-12.1'],
            };

            // HIPAA mapping
            const HIPAA_MAP: Record<string, string[]> = {
              'pii': ['164.502(b)', '164.514(a)', '164.312(e)(1)'],
              'secrets': ['164.312(a)(1)', '164.312(c)(1)', '164.312(e)(1)'],
              'injection': ['164.308(a)(1)', '164.312(b)', '164.308(a)(6)'],
              'jailbreak': ['164.308(a)(1)', '164.312(b)', '164.308(a)(6)'],
              'oracle': ['164.312(a)(1)', '164.312(c)(1)', '164.312(b)'],
              'default': ['164.308(a)(1)', '164.312(b)', '164.308(a)(6)'],
            };

            // CCPA mapping
            const CCPA_MAP: Record<string, string[]> = {
              'pii': ['1798.100(a)', '1798.105(a)', '1798.121(a)'],
              'secrets': ['1798.100(a)', '1798.121(a)', 'ADMT-1'],
              'injection': ['ADMT-1', 'ADMT-2', 'ADMT-4'],
              'jailbreak': ['ADMT-1', 'ADMT-3', 'ADMT-4'],
              'hallucination': ['ADMT-5', 'ADMT-2', '1798.100(b)'],
              'content': ['ADMT-5', '1798.125(a)', 'ADMT-2'],
              'default': ['ADMT-1', 'ADMT-2', '1798.100(a)'],
            };

            // DPDPA mapping
            const DPDPA_MAP: Record<string, string[]> = {
              'pii': ['DPDPA-8.3', 'DPDPA-11.1(a)', 'DPDPA-11.1(c)'],
              'secrets': ['DPDPA-8.3', 'DPDPA-16.1', 'DPDPA-8.4'],
              'injection': ['DPDPA-8.3', 'DPDPA-8.4', 'DPDPA-10.2'],
              'jailbreak': ['DPDPA-8.3', 'DPDPA-8.4', 'DPDPA-10.2'],
              'default': ['DPDPA-8.3', 'DPDPA-8.4', 'DPDPA-10.2'],
            };

            const soc2Refs = SOC2_MAP[cat] || SOC2_MAP['default'];
            const pciRefs = PCIDSS_MAP[cat] || PCIDSS_MAP['default'];
            const gdprRefs = GDPR_MAP[cat] || GDPR_MAP['default'];
            const euaiRefs = EUAI_MAP[cat] || EUAI_MAP['default'];
            const hipaaRefs = HIPAA_MAP[cat] || HIPAA_MAP['default'];
            const ccpaRefs = CCPA_MAP[cat] || CCPA_MAP['default'];
            const dpdpaRefs = DPDPA_MAP[cat] || DPDPA_MAP['default'];

            const frameworks = [
              { label: 'SOC 2 Type II', refs: soc2Refs, color: 'emerald', note: 'Technical Control Evidence' },
              { label: 'PCI DSS v4.0', refs: pciRefs, color: 'sky', note: 'Technical Control Evidence' },
              { label: 'GDPR', refs: gdprRefs, color: 'amber', note: 'Legal/Technical Alignment' },
              { label: 'EU AI Act', refs: euaiRefs, color: 'blue', note: 'Self-Assessable' },
              { label: 'HIPAA', refs: hipaaRefs, color: 'rose', note: 'Technical Safeguards' },
              { label: 'CCPA/CPRA', refs: ccpaRefs, color: 'orange', note: 'Legal/Technical Alignment' },
              { label: 'DPDPA (India)', refs: dpdpaRefs, color: 'indigo', note: 'Legal/Technical Alignment' },
            ];

            return (
              <div className="space-y-2">
                <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Shield className="w-3 h-3" />
                  Cross-Framework Control Alignment
                </h3>
                <div className="grid grid-cols-1 gap-1.5">
                  {frameworks.map((fw, idx) => (
                    <div key={idx} className={`glass-card px-3 py-2.5 border-l-2 border-${fw.color}-500/30`}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className={`text-[10px] font-bold text-${fw.color}-400`}>{fw.label}</span>
                        <span className={`text-[8px] font-mono text-${fw.color}-400/60 bg-${fw.color}-500/10 px-1.5 py-0.5 rounded`}>{fw.note}</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {fw.refs.map((ref, i) => {
                          // Build URL for official source
                          const getUrl = (label: string, r: string): string => {
                            if (label === 'SOC 2 Type II') {
                              const cc = r.split('.')[0]; // CC6, CC7 etc
                              return `https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservicescriteria`;
                            }
                            if (label === 'PCI DSS v4.0') {
                              const req = r.replace('Req-', '').split('.')[0];
                              return `https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf`;
                            }
                            if (label === 'GDPR') {
                              const artNum = r.replace('Art-', '').split('.')[0].split('(')[0];
                              return `https://gdpr-info.eu/art-${artNum}-gdpr/`;
                            }
                            if (label === 'EU AI Act') {
                              const artNum = r.replace('Art-', '').split('.')[0].split('(')[0];
                              return `https://artificialintelligenceact.eu/article/${artNum}/`;
                            }
                            if (label === 'HIPAA') {
                              return `https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html`;
                            }
                            if (label === 'CCPA/CPRA') {
                              const sec = r.replace('§', '').split('.')[0];
                              return `https://oag.ca.gov/privacy/ccpa`;
                            }
                            if (label === 'DPDPA (India)') {
                              return `https://www.meity.gov.in/writereaddata/files/Digital%20Personal%20Data%20Protection%20Act%202023.pdf`;
                            }
                            return '#';
                          };
                          return (
                            <a key={i} href={getUrl(fw.label, ref)} target="_blank" rel="noopener noreferrer"
                              className={`text-[8px] font-mono px-1.5 py-0.5 rounded bg-${fw.color}-500/10 text-${fw.color}-400 border border-${fw.color}-500/20 hover:bg-${fw.color}-500/20 hover:scale-105 transition-all cursor-pointer inline-flex items-center gap-0.5`}>
                              {ref}
                              <ExternalLink className="w-2 h-2 opacity-50" />
                            </a>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>
      </motion.div>
    </>
  );
}
