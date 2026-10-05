'use client';

import React from 'react';
import { X, Network, ShieldAlert, Cpu, GitBranch, MapPin, Activity, Terminal, Clock, Search, Database } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface ThreatSidePanelProps {
  attack: any | null;
  onClose: () => void;
}

export default function ThreatSidePanel({ attack, onClose }: ThreatSidePanelProps) {
  if (!attack) return null;

  if (attack.isCluster) {
    return (
      <AnimatePresence>
        <motion.div 
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 25, stiffness: 200 }}
          className="fixed top-0 right-0 h-full w-[450px] bg-[#050914]/95 backdrop-blur-xl border-l border-[#1e293b] shadow-[-20px_0_50px_rgba(0,0,0,0.8)] z-50 flex flex-col font-mono"
        >
          {/* HEADER */}
          <div className={`p-4 border-b flex items-center justify-between bg-[#1e293b]/50 border-blue-500/30 relative overflow-hidden`}>
            <div className="absolute inset-0 bg-[url('/bg/scanlines.png')] opacity-10 mix-blend-overlay pointer-events-none" />
            <div className="flex items-center gap-3 relative z-10">
              <Network className="w-6 h-6 text-blue-400 animate-pulse" />
              <div>
                <h2 className="font-bold tracking-widest uppercase text-white">
                  THREAT CLUSTER
                </h2>
                <p className="text-[10px] text-blue-400 font-bold">{attack.count} ACTIVE THREATS</p>
              </div>
            </div>
            <button 
              onClick={onClose}
              className="w-8 h-8 flex items-center justify-center bg-black/50 hover:bg-black border border-[#1e293b] rounded transition-colors text-gray-400 hover:text-white relative z-10"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-6 space-y-4 scrollbar-thin scrollbar-thumb-[#1e293b] scrollbar-track-transparent">
            <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
              <MapPin className="w-3.5 h-3.5" /> CLUSTER INTELLIGENCE
            </h3>
            
            <div className="space-y-3">
              {attack.children?.map((child: any, idx: number) => {
                const raw = child.rawAttack || {};
                return (
                <div key={idx} className="bg-[#080d1e] border border-[#1e293b] rounded-lg p-3 relative overflow-hidden group hover:border-blue-500/30 transition-colors cursor-pointer"
                  onClick={() => onClose()}
                >
                  <div className="absolute left-0 top-0 w-1 h-full" style={{ backgroundColor: child.color }} />
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold uppercase text-gray-300">{child.scan_type || raw.scan_type?.toUpperCase() || 'PROMPT'}</span>
                    <span style={{ color: child.color }} className="text-[10px] font-bold tracking-wider">{child.threat_level || raw.threat_level?.toUpperCase() || 'UNKNOWN'}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[10px]">
                    <div>
                      <div className="text-gray-500">IP</div>
                      <div className="text-gray-400 font-mono">{child.ip || raw.ip || '127.0.0.1'}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">LOCATION</div>
                      <div className="text-gray-400">{child.city || raw.city || 'Unknown'}, {child.country || raw.country || 'Unknown'}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">TARGET</div>
                      <div className="text-gray-400 truncate">{raw.model || raw.model_provider || raw.model_name || 'Unknown'}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">TOOL / AGENT</div>
                      <div className="text-gray-400 truncate">{raw.user_agent?.split('/')[0] || raw.browser || raw.tool || 'Browser'}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">ACTION</div>
                      <div className={`font-bold ${raw.action === 'blocked' ? 'text-red-400' : 'text-emerald-400'}`}>{(raw.action || 'blocked').toUpperCase()}</div>
                    </div>
                    <div>
                      <div className="text-gray-500">TIMESTAMP</div>
                      <div className="text-gray-400 font-mono">{raw.created_at ? new Date(raw.created_at).toLocaleTimeString() : '--:--:--'}</div>
                    </div>
                  </div>
                  {/* Detection categories */}
                  {raw.detections?.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-[#1e293b] flex flex-wrap gap-1">
                      {raw.detections.slice(0, 3).map((det: any, di: number) => (
                        <span key={di} className="text-[9px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded font-mono">
                          {det.category || 'threat'}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
              })}
            </div>
          </div>
        </motion.div>
      </AnimatePresence>
    );
  }

  const threatColor = 
    attack.threat_level?.toLowerCase() === 'critical' ? 'text-red-500' : 
    attack.threat_level?.toLowerCase() === 'high' ? 'text-orange-500' : 
    attack.threat_level?.toLowerCase() === 'medium' ? 'text-cyan-500' : 'text-blue-500';

  const threatBg = 
    attack.threat_level?.toLowerCase() === 'critical' ? 'bg-red-500/10 border-red-500/30' : 
    attack.threat_level?.toLowerCase() === 'high' ? 'bg-orange-500/10 border-orange-500/30' : 
    attack.threat_level?.toLowerCase() === 'medium' ? 'bg-cyan-500/10 border-cyan-500/30' : 'bg-blue-500/10 border-blue-500/30';

  return (
    <AnimatePresence>
      <motion.div 
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 25, stiffness: 200 }}
        className="fixed top-0 right-0 h-full w-[450px] bg-[#050914]/95 backdrop-blur-xl border-l border-[#1e293b] shadow-[-20px_0_50px_rgba(0,0,0,0.8)] z-50 flex flex-col font-mono"
      >
        {/* HEADER */}
        <div className={`p-4 border-b flex items-center justify-between ${threatBg} relative overflow-hidden`}>
          <div className="absolute inset-0 bg-[url('/bg/scanlines.png')] opacity-10 mix-blend-overlay pointer-events-none" />
          <div className="flex items-center gap-3 relative z-10">
            <ShieldAlert className={`w-6 h-6 ${threatColor} animate-pulse`} />
            <div>
              <h2 className={`font-bold tracking-widest uppercase ${threatColor}`}>
                THREAT INTEL // {attack.threat_level || 'UNKNOWN'}
              </h2>
              <p className="text-[10px] text-gray-400">ID: {attack.id || attack.request_id}</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center bg-black/50 hover:bg-black border border-[#1e293b] rounded transition-colors text-gray-400 hover:text-white relative z-10"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-8 scrollbar-thin scrollbar-thumb-[#1e293b] scrollbar-track-transparent">
          
          {/* LOCATION INTELLIGENCE */}
          <section>
            <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
              <MapPin className="w-3.5 h-3.5" /> LOCATION INTELLIGENCE
            </h3>
            <div className="bg-[#080d1e] border border-[#1e293b] rounded-lg p-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">ORIGIN IP</div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-gray-300 font-bold">{attack.ip || '127.0.0.1'}</span>
                    {attack.asn && <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#1e293b] text-gray-400 font-mono">{attack.asn}</span>}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">CITY / COUNTRY</div>
                  <div className="text-sm text-gray-300 font-bold">{attack.city}, {attack.country}</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">COORDINATES</div>
                  <div className="text-xs text-blue-400 bg-blue-500/10 px-2 py-1 rounded inline-block">
                    {attack.lat?.toFixed(4) || '0.0000'}, {attack.lng?.toFixed(4) || '0.0000'}
                  </div>
                </div>
                {(attack.is_vpn || attack.is_tor || attack.is_proxy) && (
                  <div>
                    <div className="text-[10px] text-gray-500 mb-1">ANONYMIZATION</div>
                    <div className="flex flex-wrap gap-1">
                      {attack.is_vpn && <span className="text-[9px] bg-orange-500/10 text-orange-400 px-1.5 py-0.5 rounded border border-orange-500/20">VPN DETECTED</span>}
                      {attack.is_tor && <span className="text-[9px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded border border-red-500/20">TOR EXIT NODE</span>}
                      {attack.is_proxy && <span className="text-[9px] bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded border border-amber-500/20">PROXY</span>}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </section>

          {/* NETWORK TELEMETRY */}
          <section>
            <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
              <Clock className="w-3.5 h-3.5" /> NETWORK TELEMETRY
            </h3>
            <div className="bg-[#080d1e] border border-[#1e293b] rounded-lg p-4 flex items-center justify-between">
              <div>
                <div className="text-[10px] text-gray-500 mb-1">RTT (LATENCY)</div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-300 font-bold">{attack.latency_ms ? `${attack.latency_ms.toFixed(1)}ms` : 'N/A'}</span>
                  {attack.latency_ms > 200 && <span className="text-[9px] text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded">HIGH LATENCY</span>}
                </div>
              </div>
              <div className="text-right">
                <div className="text-[10px] text-gray-500 mb-1">DATA PROVIDER</div>
                <div className="flex items-center gap-1 justify-end text-[10px] text-emerald-400 font-bold tracking-wider">
                  <Database className="w-3 h-3" />
                  IPINFO.IO LIVE
                </div>
              </div>
            </div>
          </section>

          {/* TRACEBACK EVIDENCE CHAIN */}
          {attack.traceback_evidence_chain?.length > 0 && (
            <section>
              <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
                <Search className="w-3.5 h-3.5" /> TRACEBACK EVIDENCE
              </h3>
              <div className="relative border-l border-[#1e293b] ml-3 space-y-4 pb-2 mt-4">
                {attack.traceback_evidence_chain.map((ev: any, idx: number) => (
                  <div key={idx} className="relative pl-6 group">
                    <div className="absolute left-[-13px] top-1 w-6 h-6 rounded-full border border-[#1e293b] bg-[#050914] flex items-center justify-center z-10 transition-colors group-hover:border-blue-500/50 group-hover:bg-blue-500/10">
                      <span className="text-[9px] font-bold text-gray-400 group-hover:text-blue-400">{idx + 1}</span>
                    </div>
                    <div className="bg-[#080d1e] p-3 rounded border border-[#1e293b] group-hover:border-blue-500/30 transition-colors">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">{ev.step}</span>
                        <span className="text-[9px] text-emerald-400/80 font-mono bg-emerald-500/10 px-1.5 py-0.5 rounded">
                          {ev.confidence ? `${(ev.confidence*100).toFixed(0)}% CONF` : '100% CONF'}
                        </span>
                      </div>
                      <div className="text-xs text-gray-300 font-medium mb-1">{ev.source}</div>
                      <p className="text-[10px] text-gray-500 leading-relaxed">{ev.details}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ATTACK INTELLIGENCE */}
          <section>
            <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
              <Activity className="w-3.5 h-3.5" /> ATTACK INTELLIGENCE
            </h3>
            <div className="bg-[#080d1e] border border-[#1e293b] rounded-lg p-4 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">SCAN TYPE</div>
                  <div className="text-sm text-gray-300 font-bold uppercase">{attack.scan_type || 'PROMPT'}</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">ACTION TAKEN</div>
                  <div className={`text-sm font-bold uppercase ${attack.action === 'blocked' ? 'text-red-400' : 'text-emerald-400'}`}>
                    {attack.action || 'ALLOWED'}
                  </div>
                </div>
              </div>
              
              <div>
                <div className="text-[10px] text-gray-500 mb-1">TARGET MODEL</div>
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-300 font-bold uppercase">{attack.model_provider || 'UNKNOWN'} // {attack.model || attack.model_name || 'UNKNOWN'}</span>
                </div>
              </div>
            </div>
          </section>

          {/* DETECTION INTELLIGENCE */}
          <section>
            <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
              <Network className="w-3.5 h-3.5" /> DETECTION INTELLIGENCE
            </h3>
            <div className="space-y-2">
              {attack.detections?.length > 0 ? (
                attack.detections.map((det: any, idx: number) => (
                  <div key={idx} className="bg-[#080d1e] border border-[#1e293b] border-l-2 border-l-red-500 p-3 rounded-r-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-red-400 uppercase">{det.category || 'UNKNOWN_THREAT'}</span>
                      <span className="text-[10px] text-gray-500">{((det.confidence || 0.95) * 100).toFixed(0)}% CONF</span>
                    </div>
                    {det.description && <p className="text-[10px] text-gray-400 mt-1">{det.description}</p>}
                  </div>
                ))
              ) : (
                <div className="text-xs text-gray-500 italic p-3 bg-[#080d1e] border border-[#1e293b] rounded-lg">No advanced heuristics available.</div>
              )}
            </div>
          </section>

          {/* PAYLOAD TELEMETRY */}
          {attack.prompt && (
            <section>
              <h3 className="text-xs text-gray-500 font-bold mb-3 flex items-center gap-2 border-b border-[#1e293b] pb-2">
                <Terminal className="w-3.5 h-3.5" /> PAYLOAD TELEMETRY
              </h3>
              <div className="bg-[#050a18] border border-[#1e293b] rounded-lg p-3 relative overflow-hidden group">
                <div className="absolute top-0 left-0 w-1 h-full bg-red-500" />
                <pre className="text-[10px] text-red-400/80 whitespace-pre-wrap pl-2 break-all max-h-[150px] overflow-y-auto scrollbar-thin">
                  {attack.prompt}
                </pre>
              </div>
            </section>
          )}

          {/* METADATA */}
          <section className="pt-4 border-t border-[#1e293b]">
            <div className="flex items-center justify-between text-[9px] text-gray-600">
              <span className="flex items-center gap-1"><GitBranch className="w-3 h-3" /> NODE: SEC-ALPHA-01</span>
              <span>TIMESTAMP: {new Date(attack.created_at).toISOString()}</span>
            </div>
          </section>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}
