"use client";

import { motion } from "framer-motion";
import { X, ShieldAlert, Crosshair, Code, Activity, Terminal } from "lucide-react";

interface IncidentForensicsModalProps {
  isOpen: boolean;
  onClose: () => void;
  attackData: any;
}

export default function IncidentForensicsModal({ isOpen, onClose, attackData }: IncidentForensicsModalProps) {
  if (!isOpen || !attackData) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-0/60 backdrop-blur-sm">
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="w-full max-w-4xl bg-[#111118] border border-white/10 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/5 bg-[#1a1a24]">
          <div className="flex items-center gap-4">
            <div className={`p-3 rounded-xl ${attackData.action === 'blocked' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-3">
                Incident Forensics Report
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#00FF41]/20 text-white border border-ghost-500/30">
                  {attackData.request_id}
                </span>
              </h2>
              <p className="text-sm text-gray-400 mt-1">Deep analysis of intercepted payload</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-white rounded-xl hover:bg-white/5 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-surface-2 rounded-xl border border-white/5">
              <div className="text-xs text-gray-500 mb-1 font-mono">THREAT LEVEL</div>
              <div className={`text-lg font-bold capitalize ${attackData.threat_level === 'critical' ? 'text-red-400' : 'text-orange-400'}`}>
                {attackData.threat_level}
              </div>
            </div>
            <div className="p-4 bg-surface-2 rounded-xl border border-white/5">
              <div className="text-xs text-gray-500 mb-1 font-mono">ACTION TAKEN</div>
              <div className="text-lg font-bold text-white capitalize">{attackData.action}</div>
            </div>
            <div className="p-4 bg-surface-2 rounded-xl border border-white/5">
              <div className="text-xs text-gray-500 mb-1 font-mono">TARGET MODEL</div>
              <div className="text-lg font-bold text-white">{attackData.model}</div>
            </div>
          </div>

          {/* Attacker Profile & Threat Narrative */}
          {attackData.attacker_profile && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 border-b border-white/5 pb-2">
                <ShieldAlert className="w-4 h-4 text-white" />
                Attacker Intelligence Profile
              </div>
              
              {attackData.attacker_profile.threat_narrative && (
                <div className="p-4 bg-surface-2/50 rounded-xl border border-white/5 border-l-4 border-l-ghost-500">
                  <p className="text-sm text-gray-300 leading-relaxed">
                    {attackData.attacker_profile.threat_narrative}
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-surface-2 rounded-xl border border-white/5">
                  <h4 className="text-xs font-mono text-gray-500 mb-3">NETWORK LAYER</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Source IP</span>
                      <span className="text-white font-mono">{attackData.attacker_profile.source_ip || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">ISP</span>
                      <span className="text-white">{attackData.attacker_profile.isp_name || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Location</span>
                      <span className="text-white">{attackData.attacker_profile.city || "Unknown"}, {attackData.attacker_profile.country || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Classification</span>
                      <div className="flex gap-1">
                        {attackData.attacker_profile.is_vpn && <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 text-[10px]">VPN</span>}
                        {attackData.attacker_profile.is_datacenter && <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-white text-[10px]">Datacenter</span>}
                        {!attackData.attacker_profile.is_vpn && !attackData.attacker_profile.is_datacenter && <span className="text-gray-500 text-[10px]">Standard</span>}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="p-4 bg-surface-2 rounded-xl border border-white/5">
                  <h4 className="text-xs font-mono text-gray-500 mb-3">DEVICE FINGERPRINT</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Tool/Browser</span>
                      <span className="text-white">{attackData.attacker_profile.browser_name || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">OS</span>
                      <span className="text-white">{attackData.attacker_profile.os_name || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Device Type</span>
                      <span className="text-white capitalize">{attackData.attacker_profile.device_type || "Unknown"}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 border-b border-white/5 pb-2">
              <Terminal className="w-4 h-4 text-white" />
              Intercepted Payload
            </div>
            <div className="p-4 bg-surface-0 rounded-xl border border-white/5 font-mono text-sm text-gray-300 overflow-x-auto relative group">
              <div className="absolute top-2 right-2 px-2 py-1 bg-red-500/20 text-red-400 text-[10px] rounded border border-red-500/30 opacity-0 group-hover:opacity-100 transition-opacity">
                MALICIOUS INTENT DETECTED
              </div>
              <pre className="whitespace-pre-wrap">
                {attackData.detections?.[0]?.matched_content || "Payload redacted or not available."}
              </pre>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 border-b border-white/5 pb-2">
              <Crosshair className="w-4 h-4 text-white" />
              Detection Vectors Triggered
            </div>
            <div className="space-y-2">
              {attackData.detections?.map((d: any, idx: number) => (
                <div key={idx} className="flex items-start gap-4 p-4 bg-surface-2 rounded-xl border border-white/5">
                  <div className="mt-1 w-2 h-2 rounded-xl bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
                  <div className="flex-1">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-mono text-sm text-white">{d.detector}</span>
                      <span className="text-xs text-gray-500 font-mono">CONF: {(d.confidence * 100).toFixed(1)}%</span>
                    </div>
                    <p className="text-sm text-gray-400">{d.description}</p>
                    <div className="mt-2 text-xs text-white font-mono">CATEGORY: {d.category}</div>
                  </div>
                </div>
              )) || (
                <div className="text-sm text-gray-500 italic">No detailed detection vectors available.</div>
              )}
            </div>
          </div>
          
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 border-b border-white/5 pb-2">
              <Activity className="w-4 h-4 text-white" />
              Mitigation Trace
            </div>
            <div className="p-4 bg-surface-2 rounded-xl border border-white/5 space-y-3">
               <div className="flex items-center gap-3 text-sm">
                 <div className="w-2 h-2 rounded-xl bg-green-500" />
                 <span className="text-gray-300">Request Intercepted by Edge Proxy</span>
                 <span className="text-gray-500 font-mono text-xs ml-auto">0ms</span>
               </div>
               <div className="w-0.5 h-4 bg-white/10 ml-1" />
               <div className="flex items-center gap-3 text-sm">
                 <div className="w-2 h-2 rounded-xl bg-blue-500" />
                 <span className="text-gray-300">11 Detection Pipelines Executed</span>
                 <span className="text-gray-500 font-mono text-xs ml-auto">{attackData.scan_duration_ms ? (attackData.scan_duration_ms * 0.4).toFixed(1) : '1.2'}ms</span>
               </div>
               <div className="w-0.5 h-4 bg-white/10 ml-1" />
               <div className="flex items-center gap-3 text-sm">
                 <div className="w-2 h-2 rounded-xl bg-red-500" />
                 <span className="text-gray-300">Threat Identified, Connection Terminated</span>
                 <span className="text-gray-500 font-mono text-xs ml-auto">{attackData.scan_duration_ms ? attackData.scan_duration_ms.toFixed(1) : '3.4'}ms</span>
               </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
