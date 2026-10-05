'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, AlertTriangle, XCircle, Clock, Zap, ExternalLink, ChevronRight } from 'lucide-react';
import IncidentDrawer from './IncidentDrawer';

interface Attack {
  id: string;
  request_id: string;
  threat_level: string;
  threat_score: number;
  action: string;
  scan_type: string;
  model: string;
  created_at: string;
  category?: string;
  prompt?: string;
  detections?: Array<{ detector: string; confidence: number; description: string; category?: string }>;
  ip?: string;
  city?: string;
  country?: string;
}

interface LiveAttackFeedProps {
  attacks: Attack[];
  fullView?: boolean;
  onAttackClick?: (attack: any) => void;
}

// ATLAS technique ID mapping — maps detection categories to MITRE ATLAS technique IDs
const ATLAS_MAP: Record<string, { id: string; name: string }> = {
  'injection': { id: 'AML.T0051', name: 'LLM Prompt Injection' },
  'injection.direct_override': { id: 'AML.T0051.000', name: 'Direct Override' },
  'injection.instruction_bypass': { id: 'AML.T0051.001', name: 'Instruction Bypass' },
  'jailbreak': { id: 'AML.T0054', name: 'LLM Jailbreak' },
  'jailbreak.persona_switch': { id: 'AML.T0054.000', name: 'Persona Switch' },
  'jailbreak.hypothetical': { id: 'AML.T0054.001', name: 'Hypothetical Framing' },
  'pliny': { id: 'AML.T0054.002', name: 'Pliny-Class Jailbreak' },
  'encoded': { id: 'AML.T0015', name: 'Evade ML Model' },
  'pii': { id: 'AML.T0024', name: 'Exfiltration via Inference API' },
  'secrets': { id: 'AML.T0024.001', name: 'Secret Exfiltration' },
  'oracle': { id: 'AML.T0044', name: 'Full ML Model Access' },
  'policy': { id: 'AML.T0048', name: 'AI Policy Violation' },
  'tokenizer': { id: 'AML.T0043', name: 'Craft Adversarial Data' },
  'zero_day': { id: 'AML.T0000', name: 'Novel Attack Vector' },
  'sponge': { id: 'AML.T0029', name: 'Denial of ML Service' },
  'agent': { id: 'AML.T0052', name: 'Agent Hijacking' },
  'external': { id: 'AML.T0051.002', name: 'Indirect Prompt Injection' },
  'memorization': { id: 'AML.T0024.002', name: 'Training Data Extraction' },
  'supply_chain': { id: 'AML.T0010', name: 'ML Supply Chain Compromise' },
  'hallucination': { id: 'AML.T0048.001', name: 'Hallucination Exploit' },
  'content': { id: 'AML.T0048.002', name: 'Content Policy Violation' },
  'semantic': { id: 'AML.T0043.001', name: 'Semantic Adversarial' },
  'multi_turn': { id: 'AML.T0051.003', name: 'Multi-Turn Manipulation' },
  'campaign': { id: 'AML.T0011', name: 'Coordinated Campaign' },
};

function getAtlasId(category?: string): { id: string; name: string } | null {
  if (!category) return null;
  const prefix = category.split('.')[0];
  return ATLAS_MAP[category] || ATLAS_MAP[prefix] || null;
}

const THREAT_ICONS: Record<string, typeof AlertTriangle> = {
  critical: XCircle,
  high: AlertTriangle,
  medium: Zap,
  low: Shield,
};

const THREAT_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20' },
  medium: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20' },
  safe: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20' },
};

const timeAgo = (date: string): string => {
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};

export default function LiveAttackFeed({ attacks, fullView, onAttackClick }: LiveAttackFeedProps) {
  const displayAttacks = fullView ? attacks : attacks.slice(0, 8);
  const [selectedAttack, setSelectedAttack] = useState<Attack | null>(null);

  return (
    <>
      <div className="glass-card overflow-hidden">
        {/* Header — Enhanced */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.04] relative">
          <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-red-500/20 to-transparent" />
          <div className="flex items-center gap-3">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
            </span>
            <h3 className="text-sm font-semibold text-white">Live Attack Feed</h3>
            <motion.span
              className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-mono font-bold border border-red-500/15"
              key={displayAttacks.length}
              initial={{ scale: 1.2 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 500 }}
            >
              {displayAttacks.length} EVENTS
            </motion.span>
          </div>
          <span className="text-[10px] text-gray-600 uppercase tracking-wider font-mono">Real-time • ATLAS Mapped</span>
        </div>

        {/* Feed — Enhanced with 3D hover */}
        <div className={`divide-y divide-white/[0.03] overflow-y-auto scrollbar-none ${fullView ? 'h-[calc(100vh-180px)]' : 'max-h-[500px]'}`}>
          {displayAttacks.map((attack, index) => {
            const Icon = THREAT_ICONS[attack.threat_level] || Shield;
            const colors = THREAT_COLORS[attack.threat_level] || THREAT_COLORS.low;
            const atlas = getAtlasId(attack.category);

            return (
              <motion.div
                key={`${attack.request_id || 'attack'}-${index}`}
                initial={{ opacity: 0, x: -12, filter: 'blur(2px)' }}
                animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
                transition={{ delay: index * 0.03, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                onClick={() => setSelectedAttack(attack)}
                whileHover={{ backgroundColor: 'rgba(255,255,255,0.02)', x: 2 }}
                className="flex items-center gap-3 px-5 py-3 transition-colors cursor-pointer group relative"
              >
                {/* Left accent line on hover */}
                <motion.div
                  className={`absolute left-0 top-0 bottom-0 w-[2px] ${
                    attack.threat_level === 'critical' ? 'bg-red-500' :
                    attack.threat_level === 'high' ? 'bg-orange-500' :
                    attack.threat_level === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                  }`}
                  initial={{ scaleY: 0 }}
                  whileHover={{ scaleY: 1 }}
                  transition={{ duration: 0.2 }}
                />

                {/* Threat severity icon */}
                <motion.div
                  className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${colors.bg} border ${colors.border}`}
                  whileHover={{ scale: 1.1 }}
                  transition={{ type: 'spring', stiffness: 400 }}
                >
                  <Icon className={`w-4 h-4 ${colors.text}`} />
                </motion.div>

                {/* Details */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider ${colors.bg} ${colors.text}`}>
                      {attack.threat_level}
                    </span>
                    {atlas && (
                      <span className="data-tag text-[9px]">
                        {atlas.id}
                      </span>
                    )}
                    <span className="text-[10px] text-gray-500 font-mono truncate">{attack.category || attack.scan_type}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] text-gray-600 font-mono">{attack.model}</span>
                    {attack.ip && (
                      <>
                        <span className="text-gray-700">·</span>
                        <span className="text-[10px] text-gray-600 font-mono">{attack.ip}</span>
                      </>
                    )}
                    {attack.city && (
                      <>
                        <span className="text-gray-700">·</span>
                        <span className="text-[10px] text-gray-600">{attack.city}, {attack.country}</span>
                      </>
                    )}
                  </div>
                </div>

                {/* Score + Action + Time */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <div className="text-right">
                    <p className={`text-xs font-bold font-mono ${
                      attack.threat_score >= 0.8 ? 'text-red-400' :
                      attack.threat_score >= 0.5 ? 'text-amber-400' : 'text-gray-400'
                    }`}>
                      {(attack.threat_score * 100).toFixed(0)}%
                    </p>
                  </div>
                  <span className={`text-[9px] font-bold px-2 py-1 rounded-md uppercase tracking-wider ${
                    attack.action === 'blocked' ? 'bg-red-500/10 text-red-400 border border-red-500/15' :
                    attack.action === 'flagged' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/15' :
                    'bg-emerald-500/10 text-emerald-400 border border-emerald-500/15'
                  }`}>
                    {attack.action}
                  </span>
                  <span className="text-[10px] text-gray-600 w-14 text-right font-mono">
                    {timeAgo(attack.created_at)}
                  </span>
                  <ChevronRight className="w-3 h-3 text-gray-700 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </motion.div>
            );
          })}

          {displayAttacks.length === 0 && (
            <div className="px-5 py-12 text-center">
              <Shield className="w-8 h-8 text-gray-700 mx-auto mb-3" />
              <p className="text-sm text-gray-500">No threat events detected</p>
              <p className="text-xs text-gray-600 mt-1">Run the Live Scanner to generate telemetry</p>
            </div>
          )}
        </div>
      </div>
    
      <AnimatePresence>
        {selectedAttack && (
          <IncidentDrawer
            isOpen={!!selectedAttack}
            onClose={() => {
              setSelectedAttack(null);
              if (onAttackClick) onAttackClick(null);
            }}
            attack={selectedAttack}
          />
        )}
      </AnimatePresence>
    </>
  );
}
