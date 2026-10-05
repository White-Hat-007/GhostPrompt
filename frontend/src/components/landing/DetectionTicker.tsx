'use client';

import { motion } from 'framer-motion';

const TECHNIQUE_IDS = [
  { id: 'AML.T0051', name: 'LLM Prompt Injection', severity: 'critical' },
  { id: 'AML.T0054', name: 'LLM Jailbreak', severity: 'high' },
  { id: 'AML.T0024', name: 'Exfiltration via Inference API', severity: 'high' },
  { id: 'AML.T0070', name: 'RAG Poisoning', severity: 'critical' },
  { id: 'AML.T0110', name: 'Agent Tool Poisoning', severity: 'high' },
  { id: 'AML.T0029', name: 'Denial of AI Service', severity: 'medium' },
  { id: 'AML.T0034', name: 'Cost Harvesting', severity: 'medium' },
  { id: 'AML.T0010', name: 'AI Supply Chain Compromise', severity: 'critical' },
  { id: 'AML.T0086', name: 'Exfil via Agent Tool', severity: 'high' },
  { id: 'AML.T0043', name: 'Data Poisoning', severity: 'critical' },
  { id: 'AML.T0015', name: 'Model Evasion', severity: 'high' },
  { id: 'AML.T0047', name: 'Backdoor ML Model', severity: 'critical' },
  { id: 'GP.PACK', name: 'Pack Hunt Fragmentation', severity: 'critical' },
  { id: 'GP.PLINY', name: 'Pliny-Class Jailbreak', severity: 'critical' },
  { id: 'GP.ZDAY', name: 'Zero-Day Pattern', severity: 'high' },
  { id: 'GP.MULTI', name: 'Multi-Agent Poisoning', severity: 'high' },
  { id: 'GP.SPONGE', name: 'Sponge DoS', severity: 'critical' },
  { id: 'GP.ORACLE', name: 'Oracle Extraction', severity: 'high' },
];

const sevDot: Record<string, string> = {
  critical: 'bg-red-400 shadow-[0_0_6px_rgba(239,68,68,0.6)]',
  high: 'bg-amber-400 shadow-[0_0_6px_rgba(245,158,11,0.4)]',
  medium: 'bg-cyan-400 shadow-[0_0_6px_rgba(6,182,212,0.3)]',
};
const sevText: Record<string, string> = {
  critical: 'text-red-400/80',
  high: 'text-amber-400/70',
  medium: 'text-cyan-400/60',
};

export default function DetectionTicker() {
  const prefersReducedMotion = typeof window !== 'undefined'
    ? window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches
    : false;

  const items = [...TECHNIQUE_IDS, ...TECHNIQUE_IDS];

  return (
    <div className="w-full py-3 border-y border-white/[0.04] bg-surface-0/50 backdrop-blur-sm overflow-hidden relative">
      {/* Edge fade masks */}
      <div className="absolute inset-y-0 left-0 w-24 bg-gradient-to-r from-surface-0 to-transparent z-10 pointer-events-none" />
      <div className="absolute inset-y-0 right-0 w-24 bg-gradient-to-l from-surface-0 to-transparent z-10 pointer-events-none" />

      <div className="marquee-container">
        <div
          className="marquee-content gap-6"
          style={prefersReducedMotion ? { animation: 'none' } : {}}
        >
          {items.map((tech, i) => (
            <span key={`${tech.id}-${i}`} className="flex items-center gap-2 flex-shrink-0 group">
              <span className={`w-1.5 h-1.5 rounded-full ${sevDot[tech.severity]} flex-shrink-0`} />
              <span className="font-mono text-[10px] tracking-wider text-gray-600 group-hover:text-gray-400 transition-colors">{tech.id}</span>
              <span className={`font-mono text-[10px] tracking-wide ${sevText[tech.severity]} group-hover:text-white/60 transition-colors`}>{tech.name}</span>
              <span className="text-gray-800/50 mx-1 select-none">•</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
