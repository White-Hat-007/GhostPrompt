'use client';

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { Grid3x3, ExternalLink } from 'lucide-react';

interface AtlasMatrixLiveProps {
  scans: Array<{
    category?: string;
    scan_type?: string;
    threat_level?: string;
    threat_score?: number;
    detections?: Array<{ detector: string; category?: string }>;
  }>;
  className?: string;
}

// ATLAS Tactics (columns) — condensed to the AI-relevant subset
const TACTICS = [
  { id: 'recon', name: 'Reconnaissance', short: 'RECON' },
  { id: 'resource', name: 'Resource Dev', short: 'RES.DEV' },
  { id: 'access', name: 'ML Model Access', short: 'ACCESS' },
  { id: 'staging', name: 'Attack Staging', short: 'STAGING' },
  { id: 'initial', name: 'Initial Access', short: 'INIT' },
  { id: 'execution', name: 'Execution', short: 'EXEC' },
  { id: 'evasion', name: 'Defense Evasion', short: 'EVASION' },
  { id: 'exfil', name: 'Exfiltration', short: 'EXFIL' },
  { id: 'impact', name: 'Impact', short: 'IMPACT' },
];

// ATLAS Techniques mapped to tactics
const TECHNIQUES: Array<{
  id: string;
  name: string;
  tactic: string;
  categories: string[]; // Detection categories that map to this technique
}> = [
  { id: 'T0051', name: 'Prompt Injection', tactic: 'initial', categories: ['injection', 'injection.direct_override', 'injection.instruction_bypass'] },
  { id: 'T0054', name: 'LLM Jailbreak', tactic: 'execution', categories: ['jailbreak', 'jailbreak.persona_switch', 'jailbreak.hypothetical', 'pliny'] },
  { id: 'T0015', name: 'Evade ML Model', tactic: 'evasion', categories: ['encoded', 'obfuscation', 'evasion'] },
  { id: 'T0043', name: 'Craft Adversarial Data', tactic: 'staging', categories: ['tokenizer', 'semantic', 'adversarial'] },
  { id: 'T0044', name: 'Full Model Access', tactic: 'access', categories: ['oracle', 'model_extraction'] },
  { id: 'T0024', name: 'Exfil via Inference', tactic: 'exfil', categories: ['pii', 'secrets', 'memorization', 'data_leak'] },
  { id: 'T0029', name: 'Denial of ML Svc', tactic: 'impact', categories: ['sponge', 'dos', 'resource_abuse'] },
  { id: 'T0010', name: 'Supply Chain', tactic: 'resource', categories: ['supply_chain', 'dependency', 'poisoning'] },
  { id: 'T0052', name: 'Agent Hijacking', tactic: 'execution', categories: ['agent', 'multi_agent', 'agent_poisoning'] },
  { id: 'T0051.2', name: 'Indirect Injection', tactic: 'initial', categories: ['external', 'indirect', 'rag_poisoning'] },
  { id: 'T0048', name: 'Policy Violation', tactic: 'impact', categories: ['content', 'policy', 'hallucination', 'toxicity'] },
  { id: 'T0011', name: 'Campaign Attack', tactic: 'recon', categories: ['campaign', 'multi_turn', 'grooming'] },
  { id: 'T0000', name: 'Novel Vector', tactic: 'staging', categories: ['zero_day', 'unknown'] },
];

function getHeatColor(count: number, maxCount: number): string {
  if (count === 0) return 'rgba(255, 255, 255, 0.02)';
  const intensity = Math.min(count / Math.max(maxCount, 1), 1);
  if (intensity > 0.75) return 'rgba(239, 68, 68, 0.6)';   // Critical red
  if (intensity > 0.5) return 'rgba(245, 158, 11, 0.5)';    // High amber
  if (intensity > 0.25) return 'rgba(59, 130, 246, 0.4)';   // Medium blue
  return 'rgba(59, 130, 246, 0.15)';                         // Low blue
}

export default function AtlasMatrixLive({ scans, className = '' }: AtlasMatrixLiveProps) {
  // Compute hit counts per technique from live scan data
  const { hitMap, maxHits, totalMapped } = useMemo(() => {
    const map: Record<string, number> = {};
    let total = 0;

    scans.forEach(scan => {
      const cat = scan.category || scan.scan_type || '';
      const catLower = cat.toLowerCase();

      TECHNIQUES.forEach(tech => {
        if (tech.categories.some(c => catLower.includes(c))) {
          map[tech.id] = (map[tech.id] || 0) + 1;
          total++;
        }
      });

      // Also check detections array
      scan.detections?.forEach(det => {
        const detCat = (det.category || det.detector || '').toLowerCase();
        TECHNIQUES.forEach(tech => {
          if (tech.categories.some(c => detCat.includes(c))) {
            map[tech.id] = (map[tech.id] || 0) + 1;
            total++;
          }
        });
      });
    });

    const max = Math.max(...Object.values(map), 1);
    return { hitMap: map, maxHits: max, totalMapped: total };
  }, [scans]);

  // Group techniques by tactic
  const tacticTechniques = useMemo(() => {
    const grouped: Record<string, typeof TECHNIQUES> = {};
    TACTICS.forEach(t => { grouped[t.id] = []; });
    TECHNIQUES.forEach(tech => {
      if (grouped[tech.tactic]) {
        grouped[tech.tactic].push(tech);
      }
    });
    return grouped;
  }, []);

  return (
    <div className={`glass-card overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.04]">
        <div className="flex items-center gap-3">
          <Grid3x3 className="w-4 h-4 text-ghost-400" />
          <h3 className="text-sm font-semibold text-white">ATLAS Matrix — Live Heat Map</h3>
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-ghost-600/10 text-ghost-400 font-mono font-bold border border-ghost-600/15">
            {totalMapped} HITS
          </span>
        </div>
        <a
          href="https://atlas.mitre.org/matrices/ATLAS"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-ghost-400 transition-colors"
        >
          MITRE ATLAS <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {/* Matrix Grid */}
      <div className="overflow-x-auto scrollbar-none">
        <div className="min-w-[700px] p-4">
          {/* Tactic headers */}
          <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, 1fr)` }}>
            {TACTICS.map(tactic => (
              <div key={tactic.id} className="text-center px-1 py-2">
                <p className="text-[8px] font-bold text-gray-500 uppercase tracking-wider leading-tight">{tactic.short}</p>
              </div>
            ))}
          </div>

          {/* Technique cells */}
          <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, 1fr)` }}>
            {TACTICS.map(tactic => {
              const techs = tacticTechniques[tactic.id] || [];
              return (
                <div key={tactic.id} className="space-y-1">
                  {techs.length === 0 && (
                    <div className="h-12 rounded-md" style={{ background: 'rgba(255,255,255,0.01)' }} />
                  )}
                  {techs.map(tech => {
                    const count = hitMap[tech.id] || 0;
                    return (
                      <motion.div
                        key={tech.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="relative rounded-md px-2 py-2 cursor-pointer group transition-all duration-200 hover:ring-1 hover:ring-ghost-500/30"
                        style={{ background: getHeatColor(count, maxHits) }}
                        title={`${tech.name} (AML.${tech.id}) — ${count} detections`}
                      >
                        <p className="text-[8px] font-bold text-gray-300 leading-tight truncate">{tech.id}</p>
                        <p className="text-[7px] text-gray-500 leading-tight truncate">{tech.name}</p>
                        {count > 0 && (
                          <span className="absolute top-1 right-1 text-[8px] font-mono font-bold text-white bg-black/30 rounded px-1">
                            {count}
                          </span>
                        )}
                      </motion.div>
                    );
                  })}
                </div>
              );
            })}
          </div>

          {/* Legend */}
          <div className="flex items-center justify-end gap-4 mt-4 pt-3 border-t border-white/[0.04]">
            <span className="text-[9px] text-gray-600 uppercase tracking-wider">Intensity:</span>
            <div className="flex items-center gap-1">
              {[
                { label: 'None', color: 'rgba(255,255,255,0.02)' },
                { label: 'Low', color: 'rgba(59,130,246,0.15)' },
                { label: 'Med', color: 'rgba(59,130,246,0.4)' },
                { label: 'High', color: 'rgba(245,158,11,0.5)' },
                { label: 'Crit', color: 'rgba(239,68,68,0.6)' },
              ].map(item => (
                <div key={item.label} className="flex items-center gap-1">
                  <div className="w-3 h-3 rounded" style={{ background: item.color }} />
                  <span className="text-[8px] text-gray-600">{item.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
