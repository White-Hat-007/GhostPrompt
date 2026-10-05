'use client';
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Info, Shield, Crosshair } from 'lucide-react';

const SEV_COLORS: Record<string,string> = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e' };
const CAT_LABELS: Record<string,string> = {
  fabricated_citation:'Fabricated Citation', fabricated_organization:'Fabricated Organization',
  fabricated_person:'Fabricated Person', fabricated_product:'Fabricated Product',
  fabricated_library:'Fabricated Library/Package', fabricated_research_paper:'Fabricated Research Paper',
  fabricated_rfc:'Fabricated RFC', fabricated_cve:'Fabricated CVE',
  fabricated_scientific_claim:'Fabricated Scientific Claim', fabricated_medical_claim:'Fabricated Medical Claim',
  fabricated_legal_claim:'Fabricated Legal Claim', fabricated_statistics:'Fabricated Statistics',
  impossible_timeline:'Impossible Timeline', contradictory_statements:'Contradictory Statements',
  internal_logical_conflict:'Internal Logical Conflict', unsupported_security_claim:'Unsupported Security Claim',
  unsupported_mathematical_result:'Mathematical Error', impossible_numerical_value:'Impossible Number',
  nonexistent_award:'Non-existent Award', fake_standards:'Fake Standard',
  fiction_as_fact:'Fiction As Fact', speculation_as_fact:'Speculation As Fact',
  overconfident_assertion:'Overconfident Assertion',
};

function RiskGauge({ score, risk }: { score: number; risk: string }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.8 ? '#ef4444' : score >= 0.6 ? '#f97316' : score >= 0.35 ? '#eab308' : score >= 0.1 ? '#3b82f6' : '#22c55e';
  const circumference = 2 * Math.PI * 54;
  
  // If risk is 0, fill the gauge completely with green to visually indicate '100% Safe'
  const visualScore = score === 0 ? 1.0 : score;
  const offset = circumference - (visualScore * 0.75 * circumference);
  return (
    <div className="relative w-36 h-36 mx-auto">
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-[135deg]">
        <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" strokeDasharray={`${circumference*0.75} ${circumference*0.25}`} strokeLinecap="round"/>
        <motion.circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="8" strokeDasharray={`${circumference*0.75} ${circumference*0.25}`} strokeLinecap="round"
          initial={{ strokeDashoffset: circumference*0.75 }} animate={{ strokeDashoffset: offset }} transition={{ duration: 1.2, ease: 'easeOut' }}/>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-black" style={{ color }}>{pct}%</span>
        <span className="text-[9px] uppercase tracking-widest font-bold" style={{ color }}>{risk}</span>
      </div>
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[10px]">
        <span className="text-gray-500 cursor-help" title="Confidence represents how certain the engine is in its own assessment, not the risk level. 99% on a Safe output means '99% sure this is safe'.">Analysis Confidence <Info className="inline w-3 h-3 ml-0.5 opacity-50"/></span>
        <span className="text-white font-bold">{pct}%</span>
      </div>
      <div className="h-2 bg-white/5 rounded-full overflow-hidden">
        <motion.div className="h-full rounded-full bg-gradient-to-r from-blue-500 to-purple-500" initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.8 }}/>
      </div>
    </div>
  );
}

function HighlightedText({ text, ranges }: { text: string; ranges: any[] }) {
  if (!ranges?.length) return <p className="text-sm text-gray-300 whitespace-pre-wrap">{text}</p>;
  const sorted = [...ranges].sort((a,b) => a.start - b.start);
  const parts: React.JSX.Element[] = [];
  let last = 0;
  sorted.forEach((r, i) => {
    if (r.start > last) parts.push(<span key={`t${i}`} className="text-gray-300">{text.slice(last, r.start)}</span>);
    const color = r.confidence >= 0.9 ? 'bg-red-500/25 border-red-500/40' : r.confidence >= 0.8 ? 'bg-orange-500/20 border-orange-500/30' : 'bg-yellow-500/15 border-yellow-500/30';
    parts.push(
      <span key={`h${i}`} className={`${color} border-b-2 cursor-help relative group`} title={`${CAT_LABELS[r.category]||r.category} (${Math.round(r.confidence*100)}%)`}>
        {text.slice(r.start, r.end)}
        <span className="absolute bottom-full left-0 mb-1 hidden group-hover:block z-50 bg-gray-900 border border-white/10 rounded-lg px-3 py-2 text-[10px] text-gray-200 whitespace-nowrap shadow-xl">
          <span className="font-bold text-red-400">{CAT_LABELS[r.category]||r.category}</span><br/>Confidence: {Math.round(r.confidence*100)}%
        </span>
      </span>
    );
    last = r.end;
  });
  if (last < text.length) parts.push(<span key="tail" className="text-gray-300">{text.slice(last)}</span>);
  return <div className="text-sm whitespace-pre-wrap leading-relaxed">{parts}</div>;
}

function ChecklistView({ checklist }: { checklist: Record<string,boolean> }) {
  const labels: Record<string,string> = {
    no_fabricated_entities:'No fabricated entities', no_fabricated_citations:'No fabricated citations',
    no_unsupported_statistics:'No unsupported statistics', no_contradictory_statements:'No contradictory statements',
    no_logical_inconsistencies:'No logical inconsistencies', response_internally_coherent:'Response internally coherent',
    no_impossible_timelines:'No impossible timelines', no_fake_standards:'No fake standards',
    no_fiction_as_fact:'No fiction as fact', no_overconfident_assertions:'No overconfident assertions',
  };
  return (
    <div className="grid grid-cols-2 gap-1.5">
      {Object.entries(checklist).map(([k,v]) => (
        <div key={k} className="flex items-center gap-2 text-[11px]">
          {v ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0"/> : <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0"/>}
          <span className={v ? 'text-gray-400' : 'text-red-300 font-medium'}>{labels[k]||k.replace(/_/g,' ')}</span>
        </div>
      ))}
    </div>
  );
}

export default function HallucinationForensicPanel({ scanResult, outputText }: { scanResult: any; outputText: string }) {
  const [expandedIssue, setExpandedIssue] = useState<string|null>(null);
  if (!scanResult?.forensic_report) return null;
  const fr = scanResult.forensic_report;
  const issues = scanResult.issues || [];
  const highlights = scanResult.highlight_ranges || [];
  const checklist = scanResult.verification_checklist || {};
  const catDist = scanResult.category_distribution || {};
  const hasIssues = issues.length > 0;
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  issues.forEach((i: any) => { if (i.severity in sevCounts) (sevCounts as any)[i.severity]++; });

  return (
    <motion.div initial={{ opacity:0, y:15 }} animate={{ opacity:1, y:0 }} className="space-y-4 mt-5">
      {/* Top Row: Gauge + Confidence + Issue Count */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card p-4 border border-white/5 flex flex-col items-center">
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-2">Hallucination Risk</p>
          <RiskGauge score={fr.overall_risk_score} risk={fr.overall_risk}/>
        </div>
        <div className="glass-card p-4 border border-white/5 space-y-4">
          <ConfidenceBar value={fr.overall_confidence}/>
          <div className="pt-2 border-t border-white/5">
            <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-2">Analysis Metadata</p>
            <div className="grid grid-cols-3 gap-2 text-center">
              {Object.entries(fr.extracted_metadata || {}).map(([k,v]) => (
                <div key={k}><p className="text-sm font-bold text-white">{v as number}</p><p className="text-[9px] text-gray-500 capitalize">{k}</p></div>
              ))}
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-2">Issues Found</p>
          <p className={`text-4xl font-black ${hasIssues ? 'text-red-400' : 'text-emerald-400'}`}>{issues.length}</p>
          {hasIssues && (
            <div className="flex gap-2 mt-3">
              {sevCounts.critical > 0 && <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 font-bold">{sevCounts.critical} Critical</span>}
              {sevCounts.high > 0 && <span className="text-[10px] px-2 py-0.5 rounded-full bg-orange-500/15 text-orange-400 font-bold">{sevCounts.high} High</span>}
              {sevCounts.medium > 0 && <span className="text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/15 text-yellow-400 font-bold">{sevCounts.medium} Med</span>}
            </div>
          )}
          <p className="text-xs text-gray-400 mt-3">{fr.summary}</p>
        </div>
      </div>

      {/* Highlighted Text View */}
      {outputText && (
        <div className="glass-card p-5 border border-white/5">
          <div className="flex items-center gap-2 mb-3">
            <Crosshair className="w-4 h-4 text-purple-400"/>
            <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold">Annotated Response</p>
            {hasIssues && <span className="text-[10px] text-gray-600 ml-auto">Hover highlighted text for details</span>}
          </div>
          <div className="p-4 bg-surface-0/50 rounded-xl border border-white/5">
            <HighlightedText text={outputText} ranges={highlights}/>
          </div>
        </div>
      )}

      {/* Issues + Checklist Row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Issue Cards */}
        <div className="xl:col-span-2 space-y-2">
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-1">Detected Issues</p>
          {!hasIssues ? (
            <div className="glass-card p-4 border border-emerald-500/20 bg-emerald-500/5 flex items-center gap-3">
              <Shield className="w-5 h-5 text-emerald-400"/>
              <div><p className="text-sm font-semibold text-emerald-400">No Hallucinations Detected</p><p className="text-xs text-gray-500">Response appears factually consistent.</p></div>
            </div>
          ) : (
            <AnimatePresence>
              {issues.map((iss: any) => (
                <motion.div key={iss.id} initial={{ opacity:0, x:-10 }} animate={{ opacity:1, x:0 }}
                  className={`glass-card border ${iss.severity==='critical'?'border-red-500/30 bg-red-500/5':iss.severity==='high'?'border-orange-500/20 bg-orange-500/5':'border-yellow-500/20 bg-yellow-500/5'} overflow-hidden`}>
                  <button onClick={() => setExpandedIssue(expandedIssue===iss.id?null:iss.id)} className="w-full p-3 flex items-center gap-3 text-left">
                    <XCircle className="w-4 h-4 flex-shrink-0" style={{ color: SEV_COLORS[iss.severity] }}/>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">{CAT_LABELS[iss.category]||iss.category.replace(/_/g,' ')}</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold" style={{ color: SEV_COLORS[iss.severity], backgroundColor: SEV_COLORS[iss.severity]+'15' }}>{iss.severity}</span>
                      </div>
                      <p className="text-[11px] text-gray-400 truncate mt-0.5">{iss.affected_text}</p>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-xs font-bold text-white">{Math.round(iss.confidence*100)}%</p>
                      <p className="text-[9px] text-gray-600">confidence</p>
                    </div>
                    {expandedIssue===iss.id ? <ChevronUp className="w-3.5 h-3.5 text-gray-500"/> : <ChevronDown className="w-3.5 h-3.5 text-gray-500"/>}
                  </button>
                  <AnimatePresence>
                    {expandedIssue===iss.id && (
                      <motion.div initial={{ height:0, opacity:0 }} animate={{ height:'auto', opacity:1 }} exit={{ height:0, opacity:0 }}
                        className="px-3 pb-3 border-t border-white/5">
                        <div className="pt-3 space-y-2">
                          <div><p className="text-[9px] uppercase text-gray-600 font-semibold">Reason</p><p className="text-xs text-gray-300">{iss.description}</p></div>
                          <div><p className="text-[9px] uppercase text-gray-600 font-semibold">Affected Text</p><p className="text-xs text-red-300 font-mono bg-red-500/5 px-2 py-1 rounded">{iss.affected_text}</p></div>
                          <div><p className="text-[9px] uppercase text-gray-600 font-semibold">Recommendation</p><p className="text-xs text-blue-300">{iss.recommendation}</p></div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              ))}
            </AnimatePresence>
          )}
        </div>

        {/* Verification Checklist + Category Distribution */}
        <div className="space-y-4">
          <div className="glass-card p-4 border border-white/5">
            <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-3">Verification Checklist</p>
            <ChecklistView checklist={checklist}/>
          </div>
          {Object.keys(catDist).length > 0 && (
            <div className="glass-card p-4 border border-white/5">
              <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-3">Category Distribution</p>
              <div className="space-y-2">
                {Object.entries(catDist).sort((a:any,b:any) => b[1]-a[1]).map(([cat, count]: any) => (
                  <div key={cat} className="flex items-center gap-2">
                    <div className="flex-1">
                      <div className="flex justify-between text-[10px] mb-0.5"><span className="text-gray-400">{CAT_LABELS[cat]||cat.replace(/_/g,' ')}</span><span className="text-white font-bold">{count}</span></div>
                      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-500" style={{ width: `${Math.min(count/Math.max(...Object.values(catDist) as number[])*100,100)}%` }}/>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recommendations */}
      {scanResult.recommendations?.length > 0 && (
        <div className="glass-card p-4 border border-white/5">
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-semibold mb-2">Recommendations</p>
          <div className="space-y-1.5">
            {scanResult.recommendations.map((r: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <Info className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0"/>
                <span className="text-gray-300">{r}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
