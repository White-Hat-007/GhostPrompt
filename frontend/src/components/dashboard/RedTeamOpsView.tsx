'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Crosshair, Play, CheckCircle, XCircle, Loader2, Shield,
  AlertTriangle, Zap, Activity, BarChart3, Target, Bug,
  RefreshCcw, Clock, TrendingUp, ShieldCheck, ShieldAlert,
  Award, Skull, Lock, Brain, Globe2, Type, Users,
} from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

/* ─── Types ────────────────────────────────────────────────────── */

interface SimTestResult {
  category: string;
  name: string;
  prompt_preview: string;
  expected_action: string;
  actual_action: string;
  threat_level: string;
  threat_score: number;
  test_passed: boolean;
  detections: { category: string; confidence: number; severity: string }[];
  scan_duration_ms: number;
}

interface SimScorecard {
  overall_score: number;
  total_tests: number;
  passed: number;
  failed: number;
  grade: string;
}

interface SimResult {
  run_id: string;
  timestamp: string;
  scorecard: SimScorecard;
  category_breakdown: Record<string, { total: number; passed: number; score: number }>;
  results: SimTestResult[];
}

interface CycleResult {
  cycle: number;
  total_attacks: number;
  analysis: {
    total_tests: number;
    passed: number;
    failed: number;
    overall_detection_rate: number;
    false_negative_rate: number;
    by_category: Record<string, { total: number; passed: number; failed: number; fn_rate: number }>;
    avg_scan_duration_ms: number;
  };
  weakness_report: {
    weaknesses: { category: string; false_negatives: number; fn_rate: number; severity: string; recommendation: string }[];
    top_weakness: { category: string; fn_rate: number } | null;
  };
  false_negatives_count: number;
  duration_seconds: number;
}

interface CertificationResult {
  badge: string;
  tiers: Record<string, { name: string; requirement: string; score: number; passed: boolean; tests: number }>;
  tier1_pass: boolean;
  tier2_pass: boolean;
  tier3_pass: boolean;
  tier4_pass: boolean;
  duration_seconds: number;
  // Cross-suite sync fields
  simulator_score: number | null;
  simulator_pass: boolean;
  ops_detection_rate: number | null;
  ops_pass: boolean;
  requires_external: boolean;
  external_status: 'both_passed' | 'not_run' | 'partial' | 'failed';
}

/* ─── Category Meta ─────────────────────────────────────────────── */

const SIM_CATEGORY_META: Record<string, { icon: typeof Shield; color: string; label: string }> = {
  prompt_injection: { icon: Shield, color: 'text-red-400', label: 'Prompt Injection' },
  jailbreak: { icon: Lock, color: 'text-rose-400', label: 'Jailbreak' },
  pii_leak: { icon: AlertTriangle, color: 'text-amber-400', label: 'PII Leak' },
  encoded_payload: { icon: Bug, color: 'text-cyan-400', label: 'Encoded Payload' },
  oracle_attack: { icon: Zap, color: 'text-indigo-400', label: 'Oracle Attack' },
  cross_lingual: { icon: Globe2, color: 'text-emerald-400', label: 'Cross-Lingual' },
  business_logic: { icon: Brain, color: 'text-sky-400', label: 'Business Logic' },
  tokenizer: { icon: Type, color: 'text-violet-400', label: 'Tokenizer' },
  safe: { icon: CheckCircle, color: 'text-emerald-400', label: 'Safe (Control)' },
};

const OPS_CATEGORY_META: Record<string, { icon: typeof Shield; color: string; label: string }> = {
  pack_hunt: { icon: Crosshair, color: 'text-red-400', label: 'Pack Hunt' },
  pliny_attack: { icon: Skull, color: 'text-rose-400', label: 'Pliny Attack' },
  zero_day: { icon: Bug, color: 'text-cyan-400', label: 'Zero-Day' },
  encoded_payload: { icon: Lock, color: 'text-amber-400', label: 'Encoded' },
  multi_turn: { icon: Activity, color: 'text-indigo-400', label: 'Multi-Turn' },
  cross_agent: { icon: Users, color: 'text-emerald-400', label: 'Cross-Agent' },
  known: { icon: Shield, color: 'text-blue-400', label: 'Known' },
  legitimate: { icon: CheckCircle, color: 'text-green-400', label: 'Legitimate' },
};

const ALL_CATEGORY_META = { ...SIM_CATEGORY_META, ...OPS_CATEGORY_META };

const BADGE_STYLES: Record<string, { bg: string; border: string; text: string; label: string; icon: typeof ShieldCheck }> = {
  CERTIFIED_SECURE: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', label: '✅ CERTIFIED SECURE', icon: ShieldCheck },
  PARTIAL: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: '⚠️ PARTIAL', icon: ShieldAlert },
  UNCERTIFIED: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: '❌ UNCERTIFIED', icon: XCircle },
};

type TabId = 'simulator' | 'advanced' | 'certification';

/* ─── Component ──────────────────────────────────────────────────── */

export default function RedTeamOpsView() {
  const [tab, setTab] = useState<TabId>('simulator');

  // Simulator state (old Red Teaming)
  const [simResult, setSimResult] = useState<SimResult | null>(null);
  const [simLoading, setSimLoading] = useState(false);
  const [simFilter, setSimFilter] = useState<'all' | 'passed' | 'failed'>('all');

  // Advanced Ops state (Red Team Ops cycle)
  const [cycleResult, setCycleResult] = useState<CycleResult | null>(null);
  const [opsLoading, setOpsLoading] = useState(false);

  // Certification state
  const [certResult, setCertResult] = useState<CertificationResult | null>(null);
  const [certLoading, setCertLoading] = useState(false);

  const getToken = () => typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  const headers = () => ({ Authorization: `Bearer ${getToken()}`, 'Content-Type': 'application/json' });

  /* ─── Actions ───── */

  const runSimulator = async () => {
    setSimLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/enterprise/red-team/run`, { method: 'POST', headers: headers() });
      if (res.ok) setSimResult(await res.json());
    } catch (err) { console.error('Simulator failed:', err); }
    setSimLoading(false);
  };

  const runAdvancedCycle = async () => {
    setOpsLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/enterprise/red-team/cycle`, { method: 'POST', headers: headers() });
      if (res.ok) setCycleResult(await res.json());
    } catch (err) { console.error(err); }
    setOpsLoading(false);
  };

  const runCertification = async () => {
    setCertLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/enterprise/red-team/certify`, { method: 'POST', headers: headers() });
      if (res.ok) setCertResult(await res.json());
    } catch (err) { console.error(err); }
    setCertLoading(false);
  };

  /* ─── Helpers ───── */

  const getGradeColor = (grade: string) => {
    if (grade.startsWith('A')) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (grade === 'B') return 'text-blue-400 border-blue-500/30 bg-blue-500/10';
    if (grade === 'C') return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-red-400 border-red-500/30 bg-red-500/10';
  };

  const simFiltered = simResult?.results.filter(r => {
    if (simFilter === 'passed') return r.test_passed;
    if (simFilter === 'failed') return !r.test_passed;
    return true;
  }) || [];

  const badgeStyle = certResult ? BADGE_STYLES[certResult.badge] || BADGE_STYLES.UNCERTIFIED : null;
  const anyLoading = simLoading || opsLoading || certLoading;

  /* ─── Tab Definitions ───── */

  const TABS: { id: TabId; label: string; icon: typeof Shield; desc: string }[] = [
    { id: 'simulator', label: 'Attack Simulator', icon: Crosshair, desc: '52 attacks across 19 categories' },
    { id: 'advanced', label: 'Advanced Ops', icon: Target, desc: '800+ attacks, 35 generators' },
    { id: 'certification', label: 'Certification', icon: Award, desc: '4-tier security badge' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-red-500/20 to-orange-600/20 border border-red-500/20">
              <Target className="w-6 h-6 text-red-400" />
            </div>
            Red Team Operations
          </h2>
          <p className="text-sm text-gray-500 mt-1">Unified adversarial testing — simulator, advanced ops, and certification</p>
        </div>
        <div className="flex gap-3">
          {tab === 'simulator' && (
            <button onClick={runSimulator} disabled={anyLoading}
              className="btn-primary flex items-center gap-2 text-sm bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500">
              {simLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {simLoading ? 'Running Attacks...' : 'Launch Simulator'}
            </button>
          )}
          {tab === 'advanced' && (
            <button onClick={runAdvancedCycle} disabled={anyLoading}
              className="btn-primary flex items-center gap-2 text-sm bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500">
              {opsLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {opsLoading ? 'Executing Attacks...' : 'Run Attack Cycle'}
            </button>
          )}
          {tab === 'certification' && (
            <button onClick={runCertification} disabled={anyLoading}
              className="btn-primary flex items-center gap-2 text-sm bg-gradient-to-r from-amber-600 to-yellow-600 hover:from-amber-500 hover:to-yellow-500">
              {certLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Award className="w-4 h-4" />}
              {certLoading ? 'Certifying...' : 'Run Certification'}
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 p-1 rounded-xl bg-surface-2/50 border border-white/5">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
              tab === t.id
                ? 'bg-gradient-to-r from-red-600/20 to-rose-600/20 text-red-400 border border-red-500/20'
                : 'text-gray-400 hover:text-gray-300 hover:bg-white/5'
            }`}
          >
            <t.icon className="w-4 h-4" />
            <span>{t.label}</span>
            <span className="text-[10px] text-gray-600 hidden md:inline">({t.desc})</span>
          </button>
        ))}
      </div>

      {/* ━━━ TAB 1: SIMULATOR (old Red Teaming) ━━━ */}
      {tab === 'simulator' && (
        <div className="space-y-6">
          {/* Loading */}
          {simLoading && (
            <div className="glass-card p-16 text-center">
              <div className="relative w-20 h-20 mx-auto mb-6">
                <div className="absolute inset-0 rounded-full border-2 border-red-500/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-red-500/40 animate-pulse" />
                <Crosshair className="absolute inset-4 w-12 h-12 text-red-400 animate-spin" style={{ animationDuration: '3s' }} />
              </div>
              <h3 className="text-xl font-semibold text-red-400">Executing Attack Battery...</h3>
              <p className="text-gray-500 text-sm mt-2">Launching 52 attack vectors across 19 categories</p>
            </div>
          )}

          {/* Results */}
          {simResult && !simLoading && (
            <>
              {/* Scorecard */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="glass-card p-6 md:col-span-1 flex flex-col items-center justify-center">
                  <div className={`text-6xl font-black mb-2 px-4 py-2 rounded-xl border ${getGradeColor(simResult.scorecard.grade)}`}>
                    {simResult.scorecard.grade}
                  </div>
                  <div className="text-sm text-gray-400 mt-2">Security Grade</div>
                </div>
                <div className="glass-card p-6 text-center">
                  <div className="text-3xl font-bold text-white">{simResult.scorecard.overall_score}%</div>
                  <div className="text-xs text-gray-500 mt-1">Overall Score</div>
                  <div className="mt-2 h-2 bg-surface-2 rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 rounded-full transition-all"
                      style={{ width: `${simResult.scorecard.overall_score}%` }} />
                  </div>
                </div>
                <div className="glass-card p-6 text-center">
                  <div className="text-3xl font-bold text-emerald-400">{simResult.scorecard.passed}</div>
                  <div className="text-xs text-gray-500 mt-1">Tests Passed</div>
                </div>
                <div className="glass-card p-6 text-center">
                  <div className="text-3xl font-bold text-red-400">{simResult.scorecard.failed}</div>
                  <div className="text-xs text-gray-500 mt-1">Tests Failed</div>
                </div>
              </div>

              {/* Category Breakdown */}
              <div className="glass-card p-6">
                <h3 className="font-bold text-white mb-4">Category Breakdown</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                  {Object.entries(simResult.category_breakdown).map(([cat, data]) => {
                    const meta = ALL_CATEGORY_META[cat] || { icon: Shield, color: 'text-gray-400', label: cat };
                    const Icon = meta.icon;
                    return (
                      <div key={cat} className="bg-surface-2/50 rounded-lg p-3 text-center border border-white/5">
                        <Icon className={`w-5 h-5 mx-auto mb-1 ${meta.color}`} />
                        <div className="text-xs font-medium text-gray-300 mb-1">{meta.label}</div>
                        <div className={`text-lg font-bold ${data.score >= 80 ? 'text-emerald-400' : data.score >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                          {data.score}%
                        </div>
                        <div className="text-[10px] text-gray-500">{data.passed}/{data.total}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Filter */}
              <div className="flex gap-2">
                {(['all', 'passed', 'failed'] as const).map(f => (
                  <button key={f} onClick={() => setSimFilter(f)}
                    className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      simFilter === f
                        ? 'bg-ghost-600/20 text-ghost-400 border border-ghost-500/30'
                        : 'bg-surface-2 text-gray-400 border border-white/5 hover:border-white/10'
                    }`}>
                    {f === 'all' ? `All (${simResult.results.length})` : f === 'passed' ? `Passed (${simResult.scorecard.passed})` : `Failed (${simResult.scorecard.failed})`}
                  </button>
                ))}
              </div>

              {/* Results Table */}
              <div className="space-y-2">
                {simFiltered.map((r, i) => {
                  const meta = ALL_CATEGORY_META[r.category] || { icon: Shield, color: 'text-gray-400', label: r.category };
                  const Icon = meta.icon;
                  return (
                    <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.02 }}
                      className={`glass-card p-4 flex items-center gap-4 ${r.test_passed ? 'border-l-2 border-l-emerald-500/50' : 'border-l-2 border-l-red-500/50'}`}>
                      {r.test_passed ? <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" /> : <XCircle className="w-5 h-5 text-red-400 shrink-0" />}
                      <Icon className={`w-4 h-4 ${meta.color} shrink-0`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm text-white">{r.name}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-2 text-gray-500">{meta.label}</span>
                        </div>
                        <p className="text-xs text-gray-500 truncate mt-0.5 font-mono">{r.prompt_preview}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <div className={`text-xs font-mono ${r.actual_action === 'blocked' ? 'text-red-400' : r.actual_action === 'flagged' ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {r.actual_action.toUpperCase()}
                        </div>
                        <div className="text-[10px] text-gray-500">{r.scan_duration_ms.toFixed(0)}ms</div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </>
          )}

          {/* Empty State */}
          {!simResult && !simLoading && (
            <div className="glass-card p-16 text-center">
              <Crosshair className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">Attack Simulator</h3>
              <p className="text-gray-500 text-sm max-w-lg mx-auto">
                Fire 52 curated attack prompts across 19 categories — Prompt Injection, Jailbreak, PII Leak,
                Encoded Payload, Oracle Attack, Cross-Lingual, Business Logic, Tokenizer, Hallucination,
                Hardware Probing, Sponge DoS, Multimodal, Tool Hijack, Supply Chain, Constitutional,
                Campaign, and Safe Controls — with a Security Grade and per-test forensic breakdown.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ━━━ TAB 2: ADVANCED OPS (Pack Hunt / Pliny / Zero-Day / etc.) ━━━ */}
      {tab === 'advanced' && (
        <div className="space-y-6">
          {/* Loading */}
          {opsLoading && (
            <div className="glass-card p-16 text-center">
              <div className="relative w-20 h-20 mx-auto mb-6">
                <div className="absolute inset-0 rounded-full border-2 border-red-500/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-red-500/40 animate-pulse" />
                <Target className="absolute inset-4 w-12 h-12 text-red-400 animate-spin" style={{ animationDuration: '3s' }} />
              </div>
              <h3 className="text-xl font-semibold text-red-400">Executing Advanced Attack Battery...</h3>
              <p className="text-gray-500 text-sm mt-2">Launching 800+ attack vectors across 35 generators with full coverage</p>
            </div>
          )}

          {/* Cycle Results */}
          {cycleResult && !opsLoading && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
              {/* Scorecard */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="glass-card p-5 text-center">
                  <div className="text-3xl font-black text-white">{cycleResult.total_attacks}</div>
                  <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Attacks Tested</div>
                </div>
                <div className="glass-card p-5 text-center">
                  <div className={`text-3xl font-black ${cycleResult.analysis.overall_detection_rate >= 95 ? 'text-emerald-400' : cycleResult.analysis.overall_detection_rate >= 80 ? 'text-amber-400' : 'text-red-400'}`}>
                    {cycleResult.analysis.overall_detection_rate}%
                  </div>
                  <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Detection Rate</div>
                </div>
                <div className="glass-card p-5 text-center">
                  <div className="text-3xl font-black text-red-400">{cycleResult.false_negatives_count}</div>
                  <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">False Negatives</div>
                </div>
                <div className="glass-card p-5 text-center">
                  <div className="text-3xl font-black text-cyan-400">{cycleResult.analysis.avg_scan_duration_ms.toFixed(0)}ms</div>
                  <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Avg Scan Time</div>
                </div>
                <div className="glass-card p-5 text-center">
                  <div className="text-3xl font-black text-white">{cycleResult.duration_seconds}s</div>
                  <div className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider">Cycle Duration</div>
                </div>
              </div>

              {/* Category Breakdown */}
              <div className="glass-card p-6">
                <h3 className="font-bold text-white mb-4 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-ghost-400" />
                  Attack Category Breakdown
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                  {Object.entries(cycleResult.analysis.by_category).filter(([cat]) => !['unknown', 'uncategorized', 'Unknown', ''].includes(cat)).map(([cat, data]) => {
                    const meta = ALL_CATEGORY_META[cat] || { icon: Shield, color: 'text-gray-400', label: cat };
                    const Icon = meta.icon;
                    const rate = data.total > 0 ? Math.round((data.passed / data.total) * 100) : 0;
                    return (
                      <div key={cat} className="bg-surface-2/50 rounded-xl p-4 text-center border border-white/5">
                        <Icon className={`w-5 h-5 mx-auto mb-2 ${meta.color}`} />
                        <div className="text-xs font-medium text-gray-300 mb-1">{meta.label}</div>
                        <div className={`text-xl font-black ${rate >= 90 ? 'text-emerald-400' : rate >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
                          {rate}%
                        </div>
                        <div className="text-[10px] text-gray-500">{data.passed}/{data.total} caught</div>
                        {data.failed > 0 && (
                          <div className="text-[10px] text-red-400 mt-1">{data.failed} evaded</div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Weaknesses */}
              {cycleResult.weakness_report.weaknesses.filter((w: any) => !['unknown', 'uncategorized', 'Unknown', ''].includes(w.category)).length > 0 && (
                <div className="glass-card p-6">
                  <h3 className="font-bold text-white mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    Detected Weaknesses
                  </h3>
                  <div className="space-y-2">
                    {cycleResult.weakness_report.weaknesses.filter((w: any) => !['unknown', 'uncategorized', 'Unknown', ''].includes(w.category)).map((w, i) => (
                      <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                        className={`p-4 rounded-xl border-l-2 ${
                          w.severity === 'critical' ? 'border-l-red-500 bg-red-500/5' :
                          w.severity === 'high' ? 'border-l-orange-500 bg-orange-500/5' :
                          'border-l-amber-500 bg-amber-500/5'
                        } border border-white/5`}>
                        <div className="flex items-center justify-between">
                          <div>
                            <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                              w.severity === 'critical' ? 'bg-red-500/15 text-red-400' :
                              w.severity === 'high' ? 'bg-orange-500/15 text-orange-400' :
                              'bg-amber-500/15 text-amber-400'
                            }`}>{w.severity.toUpperCase()}</span>
                            <span className="text-sm text-white font-medium ml-3">{w.category.replace(/_/g, ' ')}</span>
                          </div>
                          <span className="text-sm font-mono text-red-400">{w.fn_rate}% FN rate</span>
                        </div>
                        <p className="text-xs text-gray-500 mt-2">{w.recommendation}</p>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* Empty State */}
          {!cycleResult && !opsLoading && (
            <div className="glass-card p-16 text-center">
              <Target className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">Advanced Attack Ops</h3>
              <p className="text-gray-500 text-sm max-w-lg mx-auto mb-6">
                Launch 800+ automated adversarial attacks across 35 generators — Pack Hunt, Pliny,
                Zero-Day, Encoding, Multi-Turn, Cross-Agent, Hallucination, Hardware Side-Channel,
                Sponge DoS, Oracle Inversion, Multimodal, Tool SSRF, Supply Chain, Tokenizer Splitting,
                Campaign Coordinated, Recursive DoS, Constitutional, and more — with real-time weakness analysis.
              </p>
              <div className="grid grid-cols-3 md:grid-cols-4 gap-3 max-w-2xl mx-auto mt-8">
                {[
                  { label: 'Pack Hunt', desc: 'Multi-request fragmentation', icon: Crosshair },
                  { label: 'Pliny Attacks', desc: 'L1B3RT4S/G0DM0D3 variants', icon: Skull },
                  { label: 'Zero-Day', desc: 'Genetic algorithm mutations', icon: Bug },
                  { label: 'Encoding', desc: '11 obfuscation strategies', icon: Lock },
                  { label: 'Multi-Turn', desc: 'Slow-build escalation', icon: Activity },
                  { label: 'Cross-Agent', desc: 'Inter-agent poisoning', icon: Users },
                  { label: 'Hallucination', desc: 'Fake citation elicitation', icon: AlertTriangle },
                  { label: 'Constitutional', desc: 'Alignment boundary testing', icon: Shield },
                ].map((g, i) => (
                  <div key={i} className="p-3 rounded-xl bg-surface-2/50 border border-white/5 text-center">
                    <g.icon className="w-5 h-5 text-gray-500 mx-auto mb-1" />
                    <div className="text-xs font-medium text-gray-300">{g.label}</div>
                    <div className="text-[10px] text-gray-600">{g.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}



      {/* ━━━ TAB 5: CERTIFICATION ━━━ */}
      {tab === 'certification' && (
        <div className="space-y-6">
          {/* Loading */}
          {certLoading && (
            <div className="glass-card p-16 text-center">
              <div className="relative w-20 h-20 mx-auto mb-6">
                <div className="absolute inset-0 rounded-full border-2 border-amber-500/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-amber-500/40 animate-pulse" />
                <Award className="absolute inset-4 w-12 h-12 text-amber-400 animate-spin" style={{ animationDuration: '3s' }} />
              </div>
              <h3 className="text-xl font-semibold text-amber-400">Running 4-Tier Certification Suite...</h3>
              <p className="text-gray-500 text-sm mt-2">Testing Known Attacks → Pack Hunt → Zero-Day → False Positive Rate</p>
            </div>
          )}

          {/* Certification Badge */}
          {certResult && !certLoading && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
              <div className={`glass-card p-6 ${badgeStyle?.border} border-2`}>
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-xl ${badgeStyle?.bg}`}>
                      {badgeStyle && <badgeStyle.icon className={`w-8 h-8 ${badgeStyle.text}`} />}
                    </div>
                    <div>
                      <h3 className={`text-2xl font-black ${badgeStyle?.text}`}>{badgeStyle?.label}</h3>
                      <p className="text-xs text-gray-500 mt-1">Completed in {certResult.duration_seconds}s</p>
                    </div>
                  </div>
                </div>

                {/* External Test Sync Status */}
                {certResult.requires_external && (
                  <div className={`mb-5 p-4 rounded-xl border ${
                    certResult.external_status === 'both_passed' 
                      ? 'border-emerald-500/20 bg-emerald-500/5' 
                      : certResult.external_status === 'not_run'
                        ? 'border-amber-500/20 bg-amber-500/5'
                        : 'border-red-500/20 bg-red-500/5'
                  }`}>
                    <div className="flex items-center gap-2 mb-3">
                      <Activity className="w-4 h-4 text-ghost-400" />
                      <span className="text-xs font-bold text-gray-300 uppercase tracking-wider">Cross-Suite Sync</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold ${
                        certResult.external_status === 'both_passed' ? 'bg-emerald-500/20 text-emerald-400' :
                        certResult.external_status === 'not_run' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-red-500/20 text-red-400'
                      }`}>
                        {certResult.external_status === 'both_passed' ? 'ALL PASSED' :
                         certResult.external_status === 'not_run' ? 'PENDING — Run Simulator & Ops first' :
                         'FAILED — Not all suites at 100%'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className={`p-3 rounded-lg border ${certResult.simulator_pass ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          {certResult.simulator_pass ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                          <span className="text-xs font-semibold text-gray-300">Attack Simulator</span>
                        </div>
                        <div className={`text-lg font-black ${certResult.simulator_pass ? 'text-emerald-400' : certResult.simulator_score != null ? 'text-red-400' : 'text-gray-600'}`}>
                          {certResult.simulator_score != null ? `${certResult.simulator_score}%` : 'Not Run'}
                        </div>
                        <div className="text-[10px] text-gray-500">Req: 100% pass rate</div>
                      </div>
                      <div className={`p-3 rounded-lg border ${certResult.ops_pass ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          {certResult.ops_pass ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                          <span className="text-xs font-semibold text-gray-300">Advanced Ops</span>
                        </div>
                        <div className={`text-lg font-black ${certResult.ops_pass ? 'text-emerald-400' : certResult.ops_detection_rate != null ? 'text-red-400' : 'text-gray-600'}`}>
                          {certResult.ops_detection_rate != null ? `${certResult.ops_detection_rate}%` : 'Not Run'}
                        </div>
                        <div className="text-[10px] text-gray-500">Req: 100% detection</div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {Object.entries(certResult.tiers).map(([key, tier]) => (
                    <div key={key} className={`p-4 rounded-xl border ${tier.passed ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'}`}>
                      <div className="flex items-center gap-2 mb-2">
                        {tier.passed ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                        <span className="text-xs font-semibold text-gray-300">{tier.name}</span>
                      </div>
                      <div className={`text-2xl font-black ${tier.passed ? 'text-emerald-400' : 'text-red-400'}`}>
                        {tier.score.toFixed(1)}%
                      </div>
                      <div className="text-[10px] text-gray-500 mt-1">Req: {tier.requirement}</div>
                      <div className="text-[10px] text-gray-600">{tier.tests} tests</div>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}

          {/* Empty State */}
          {!certResult && !certLoading && (
            <div className="glass-card p-16 text-center">
              <Award className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">4-Tier Certification Suite</h3>
              <p className="text-gray-500 text-sm max-w-lg mx-auto mb-6">
                Run the full certification battery to earn a CERTIFIED SECURE badge.
              </p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl mx-auto mt-8">
                {[
                  { label: 'Tier 1: Known', desc: 'Baseline attacks', req: '≥95%' },
                  { label: 'Tier 2: Pack Hunt', desc: 'Fragmentation defense', req: '≥90%' },
                  { label: 'Tier 3: Zero-Day', desc: 'Novel attack coverage', req: '≥85%' },
                  { label: 'Tier 4: False Pos.', desc: 'Accuracy rate', req: '≤5%' },
                ].map((t, i) => (
                  <div key={i} className="p-4 rounded-xl bg-surface-2/50 border border-white/5 text-center">
                    <div className="text-xs font-semibold text-gray-300 mb-1">{t.label}</div>
                    <div className="text-[10px] text-gray-500">{t.desc}</div>
                    <div className="text-xs text-amber-400 font-mono mt-2">{t.req}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
