'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import HallucinationForensicPanel from './HallucinationForensicPanel';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart,
  Legend
} from 'recharts';
import { AlertTriangle, Brain, CheckCircle, Shield, Search, Zap, Eye, TrendingUp } from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface HallucinationStats {
  total_outputs_scanned: number;
  hallucinations_detected: number;
  hallucination_rate: number;
  avg_hallucination_score: number;
  category_breakdown: Record<string, number>;
  severity_distribution: Record<string, number>;
  model_breakdown: Record<string, { scanned: number; hallucinated: number; rate: number }>;
  trend_data: Array<{ date: string; scanned: number; hallucinated: number }>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const CATEGORY_COLORS = ['#8b5cf6', '#6366f1', '#3b82f6', '#06b6d4', '#14b8a6', '#22c55e', '#eab308'];

const MODEL_COLORS: Record<string, string> = {
  'gpt-4': '#10b981',
  'gpt-3.5-turbo': '#3b82f6',
  'claude-3-sonnet': '#8b5cf6',
  'llama-3-70b': '#f97316',
  'mistral-7b': '#ef4444',
};

const CATEGORY_LABELS: Record<string, string> = {
  fabricated_citation: 'Fabricated Citations',
  self_contradiction: 'Self-Contradictions',
  excessive_hedging: 'Excessive Hedging',
  statistical_anomaly: 'Statistical Anomalies',
  entity_fabrication: 'Entity Fabrication',
  repetition_drift: 'Repetition Drift',
  elicitation_attempt: 'Elicitation Attempts',
};

export default function HallucinationView() {
  const [stats, setStats] = useState<HallucinationStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [testInput, setTestInput] = useState('');
  const [testOutput, setTestOutput] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [policyTier, setPolicyTier] = useState('ADAPTIVE');
  const [contextDocs, setContextDocs] = useState('');

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(`/api/v1/model-security/hallucination/stats`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error('Failed to fetch hallucination stats:', e);
    } finally {
      setLoading(false);
    }
  };

  const runScan = async () => {
    if (!testOutput.trim()) return;
    setScanning(true);
    setScanResult(null);
    setScanError(null);
    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(`/api/v1/model-security/hallucination/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          output_text: testOutput,
          input_text: testInput || undefined,
          context_documents: contextDocs ? [contextDocs] : undefined,
          policy_tier: policyTier
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanResult(data);
      } else {
        const errData = await res.json().catch(() => ({}));
        setScanError(errData.detail || `Error ${res.status}: ${res.statusText}`);
      }
    } catch (e: any) {
      setScanError(e?.message || 'Failed to connect to backend. Is the server running?');
    } finally {
      setScanning(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 rounded-full border-2 border-purple-500 border-t-transparent animate-spin" />
      </div>
    );
  }

  const categoryData = stats
    ? Object.entries(stats.category_breakdown).map(([key, value]) => ({
        name: CATEGORY_LABELS[key] || key,
        value,
        key,
      }))
    : [];

  const severityData = stats
    ? Object.entries(stats.severity_distribution).map(([key, value]) => ({
        name: key.charAt(0).toUpperCase() + key.slice(1),
        value,
        color: SEVERITY_COLORS[key],
      }))
    : [];

  const modelData = stats
    ? Object.entries(stats.model_breakdown).map(([model, data]) => ({
        model,
        ...data,
      }))
    : [];

  const trendData = stats?.trend_data || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20">
          <Brain className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-white">Hallucination Detection</h2>
          <p className="text-xs text-gray-500">Real-time LLM output factuality analysis</p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10">
              <Eye className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{(stats?.total_outputs_scanned || 0).toLocaleString()}</p>
              <p className="text-xs text-gray-500">Outputs Scanned</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10">
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-red-400">{(stats?.hallucinations_detected || 0).toLocaleString()}</p>
              <p className="text-xs text-gray-500">Hallucinations Detected</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-yellow-500/10">
              <TrendingUp className="w-4 h-4 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-yellow-400">{stats?.hallucination_rate || 0}%</p>
              <p className="text-xs text-gray-500">Hallucination Rate</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10">
              <Zap className="w-4 h-4 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-emerald-400">{stats?.avg_hallucination_score?.toFixed(2) || 0}</p>
              <p className="text-xs text-gray-500">Avg Score</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <div className="xl:col-span-2 glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Detection Trend (7 Days)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="hallGradScanned" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="hallGradDetected" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="date" stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} tickFormatter={(v) => v.slice(5)} />
              <YAxis stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }}
                itemStyle={{ color: '#e5e7eb' }}
                labelStyle={{ color: '#fff', fontWeight: 600 }}
              />
              <Area type="monotone" dataKey="scanned" stroke="#6366f1" fill="url(#hallGradScanned)" name="Outputs Scanned" strokeWidth={2} />
              <Area type="monotone" dataKey="hallucinated" stroke="#ef4444" fill="url(#hallGradDetected)" name="Hallucinations" strokeWidth={2} />
              <Legend formatter={(value) => <span style={{ color: '#e5e7eb', fontSize: 11, fontWeight: 500 }}>{value}</span>} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Pie */}
        <div className="glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={4} dataKey="value">
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} itemStyle={{ color: '#e5e7eb' }} labelStyle={{ color: '#fff', fontWeight: 600 }} />
              <Legend formatter={(value) => <span style={{ color: '#e5e7eb', fontSize: 11, fontWeight: 500 }}>{value}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Category Breakdown */}
        <div className="glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Hallucination Categories</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={categoryData} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis type="number" stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="#4b5563" tick={{ fill: '#d1d5db', fontSize: 10 }} width={130} />
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} itemStyle={{ color: '#e5e7eb' }} labelStyle={{ color: '#fff', fontWeight: 600 }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]} name="Detections">
                {categoryData.map((_, i) => (
                  <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Model Comparison */}
        <div className="glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Hallucination Rate by Model</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={modelData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="model" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10 }} />
              <YAxis stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} unit="%" />
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} itemStyle={{ color: '#e5e7eb' }} labelStyle={{ color: '#fff', fontWeight: 600 }} />
              <Bar dataKey="rate" radius={[6, 6, 0, 0]} name="Hallucination Rate %">
                {modelData.map((entry, i) => (
                  <Cell key={i} fill={MODEL_COLORS[entry.model] || '#6366f1'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Live Scanner */}
      <div className="glass-card p-6 border border-white/5">
        <div className="flex items-center gap-2 mb-4">
          <Search className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-white">Live Multi-Layer Hallucination Scanner</h3>
          <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">Live Backend</span>
        </div>
        
        <div className="flex flex-wrap items-center gap-3 mb-4 p-3 bg-surface-1/30 rounded-xl border border-white/5">
            <span className="text-xs text-gray-400 font-semibold">Policy Tier:</span>
            {['FAST', 'STANDARD', 'THOROUGH', 'MAXIMUM', 'ADAPTIVE'].map((tier) => (
                <button
                    key={tier}
                    onClick={() => setPolicyTier(tier)}
                    className={`text-[10px] px-3 py-1.5 rounded-lg border transition-all ${
                        policyTier === tier
                            ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                            : 'bg-surface-2/50 text-gray-500 border-transparent hover:text-gray-300 hover:bg-surface-2'
                    }`}
                >
                    {tier}
                </button>
            ))}
        </div>

        {/* Sample outputs */}
        <div className="mb-3">
          <p className="text-[10px] uppercase tracking-wider text-gray-600 font-semibold mb-2">Sample LLM Outputs</p>
          <div className="flex flex-wrap gap-2">
            {[
              { label: '🟢 Clean Output', text: 'The Eiffel Tower is located in Paris, France. It was built in 1889 and stands 330 meters tall.' },
              { label: '🔴 Fabricated Citation', text: 'According to Smith et al. (2023) in Nature vol. 891, quantum computers have achieved 99.9% accuracy. DOI: 10.1038/fake12345.' },
              { label: '🟡 Contradictory', text: 'Water boils at 100°C. However, water typically boils at around 50°C at sea level under standard conditions.' },
              { label: '🔴 Excessive Hedging', text: 'I think it might possibly be the case that perhaps the answer could potentially be around 42, but I am not entirely sure and cannot confirm this.' },
            ].map((s) => (
              <button
                key={s.label}
                onClick={() => setTestOutput(s.text)}
                className="text-[11px] px-3 py-1.5 rounded-xl bg-surface-2/80 text-gray-400 border border-white/5 hover:border-white/15 hover:text-gray-200 transition-all"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-4">
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Input Prompt (optional)</label>
              <textarea
                value={testInput}
                onChange={(e) => setTestInput(e.target.value)}
                className="w-full h-16 bg-surface-1/50 border border-white/10 rounded-xl px-4 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 resize-none"
                placeholder="Enter the original prompt..."
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Context Documents (for RAG Grounding)</label>
              <textarea
                value={contextDocs}
                onChange={(e) => setContextDocs(e.target.value)}
                className="w-full h-16 bg-surface-1/50 border border-white/10 rounded-xl px-4 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 resize-none"
                placeholder="Paste context documents to verify if the output is grounded..."
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">LLM Output to Analyze *</label>
            <textarea
              value={testOutput}
              onChange={(e) => setTestOutput(e.target.value)}
              className="w-full h-[8.5rem] bg-surface-1/50 border border-white/10 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 resize-none"
              placeholder="Paste the LLM response to check for hallucinations..."
            />
          </div>
        </div>

        <div className="flex items-center gap-3 mt-3">
          <button
            onClick={runScan}
            disabled={scanning || !testOutput.trim()}
            className="px-6 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-xl transition-all flex items-center gap-2"
          >
            {scanning ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Brain className="w-3.5 h-3.5" />
                Scan for Hallucinations
              </>
            )}
          </button>
          {scanResult && (
            <button onClick={() => { setScanResult(null); setScanError(null); }} className="text-xs text-gray-500 hover:text-gray-300 transition-colors">
              Clear
            </button>
          )}
        </div>

        {/* Error display */}
        {scanError && (
          <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-3 p-3 rounded-xl border border-red-500/30 bg-red-500/10 flex items-start gap-2"
          >
            <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-xs font-semibold text-red-400">Scan Failed</p>
              <p className="text-xs text-gray-400 mt-0.5">{scanError}</p>
            </div>
          </motion.div>
        )}

        {/* Scan Result */}
        {scanResult && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 p-4 rounded-xl border border-white/10 bg-surface-1/30"
          >
            <div className="flex items-center gap-3 mb-3">
              <div className={`px-3 py-1 rounded-full text-xs font-bold ${
                scanResult.risk_level === 'safe' ? 'bg-emerald-500/15 text-emerald-400' :
                scanResult.risk_level === 'low' ? 'bg-blue-500/15 text-blue-400' :
                scanResult.risk_level === 'medium' ? 'bg-yellow-500/15 text-yellow-400' :
                scanResult.risk_level === 'high' ? 'bg-orange-500/15 text-orange-400' :
                'bg-red-500/15 text-red-400'
              }`}>
                {scanResult.risk_level?.toUpperCase()}
              </div>
              <span className="text-white text-sm font-semibold">
                Hallucination Score: {((scanResult.hallucination_score || 0) * 100).toFixed(1)}%
              </span>
              <span className="text-gray-500 text-xs ml-auto">{scanResult.scan_duration_ms?.toFixed(1)}ms</span>
            </div>

            {scanResult.detections?.length > 0 ? (
              <div className="space-y-2">
                {scanResult.detections.map((d: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-surface-0/50 border border-white/5">
                    <AlertTriangle className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${
                      d.severity === 'critical' ? 'text-red-400' :
                      d.severity === 'high' ? 'text-orange-400' :
                      d.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'
                    }`} />
                    <div>
                      <p className="text-[11px] uppercase tracking-wide text-gray-400 font-bold">Layer 0: {d.category}</p>
                      <p className="text-xs text-gray-300">{d.description}</p>
                      {d.matched_content && (
                        <p className="text-[10px] text-gray-500 mt-1 font-mono bg-surface-1/80 px-2 py-1 rounded">
                          {d.matched_content}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
            
            {scanResult.layer_results && Object.keys(scanResult.layer_results).length > 0 && (
              <div className="mt-4 space-y-2">
                <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-2">Layer Breakdown</p>
                {Object.entries(scanResult.layer_results).map(([layerName, res]: [string, any]) => (
                    <div key={layerName} className={`p-3 rounded-lg border ${res.is_hallucination ? 'bg-red-500/5 border-red-500/20' : 'bg-surface-0/50 border-white/5'}`}>
                        <div className="flex items-center gap-2 mb-1">
                            <div className={`w-2 h-2 rounded-full ${res.is_hallucination ? 'bg-red-500' : 'bg-emerald-500'}`} />
                            <span className="text-xs font-bold text-gray-200 capitalize">{layerName.replace(/_/g, ' ')}</span>
                            {res.skipped && <span className="text-[10px] text-gray-500 ml-2">(Skipped: {res.reason})</span>}
                            <span className="text-[10px] text-gray-600 ml-auto">{res.duration_ms?.toFixed(1)}ms</span>
                        </div>
                        
                        {/* Render Claim Details if available */}
                        {res.details?.incorrect_claims && res.details.incorrect_claims.length > 0 && (
                            <div className="mt-2 pl-4 border-l-2 border-red-500/20">
                                {res.details.incorrect_claims.map((c: any, i: number) => (
                                    <div key={i} className="mb-2 last:mb-0">
                                        <p className="text-xs text-red-300 font-medium">"{c.text}"</p>
                                        <p className="text-[11px] text-gray-400 mt-0.5">Correction: {c.correction}</p>
                                    </div>
                                ))}
                            </div>
                        )}
                        
                        {/* Render Citation Details */}
                        {res.details?.verification_results && (
                            <div className="mt-2 pl-4 border-l-2 border-white/10 space-y-1">
                                {res.details.verification_results.map((c: any, i: number) => (
                                    <p key={i} className={`text-xs ${c.verdict === 'FABRICATED' ? 'text-red-400' : c.verdict === 'VERIFIED' ? 'text-emerald-400' : 'text-gray-500'}`}>
                                        [{c.verdict}] {c.item || c.entity}
                                    </p>
                                ))}
                            </div>
                        )}
                    </div>
                ))}
              </div>
            )}

            {!scanResult.is_hallucinated && (
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle className="w-4 h-4" />
                <span className="text-sm">No hallucination signals detected. Output appears factually reliable.</span>
              </div>
            )}
            
            {scanResult.is_hallucinated && (
              <div className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="w-4 h-4" />
                <span className="text-sm">Hallucination signals detected. Review forensic report below.</span>
              </div>
            )}

            {scanResult.recommendations?.length > 0 && (
              <div className="mt-3 pt-3 border-t border-white/5">
                <p className="text-xs font-semibold text-gray-400 mb-1">Recommendations:</p>
                {scanResult.recommendations.map((r: string, i: number) => (
                  <p key={i} className="text-xs text-gray-500 flex items-start gap-1.5">
                    <span className="text-purple-400 mt-0.5">&#x2022;</span> {r}
                  </p>
                ))}
              </div>
            )}

            {/* Enterprise Forensic Intelligence Panel */}
            <HallucinationForensicPanel scanResult={scanResult} outputText={testOutput} />
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}
