'use client';

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart,
  Legend
} from 'recharts';
import { ShieldAlert, Cpu, HardDrive, Activity, AlertTriangle, Server, Zap, Lock, Eye } from 'lucide-react';

export interface ScanEvent {
  id: string;
  request_id: string;
  timestamp?: string;
  created_at?: string;
  action: 'allowed' | 'flagged' | 'blocked';
  threat_level: 'low' | 'medium' | 'high' | 'critical' | 'safe';
  threat_score: number;
  scan_duration_ms: number;
  scan_type?: string;
  prompt?: string;
  model?: string;
  detections: Array<{
    detector: string;
    confidence: number;
    description: string;
    category?: string;
    severity?: string;
  }>;
  lat?: number;
  lng?: number;
  city?: string;
  country?: string;
  ip?: string;
  browser?: string;
  os?: string;
}

interface HardwareSecurityViewProps {
  scans: ScanEvent[];
}

// Map real detection category PREFIXES to hardware security contexts
// Actual categories use dotted notation: injection.direct_override, jailbreak.persona_switch, etc.
const HARDWARE_PREFIX_MAP: [string, string][] = [
  ['injection', 'inference.prompt_boundary'],
  ['jailbreak', 'inference.model_override'],
  ['pliny', 'inference.jailbreak_variant'],
  ['encoded', 'inference.encoding_evasion'],
  ['pii', 'memory.data_exfiltration'],
  ['secrets', 'memory.secret_leak'],
  ['oracle', 'inference.model_probing'],
  ['policy', 'inference.policy_violation'],
  ['tokenizer', 'memory.tokenizer_exploit'],
  ['zero_day', 'inference.zero_day'],
  ['sponge', 'compute.resource_exhaustion'],
  ['agent', 'inference.agent_hijack'],
  ['external', 'inference.external_injection'],
  ['memorization', 'memory.training_data_leak'],
  ['supply_chain', 'inference.supply_chain'],
  ['hallucination', 'inference.hallucination'],
  ['content', 'inference.content_violation'],
  ['semantic', 'inference.semantic_attack'],
  ['multi_turn', 'session.context_manipulation'],
  ['campaign', 'session.coordinated_attack'],
  ['hardware', 'compute.hardware_exploit'],
];

function mapCategoryToInfra(rawCat: string): string {
  const prefix = rawCat.split('.')[0];
  for (const [matchPrefix, infraCat] of HARDWARE_PREFIX_MAP) {
    if (prefix === matchPrefix) return infraCat;
  }
  return `inference.${prefix}`;
}

const INFRA_CATEGORIES: Record<string, { label: string; color: string; icon: typeof Cpu }> = {
  'inference.prompt_boundary': { label: 'Prompt Boundary Bypass', color: '#f43f5e', icon: ShieldAlert },
  'inference.model_override': { label: 'Model Override Attempt', color: '#ef4444', icon: Lock },
  'inference.jailbreak_variant': { label: 'Jailbreak Variant', color: '#e11d48', icon: Lock },
  'inference.encoding_evasion': { label: 'Encoding Evasion', color: '#f97316', icon: Zap },
  'inference.model_probing': { label: 'Model Probing', color: '#8b5cf6', icon: Eye },
  'inference.policy_violation': { label: 'Policy Violation', color: '#ec4899', icon: ShieldAlert },
  'inference.semantic_attack': { label: 'Semantic Attack', color: '#a855f7', icon: Cpu },
  'inference.zero_day': { label: 'Zero-Day Vector', color: '#06b6d4', icon: AlertTriangle },
  'inference.agent_hijack': { label: 'Agent Hijacking', color: '#d946ef', icon: Activity },
  'inference.external_injection': { label: 'External Injection', color: '#fb923c', icon: Zap },
  'inference.supply_chain': { label: 'Supply Chain', color: '#14b8a6', icon: Server },
  'inference.hallucination': { label: 'Hallucination', color: '#818cf8', icon: Eye },
  'inference.content_violation': { label: 'Content Violation', color: '#f472b6', icon: ShieldAlert },
  'memory.data_exfiltration': { label: 'Data Exfiltration', color: '#f43f5e', icon: HardDrive },
  'memory.secret_leak': { label: 'Secret Leak', color: '#dc2626', icon: Lock },
  'memory.tokenizer_exploit': { label: 'Tokenizer Exploit', color: '#14b8a6', icon: Server },
  'memory.training_data_leak': { label: 'Training Data Leak', color: '#f59e0b', icon: HardDrive },
  'compute.resource_exhaustion': { label: 'Resource Exhaustion', color: '#eab308', icon: Cpu },
  'compute.hardware_exploit': { label: 'Hardware Exploit', color: '#ef4444', icon: Cpu },
  'session.context_manipulation': { label: 'Context Manipulation', color: '#6366f1', icon: Activity },
  'session.coordinated_attack': { label: 'Coordinated Attack', color: '#e879f9', icon: Activity },
};

export default function HardwareSecurityView({ scans }: HardwareSecurityViewProps) {
  // Map ALL scans with detections into hardware-contextualized data
  const infraScans = useMemo(() => {
    return scans.filter(scan => {
      // Include any scan that was actioned on (blocked/flagged/sanitized)
      // or has a non-safe threat level, or has detections
      const isActioned = scan.action !== 'allowed';
      const hasThreat = scan.threat_level && scan.threat_level !== 'safe' && scan.threat_level !== 'low';
      const hasDetections = scan.detections && scan.detections.length > 0;
      return isActioned || hasThreat || hasDetections;
    }).map(scan => {
      const mappedCategories = (scan.detections || []).map(d => {
        const rawCat = d.category || 'unknown';
        return mapCategoryToInfra(rawCat);
      });
      // If no detections but still actioned, infer from threat level
      if (mappedCategories.length === 0 && scan.action !== 'allowed') {
        mappedCategories.push('inference.prompt_boundary');
      }
      return { ...scan, infraCategories: mappedCategories };
    });
  }, [scans]);

  const stats = useMemo(() => {
    const categoryCounts: Record<string, number> = {};
    let totalBlocked = 0;
    let totalFlagged = 0;
    let avgScanTime = 0;

    infraScans.forEach(scan => {
      if (scan.action === 'blocked') totalBlocked++;
      if (scan.action === 'flagged') totalFlagged++;
      avgScanTime += scan.scan_duration_ms || 0;
      
      scan.infraCategories.forEach(cat => {
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      });
    });

    avgScanTime = infraScans.length > 0 ? Math.round(avgScanTime / infraScans.length) : 0;

    // Get top categories
    const sortedCats = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);

    return {
      total: infraScans.length,
      blocked: totalBlocked,
      flagged: totalFlagged,
      avgScanTime,
      categoryCounts,
      topCategories: sortedCats,
    };
  }, [infraScans]);

  const pieData = stats.topCategories.map(([cat, count]) => {
    const meta = INFRA_CATEGORIES[cat] || { label: cat.split('.').pop() || cat, color: '#6b7280', icon: Cpu };
    return {
      name: meta.label,
      value: count,
      color: meta.color,
    };
  });

  // Time-series data grouped by minute
  const timeData = useMemo(() => {
    const grouped = new Map<string, { time: string; blocked: number; flagged: number; total: number }>();
    infraScans.forEach(scan => {
      const ts = scan.created_at || scan.timestamp;
      if (!ts) return;
      const d = new Date(ts);
      const minKey = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
      
      if (!grouped.has(minKey)) {
        grouped.set(minKey, { time: minKey, blocked: 0, flagged: 0, total: 0 });
      }
      const entry = grouped.get(minKey)!;
      entry.total++;
      if (scan.action === 'blocked') entry.blocked++;
      if (scan.action === 'flagged') entry.flagged++;
    });
    
    return Array.from(grouped.values()).slice(-20);
  }, [infraScans]);

  // Threat level distribution for bar chart
  const threatDistribution = useMemo(() => {
    const dist: Record<string, number> = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
    infraScans.forEach(scan => {
      const level = scan.threat_level || 'safe';
      dist[level] = (dist[level] || 0) + 1;
    });
    return [
      { level: 'Medium', count: dist.medium, color: '#eab308' },
      { level: 'High', count: dist.high, color: '#f97316' },
      { level: 'Critical', count: dist.critical, color: '#ef4444' },
    ].filter(d => d.count > 0);
  }, [infraScans]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Cpu className="w-8 h-8 text-rose-500" />
            Hardware-Level Security Monitoring
          </h2>
          <p className="text-gray-400 mt-2 max-w-2xl">
            Infrastructure-layer threat analysis — maps all AI Firewall detections to compute boundary violations, memory access patterns, and inference pipeline attacks.
          </p>
        </div>
        <div className="flex items-center gap-3 bg-rose-500/10 border border-rose-500/20 px-4 py-2 rounded-xl">
          <Activity className="w-5 h-5 text-rose-400 animate-pulse" />
          <span className="text-rose-400 font-medium">Live Sync Active</span>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <ShieldAlert className="w-16 h-16 text-rose-500" />
          </div>
          <p className="text-gray-400 text-sm">Total Threats Intercepted</p>
          <p className="text-3xl font-bold text-white mt-2">{stats.total}</p>
        </div>
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6">
          <p className="text-gray-400 text-sm">Blocked</p>
          <p className="text-3xl font-bold text-red-400 mt-2">{stats.blocked}</p>
        </div>
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6">
          <p className="text-gray-400 text-sm">Flagged</p>
          <p className="text-3xl font-bold text-amber-400 mt-2">{stats.flagged}</p>
        </div>
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6">
          <p className="text-gray-400 text-sm">Avg Scan Time</p>
          <p className="text-3xl font-bold text-cyan-400 mt-2">{stats.avgScanTime}ms</p>
        </div>
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6">
          <p className="text-gray-400 text-sm">Unique Vectors</p>
          <p className="text-3xl font-bold text-purple-400 mt-2">{Object.keys(stats.categoryCounts).length}</p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Timeline */}
        <div className="xl:col-span-2 bg-surface-0 border border-white/5 rounded-2xl p-6">
          <h3 className="text-lg font-bold text-white mb-6">Threat Interception Velocity (Live)</h3>
          <div className="h-[300px]">
            {timeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeData}>
                  <defs>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorFlagged" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#eab308" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#eab308" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                  <XAxis dataKey="time" stroke="#ffffff50" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#ffffff50" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111', borderColor: '#333', borderRadius: '8px', color: '#fff' }}
                    itemStyle={{ color: '#fff' }}
                    labelStyle={{ color: '#d1d5db', fontWeight: 600 }}
                  />
                  <Area type="monotone" dataKey="blocked" stroke="#f43f5e" fillOpacity={1} fill="url(#colorBlocked)" name="Blocked" />
                  <Area type="monotone" dataKey="flagged" stroke="#eab308" fillOpacity={1} fill="url(#colorFlagged)" name="Flagged" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="w-full h-full flex flex-col items-center justify-center text-gray-500">
                <Activity className="w-12 h-12 mb-3 opacity-20" />
                <p>Waiting for threat data...</p>
                <p className="text-xs mt-1">Scan payloads via Live Scanner to populate.</p>
              </div>
            )}
          </div>
        </div>

        {/* Pie: Attack Vectors */}
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6">
          <h3 className="text-lg font-bold text-white mb-6">Attack Vector Distribution</h3>
          <div className="h-[300px]">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="45%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111', borderColor: '#333', borderRadius: '8px', color: '#fff' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="w-full h-full flex items-center justify-center text-gray-500">
                No attack vectors detected yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Threat Level Distribution */}
      {threatDistribution.length > 0 && (
        <div className="bg-surface-0 border border-white/5 rounded-2xl p-6">
          <h3 className="text-lg font-bold text-white mb-4">Threat Severity Distribution</h3>
          <div className="h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatDistribution} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" horizontal={false} />
                <XAxis type="number" stroke="#ffffff50" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis dataKey="level" type="category" stroke="#ffffff50" fontSize={12} tickLine={false} axisLine={false} width={80} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111', borderColor: '#333', borderRadius: '8px' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Bar dataKey="count" fill="#f43f5e" radius={[0, 6, 6, 0]}>
                  {threatDistribution.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recent Interceptions */}
      <div className="bg-surface-0 border border-white/5 rounded-2xl overflow-hidden">
        <div className="px-6 py-5 border-b border-white/5 bg-white/[0.02] flex items-center justify-between">
          <h3 className="text-lg font-bold text-white">Recent Infrastructure Interceptions</h3>
          <span className="text-xs text-gray-500 font-mono">{infraScans.length} events synced</span>
        </div>
        <div className="divide-y divide-white/5 max-h-[400px] overflow-y-auto">
          {infraScans.length > 0 ? (
            infraScans.slice(0, 50).map((scan, idx) => {
              const primaryCat = scan.infraCategories[0] || 'unknown';
              const meta = INFRA_CATEGORIES[primaryCat] || { label: primaryCat, color: '#6b7280', icon: Cpu };
              const Icon = meta.icon;
              const ts = scan.created_at || scan.timestamp;
              return (
                <motion.div 
                  key={scan.id || idx}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.02 }}
                  className="p-5 hover:bg-white/[0.02] transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2 flex-wrap">
                        <Icon className="w-4 h-4 shrink-0" style={{ color: meta.color }} />
                        <span className="px-2 py-0.5 text-xs font-semibold rounded uppercase tracking-wider" 
                          style={{ backgroundColor: `${meta.color}15`, color: meta.color }}>
                          {meta.label}
                        </span>
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                          scan.action === 'blocked' ? 'bg-red-500/15 text-red-400' :
                          scan.action === 'flagged' ? 'bg-amber-500/15 text-amber-400' :
                          'bg-emerald-500/15 text-emerald-400'
                        }`}>{scan.action}</span>
                        {ts && (
                          <span className="text-xs text-gray-500">
                            {new Date(ts).toLocaleTimeString()}
                          </span>
                        )}
                        <span className="text-[10px] text-gray-600 font-mono">
                          {scan.ip || 'N/A'}
                        </span>
                        {scan.browser && (
                          <span className="text-[10px] text-gray-600 font-mono">{scan.browser}</span>
                        )}
                      </div>
                      {scan.prompt && (
                        <p className="text-gray-300 font-mono text-xs break-all bg-black/20 p-3 rounded-lg border border-white/5 mt-2 line-clamp-2">
                          {scan.prompt}
                        </p>
                      )}
                      {scan.detections.length > 0 && (
                        <div className="flex gap-1.5 mt-2 flex-wrap">
                          {scan.detections.slice(0, 4).map((d, di) => (
                            <span key={di} className="text-[10px] px-1.5 py-0.5 rounded bg-surface-2 text-gray-400 border border-white/5">
                              {d.category} ({(d.confidence * 100).toFixed(0)}%)
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="flex flex-col items-end shrink-0 ml-4">
                      <span className={`text-xl font-bold ${
                        scan.threat_score >= 0.8 ? 'text-red-500' :
                        scan.threat_score >= 0.5 ? 'text-amber-500' :
                        'text-yellow-500'
                      }`}>
                        {(scan.threat_score * 100).toFixed(0)}%
                      </span>
                      <span className="text-[10px] text-gray-500">Severity</span>
                      <span className="text-[10px] text-gray-600 mt-1">{scan.scan_duration_ms}ms</span>
                    </div>
                  </div>
                </motion.div>
              );
            })
          ) : (
            <div className="p-12 text-center text-gray-500">
              <HardDrive className="w-12 h-12 mx-auto mb-4 opacity-20" />
              <p>No threats detected in the current session.</p>
              <p className="text-xs mt-1 text-gray-600">Send prompts via the Live Scanner or API proxy to populate.</p>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}
