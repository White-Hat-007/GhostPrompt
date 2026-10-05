'use client';

import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, CheckCircle, XCircle, FileText, Download, AlertTriangle, Info,
  Globe2, Building2, Heart, Lock, ChevronDown, ChevronRight, Loader2, BarChart3,
  Brain, Landmark, Target, TrendingUp, AlertOctagon, Wrench, BookOpen,
} from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

/* ─── Framework Metadata ─── */
const FRAMEWORK_META: Record<string, { icon: typeof Shield; color: string; gradient: string; label: string }> = {
  eu_ai_act: { icon: Globe2, color: 'text-blue-400', gradient: 'from-blue-500 to-indigo-600', label: 'EU AI Act' },
  soc2: { icon: Building2, color: 'text-emerald-400', gradient: 'from-emerald-500 to-teal-600', label: 'SOC 2 Type II' },
  soc2_type2: { icon: Building2, color: 'text-emerald-400', gradient: 'from-emerald-500 to-teal-600', label: 'SOC 2 Type II' },
  hipaa: { icon: Heart, color: 'text-rose-400', gradient: 'from-rose-500 to-red-600', label: 'HIPAA' },
  gdpr: { icon: Lock, color: 'text-amber-400', gradient: 'from-amber-500 to-orange-600', label: 'GDPR' },
  nist_ai_rmf: { icon: Landmark, color: 'text-cyan-400', gradient: 'from-cyan-500 to-blue-600', label: 'NIST AI RMF 1.0' },
  iso_42001: { icon: BookOpen, color: 'text-violet-400', gradient: 'from-violet-500 to-purple-600', label: 'ISO/IEC 42001:2023' },
  pci_dss: { icon: Shield, color: 'text-sky-400', gradient: 'from-sky-500 to-cyan-600', label: 'PCI DSS v4.0' },
  ccpa: { icon: Lock, color: 'text-orange-400', gradient: 'from-orange-500 to-red-600', label: 'CCPA/CPRA' },
  dpdpa: { icon: Globe2, color: 'text-indigo-400', gradient: 'from-indigo-500 to-violet-600', label: 'DPDPA (India)' },
};

/* ─── NIST Function Icons ─── */
const NIST_FUNCTION_META: Record<string, { icon: typeof Shield; color: string }> = {
  GOVERN: { icon: Landmark, color: 'text-blue-400' },
  MAP: { icon: Target, color: 'text-amber-400' },
  MEASURE: { icon: BarChart3, color: 'text-emerald-400' },
  MANAGE: { icon: Wrench, color: 'text-rose-400' },
};

/* ─── Interfaces ─── */
interface Requirement { id: string; title: string; description: string; status: string; details: string; }
interface Framework { framework: string; version: string; compliance_score: number; total_requirements: number; passed: number; failed: number; requirements: Requirement[]; }
interface ComplianceReport { report_id: string; generated_at: string; report_period_days: number; total_scans: number; threats_blocked: number; active_policies: number; frameworks: Framework[]; }

interface NISTSubcategory { requirement: string; status: string; evidence_sources: string[]; evidence_type: string; last_verified: string; }
interface NISTFunction { description: string; subcategories: Record<string, NISTSubcategory>; score: number; }
interface NISTReport { report_id: string; framework: string; generated_at: string; overall_alignment_score: number; total_subcategories: number; satisfied: number; partial: number; gap: number; functions: Record<string, NISTFunction>; gaps: any[]; disclaimer: string; }

interface ISORequirement { requirement: string; status: string; evidence_sources: string[]; last_verified: string; }
interface ISOClause { title: string; requirements: Record<string, ISORequirement>; score: number; }
interface ISOReport { report_id: string; framework: string; generated_at: string; overall_readiness_score: number; total_requirements: number; satisfied: number; partial: number; gap: number; clauses: Record<string, ISOClause>; gaps: any[]; disclaimer: string; }

/* ─── Generic Framework Report (ComplianceSnapshot format — SOC2, PCI DSS, GDPR, EU AI Act, HIPAA, CCPA, DPDPA) ─── */
interface GenericControl { control_id: string; title: string; requirement: string; status: string; evidence_sources: string[]; evidence_type: string; gap_note: string; remediation: string; requires_external_audit: boolean; last_verified: string; }
interface GenericSection { title: string; controls: Record<string, GenericControl>; score: number; }
interface GenericFrameworkReport { report_id: string; framework: string; framework_id: string; framework_version: string; generated_at: string; overall_score: number; total_controls: number; satisfied: number; partial: number; gap: number; not_applicable: number; sections: Record<string, GenericSection>; gaps: any[]; disclaimer: string; hmac_signature: string; }

interface CrossFrameworkSummary { frameworks: Record<string, { name: string; score: number }>; overall_governance_maturity: number; disclaimer: string; }

/* ─── Disclaimer Tooltip ─── */
function DisclaimerTooltip() {
  const [show, setShow] = useState(false);
  return (
    <div className="relative inline-block ml-2">
      <button
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onClick={() => setShow(!show)}
        className="p-1 rounded-full hover:bg-white/5 transition-colors"
      >
        <Info className="w-3.5 h-3.5 text-gray-500" />
      </button>
      <AnimatePresence>
        {show && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-72 p-3 rounded-lg bg-surface-2 border border-white/10 shadow-xl text-[10px] text-gray-400 leading-relaxed"
          >
            This report documents technical control mapping to support your organization's certification or alignment efforts. GhostPrompt is not itself NIST or ISO certified.
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ─── Status Badge ─── */
function StatusBadge({ status }: { status: string }) {
  if (status === 'SATISFIED' || status === 'pass') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
        <CheckCircle className="w-3 h-3" /> SATISFIED
      </span>
    );
  }
  if (status === 'PARTIAL') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
        <AlertTriangle className="w-3 h-3" /> PARTIAL
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
      <XCircle className="w-3 h-3" /> GAP
    </span>
  );
}

/* ─── Score Ring ─── */
function ScoreRing({ score, size = 80, strokeWidth = 6 }: { score: number; size?: number; strokeWidth?: number }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 95 ? '#34d399' : score >= 80 ? '#60a5fa' : score >= 60 ? '#fbbf24' : '#f87171';

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={radius} strokeWidth={strokeWidth} stroke="rgba(255,255,255,0.05)" fill="none" />
        <motion.circle
          cx={size / 2} cy={size / 2} r={radius} strokeWidth={strokeWidth} stroke={color} fill="none"
          strokeLinecap="round" strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-lg font-bold text-white">{score}%</span>
      </div>
    </div>
  );
}

/* ─── Radar Chart (Cross-Framework) ─── */
function GovernanceRadar({ data }: { data: Record<string, { name: string; score: number }> }) {
  const entries = Object.values(data).filter(d => typeof d.score === 'number');
  if (entries.length < 3) return null;

  const size = 280;
  const center = size / 2;
  const maxRadius = center - 40;
  const angleStep = (2 * Math.PI) / entries.length;

  const getPoint = (index: number, value: number) => {
    const angle = index * angleStep - Math.PI / 2;
    const r = (value / 100) * maxRadius;
    return { x: center + r * Math.cos(angle), y: center + r * Math.sin(angle) };
  };

  const polygonPoints = entries.map((e, i) => {
    const p = getPoint(i, e.score);
    return `${p.x},${p.y}`;
  }).join(' ');

  const gridLevels = [25, 50, 75, 100];

  return (
    <div className="flex justify-center">
      <svg width={size} height={size} className="overflow-visible">
        {/* Grid */}
        {gridLevels.map(level => {
          const points = entries.map((_, i) => {
            const p = getPoint(i, level);
            return `${p.x},${p.y}`;
          }).join(' ');
          return <polygon key={level} points={points} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="1" />;
        })}
        {/* Axes */}
        {entries.map((_, i) => {
          const p = getPoint(i, 100);
          return <line key={i} x1={center} y1={center} x2={p.x} y2={p.y} stroke="rgba(255,255,255,0.08)" strokeWidth="1" />;
        })}
        {/* Data polygon */}
        <motion.polygon
          points={polygonPoints}
          fill="rgba(99, 102, 241, 0.15)"
          stroke="rgb(99, 102, 241)"
          strokeWidth="2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.3 }}
        />
        {/* Data points */}
        {entries.map((e, i) => {
          const p = getPoint(i, e.score);
          return <circle key={i} cx={p.x} cy={p.y} r="4" fill="rgb(99, 102, 241)" stroke="rgba(255,255,255,0.3)" strokeWidth="1.5" />;
        })}
        {/* Labels */}
        {entries.map((e, i) => {
          const p = getPoint(i, 115);
          return (
            <text key={i} x={p.x} y={p.y} textAnchor="middle" dominantBaseline="central" className="text-[9px] fill-gray-400">
              {e.name.length > 14 ? e.name.slice(0, 12) + '…' : e.name}
            </text>
          );
        })}
      </svg>
    </div>
  );
}

/* ─── Generic Framework Detail Panel ─── */
const GENERIC_FRAMEWORK_CONFIG: Record<string, { apiSlug: string; description: string }> = {
  soc2_type2: { apiSlug: 'soc2-type2', description: '5 Trust Service Criteria — Security, Availability, Processing Integrity, Confidentiality, Privacy.' },
  pci_dss: { apiSlug: 'pci-dss', description: '12 PCI DSS v4.0 requirements for payment card data security.' },
  gdpr: { apiSlug: 'gdpr', description: 'Articles 5–35 — Data protection, DPIA, breach notification, subject rights.' },
  eu_ai_act: { apiSlug: 'eu-ai-act', description: 'Articles 9–15/50, Annex III risk-tier classification for AI systems.' },
  hipaa: { apiSlug: 'hipaa', description: 'Privacy Rule, Security Rule, Breach Notification Rule — Administrative, Physical & Technical safeguards.' },
  ccpa: { apiSlug: 'ccpa', description: 'Consumer privacy rights + ADMT risk assessment for automated decision-making.' },
  dpdpa: { apiSlug: 'dpdpa', description: 'Data Principal rights, Consent Managers, 90-day grievance timeline, cross-border restrictions.' },
};

function FrameworkDetailPanel({ report, frameworkId, onDownload, expandedSection, setExpandedSection }: {
  report: GenericFrameworkReport;
  frameworkId: string;
  onDownload: (slug: string, format: 'json' | 'pdf' | 'csv') => void;
  expandedSection: string | null;
  setExpandedSection: (v: string | null) => void;
}) {
  const meta = FRAMEWORK_META[frameworkId] || FRAMEWORK_META['eu_ai_act'];
  const Icon = meta.icon;
  const slug = GENERIC_FRAMEWORK_CONFIG[frameworkId]?.apiSlug || frameworkId.replace(/_/g, '-');

  const getScoreColor = (score: number) => {
    if (score >= 95) return 'text-emerald-400';
    if (score >= 80) return 'text-blue-400';
    if (score >= 60) return 'text-amber-400';
    return 'text-red-400';
  };

  return (
    <>
      {/* Summary Bar */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl bg-gradient-to-br ${meta.gradient} bg-opacity-20 border border-white/10`}>
              <Icon className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="font-bold text-white flex items-center gap-1">{report.framework} <DisclaimerTooltip /></h3>
              <span className="text-xs text-gray-500">Version {report.framework_version} • Generated {new Date(report.generated_at).toLocaleString()}</span>
            </div>
          </div>
          <ScoreRing score={report.overall_score} />
        </div>
        <div className="grid grid-cols-5 gap-3 text-center">
          <div className="p-3 rounded-lg bg-surface-2/50">
            <div className="text-lg font-bold text-white">{report.total_controls}</div>
            <div className="text-[10px] text-gray-500">Total Controls</div>
          </div>
          <div className="p-3 rounded-lg bg-emerald-500/5">
            <div className="text-lg font-bold text-emerald-400">{report.satisfied}</div>
            <div className="text-[10px] text-gray-500">Satisfied</div>
          </div>
          <div className="p-3 rounded-lg bg-amber-500/5">
            <div className="text-lg font-bold text-amber-400">{report.partial}</div>
            <div className="text-[10px] text-gray-500">Partial</div>
          </div>
          <div className="p-3 rounded-lg bg-red-500/5">
            <div className="text-lg font-bold text-red-400">{report.gap}</div>
            <div className="text-[10px] text-gray-500">Gaps</div>
          </div>
          <div className="p-3 rounded-lg bg-gray-500/5">
            <div className="text-lg font-bold text-gray-400">{report.not_applicable}</div>
            <div className="text-[10px] text-gray-500">N/A</div>
          </div>
        </div>
      </div>

      {/* Section Accordions */}
      {Object.entries(report.sections).map(([sectionName, sectionData]) => {
        const isOpen = expandedSection === sectionName;
        const controlEntries = Object.entries(sectionData.controls);

        return (
          <motion.div key={sectionName} layout className="glass-card overflow-hidden">
            <div
              className="p-6 cursor-pointer hover:bg-white/[0.02] transition-colors"
              onClick={() => setExpandedSection(isOpen ? null : sectionName)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Icon className={`w-5 h-5 ${meta.color}`} />
                  <div>
                    <h4 className="font-bold text-white">{sectionData.title || sectionName}</h4>
                    <p className="text-xs text-gray-500">{sectionName}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className={`text-lg font-bold ${getScoreColor(sectionData.score)}`}>{sectionData.score}%</div>
                  <span className="text-xs text-gray-500">{controlEntries.length} controls</span>
                  {isOpen ? <ChevronDown className="w-5 h-5 text-gray-500" /> : <ChevronRight className="w-5 h-5 text-gray-500" />}
                </div>
              </div>
            </div>
            <AnimatePresence>
              {isOpen && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="border-t border-white/5"
                >
                  <div className="p-4 space-y-2">
                    {controlEntries.map(([ctrlId, ctrl]) => (
                      <div key={ctrlId} className="p-3 rounded-lg bg-surface-2/50 hover:bg-surface-2 transition-colors">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1 flex-wrap">
                              <span className="text-xs font-mono text-ghost-400">{ctrlId}</span>
                              <StatusBadge status={ctrl.status} />
                              {ctrl.requires_external_audit && (
                                <span className="text-[8px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20 font-bold uppercase tracking-widest">Ext. Audit</span>
                              )}
                            </div>
                            {ctrl.title && <p className="text-xs font-semibold text-gray-200 mb-0.5">{ctrl.title}</p>}
                            <p className="text-sm text-gray-300">{ctrl.requirement}</p>
                            {ctrl.gap_note && (
                              <div className="mt-1.5 flex items-start gap-1.5 p-1.5 rounded bg-amber-500/5 border border-amber-500/10">
                                <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
                                <p className="text-[10px] text-amber-300/80">{ctrl.gap_note}</p>
                              </div>
                            )}
                            {ctrl.remediation && (
                              <div className="mt-1.5 flex items-start gap-1.5 p-1.5 rounded bg-blue-500/5 border border-blue-500/10">
                                <Wrench className="w-3 h-3 text-blue-400 shrink-0 mt-0.5" />
                                <p className="text-[10px] text-blue-300/80">{ctrl.remediation}</p>
                              </div>
                            )}
                            <div className="mt-2 space-y-1">
                              {ctrl.evidence_sources.map((ev, i) => (
                                <div key={i} className="text-[10px] text-gray-500 flex items-start gap-1">
                                  <CheckCircle className="w-3 h-3 text-emerald-500/50 shrink-0 mt-0.5" />
                                  <span>{ev}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                          <div className="text-[9px] text-gray-600 text-right shrink-0">
                            <div className="font-mono">{ctrl.evidence_type}</div>
                            <div className="mt-1">{new Date(ctrl.last_verified).toLocaleDateString()}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        );
      })}

      {/* Disclaimer */}
      {report.disclaimer && (
        <div className="glass-card p-4 border-l-2 border-amber-500/30">
          <div className="flex items-start gap-2">
            <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-[11px] text-gray-400 leading-relaxed">{report.disclaimer}</p>
          </div>
        </div>
      )}

      {/* Report Footer with Downloads */}
      <div className="glass-card p-4 flex items-center justify-between">
        <span className="text-xs text-gray-500">Report ID: {report.report_id.slice(0, 8)}… • HMAC-signed</span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onDownload(slug, 'csv')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-gray-400 hover:text-white hover:border-emerald-500/30 transition-all"
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={() => onDownload(slug, 'json')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-gray-400 hover:text-white hover:border-${meta.color.replace('text-', '')?.split('-')[0]}-500/30 transition-all`}
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
          <button
            onClick={() => onDownload(slug, 'pdf')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r ${meta.gradient.replace(/from-/,'from-').replace(/to-/,'to-')} bg-opacity-10 border border-white/10 text-xs ${meta.color} hover:text-white transition-all`}
          >
            <FileText className="w-3.5 h-3.5" /> PDF Report
          </button>
        </div>
      </div>
    </>
  );
}
type TabId = 'overview' | 'nist' | 'iso' | 'soc2_type2' | 'pci_dss' | 'gdpr' | 'eu_ai_act' | 'hipaa' | 'ccpa' | 'dpdpa' | 'existing' | 'gaps';

export default function ComplianceView() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  // Existing framework report
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [days, setDays] = useState(30);
  const [expanded, setExpanded] = useState<string | null>(null);

  // NIST report
  const [nistReport, setNistReport] = useState<NISTReport | null>(null);
  const [nistLoading, setNistLoading] = useState(false);
  const [nistExpanded, setNistExpanded] = useState<string | null>(null);

  // ISO report
  const [isoReport, setIsoReport] = useState<ISOReport | null>(null);
  const [isoLoading, setIsoLoading] = useState(false);
  const [isoExpanded, setIsoExpanded] = useState<string | null>(null);

  // Cross-framework summary
  const [crossSummary, setCrossSummary] = useState<CrossFrameworkSummary | null>(null);
  const [crossLoading, setCrossLoading] = useState(false);

  // Generic framework reports (SOC2, PCI DSS, GDPR, EU AI Act, HIPAA, CCPA, DPDPA)
  const [genericReports, setGenericReports] = useState<Record<string, GenericFrameworkReport>>({});
  const [genericLoading, setGenericLoading] = useState<Record<string, boolean>>({});
  const [genericExpanded, setGenericExpanded] = useState<string | null>(null);

  const getAuthHeader = () => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    return { Authorization: `Bearer ${token}` };
  };

  const getScoreColor = (score: number) => {
    if (score >= 95) return 'text-emerald-400';
    if (score >= 80) return 'text-blue-400';
    if (score >= 60) return 'text-amber-400';
    return 'text-red-400';
  };

  // ── Fetch Existing Compliance Report ──
  const generateReport = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/enterprise/compliance/report?framework=all&days=${days}`, { headers: getAuthHeader() });
      if (res.ok) setReport(await res.json());
    } catch (err) { console.error('Failed to generate report:', err); }
    setLoading(false);
  };

  // ── Fetch NIST Report ──
  const generateNIST = async () => {
    setNistLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/compliance-frameworks/nist-ai-rmf`, { headers: getAuthHeader() });
      if (res.ok) setNistReport(await res.json());
    } catch (err) { console.error('Failed to generate NIST report:', err); }
    setNistLoading(false);
  };

  // ── Fetch ISO Report ──
  const generateISO = async () => {
    setIsoLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/compliance-frameworks/iso-42001`, { headers: getAuthHeader() });
      if (res.ok) setIsoReport(await res.json());
    } catch (err) { console.error('Failed to generate ISO report:', err); }
    setIsoLoading(false);
  };

  // ── Fetch Cross-Framework Summary ──
  const fetchCrossSummary = async () => {
    setCrossLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/compliance-frameworks/summary`, { headers: getAuthHeader() });
      if (res.ok) setCrossSummary(await res.json());
    } catch (err) { console.error('Failed to fetch cross-framework summary:', err); }
    setCrossLoading(false);
  };

  // ── Fetch Generic Framework Report ──
  const fetchGenericReport = async (frameworkId: string) => {
    setGenericLoading(prev => ({ ...prev, [frameworkId]: true }));
    try {
      const res = await fetch(`${API_URL}/api/v1/compliance-frameworks/report/${frameworkId}`, { headers: getAuthHeader() });
      if (res.ok) {
        const data = await res.json();
        setGenericReports(prev => ({ ...prev, [frameworkId]: data }));
      }
    } catch (err) { console.error(`Failed to fetch ${frameworkId} report:`, err); }
    setGenericLoading(prev => ({ ...prev, [frameworkId]: false }));
  };

  // ── Download Report (JSON, PDF, or CSV) for any framework ──
  const downloadReport = async (framework: string, format: 'json' | 'pdf' | 'csv') => {
    try {
      const res = await fetch(
        `${API_URL}/api/v1/compliance-frameworks/download/${framework}?format=${format}`,
        { headers: getAuthHeader() },
      );
      if (!res.ok) throw new Error('Download failed');

      const blob = await res.blob();
      const hmac = res.headers.get('X-GhostPrompt-Report-HMAC') || '';
      const disposition = res.headers.get('Content-Disposition') || '';
      const filenameMatch = disposition.match(/filename="(.+)"/);
      const filename = filenameMatch ? filenameMatch[1] : `ghostprompt_${framework.replace(/-/g, '_')}_report.${format}`;

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      console.log(`Report downloaded: ${filename} | HMAC: ${hmac.slice(0, 16)}…`);
    } catch (err) {
      console.error(`Failed to download ${framework} ${format}:`, err);
    }
  };

  // ── Download CSV from in-memory report data ──
  const downloadCSV = (framework: 'nist' | 'iso') => {
    let csvRows: string[] = [];
    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');

    if (framework === 'nist' && nistReport) {
      csvRows.push('Function,Subcategory,Requirement,Status,Evidence Sources,Evidence Type,Last Verified');
      for (const [fnName, fnData] of Object.entries(nistReport.functions)) {
        for (const [subId, sub] of Object.entries(fnData.subcategories)) {
          const ev = sub.evidence_sources.map(e => e.replace(/,/g, ';')).join(' | ');
          csvRows.push(`"${fnName}","${subId}","${sub.requirement.replace(/"/g, '""')}","${sub.status}","${ev}","${sub.evidence_type}","${sub.last_verified}"`);
        }
      }
    } else if (framework === 'iso' && isoReport) {
      csvRows.push('Clause,Requirement ID,Requirement,Status,Evidence Sources,Last Verified');
      for (const [clauseId, clauseData] of Object.entries(isoReport.clauses)) {
        for (const [reqId, req] of Object.entries(clauseData.requirements)) {
          const ev = req.evidence_sources.map(e => e.replace(/,/g, ';')).join(' | ');
          csvRows.push(`"${clauseId}","${reqId}","${req.requirement.replace(/"/g, '""')}","${req.status}","${ev}","${req.last_verified}"`);
        }
      }
    }

    if (csvRows.length === 0) return;
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ghostprompt_${framework === 'nist' ? 'nist_ai_rmf' : 'iso_42001'}_report_${ts}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Auto-fetch cross-framework summary on mount
  useEffect(() => { fetchCrossSummary(); }, []);

  // Auto-fetch generic framework report when switching to its tab
  useEffect(() => {
    const genericIds = Object.keys(GENERIC_FRAMEWORK_CONFIG);
    if (genericIds.includes(activeTab) && !genericReports[activeTab] && !genericLoading[activeTab]) {
      fetchGenericReport(activeTab);
    }
  }, [activeTab]);


  const tabs: { id: TabId; label: string; icon: typeof Shield }[] = [
    { id: 'overview', label: 'Governance Overview', icon: BarChart3 },
    { id: 'nist', label: 'NIST AI RMF', icon: Landmark },
    { id: 'iso', label: 'ISO 42001', icon: BookOpen },
    { id: 'soc2_type2', label: 'SOC 2', icon: Building2 },
    { id: 'pci_dss', label: 'PCI DSS', icon: Shield },
    { id: 'gdpr', label: 'GDPR', icon: Lock },
    { id: 'eu_ai_act', label: 'EU AI Act', icon: Globe2 },
    { id: 'hipaa', label: 'HIPAA', icon: Heart },
    { id: 'ccpa', label: 'CCPA', icon: Lock },
    { id: 'dpdpa', label: 'DPDPA', icon: Globe2 },
    { id: 'gaps', label: 'Gap Remediation', icon: AlertOctagon },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-blue-500/20 to-indigo-600/20 border border-blue-500/20">
              <FileText className="w-6 h-6 text-blue-400" />
            </div>
            Compliance & Governance
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            9-framework governance suite — NIST AI RMF, ISO 42001, SOC2, PCI DSS, GDPR, EU AI Act, HIPAA, CCPA & DPDPA
          </p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-white/10 pb-0 overflow-x-auto">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-ghost-500 text-ghost-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-white/20'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>


      {/* ═══════════════════════════════════════════════════════════
          TAB: GOVERNANCE OVERVIEW
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {crossLoading ? (
            <div className="glass-card p-16 text-center">
              <Loader2 className="w-12 h-12 text-ghost-400 mx-auto mb-4 animate-spin" />
              <h3 className="text-xl font-semibold text-gray-400">Loading Governance Dashboard...</h3>
            </div>
          ) : crossSummary ? (
            <>
              {/* Maturity Index */}
              <div className="glass-card p-8">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      <TrendingUp className="w-5 h-5 text-ghost-400" />
                      Overall Governance Maturity Index
                      <DisclaimerTooltip />
                    </h3>
                    <p className="text-xs text-gray-500 mt-1">Composite score across all 9 compliance frameworks</p>
                  </div>
                  <ScoreRing score={crossSummary.overall_governance_maturity} size={100} strokeWidth={8} />
                </div>

                {/* Framework Score Cards */}
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                  {Object.entries(crossSummary.frameworks).map(([key, fw]) => {
                    const metaKey = key.toLowerCase();
                    const meta = FRAMEWORK_META[metaKey] || FRAMEWORK_META['eu_ai_act'];
                    const Icon = meta.icon;
                    return (
                      <div key={key} className="glass-card p-4 text-center hover:bg-white/[0.02] transition-colors">
                        <div className={`p-2 rounded-xl bg-gradient-to-br ${meta.gradient} bg-opacity-20 w-fit mx-auto mb-2`}>
                          <Icon className="w-4 h-4 text-white" />
                        </div>
                        <div className={`text-xl font-bold ${getScoreColor(fw.score)}`}>{fw.score}%</div>
                        <div className="text-[10px] text-gray-500 mt-1">{fw.name}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Radar Chart */}
              <div className="glass-card p-8">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <Target className="w-5 h-5 text-ghost-400" />
                  Cross-Framework Alignment Radar
                </h3>
                <GovernanceRadar data={crossSummary.frameworks} />
              </div>

              {/* (NIST and ISO quick actions removed as they have dedicated tabs) */}
            </>
          ) : (
            <div className="glass-card p-16 text-center">
              <BarChart3 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">Unable to Load Governance Data</h3>
              <p className="text-gray-500 text-sm">Ensure you&apos;re signed in with a Pro plan or higher.</p>
              <button onClick={fetchCrossSummary} className="btn-primary mt-4 text-sm">Retry</button>
            </div>
          )}
        </div>
      )}


      {/* ═══════════════════════════════════════════════════════════
          TAB: NIST AI RMF
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'nist' && (
        <div className="space-y-6">
          {!nistReport && !nistLoading && (
            <div className="glass-card p-16 text-center">
              <Landmark className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">NIST AI RMF 1.0 Alignment</h3>
              <p className="text-gray-500 text-sm max-w-md mx-auto mb-6">
                Generate a comprehensive mapping of GhostPrompt&apos;s capabilities to the NIST AI Risk Management Framework.
              </p>
              <button onClick={generateNIST} className="btn-primary flex items-center gap-2 mx-auto text-sm">
                <BarChart3 className="w-4 h-4" /> Generate NIST AI RMF Report
              </button>
            </div>
          )}

          {nistLoading && (
            <div className="glass-card p-16 text-center">
              <Loader2 className="w-12 h-12 text-cyan-400 mx-auto mb-4 animate-spin" />
              <h3 className="text-xl font-semibold text-gray-400">Generating NIST AI RMF Alignment Report...</h3>
              <p className="text-gray-500 text-sm mt-2">Mapping across Govern, Map, Measure, and Manage functions</p>
            </div>
          )}

          {nistReport && !nistLoading && (
            <>
              {/* Summary Bar */}
              <div className="glass-card p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/20">
                      <Landmark className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white flex items-center gap-1">NIST AI RMF 1.0 Alignment <DisclaimerTooltip /></h3>
                      <span className="text-xs text-gray-500">Generated {new Date(nistReport.generated_at).toLocaleString()}</span>
                    </div>
                  </div>
                  <ScoreRing score={nistReport.overall_alignment_score} />
                </div>
                <div className="grid grid-cols-4 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-surface-2/50">
                    <div className="text-lg font-bold text-white">{nistReport.total_subcategories}</div>
                    <div className="text-[10px] text-gray-500">Total Controls</div>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-500/5">
                    <div className="text-lg font-bold text-emerald-400">{nistReport.satisfied}</div>
                    <div className="text-[10px] text-gray-500">Satisfied</div>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/5">
                    <div className="text-lg font-bold text-amber-400">{nistReport.partial}</div>
                    <div className="text-[10px] text-gray-500">Partial</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/5">
                    <div className="text-lg font-bold text-red-400">{nistReport.gap}</div>
                    <div className="text-[10px] text-gray-500">Gaps</div>
                  </div>
                </div>
              </div>

              {/* Function Accordions */}
              {Object.entries(nistReport.functions).map(([funcName, funcData]) => {
                const isOpen = nistExpanded === funcName;
                const meta = NIST_FUNCTION_META[funcName] || { icon: Shield, color: 'text-gray-400' };
                const FuncIcon = meta.icon;
                const subcatEntries = Object.entries(funcData.subcategories);

                return (
                  <motion.div key={funcName} layout className="glass-card overflow-hidden">
                    <div
                      className="p-6 cursor-pointer hover:bg-white/[0.02] transition-colors"
                      onClick={() => setNistExpanded(isOpen ? null : funcName)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <FuncIcon className={`w-5 h-5 ${meta.color}`} />
                          <div>
                            <h4 className="font-bold text-white">{funcName}</h4>
                            <p className="text-xs text-gray-500">{funcData.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className={`text-lg font-bold ${getScoreColor(funcData.score)}`}>{funcData.score}%</div>
                          <span className="text-xs text-gray-500">{subcatEntries.length} controls</span>
                          {isOpen ? <ChevronDown className="w-5 h-5 text-gray-500" /> : <ChevronRight className="w-5 h-5 text-gray-500" />}
                        </div>
                      </div>
                    </div>
                    <AnimatePresence>
                      {isOpen && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="border-t border-white/5"
                        >
                          <div className="p-4 space-y-2">
                            {subcatEntries.map(([subId, sub]) => (
                              <div key={subId} className="p-3 rounded-lg bg-surface-2/50 hover:bg-surface-2 transition-colors">
                                <div className="flex items-start justify-between gap-4">
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="text-xs font-mono text-ghost-400">{subId}</span>
                                      <StatusBadge status={sub.status} />
                                    </div>
                                    <p className="text-sm text-gray-300">{sub.requirement}</p>
                                    <div className="mt-2 space-y-1">
                                      {sub.evidence_sources.map((ev, i) => (
                                        <div key={i} className="text-[10px] text-gray-500 flex items-start gap-1">
                                          <CheckCircle className="w-3 h-3 text-emerald-500/50 shrink-0 mt-0.5" />
                                          <span>{ev}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                  <div className="text-[9px] text-gray-600 text-right shrink-0">
                                    <div className="font-mono">{sub.evidence_type}</div>
                                    <div className="mt-1">{new Date(sub.last_verified).toLocaleDateString()}</div>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}

              {/* Report Footer with Downloads */}
              <div className="glass-card p-4 flex items-center justify-between">
                <span className="text-xs text-gray-500">Report ID: {nistReport.report_id.slice(0, 8)}… • HMAC-signed</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => downloadReport('nist-ai-rmf', 'csv')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-gray-400 hover:text-white hover:border-emerald-500/30 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" /> CSV
                  </button>
                  <button
                    onClick={() => downloadReport('nist-ai-rmf', 'json')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-gray-400 hover:text-white hover:border-cyan-500/30 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" /> JSON
                  </button>
                  <button
                    onClick={() => downloadReport('nist-ai-rmf', 'pdf')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 text-xs text-cyan-400 hover:text-white hover:border-cyan-500/40 transition-all"
                  >
                    <FileText className="w-3.5 h-3.5" /> PDF Report
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}


      {/* ═══════════════════════════════════════════════════════════
          TAB: ISO 42001
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'iso' && (
        <div className="space-y-6">
          {!isoReport && !isoLoading && (
            <div className="glass-card p-16 text-center">
              <BookOpen className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">ISO/IEC 42001:2023 Readiness</h3>
              <p className="text-gray-500 text-sm max-w-md mx-auto mb-6">
                Generate a comprehensive readiness assessment against the ISO AI Management System standard.
              </p>
              <button onClick={generateISO} className="btn-primary flex items-center gap-2 mx-auto text-sm">
                <BarChart3 className="w-4 h-4" /> Generate ISO 42001 Report
              </button>
            </div>
          )}

          {isoLoading && (
            <div className="glass-card p-16 text-center">
              <Loader2 className="w-12 h-12 text-violet-400 mx-auto mb-4 animate-spin" />
              <h3 className="text-xl font-semibold text-gray-400">Generating ISO 42001 Readiness Report...</h3>
              <p className="text-gray-500 text-sm mt-2">Mapping Clauses 4–10 and Annex A controls</p>
            </div>
          )}

          {isoReport && !isoLoading && (
            <>
              {/* Summary Bar */}
              <div className="glass-card p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-600/20 border border-violet-500/20">
                      <BookOpen className="w-5 h-5 text-violet-400" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white flex items-center gap-1">ISO/IEC 42001:2023 Readiness <DisclaimerTooltip /></h3>
                      <span className="text-xs text-gray-500">Generated {new Date(isoReport.generated_at).toLocaleString()}</span>
                    </div>
                  </div>
                  <ScoreRing score={isoReport.overall_readiness_score} />
                </div>
                <div className="grid grid-cols-4 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-surface-2/50">
                    <div className="text-lg font-bold text-white">{isoReport.total_requirements}</div>
                    <div className="text-[10px] text-gray-500">Total Requirements</div>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-500/5">
                    <div className="text-lg font-bold text-emerald-400">{isoReport.satisfied}</div>
                    <div className="text-[10px] text-gray-500">Satisfied</div>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/5">
                    <div className="text-lg font-bold text-amber-400">{isoReport.partial}</div>
                    <div className="text-[10px] text-gray-500">Partial</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/5">
                    <div className="text-lg font-bold text-red-400">{isoReport.gap}</div>
                    <div className="text-[10px] text-gray-500">Gaps</div>
                  </div>
                </div>
              </div>

              {/* Clause Accordions */}
              {Object.entries(isoReport.clauses).map(([clauseId, clauseData]) => {
                const isOpen = isoExpanded === clauseId;
                const reqEntries = Object.entries(clauseData.requirements);

                return (
                  <motion.div key={clauseId} layout className="glass-card overflow-hidden">
                    <div
                      className="p-6 cursor-pointer hover:bg-white/[0.02] transition-colors"
                      onClick={() => setIsoExpanded(isOpen ? null : clauseId)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <BookOpen className="w-5 h-5 text-violet-400" />
                          <div>
                            <h4 className="font-bold text-white">{clauseId}: {clauseData.title}</h4>
                            <p className="text-xs text-gray-500">{reqEntries.length} requirement{reqEntries.length !== 1 ? 's' : ''}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className={`text-lg font-bold ${getScoreColor(clauseData.score)}`}>{clauseData.score}%</div>
                          {isOpen ? <ChevronDown className="w-5 h-5 text-gray-500" /> : <ChevronRight className="w-5 h-5 text-gray-500" />}
                        </div>
                      </div>
                    </div>
                    <AnimatePresence>
                      {isOpen && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="border-t border-white/5"
                        >
                          <div className="p-4 space-y-2">
                            {reqEntries.map(([reqId, req]) => (
                              <div key={reqId} className="p-3 rounded-lg bg-surface-2/50 hover:bg-surface-2 transition-colors">
                                <div className="flex items-start justify-between gap-4">
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="text-xs font-mono text-ghost-400">{reqId}</span>
                                      <StatusBadge status={req.status} />
                                    </div>
                                    <p className="text-sm text-gray-300">{req.requirement}</p>
                                    <div className="mt-2 space-y-1">
                                      {req.evidence_sources.map((ev, i) => (
                                        <div key={i} className="text-[10px] text-gray-500 flex items-start gap-1">
                                          <CheckCircle className="w-3 h-3 text-emerald-500/50 shrink-0 mt-0.5" />
                                          <span>{ev}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                  <div className="text-[9px] text-gray-600 text-right shrink-0">
                                    {new Date(req.last_verified).toLocaleDateString()}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}

              {/* Report Footer with Downloads */}
              <div className="glass-card p-4 flex items-center justify-between">
                <span className="text-xs text-gray-500">Report ID: {isoReport.report_id.slice(0, 8)}… • HMAC-signed</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => downloadReport('iso-42001', 'csv')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-gray-400 hover:text-white hover:border-emerald-500/30 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" /> CSV
                  </button>
                  <button
                    onClick={() => downloadReport('iso-42001', 'json')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-gray-400 hover:text-white hover:border-violet-500/30 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" /> JSON
                  </button>
                  <button
                    onClick={() => downloadReport('iso-42001', 'pdf')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-violet-500/10 to-purple-500/10 border border-violet-500/20 text-xs text-violet-400 hover:text-white hover:border-violet-500/40 transition-all"
                  >
                    <FileText className="w-3.5 h-3.5" /> PDF Report
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}


      {/* ═══════════════════════════════════════════════════════════
          TABs: SOC2, PCI DSS, GDPR, EU AI Act, HIPAA, CCPA, DPDPA
         ═══════════════════════════════════════════════════════════ */}
      {Object.keys(GENERIC_FRAMEWORK_CONFIG).map((fwId) => {
        if (activeTab !== fwId) return null;
        const config = GENERIC_FRAMEWORK_CONFIG[fwId];
        const meta = FRAMEWORK_META[fwId] || FRAMEWORK_META['eu_ai_act'];
        const FwIcon = meta.icon;
        const report = genericReports[fwId];
        const isLoading = genericLoading[fwId];

        return (
          <div key={fwId} className="space-y-6">
            {!report && !isLoading && (
              <div className="glass-card p-16 text-center">
                <FwIcon className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-gray-400 mb-2">{meta.label}</h3>
                <p className="text-gray-500 text-sm max-w-md mx-auto mb-6">
                  {config.description}
                </p>
                <button
                  onClick={() => fetchGenericReport(fwId)}
                  className="btn-primary flex items-center gap-2 mx-auto text-sm"
                >
                  <BarChart3 className="w-4 h-4" /> Generate {meta.label} Report
                </button>
              </div>
            )}

            {isLoading && (
              <div className="glass-card p-16 text-center">
                <Loader2 className="w-12 h-12 text-ghost-400 mx-auto mb-4 animate-spin" />
                <h3 className="text-xl font-semibold text-gray-400">Generating {meta.label} Report...</h3>
                <p className="text-gray-500 text-sm mt-2">{config.description}</p>
              </div>
            )}

            {report && !isLoading && (
              <FrameworkDetailPanel
                report={report}
                frameworkId={fwId}
                onDownload={downloadReport}
                expandedSection={genericExpanded}
                setExpandedSection={setGenericExpanded}
              />
            )}
          </div>
        );
      })}


      {/* ═══════════════════════════════════════════════════════════
          TAB: EXISTING FRAMEWORKS (SOC2, GDPR, HIPAA, EU AI Act)
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'existing' && (
        <div className="space-y-6">
          <div className="flex items-center justify-end gap-3">
            <select
              value={days}
              onChange={e => setDays(Number(e.target.value))}
              className="bg-surface-2 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-ghost-500/50"
            >
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
              <option value={365}>Last year</option>
            </select>
            <button
              onClick={generateReport}
              disabled={loading}
              className="btn-primary flex items-center gap-2 text-sm"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
              Generate Report
            </button>
          </div>

          {!report && !loading && (
            <div className="glass-card p-16 text-center">
              <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">No Report Generated</h3>
              <p className="text-gray-500 text-sm max-w-md mx-auto">
                Click &quot;Generate Report&quot; to run a full compliance check against EU AI Act, SOC 2, HIPAA, and GDPR.
              </p>
            </div>
          )}

          {loading && (
            <div className="glass-card p-16 text-center">
              <Loader2 className="w-12 h-12 text-ghost-400 mx-auto mb-4 animate-spin" />
              <h3 className="text-xl font-semibold text-gray-400">Generating Compliance Report...</h3>
              <p className="text-gray-500 text-sm mt-2">Scanning {days} days of security activity across 4 frameworks</p>
            </div>
          )}

          {report && !loading && (
            <>
              {/* Summary Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="glass-card p-4 text-center">
                  <div className="text-2xl font-bold text-white">{report.total_scans.toLocaleString()}</div>
                  <div className="text-xs text-gray-500 mt-1">Total Scans</div>
                </div>
                <div className="glass-card p-4 text-center">
                  <div className="text-2xl font-bold text-red-400">{report.threats_blocked.toLocaleString()}</div>
                  <div className="text-xs text-gray-500 mt-1">Threats Blocked</div>
                </div>
                <div className="glass-card p-4 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{report.active_policies}</div>
                  <div className="text-xs text-gray-500 mt-1">Active Policies</div>
                </div>
                <div className="glass-card p-4 text-center">
                  <div className="text-2xl font-bold text-ghost-400">{report.frameworks.length}</div>
                  <div className="text-xs text-gray-500 mt-1">Frameworks Checked</div>
                </div>
              </div>

              {/* Framework Cards */}
              <div className="grid md:grid-cols-2 gap-6">
                {report.frameworks.map((fw, idx) => {
                  const normalizedName = fw.framework.toLowerCase().replace(/[\s\/\-\.]+/g, '_');
                  const fwKey = Object.keys(FRAMEWORK_META).find(k =>
                    FRAMEWORK_META[k].label === fw.framework ||
                    normalizedName.includes(k.replace(/_/g, ''))
                  ) || `fw_${idx}`;
                  const meta = FRAMEWORK_META[fwKey] || FRAMEWORK_META['eu_ai_act'];
                  const Icon = meta?.icon || Shield;
                  const isExpanded2 = expanded === `${fwKey}_${idx}`;

                  return (
                    <motion.div key={`${fwKey}_${idx}`} layout className="glass-card overflow-hidden">
                      <div
                        className="p-6 cursor-pointer hover:bg-white/[0.02] transition-colors"
                        onClick={() => setExpanded(isExpanded2 ? null : `${fwKey}_${idx}`)}
                      >
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-3">
                            <div className={`p-2 rounded-xl bg-gradient-to-br ${meta?.gradient || 'from-gray-500 to-gray-600'} bg-opacity-20`}>
                              <Icon className="w-5 h-5 text-white" />
                            </div>
                            <div>
                              <h3 className="font-bold text-white">{fw.framework}</h3>
                              <span className="text-xs text-gray-500">Version {fw.version}</span>
                            </div>
                          </div>
                          {isExpanded2 ? <ChevronDown className="w-5 h-5 text-gray-500" /> : <ChevronRight className="w-5 h-5 text-gray-500" />}
                        </div>
                        <div className={`rounded-xl bg-gradient-to-br ${fw.compliance_score >= 95 ? 'from-emerald-500/20 to-emerald-600/5' : fw.compliance_score >= 80 ? 'from-blue-500/20 to-blue-600/5' : 'from-amber-500/20 to-amber-600/5'} p-4 flex items-center justify-between`}>
                          <div>
                            <div className={`text-3xl font-bold ${getScoreColor(fw.compliance_score)}`}>{fw.compliance_score}%</div>
                            <div className="text-xs text-gray-500 mt-1">Compliance Score</div>
                          </div>
                          <div className="text-right text-sm">
                            <div className="text-emerald-400">{fw.passed} passed</div>
                            <div className="text-red-400">{fw.failed} failed</div>
                          </div>
                        </div>
                      </div>
                      <AnimatePresence>
                        {isExpanded2 && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="border-t border-white/5"
                          >
                            <div className="p-4 space-y-2">
                              {fw.requirements.map((req, i) => (
                                <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-surface-2/50 hover:bg-surface-2 transition-colors">
                                  {req.status === 'pass' ? (
                                    <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                                  ) : (
                                    <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                                  )}
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs font-mono text-ghost-400">{req.id}</span>
                                      <span className="font-medium text-sm text-white">{req.title}</span>
                                    </div>
                                    <p className="text-xs text-gray-500 mt-0.5">{req.details}</p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </div>

              {/* Report Meta */}
              <div className="glass-card p-4 flex items-center justify-between text-xs text-gray-500">
                <span>Report ID: {report.report_id.slice(0, 8)}...</span>
                <span>Generated: {new Date(report.generated_at).toLocaleString()}</span>
                <span>Period: {report.report_period_days} days</span>
              </div>
            </>
          )}
        </div>
      )}


      {/* ═══════════════════════════════════════════════════════════
          TAB: GAP REMEDIATION
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'gaps' && (
        <div className="space-y-6">
          <div className="glass-card p-6">
            <div className="flex items-center gap-3 mb-4">
              <AlertOctagon className="w-5 h-5 text-amber-400" />
              <h3 className="font-bold text-white">Gap Remediation Tracker</h3>
              <DisclaimerTooltip />
            </div>
            <p className="text-sm text-gray-500 mb-6">
              Actionable remediation steps for every subcategory or requirement that is not fully satisfied.
            </p>

            {/* Load gaps from all framework reports */}
            {(() => {
              const nistGaps = nistReport?.gaps || [];
              const isoGaps = isoReport?.gaps || [];
              const genericGapsList = Object.entries(genericReports).flatMap(([fwId, report]) =>
                (report?.gaps || []).map((g: any) => ({ ...g, framework: FRAMEWORK_META[fwId]?.label || fwId }))
              );
              const allGaps = [
                ...nistGaps.map((g: any) => ({ ...g, framework: 'NIST AI RMF' })),
                ...isoGaps.map((g: any) => ({ ...g, framework: 'ISO 42001' })),
                ...genericGapsList,
              ];

              const hasAnyReport = nistReport || isoReport || Object.keys(genericReports).length > 0;

              if (allGaps.length === 0 && !hasAnyReport) {
                return (
                  <div className="text-center py-12">
                    <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-500 text-sm mb-4">Generate framework reports first to see gaps across all 9 frameworks.</p>
                    <div className="flex items-center gap-3 justify-center flex-wrap">
                      <button onClick={generateNIST} disabled={nistLoading} className="btn-primary text-sm">Generate NIST</button>
                      <button onClick={generateISO} disabled={isoLoading} className="btn-primary text-sm">Generate ISO</button>
                    </div>
                  </div>
                );
              }

              if (allGaps.length === 0) {
                return (
                  <div className="text-center py-12">
                    <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
                    <h4 className="text-lg font-semibold text-white mb-2">No Gaps Found</h4>
                    <p className="text-gray-500 text-sm">All mapped controls are fully satisfied. Excellent compliance posture.</p>
                  </div>
                );
              }

              return (
                <div className="space-y-3">
                  {allGaps.map((gap: any, i: number) => (
                    <div key={i} className="p-4 rounded-lg bg-surface-2/50 border border-white/5 hover:bg-surface-2 transition-colors">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-[10px] px-2 py-0.5 rounded bg-white/5 text-gray-400 font-mono">{gap.framework}</span>
                            <span className="text-xs font-mono text-ghost-400">{gap.id}</span>
                            <StatusBadge status={gap.status} />
                          </div>
                          <p className="text-sm text-gray-300 mb-2">{gap.requirement}</p>
                          {gap.remediation && (
                            <div className="flex items-start gap-2 p-2 rounded bg-amber-500/5 border border-amber-500/10">
                              <Wrench className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                              <p className="text-xs text-amber-300/80">{gap.remediation}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                  <div className="text-xs text-gray-500 text-right mt-4">
                    {allGaps.length} gap{allGaps.length !== 1 ? 's' : ''} requiring remediation
                  </div>
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
}
