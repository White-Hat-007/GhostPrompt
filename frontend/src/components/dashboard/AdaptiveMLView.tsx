'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Brain, Sliders, TrendingUp, AlertTriangle, RefreshCw,
  Activity, BarChart3, Zap, CheckCircle, XCircle, Loader2, Clock,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface AdaptiveMLViewProps {
  token?: string;
}

interface DetectorBaseline {
  detector: string;
  current_threshold: number;
  baseline_mean: number;
  sample_count: number;
  drift_detected: boolean;
  drift_magnitude: number;
  suggested_threshold: number;
  last_updated: string;
}

interface ThresholdChange {
  id: string;
  detector_name: string;
  old_threshold: number;
  new_threshold: number;
  delta: number;
  reason: string;
  auto_approved: boolean;
  pending_approval: boolean;
  approved_by: string | null;
  created_at: string;
}

interface MLSummary {
  total_detectors: number;
  avg_threshold: number;
  drifting_detectors: number;
  total_samples: number;
  pending_approvals: number;
  total_changes: number;
}

interface MLSettings {
  auto_tune: boolean;
  detection_sensitivity: number;
  auto_tune_aggressiveness: number;
  min_confidence: number;
}

export default function AdaptiveMLView({ token }: AdaptiveMLViewProps) {
  const [baselines, setBaselines] = useState<DetectorBaseline[]>([]);
  const [pending, setPending] = useState<ThresholdChange[]>([]);
  const [changes, setChanges] = useState<ThresholdChange[]>([]);
  const [summary, setSummary] = useState<MLSummary | null>(null);
  const [settings, setSettings] = useState<MLSettings>({
    auto_tune: true,
    detection_sensitivity: 75,
    auto_tune_aggressiveness: 60,
    min_confidence: 40,
  });
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const authHeaders = useCallback(() => {
    const t = token || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null);
    return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
  }, [token]);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/adaptive-ml/status`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setBaselines(data.baselines || []);
        setPending(data.pending_approvals || []);
        setChanges(data.recent_changes || []);
        setSummary(data.summary || null);
        if (data.settings) setSettings(data.settings);
      }
    } catch (err) {
      console.error('Failed to fetch adaptive ML status:', err);
    } finally {
      setLoading(false);
    }
  }, [authHeaders]);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const toggleAutoTune = async () => {
    const newValue = !settings.auto_tune;
    try {
      await fetch(`${API}/api/v1/adaptive-ml/toggle-auto-tune`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ enabled: newValue }),
      });
      setSettings(s => ({ ...s, auto_tune: newValue }));
    } catch (err) {
      console.error(err);
    }
  };

  const approveChange = async (changeId: string) => {
    setActionLoading(changeId);
    try {
      await fetch(`${API}/api/v1/adaptive-ml/approve`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ change_id: changeId }),
      });
      await fetchStatus();
    } catch (err) {
      console.error(err);
    }
    setActionLoading(null);
  };

  const rejectChange = async (changeId: string) => {
    setActionLoading(changeId);
    try {
      await fetch(`${API}/api/v1/adaptive-ml/reject`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ change_id: changeId }),
      });
      await fetchStatus();
    } catch (err) {
      console.error(err);
    }
    setActionLoading(null);
  };

  const updateSensitivity = async (key: string, value: number) => {
    setSettings(s => ({ ...s, [key]: value }));
    try {
      await fetch(`${API}/api/v1/adaptive-ml/settings`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ [key]: value }),
      });
    } catch (err) {
      console.error(err);
    }
  };

  const formatDetectorName = (name: string) =>
    name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-ghost-400 animate-spin" />
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Adaptive ML Thresholds</h2>
          <p className="text-sm text-gray-500 mt-1">Self-tuning detection thresholds that adapt to your traffic patterns</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={toggleAutoTune}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium border transition-all ${
              settings.auto_tune ? 'bg-ghost-600/15 text-ghost-400 border-ghost-500/20' : 'bg-surface-2 text-gray-500 border-white/[0.06]'
            }`}
          >
            <Brain className="w-3.5 h-3.5" />
            {settings.auto_tune ? 'Auto-Tune ON' : 'Auto-Tune OFF'}
          </button>
          <button onClick={fetchStatus} className="btn-ghost text-[10px] gap-1">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Avg Threshold', value: summary ? `${(summary.avg_threshold * 100).toFixed(1)}%` : '—', delta: '', icon: TrendingUp, color: 'text-emerald-400' },
          { label: 'Drifting', value: summary ? `${summary.drifting_detectors}` : '0', delta: summary && summary.drifting_detectors > 0 ? 'needs attention' : '', icon: AlertTriangle, color: summary && summary.drifting_detectors > 0 ? 'text-amber-400' : 'text-emerald-400' },
          { label: 'Detectors Active', value: summary ? `${summary.total_detectors}` : '0', delta: '', icon: Brain, color: 'text-ghost-400' },
          { label: 'Pending Approvals', value: summary ? `${summary.pending_approvals}` : '0', delta: '', icon: Clock, color: summary && summary.pending_approvals > 0 ? 'text-red-400' : 'text-cyan-400' },
        ].map((s, i) => (
          <div key={i} className="glass-card p-4">
            <div className="flex items-center gap-2 mb-2">
              <s.icon className={`w-4 h-4 ${s.color}`} />
              <span className="text-[10px] text-gray-500 uppercase tracking-wider">{s.label}</span>
            </div>
            <div className="flex items-baseline gap-2">
              <p className="text-2xl font-bold text-white font-mono">{s.value}</p>
              {s.delta && <span className="text-[10px] font-mono text-amber-400">{s.delta}</span>}
            </div>
          </div>
        ))}
      </div>

      {/* Pending Approvals */}
      {pending.length > 0 && (
        <div className="glass-card overflow-hidden border-l-2 border-amber-500/40">
          <div className="px-5 py-3 border-b border-white/[0.04] flex items-center justify-between">
            <h3 className="text-sm font-semibold text-amber-400">⚠ Pending Threshold Approvals</h3>
            <span className="text-[9px] font-mono text-gray-500">{pending.length} pending</span>
          </div>
          <div className="divide-y divide-white/[0.03]">
            {pending.map((change) => (
              <div key={change.id} className="flex items-center justify-between px-5 py-3 hover:bg-white/[0.02]">
                <div>
                  <p className="text-sm text-gray-300">{formatDetectorName(change.detector_name)}</p>
                  <p className="text-[10px] text-gray-600 font-mono">
                    {(change.old_threshold * 100).toFixed(1)}% → {(change.new_threshold * 100).toFixed(1)}%
                    <span className="text-amber-400 ml-2">Δ {(change.delta * 100).toFixed(2)}%</span>
                  </p>
                  <p className="text-[9px] text-gray-600 mt-0.5">{change.reason}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => approveChange(change.id)}
                    disabled={actionLoading === change.id}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/15 hover:bg-emerald-500/20"
                  >
                    {actionLoading === change.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3 h-3" />}
                    Approve
                  </button>
                  <button
                    onClick={() => rejectChange(change.id)}
                    disabled={actionLoading === change.id}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/15 hover:bg-red-500/20"
                  >
                    <XCircle className="w-3 h-3" /> Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detector Grid */}
      <div className="glass-card overflow-hidden">
        <div className="px-5 py-3 border-b border-white/[0.04] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">Detection Engine Thresholds</h3>
          <span className="text-[9px] font-mono text-gray-500">
            {baselines.length} engines • {summary?.total_samples?.toLocaleString() || 0} samples
          </span>
        </div>

        {/* Table header */}
        <div className="grid grid-cols-7 gap-4 px-5 py-2 border-b border-white/[0.04] text-[9px] text-gray-600 uppercase tracking-wider font-bold">
          <span className="col-span-2">Engine</span>
          <span>Threshold</span>
          <span>Mean Score</span>
          <span>Samples</span>
          <span>Drift</span>
          <span>Updated</span>
        </div>

        <div className="divide-y divide-white/[0.03]">
          {baselines.length === 0 ? (
            <div className="px-5 py-8 text-center text-sm text-gray-600">
              No detector baselines yet. Run scans to populate drift data.
            </div>
          ) : (
            baselines.map((det, i) => (
              <div key={i} className="grid grid-cols-7 gap-4 px-5 py-3 items-center hover:bg-white/[0.02] transition-colors">
                <div className="col-span-2 flex items-center gap-2">
                  <div className={`w-1.5 h-1.5 rounded-full ${det.drift_detected ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400'}`} />
                  <span className="text-sm text-gray-300 truncate">{formatDetectorName(det.detector)}</span>
                </div>
                <span className="text-xs font-mono font-bold text-white">{(det.current_threshold * 100).toFixed(0)}%</span>
                <span className="text-xs text-gray-500 font-mono">{(det.baseline_mean * 100).toFixed(1)}%</span>
                <span className="text-xs text-gray-500 font-mono">{det.sample_count.toLocaleString()}</span>
                <span className={`text-[10px] font-mono font-bold ${det.drift_detected ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {det.drift_detected ? `⚠ ${(det.drift_magnitude * 100).toFixed(2)}%` : 'Stable'}
                </span>
                <span className="text-[10px] text-gray-600 font-mono">
                  {det.last_updated ? new Date(det.last_updated).toLocaleTimeString() : '—'}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Threshold Sensitivity Slider */}
      <div className="glass-card p-6">
        <h3 className="text-sm font-semibold text-white mb-4">Global Sensitivity Control</h3>
        <div className="space-y-4">
          {[
            { key: 'detection_sensitivity', name: 'Detection Sensitivity', value: settings.detection_sensitivity, desc: 'Higher = more aggressive detection (more false positives)' },
            { key: 'auto_tune_aggressiveness', name: 'Auto-Tune Aggressiveness', value: settings.auto_tune_aggressiveness, desc: 'How quickly thresholds adapt to new patterns' },
            { key: 'min_confidence', name: 'Minimum Confidence', value: settings.min_confidence, desc: 'Minimum ML confidence score to trigger a detection' },
          ].map((slider) => (
            <div key={slider.key}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-400">{slider.name}</span>
                <span className="text-xs font-mono text-ghost-400 font-bold">{slider.value}%</span>
              </div>
              <input
                type="range" min="0" max="100" value={slider.value}
                onChange={(e) => updateSensitivity(slider.key, parseInt(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none bg-surface-3 cursor-pointer
                  [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3
                  [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-ghost-400 [&::-webkit-slider-thumb]:cursor-pointer"
              />
              <p className="text-[10px] text-gray-600 mt-1">{slider.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Changes */}
      {changes.length > 0 && (
        <div className="glass-card overflow-hidden">
          <div className="px-5 py-3 border-b border-white/[0.04]">
            <h3 className="text-sm font-semibold text-white">Recent Threshold Changes</h3>
          </div>
          <div className="divide-y divide-white/[0.03]">
            {changes.slice(-10).reverse().map((change, i) => (
              <div key={i} className="flex items-center justify-between px-5 py-2.5 hover:bg-white/[0.02]">
                <div className="flex items-center gap-3">
                  {change.auto_approved ? (
                    <Zap className="w-3.5 h-3.5 text-ghost-400" />
                  ) : (
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                  )}
                  <div>
                    <p className="text-xs text-gray-300">{formatDetectorName(change.detector_name)}</p>
                    <p className="text-[9px] text-gray-600 font-mono">
                      {(change.old_threshold * 100).toFixed(1)}% → {(change.new_threshold * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                    change.auto_approved ? 'bg-ghost-500/10 text-ghost-400' : 'bg-emerald-500/10 text-emerald-400'
                  }`}>
                    {change.auto_approved ? 'Auto' : `By ${change.approved_by}`}
                  </span>
                  <p className="text-[9px] text-gray-600 mt-0.5 font-mono">
                    {change.created_at ? new Date(change.created_at).toLocaleString() : ''}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
