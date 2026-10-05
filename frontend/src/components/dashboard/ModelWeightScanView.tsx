'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart,
  Legend
} from 'recharts';
import { Shield, Upload, FileWarning, CheckCircle, AlertTriangle, HardDrive, Search, Lock, Bug, Cpu } from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface WeightScanStats {
  total_models_scanned: number;
  threats_found: number;
  clean_models: number;
  threat_rate: number;
  avg_scan_duration_ms: number;
  format_breakdown: Record<string, { scanned: number; threats: number; rate: number }>;
  threat_category_breakdown: Record<string, number>;
  severity_distribution: Record<string, number>;
  recent_scans: Array<{
    file_name: string;
    format: string;
    file_size_gb: number;
    risk_level: string;
    threats: number;
    scan_time: string;
    parameters: string;
    hash: string;
  }>;
  trend_data: Array<{ date: string; scanned: number; threats: number }>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const FORMAT_COLORS: Record<string, string> = {
  pytorch: '#ef4444',
  safetensors: '#22c55e',
  onnx: '#3b82f6',
  tensorflow: '#f97316',
  gguf: '#8b5cf6',
};

const THREAT_CATEGORY_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899'];

const THREAT_LABELS: Record<string, string> = {
  pickle_exploit: 'Pickle Exploits',
  embedded_script: 'Embedded Scripts',
  dangerous_import: 'Dangerous Imports',
  network_callback: 'Network Callbacks',
  trojan_signature: 'Trojan Signatures',
  metadata_poisoning: 'Metadata Poisoning',
  size_anomaly: 'Size Anomalies',
};

const RISK_STYLES: Record<string, string> = {
  safe: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
};

export default function ModelWeightScanView() {
  const [stats, setStats] = useState<WeightScanStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(`/api/v1/model-security/weight-scan/stats`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error('Failed to fetch weight scan stats:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleFileDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files[0];
    if (file) await uploadFile(file);
  }, []);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) await uploadFile(file);
  };

  const uploadFile = async (file: File) => {
    setUploading(true);
    setUploadResult(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const token = localStorage.getItem('access_token');
      const res = await fetch(`/api/v1/model-security/weight-scan/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData,
      });
      if (res.ok) {
        const data = await res.json();
        setUploadResult(data);
      }
    } catch (e) {
      console.error('Model upload scan failed:', e);
    } finally {
      setUploading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
      </div>
    );
  }

  const threatCategoryData = stats
    ? Object.entries(stats.threat_category_breakdown).map(([key, value]) => ({
        name: THREAT_LABELS[key] || key,
        value,
      }))
    : [];

  const severityData = stats
    ? Object.entries(stats.severity_distribution).map(([key, value]) => ({
        name: key.charAt(0).toUpperCase() + key.slice(1),
        value,
        color: SEVERITY_COLORS[key],
      }))
    : [];

  const formatData = stats
    ? Object.entries(stats.format_breakdown).map(([format, data]) => ({
        format: format.toUpperCase(),
        formatKey: format,
        ...data,
      }))
    : [];

  const trendData = stats?.trend_data || [];
  const recentScans = stats?.recent_scans || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
          <HardDrive className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-white">Model Weight Scanner</h2>
          <p className="text-xs text-gray-500">Detect malware, backdoors & trojans in model files</p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10"><Cpu className="w-4 h-4 text-blue-400" /></div>
            <div>
              <p className="text-2xl font-bold text-white">{(stats?.total_models_scanned || 0).toLocaleString()}</p>
              <p className="text-xs text-gray-500">Models Scanned</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10"><Bug className="w-4 h-4 text-red-400" /></div>
            <div>
              <p className="text-2xl font-bold text-red-400">{stats?.threats_found || 0}</p>
              <p className="text-xs text-gray-500">Threats Found</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10"><CheckCircle className="w-4 h-4 text-emerald-400" /></div>
            <div>
              <p className="text-2xl font-bold text-emerald-400">{(stats?.clean_models || 0).toLocaleString()}</p>
              <p className="text-xs text-gray-500">Clean Models</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-yellow-500/10"><AlertTriangle className="w-4 h-4 text-yellow-400" /></div>
            <div>
              <p className="text-2xl font-bold text-yellow-400">{stats?.threat_rate || 0}%</p>
              <p className="text-xs text-gray-500">Threat Rate</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10"><Search className="w-4 h-4 text-purple-400" /></div>
            <div>
              <p className="text-2xl font-bold text-purple-400">{stats?.avg_scan_duration_ms?.toFixed(0) || 0}ms</p>
              <p className="text-xs text-gray-500">Avg Scan Time</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Trend */}
        <div className="xl:col-span-2 glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Scan Trend (7 Days)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="wScanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="wThreatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="date" stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} tickFormatter={(v) => v.slice(5)} />
              <YAxis stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} />
              <Area type="monotone" dataKey="scanned" stroke="#06b6d4" fill="url(#wScanGrad)" name="Models Scanned" strokeWidth={2} />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#wThreatGrad)" name="Threats Found" strokeWidth={2} />
              <Legend />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Pie */}
        <div className="glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Threat Severity</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={4} dataKey="value">
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} />
              <Legend formatter={(value) => <span style={{ color: '#e5e7eb', fontSize: 11, fontWeight: 500 }}>{value}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Threat Categories */}
        <div className="glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Threat Categories</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={threatCategoryData} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis type="number" stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10 }} width={130} />
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]} name="Detections">
                {threatCategoryData.map((_, i) => (
                  <Cell key={i} fill={THREAT_CATEGORY_COLORS[i % THREAT_CATEGORY_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Format Comparison */}
        <div className="glass-card p-5 border border-white/5">
          <h3 className="text-sm font-semibold text-white mb-4">Threat Rate by Format</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={formatData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="format" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <YAxis stroke="#4b5563" tick={{ fill: '#6b7280', fontSize: 11 }} unit="%" />
              <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', color: '#fff' }} />
              <Bar dataKey="rate" radius={[6, 6, 0, 0]} name="Threat Rate %">
                {formatData.map((entry, i) => (
                  <Cell key={i} fill={FORMAT_COLORS[entry.formatKey] || '#6366f1'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glass-card p-5 border border-white/5">
        <h3 className="text-sm font-semibold text-white mb-4">Recent Model Scans</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-white/5">
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Model File</th>
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Format</th>
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Size</th>
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Parameters</th>
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Threats</th>
                <th className="pb-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {recentScans.map((scan, i) => (
                <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <HardDrive className="w-3.5 h-3.5 text-gray-600" />
                      <span className="text-sm text-white font-medium">{scan.file_name}</span>
                    </div>
                  </td>
                  <td className="py-3 pr-4">
                    <span className="px-2 py-0.5 rounded-md text-xs font-mono" style={{
                      backgroundColor: `${FORMAT_COLORS[scan.format] || '#6366f1'}15`,
                      color: FORMAT_COLORS[scan.format] || '#6366f1',
                    }}>
                      {scan.format}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-sm text-gray-400">{scan.file_size_gb} GB</td>
                  <td className="py-3 pr-4 text-sm text-gray-400">{scan.parameters}</td>
                  <td className="py-3 pr-4">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${RISK_STYLES[scan.risk_level] || RISK_STYLES.safe}`}>
                      {scan.risk_level.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`text-sm font-bold ${scan.threats > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {scan.threats}
                    </span>
                  </td>
                  <td className="py-3 text-xs text-gray-600 font-mono">{scan.hash.slice(0, 16)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Upload Scanner */}
      <div className="glass-card p-6 border border-white/5">
        <div className="flex items-center gap-2 mb-4">
          <Upload className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Upload Model for Security Scan</h3>
        </div>
        
        <div
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleFileDrop}
          className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer ${
            dragActive ? 'border-cyan-500 bg-cyan-500/5' : 'border-white/10 hover:border-white/20'
          }`}
        >
          <input
            type="file"
            onChange={handleFileSelect}
            accept=".pt,.pth,.bin,.pkl,.pickle,.onnx,.h5,.hdf5,.pb,.tflite,.safetensors,.ckpt,.gguf,.ggml"
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          />
          <div className="flex flex-col items-center gap-3">
            {uploading ? (
              <>
                <div className="w-10 h-10 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
                <p className="text-sm text-cyan-400 font-medium">Scanning model file...</p>
              </>
            ) : (
              <>
                <div className="p-3 rounded-xl bg-cyan-500/10">
                  <Shield className="w-6 h-6 text-cyan-400" />
                </div>
                <p className="text-sm text-white font-medium">Drop a model file here or click to upload</p>
                <p className="text-xs text-gray-500">
                  Supports: .pt, .pth, .bin, .pkl, .onnx, .h5, .safetensors, .gguf, .ckpt (max 500MB)
                </p>
              </>
            )}
          </div>
        </div>

        {/* Upload Result */}
        {uploadResult && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 p-4 rounded-xl border border-white/10 bg-surface-1/30"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-3">
                <HardDrive className="w-4 h-4 text-gray-400" />
                <span className="text-white text-sm font-semibold">{uploadResult.scan_result?.file_name}</span>
                <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${
                  RISK_STYLES[uploadResult.scan_result?.risk_level] || RISK_STYLES.safe
                }`}>
                  {uploadResult.scan_result?.risk_level?.toUpperCase()}
                </span>
              </div>
              <span className="text-xs text-gray-500">{uploadResult.scan_result?.scan_duration_ms?.toFixed(1)}ms</span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
              <div className="p-2 rounded-lg bg-surface-0/50">
                <p className="text-xs text-gray-500">Format</p>
                <p className="text-sm text-white font-mono">{uploadResult.scan_result?.format_detected}</p>
              </div>
              <div className="p-2 rounded-lg bg-surface-0/50">
                <p className="text-xs text-gray-500">Size</p>
                <p className="text-sm text-white">{(uploadResult.scan_result?.file_size_bytes / 1024 / 1024).toFixed(1)} MB</p>
              </div>
              <div className="p-2 rounded-lg bg-surface-0/50">
                <p className="text-xs text-gray-500">Threats</p>
                <p className={`text-sm font-bold ${uploadResult.scan_result?.threats_found > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {uploadResult.scan_result?.threats_found}
                </p>
              </div>
              <div className="p-2 rounded-lg bg-surface-0/50">
                <p className="text-xs text-gray-500">Risk Score</p>
                <p className="text-sm text-white font-bold">{(uploadResult.scan_result?.risk_score * 100).toFixed(1)}%</p>
              </div>
            </div>

            <div className="p-2 rounded-lg bg-surface-0/50 mb-3">
              <p className="text-xs text-gray-500">SHA-256</p>
              <p className="text-xs text-gray-400 font-mono break-all">{uploadResult.scan_result?.file_hash_sha256}</p>
            </div>

            {uploadResult.scan_result?.detections?.length > 0 ? (
              <div className="space-y-2">
                <p className="text-xs font-semibold text-red-400">Threats Detected:</p>
                {uploadResult.scan_result.detections.map((d: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-red-500/5 border border-red-500/10">
                    <FileWarning className="w-3.5 h-3.5 mt-0.5 flex-shrink-0 text-red-400" />
                    <div>
                      <p className="text-xs text-white font-medium">{d.type?.replace(/_/g, ' ').toUpperCase()}</p>
                      <p className="text-xs text-gray-500">{d.description}</p>
                    </div>
                    <span className={`ml-auto px-2 py-0.5 rounded text-xs font-bold ${
                      d.severity === 'critical' ? 'text-red-400 bg-red-500/10' :
                      d.severity === 'high' ? 'text-orange-400 bg-orange-500/10' :
                      'text-yellow-400 bg-yellow-500/10'
                    }`}>
                      {d.severity?.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/10">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span className="text-sm text-emerald-400 font-medium">Model file is clean — no threats detected.</span>
              </div>
            )}
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}
