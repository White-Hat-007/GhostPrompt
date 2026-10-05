'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Cpu, Upload, Play, CheckCircle, Clock, AlertTriangle, Database,
  Layers, Settings, TrendingUp, Loader2, RefreshCw, XCircle, Zap,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface CustomModelsViewProps {
  token?: string;
}

interface TrainingJob {
  id: string;
  org_id: string;
  model_type: string;
  base_model: string;
  status: string;
  progress: number;
  current_epoch: number;
  total_epochs: number;
  metrics: Record<string, number>;
  output_dir: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

interface Dataset {
  id: string;
  filename: string;
  samples: number;
  size_bytes: number;
  uploaded_at: string;
}

interface GPUStatus {
  available: boolean;
  device: string;
  memory_total_gb?: number;
  memory_used_gb?: number;
  memory_free_gb?: number;
  cuda_version?: string;
  running_jobs?: number;
  remote_backends?: string[];
}

interface GPUBackend {
  id: string;
  name: string;
  type: string;
  status: string;
  gpu_type: string;
  cost_per_hour: number;
  max_concurrent: number;
}

export default function CustomModelsView({ token }: CustomModelsViewProps) {
  const [activeTab, setActiveTab] = useState<'models' | 'training' | 'datasets' | 'backends' | 'queue' | 'billing'>('models');
  const [jobs, setJobs] = useState<TrainingJob[]>([]);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [gpu, setGpu] = useState<GPUStatus | null>(null);
  const [backends, setBackends] = useState<GPUBackend[]>([]);
  const [queueStatus, setQueueStatus] = useState<any>(null);
  const [billing, setBilling] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [startingJob, setStartingJob] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const authHeaders = useCallback(() => {
    const t = token || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null);
    return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
  }, [token]);

  const authHeadersMultipart = useCallback(() => {
    const t = token || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null);
    return { Authorization: `Bearer ${t}` };
  }, [token]);

  const fetchAll = useCallback(async () => {
    try {
      const [jobsRes, datasetsRes, gpuRes, backendsRes, queueRes, billingRes] = await Promise.all([
        fetch(`${API}/api/v1/training/jobs`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/training/datasets`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/training/gpu-status`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/training/backends`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/training/queue/status`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/training/billing/gpu-hours`, { headers: authHeaders() }),
      ]);

      if (jobsRes.ok) setJobs(await jobsRes.json());
      if (datasetsRes.ok) setDatasets(await datasetsRes.json());
      if (gpuRes.ok) setGpu(await gpuRes.json());
      if (backendsRes.ok) { const d = await backendsRes.json(); setBackends(d.backends || []); }
      if (queueRes.ok) setQueueStatus(await queueRes.json());
      if (billingRes.ok) setBilling(await billingRes.json());
    } catch (err) {
      console.error('Failed to fetch training data:', err);
    } finally {
      setLoading(false);
    }
  }, [authHeaders]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Auto-refresh for running jobs
  useEffect(() => {
    const hasRunning = jobs.some(j => j.status === 'running' || j.status === 'pending');
    if (!hasRunning) return;
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [jobs, fetchAll]);

  const uploadDataset = async (file: File) => {
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API}/api/v1/training/datasets/upload`, {
        method: 'POST',
        headers: authHeadersMultipart(),
        body: formData,
      });
      if (res.ok) {
        await fetchAll();
        setActiveTab('datasets');
      } else {
        const err = await res.json().catch(() => ({}));
        alert(err.detail || 'Upload failed');
      }
    } catch (err) {
      console.error(err);
    }
    setUploading(false);
  };

  const startTrainingJob = async (modelType: string = 'threat_classifier') => {
    setStartingJob(true);
    try {
      const res = await fetch(`${API}/api/v1/training/start`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ model_type: modelType, epochs: 5 }),
      });
      if (res.ok) {
        await fetchAll();
        setActiveTab('training');
      } else {
        const err = await res.json().catch(() => ({}));
        alert(err.detail || 'Failed to start training');
      }
    } catch (err) {
      console.error(err);
    }
    setStartingJob(false);
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  };

  const statusBadge = (status: string) => {
    const config: Record<string, string> = {
      completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/15',
      running: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
      pending: 'bg-surface-2 text-gray-500 border-white/[0.06]',
      failed: 'bg-red-500/10 text-red-400 border-red-500/15',
    };
    return config[status] || config.pending;
  };

  // Derive model registry from completed jobs
  const deployedModels = jobs.filter(j => j.status === 'completed');
  const runningJobs = jobs.filter(j => j.status === 'running' || j.status === 'pending');
  const avgAccuracy = deployedModels.length > 0
    ? deployedModels.reduce((sum, j) => sum + (j.metrics?.accuracy || 0), 0) / deployedModels.length * 100
    : 0;

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
          <h2 className="text-lg font-bold text-white">Custom Fine-Tuned Models</h2>
          <p className="text-sm text-gray-500 mt-1">Train organization-specific detection models with your labeled data</p>
        </div>
        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef} type="file" accept=".jsonl" className="hidden"
            onChange={e => e.target.files?.[0] && uploadDataset(e.target.files[0])}
          />
          <button onClick={() => fileInputRef.current?.click()} disabled={uploading}
            className="btn-ghost text-xs gap-2"
          >
            {uploading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
            Upload Dataset
          </button>
          <button onClick={() => startTrainingJob()} disabled={startingJob}
            className="btn-primary text-xs gap-2"
          >
            {startingJob ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            New Training Job
          </button>
        </div>
      </div>

      {/* GPU Status */}
      {gpu && (
        <div className={`glass-card p-3 flex items-center justify-between text-xs ${gpu.available ? 'border-l-2 border-emerald-500/40' : 'border-l-2 border-amber-500/40'}`}>
          <div className="flex items-center gap-3">
            <Zap className={`w-4 h-4 ${gpu.available ? 'text-emerald-400' : 'text-amber-400'}`} />
            <span className="text-gray-300 font-mono">{gpu.device}</span>
            {gpu.cuda_version && <span className="text-gray-600 font-mono">CUDA {gpu.cuda_version}</span>}
          </div>
          {gpu.memory_total_gb && (
            <span className="text-gray-500 font-mono">
              {gpu.memory_used_gb?.toFixed(1) || '?'}GB / {gpu.memory_total_gb.toFixed(1)}GB
            </span>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface-1/50 border border-white/[0.04] w-fit flex-wrap">
        {(['models', 'training', 'datasets', 'backends', 'queue', 'billing'] as const).map(tab => {
          const labels: Record<string, string> = {
            models: `Models (${deployedModels.length})`,
            training: `Jobs (${runningJobs.length})`,
            datasets: `Datasets (${datasets.length})`,
            backends: `GPU Backends (${backends.length})`,
            queue: `Queue (${queueStatus?.total_queued || 0})`,
            billing: 'Billing',
          };
          return (
            <button key={tab} onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-md text-xs font-medium transition-all ${
                activeTab === tab ? 'bg-ghost-600/20 text-ghost-400' : 'text-gray-500 hover:text-gray-300'
              }`}
            >{labels[tab]}</button>
          );
        })}
      </div>

      {activeTab === 'models' && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { label: 'Deployed Models', value: deployedModels.length.toString(), icon: Cpu, color: 'text-emerald-400' },
              { label: 'In Training', value: runningJobs.length.toString(), icon: Play, color: 'text-amber-400' },
              { label: 'Avg Accuracy', value: avgAccuracy > 0 ? `${avgAccuracy.toFixed(1)}%` : '—', icon: TrendingUp, color: 'text-ghost-400' },
              { label: 'Total Jobs', value: jobs.length.toString(), icon: Layers, color: 'text-cyan-400' },
            ].map((s, i) => (
              <div key={i} className="glass-card p-4">
                <div className="flex items-center gap-2 mb-2">
                  <s.icon className={`w-4 h-4 ${s.color}`} />
                  <span className="text-[10px] text-gray-500 uppercase tracking-wider">{s.label}</span>
                </div>
                <p className="text-2xl font-bold text-white font-mono">{s.value}</p>
              </div>
            ))}
          </div>

          {/* Model Registry (from completed jobs) */}
          <div className="glass-card overflow-hidden">
            <div className="px-5 py-3 border-b border-white/[0.04]">
              <h3 className="text-sm font-semibold text-white">Model Registry</h3>
            </div>
            <div className="divide-y divide-white/[0.03]">
              {jobs.length === 0 ? (
                <div className="px-5 py-8 text-center text-sm text-gray-600">
                  No models yet. Upload a dataset and start training.
                </div>
              ) : (
                jobs.map((job) => (
                  <div key={job.id} className="flex items-center justify-between px-5 py-3.5 hover:bg-white/[0.02] transition-colors">
                    <div className="flex items-center gap-3">
                      <Cpu className={`w-4 h-4 ${
                        job.status === 'completed' ? 'text-emerald-400' :
                        job.status === 'running' ? 'text-amber-400' :
                        job.status === 'failed' ? 'text-red-400' : 'text-gray-600'
                      }`} />
                      <div>
                        <p className="text-sm font-mono text-gray-300">{job.model_type}-{job.id.slice(0, 8)}</p>
                        <p className="text-[10px] text-gray-600">
                          Base: {job.base_model.split('/').pop()} • Epochs: {job.current_epoch}/{job.total_epochs}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {job.metrics?.accuracy && (
                        <span className="text-xs font-mono text-white font-bold">{(job.metrics.accuracy * 100).toFixed(1)}%</span>
                      )}
                      <span className={`text-[9px] font-bold px-2 py-1 rounded-md uppercase border ${statusBadge(job.status)}`}>
                        {job.status}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'training' && (
        <div className="space-y-4">
          {jobs.length === 0 ? (
            <div className="glass-card p-8 text-center">
              <Cpu className="w-8 h-8 text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-500">No training jobs yet</p>
              <p className="text-xs text-gray-600 mt-1">Upload a dataset and click &quot;New Training Job&quot; to start</p>
            </div>
          ) : (
            jobs.map((job) => (
              <div key={job.id} className="glass-card p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    {job.status === 'running' ? (
                      <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/15 flex items-center justify-center">
                        <Loader2 className="w-4 h-4 text-amber-400 animate-spin" />
                      </div>
                    ) : job.status === 'completed' ? (
                      <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/15 flex items-center justify-center">
                        <CheckCircle className="w-4 h-4 text-emerald-400" />
                      </div>
                    ) : job.status === 'failed' ? (
                      <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/15 flex items-center justify-center">
                        <XCircle className="w-4 h-4 text-red-400" />
                      </div>
                    ) : (
                      <div className="w-8 h-8 rounded-lg bg-surface-2 border border-white/[0.06] flex items-center justify-center">
                        <Clock className="w-4 h-4 text-gray-500" />
                      </div>
                    )}
                    <div>
                      <p className="text-sm font-mono text-white">{job.model_type}</p>
                      <p className="text-[10px] text-gray-600 font-mono">
                        Job: {job.id.slice(0, 8)} • Base: {job.base_model.split('/').pop()}
                      </p>
                    </div>
                  </div>
                  <span className={`text-[9px] font-bold px-2 py-1 rounded-md uppercase border ${statusBadge(job.status)}`}>
                    {job.status}
                  </span>
                </div>

                {(job.status === 'running' || job.progress > 0) && (
                  <>
                    <div className="w-full h-2 rounded-full bg-surface-3 mb-2">
                      <div className="h-full rounded-full bg-gradient-to-r from-amber-600 to-amber-400 transition-all"
                        style={{ width: `${job.progress}%` }} />
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-gray-500 font-mono">
                      <span>Epoch {job.current_epoch}/{job.total_epochs}</span>
                      {job.metrics?.loss !== undefined && <span>Loss: {job.metrics.loss.toFixed(4)}</span>}
                      <span>{job.progress.toFixed(1)}%</span>
                    </div>
                  </>
                )}

                {job.status === 'completed' && job.metrics && (
                  <div className="grid grid-cols-3 gap-4 mt-3 text-xs">
                    {Object.entries(job.metrics).map(([key, val]) => (
                      <div key={key}>
                        <span className="text-gray-600 capitalize">{key}</span>
                        <p className="text-white font-mono">{typeof val === 'number' ? val.toFixed(4) : val}</p>
                      </div>
                    ))}
                  </div>
                )}

                {job.error && (
                  <p className="text-xs text-red-400 mt-2 font-mono">{job.error}</p>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'datasets' && (
        <div className="space-y-4">
          <div className="glass-card overflow-hidden">
            <div className="px-5 py-3 border-b border-white/[0.04] flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Training Datasets</h3>
              <button onClick={() => fileInputRef.current?.click()} className="btn-ghost text-[10px] gap-1">
                <Upload className="w-3 h-3" /> Upload
              </button>
            </div>
            <div className="divide-y divide-white/[0.03]">
              {datasets.length === 0 ? (
                <div className="px-5 py-8 text-center text-sm text-gray-600">
                  No datasets uploaded yet. Upload a .jsonl file to start training.
                </div>
              ) : (
                datasets.map((ds) => (
                  <div key={ds.id} className="flex items-center justify-between px-5 py-3 hover:bg-white/[0.02] transition-colors">
                    <div className="flex items-center gap-3">
                      <Database className="w-4 h-4 text-gray-500" />
                      <div>
                        <p className="text-sm font-mono text-gray-300">{ds.filename}</p>
                        <p className="text-[10px] text-gray-600">
                          {ds.samples.toLocaleString()} samples • {formatBytes(ds.size_bytes)} • {new Date(ds.uploaded_at).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => startTrainingJob()}
                      className="btn-ghost text-[10px] gap-1"
                    >
                      <Play className="w-3 h-3" /> Train
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* GPU Backends Tab */}
      {activeTab === 'backends' && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-white">Remote GPU Backends</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {backends.map(b => (
              <div key={b.id} className={`glass-card p-4 border-l-2 ${
                b.status === 'active' ? 'border-emerald-500/50' :
                b.status === 'configured' ? 'border-amber-500/50' : 'border-gray-600/50'
              }`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-bold text-white">{b.name}</span>
                  <span className={`text-[9px] font-bold px-2 py-1 rounded-md uppercase border ${
                    b.status === 'active' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/15' :
                    b.status === 'configured' ? 'bg-amber-500/10 text-amber-400 border-amber-500/15' :
                    'bg-surface-2 text-gray-500 border-white/[0.06]'
                  }`}>{b.status}</span>
                </div>
                <div className="space-y-1 text-xs text-gray-400">
                  <div className="flex justify-between"><span>GPU</span><span className="text-gray-300 font-mono">{b.gpu_type}</span></div>
                  <div className="flex justify-between"><span>Cost</span><span className="text-ghost-400 font-mono">${b.cost_per_hour.toFixed(2)}/hr</span></div>
                  <div className="flex justify-between"><span>Max Concurrent</span><span className="text-gray-300 font-mono">{b.max_concurrent}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Queue Tab */}
      {activeTab === 'queue' && queueStatus && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-white">Fairness Job Queue</h3>
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: 'Total Queued', value: queueStatus.total_queued, color: 'text-ghost-400' },
              { label: 'Your Queued', value: queueStatus.org_queued, color: 'text-amber-400' },
              { label: 'Active', value: queueStatus.org_active, color: 'text-emerald-400' },
              { label: 'Max Concurrent', value: queueStatus.org_max_concurrent, color: 'text-gray-400' },
            ].map(s => (
              <div key={s.label} className="glass-card p-3 text-center">
                <div className={`text-lg font-bold font-mono ${s.color}`}>{s.value}</div>
                <div className="text-[10px] text-gray-500 mt-1">{s.label}</div>
              </div>
            ))}
          </div>
          {queueStatus.your_jobs?.length > 0 && (
            <div className="glass-card p-4">
              <h4 className="text-xs font-semibold text-gray-400 mb-3">Your Queued Jobs</h4>
              {queueStatus.your_jobs.map((j: any) => (
                <div key={j.job_id} className="flex items-center justify-between py-2 border-b border-white/[0.03] last:border-0">
                  <div>
                    <span className="text-xs font-mono text-gray-300">{j.model_type}</span>
                    <span className="text-[10px] text-gray-600 ml-2">on {j.backend}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-gray-500">P{j.priority}</span>
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${
                      j.status === 'queued' ? 'bg-ghost-600/20 text-ghost-400' : 'bg-amber-500/10 text-amber-400'
                    }`}>{j.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Billing Tab */}
      {activeTab === 'billing' && billing && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-white">GPU-Hour Billing</h3>
          <div className="grid grid-cols-3 gap-3">
            <div className="glass-card p-4 text-center border-l-2 border-ghost-500/40">
              <div className="text-xl font-bold font-mono text-ghost-400">{billing.total_gpu_hours}h</div>
              <div className="text-[10px] text-gray-500 mt-1">GPU Hours Used</div>
            </div>
            <div className="glass-card p-4 text-center border-l-2 border-emerald-500/40">
              <div className="text-xl font-bold font-mono text-emerald-400">${billing.total_cost_usd}</div>
              <div className="text-[10px] text-gray-500 mt-1">Total Cost</div>
            </div>
            <div className="glass-card p-4 text-center border-l-2 border-amber-500/40">
              <div className="text-xl font-bold font-mono text-amber-400">${billing.budget_remaining}</div>
              <div className="text-[10px] text-gray-500 mt-1">Budget Remaining</div>
            </div>
          </div>
          {/* Budget progress bar */}
          <div className="glass-card p-4">
            <div className="flex justify-between text-xs mb-2">
              <span className="text-gray-400">Budget Usage</span>
              <span className="text-gray-300 font-mono">${billing.total_cost_usd} / ${billing.budget_limit}</span>
            </div>
            <div className="w-full bg-surface-2 rounded-full h-2">
              <div className={`h-2 rounded-full transition-all ${
                (billing.total_cost_usd / billing.budget_limit) > 0.8 ? 'bg-red-500' :
                (billing.total_cost_usd / billing.budget_limit) > 0.5 ? 'bg-amber-500' : 'bg-emerald-500'
              }`} style={{ width: `${Math.min(100, (billing.total_cost_usd / billing.budget_limit) * 100)}%` }} />
            </div>
          </div>
          {/* Per-backend breakdown */}
          <div className="glass-card p-4">
            <h4 className="text-xs font-semibold text-gray-400 mb-3">Cost by Backend</h4>
            {Object.entries(billing.backend_breakdown || {}).map(([bid, b]: [string, any]) => (
              <div key={bid} className="flex items-center justify-between py-2 border-b border-white/[0.03] last:border-0">
                <span className="text-xs text-gray-300 capitalize">{bid}</span>
                <div className="flex items-center gap-4 text-xs font-mono">
                  <span className="text-gray-500">{b.gpu_hours}h</span>
                  <span className="text-gray-400">${b.cost_per_hour}/hr</span>
                  <span className="text-white font-bold">${b.total_cost}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
