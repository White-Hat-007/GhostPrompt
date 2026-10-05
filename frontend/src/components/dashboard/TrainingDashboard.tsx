'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cpu, Upload, Play, BarChart3, Loader2, CheckCircle2,
  XCircle, Clock, Zap, HardDrive, ArrowUpCircle,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface GPUStatus {
  available: boolean;
  device: string;
  compute_capability?: string;
  memory_total_gb?: number;
  memory_used_gb?: number;
  memory_free_gb?: number;
  cuda_version?: string;
  running_jobs?: number;
}

interface TrainingJob {
  id: string;
  model_type: string;
  base_model: string;
  status: string;
  progress: number;
  current_epoch: number;
  total_epochs: number;
  metrics: Record<string, number>;
  created_at: string;
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

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; icon: React.ReactNode }> = {
    pending: { color: 'bg-gray-500/10 text-gray-400', icon: <Clock className="w-3 h-3" /> },
    running: { color: 'bg-blue-500/10 text-blue-400', icon: <Loader2 className="w-3 h-3 animate-spin" /> },
    completed: { color: 'bg-emerald-500/10 text-emerald-400', icon: <CheckCircle2 className="w-3 h-3" /> },
    failed: { color: 'bg-red-500/10 text-red-400', icon: <XCircle className="w-3 h-3" /> },
  };
  const c = config[status] || config.pending;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${c.color}`}>
      {c.icon} {status}
    </span>
  );
}

export default function TrainingDashboard({ token }: { token?: string }) {
  const [gpu, setGpu] = useState<GPUStatus | null>(null);
  const [jobs, setJobs] = useState<TrainingJob[]>([]);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [uploading, setUploading] = useState(false);
  const [starting, setStarting] = useState(false);
  const [selectedDataset, setSelectedDataset] = useState('');
  const [modelType, setModelType] = useState<'threat_classifier' | 'zero_day_embedding'>('threat_classifier');
  const [epochs, setEpochs] = useState(5);

  const headers = useCallback(() => {
    const t = token || localStorage.getItem('access_token') || '';
    return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
  }, [token]);

  const fetchAll = useCallback(async () => {
    try {
      const [gpuRes, jobsRes, dsRes] = await Promise.all([
        fetch(`${API}/api/v1/training/gpu-status`, { headers: headers() }),
        fetch(`${API}/api/v1/training/jobs`, { headers: headers() }),
        fetch(`${API}/api/v1/training/datasets`, { headers: headers() }),
      ]);
      if (gpuRes.ok) setGpu(await gpuRes.json());
      if (jobsRes.ok) setJobs(await jobsRes.json());
      if (dsRes.ok) setDatasets(await dsRes.json());
    } catch (e) {
      console.error('Training fetch error:', e);
    }
  }, [headers]);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, [fetchAll]);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API}/api/v1/training/datasets/upload`, {
        method: 'POST',
        headers: { Authorization: headers().Authorization },
        body: formData,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Upload failed');
      }
      await fetchAll();
    } catch (err: any) {
      alert(err.message);
    }
    setUploading(false);
  };

  const handleStartTraining = async () => {
    if (!selectedDataset) return;
    setStarting(true);
    try {
      const res = await fetch(`${API}/api/v1/training/start`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({
          model_type: modelType,
          dataset_id: selectedDataset,
          epochs,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Failed to start training');
      }
      await fetchAll();
    } catch (err: any) {
      alert(err.message);
    }
    setStarting(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-ghost-400" />
            ML Training Pipeline
          </h2>
          <p className="text-xs text-gray-500 font-mono mt-1">LORA/PEFT GPU TRAINING — REAL-TIME MONITORING</p>
        </div>
      </div>

      {/* GPU Status Card */}
      <div className="glass-card p-5">
        <div className="flex items-center gap-3 mb-4">
          <HardDrive className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-bold text-white">GPU Status</h3>
          {gpu?.available ? (
            <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded-full font-bold">READY</span>
          ) : (
            <span className="text-[10px] bg-amber-500/10 text-amber-400 px-2 py-0.5 rounded-full font-bold">CPU MODE</span>
          )}
        </div>
        {gpu && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div>
              <span className="text-[10px] text-gray-600 uppercase font-mono">Device</span>
              <p className="text-sm text-white font-medium mt-0.5">{gpu.device || 'CPU'}</p>
            </div>
            <div>
              <span className="text-[10px] text-gray-600 uppercase font-mono">Compute</span>
              <p className="text-sm text-white font-mono mt-0.5">{gpu.compute_capability || 'N/A'}</p>
            </div>
            <div>
              <span className="text-[10px] text-gray-600 uppercase font-mono">VRAM Total</span>
              <p className="text-sm text-white font-mono mt-0.5">{gpu.memory_total_gb?.toFixed(1) || '—'} GB</p>
            </div>
            <div>
              <span className="text-[10px] text-gray-600 uppercase font-mono">VRAM Free</span>
              <p className="text-sm text-emerald-400 font-mono mt-0.5">{gpu.memory_free_gb?.toFixed(1) || '—'} GB</p>
            </div>
            <div>
              <span className="text-[10px] text-gray-600 uppercase font-mono">CUDA</span>
              <p className="text-sm text-white font-mono mt-0.5">{gpu.cuda_version || 'N/A'}</p>
            </div>
          </div>
        )}
        {gpu?.available && gpu.memory_total_gb && (
          <div className="mt-3">
            <div className="h-2 bg-surface-2 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-ghost-500 to-cyan-500 rounded-full transition-all duration-500"
                style={{ width: `${((gpu.memory_used_gb || 0) / gpu.memory_total_gb) * 100}%` }}
              />
            </div>
            <p className="text-[10px] text-gray-600 mt-1 font-mono">
              {gpu.memory_used_gb?.toFixed(1)} / {gpu.memory_total_gb.toFixed(1)} GB used
            </p>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Dataset Upload + Training Trigger */}
        <div className="glass-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Upload className="w-4 h-4 text-ghost-400" />
            Training Configuration
          </h3>

          {/* Upload */}
          <div>
            <label className="text-[10px] text-gray-500 uppercase font-mono block mb-2">Upload Dataset (.jsonl)</label>
            <label className="flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-white/[0.08] rounded-xl cursor-pointer hover:border-ghost-500/30 transition-colors">
              {uploading ? <Loader2 className="w-4 h-4 animate-spin text-ghost-400" /> : <ArrowUpCircle className="w-4 h-4 text-gray-500" />}
              <span className="text-sm text-gray-400">{uploading ? 'Uploading...' : 'Click to upload .jsonl'}</span>
              <input type="file" accept=".jsonl" onChange={handleUpload} className="hidden" />
            </label>
          </div>

          {/* Datasets */}
          {datasets.length > 0 && (
            <div>
              <label className="text-[10px] text-gray-500 uppercase font-mono block mb-2">Select Dataset</label>
              <select
                value={selectedDataset}
                onChange={e => setSelectedDataset(e.target.value)}
                className="w-full bg-surface-2 border border-white/[0.06] rounded-lg px-3 py-2 text-sm text-white outline-none"
              >
                <option value="">Choose a dataset...</option>
                {datasets.map(d => (
                  <option key={d.id} value={d.id}>{d.filename} ({d.samples} samples)</option>
                ))}
              </select>
            </div>
          )}

          {/* Model Type */}
          <div>
            <label className="text-[10px] text-gray-500 uppercase font-mono block mb-2">Model Type</label>
            <div className="flex gap-2">
              {[
                { value: 'threat_classifier' as const, label: 'Threat Classifier', desc: 'DeBERTa + LoRA' },
                { value: 'zero_day_embedding' as const, label: 'Zero-Day Embeddings', desc: 'Sentence-Transformer' },
              ].map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setModelType(opt.value)}
                  className={`flex-1 p-3 rounded-lg border text-left transition-all ${
                    modelType === opt.value
                      ? 'border-ghost-500/30 bg-ghost-600/10'
                      : 'border-white/[0.06] hover:border-white/[0.1]'
                  }`}
                >
                  <span className="text-xs font-bold text-white block">{opt.label}</span>
                  <span className="text-[10px] text-gray-500">{opt.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Epochs */}
          <div>
            <label className="text-[10px] text-gray-500 uppercase font-mono block mb-2">Epochs: {epochs}</label>
            <input
              type="range"
              min={1} max={20}
              value={epochs}
              onChange={e => setEpochs(Number(e.target.value))}
              className="w-full accent-ghost-500"
            />
          </div>

          {/* Start */}
          <button
            onClick={handleStartTraining}
            disabled={!selectedDataset || starting}
            className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {starting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Start Training
          </button>
        </div>

        {/* Training Jobs */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-4">
            <BarChart3 className="w-4 h-4 text-ghost-400" />
            Training Jobs
          </h3>
          <div className="space-y-3">
            {jobs.length === 0 && (
              <p className="text-sm text-gray-600 text-center py-8">No training jobs yet</p>
            )}
            {jobs.map(job => (
              <div key={job.id} className="p-3 bg-surface-0/50 rounded-lg border border-white/[0.04]">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-white">{job.model_type === 'threat_classifier' ? 'Threat Classifier' : 'Zero-Day Embeddings'}</span>
                  <StatusBadge status={job.status} />
                </div>
                <div className="text-[10px] text-gray-500 font-mono mb-2">{job.base_model}</div>

                {/* Progress bar */}
                {(job.status === 'running' || job.status === 'completed') && (
                  <div className="mb-2">
                    <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${job.progress * 100}%` }}
                        className={`h-full rounded-full ${
                          job.status === 'completed' ? 'bg-emerald-500' : 'bg-gradient-to-r from-ghost-500 to-cyan-500'
                        }`}
                      />
                    </div>
                    <p className="text-[10px] text-gray-600 mt-1 font-mono">
                      Epoch {job.current_epoch}/{job.total_epochs} — {(job.progress * 100).toFixed(0)}%
                    </p>
                  </div>
                )}

                {/* Metrics */}
                {Object.keys(job.metrics).length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {Object.entries(job.metrics).map(([k, v]) => (
                      <span key={k} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-2 text-gray-400">
                        {k.replace('eval_', '')}: <span className="text-white">{typeof v === 'number' ? v.toFixed(4) : v}</span>
                      </span>
                    ))}
                  </div>
                )}

                {job.error && (
                  <p className="text-[10px] text-red-400 mt-2 font-mono">{job.error}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
