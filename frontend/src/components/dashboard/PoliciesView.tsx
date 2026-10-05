'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Plus, X, Save, AlertTriangle, Activity, Database, Lock, EyeOff, Bot, MessageSquare, Terminal, Crosshair, Radar, Brain, Users, Scale } from 'lucide-react';
import { format } from 'date-fns';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface PolicyRule {
  id?: string;
  name: string;
  description: string;
  rule_type: string;
  detector: string;
  threshold: number;
  action: string;
  severity: string;
  is_active: boolean;
  priority: number;
  parameters: Record<string, any>;
}

interface Policy {
  id: string;
  name: string;
  description: string;
  policy_type: string;
  applies_to: string[];
  priority: number;
  is_active: boolean;
  rules: PolicyRule[];
  created_at: string;
}

const DETECTORS = [
  // Core AI Firewall Detectors
  { id: 'pii_detector', name: 'PII Detection', icon: Shield, description: 'Catches leaked personally identifiable info' },
  { id: 'secret_detector', name: 'Secrets & API Keys', icon: Lock, description: 'Catches AWS keys, JWTs, and passwords' },
  { id: 'content_policy', name: 'Content Policy', icon: Shield, description: 'Catches malware, fraud, and illegal data requests' },
  { id: 'context_analyzer', name: 'Context Analyzer', icon: Database, description: 'Catches multi-turn attacks across history' },
  { id: 'semantic_classifier', name: 'Semantic Intent', icon: MessageSquare, description: 'Catches unknown zero-day attacks via ML' },
  
  // The 12 Enterprise Roadmap Phase 3 Categories
  { id: 'direct_instruction_override', name: 'Direct Override', icon: Terminal, description: 'Catches direct system prompt overrides' },
  { id: 'jailbreak_persona_switch', name: 'Jailbreak Persona Switch', icon: AlertTriangle, description: 'Catches persona adoption and bypasses' },
  { id: 'system_prompt_extraction', name: 'Prompt Extraction', icon: Database, description: 'Catches attempts to leak the system prompt' },
  { id: 'multi_turn_slow_build', name: 'Multi-Turn Slow Build', icon: MessageSquare, description: 'Catches slow-build conversational attacks' },
  { id: 'encoding_obfuscation', name: 'Encoding Obfuscation', icon: EyeOff, description: 'Catches Base64, Hex, and obfuscated text' },
  { id: 'data_exfiltration', name: 'Data Exfiltration', icon: Shield, description: 'Catches unauthorized data retrieval attempts' },
  { id: 'agentic_tool_hijacking', name: 'Tool/Agent Hijacking', icon: Bot, description: 'Catches malicious agent function calls' },
  { id: 'social_engineering', name: 'Social Engineering', icon: Shield, description: 'Catches urgency and authority manipulation' },
  { id: 'delimiter_injection', name: 'Delimiter Injection', icon: Terminal, description: 'Catches fake system or role delimiters' },
  { id: 'output_manipulation', name: 'Output Manipulation', icon: EyeOff, description: 'Catches forced output formatting constraints' },
  { id: 'adversarial_suffix', name: 'Adversarial Suffix', icon: Terminal, description: 'Catches anomalous special character strings' },
  { id: 'sensitive_topic_escalation', name: 'Sensitive Topic Escalation', icon: AlertTriangle, description: 'Catches requests for harmful materials/software' },
  
  // Ultra-Advanced Threat Protection (Layers 27-31)
  { id: 'pliny_defense', name: 'Pliny Defense Engine', icon: Crosshair, description: 'Detects Pliny the Liberator techniques: nested fiction, authority chains, OBLITERATUS' },
  { id: 'zero_day_radar', name: 'Zero-Day Jailbreak Radar', icon: Radar, description: 'Detects novel attacks via entropy analysis, adversarial suffix detection' },
  { id: 'ml_ensemble', name: 'ML Threat Classifier', icon: Brain, description: 'Three-model ensemble trained on 50K+ jailbreak samples' },
  { id: 'campaign_detector', name: 'Coordinated Campaign Detector', icon: Users, description: 'Detects coordinated multi-session jailbreak campaigns' },
  { id: 'constitutional_auditor', name: 'Constitutional Response Auditor', icon: Scale, description: 'Post-response safety judge — catches jailbreaks that evade input inspection' },

  // Base Defense Layers & Hardware Vectors
  { id: 'prompt_injection', name: 'Prompt Injection', icon: Shield, description: 'Catches basic prompt injection attempts' },
  { id: 'jailbreak', name: 'Jailbreak', icon: AlertTriangle, description: 'Catches basic jailbreak patterns' },
  { id: 'encoded_payload', name: 'Encoded Payload', icon: EyeOff, description: 'Catches deeply encoded payloads' },
  { id: 'obfuscation', name: 'Obfuscation', icon: EyeOff, description: 'Catches text obfuscation techniques' },
  { id: 'multimodal_inspector', name: 'Multimodal Inspector', icon: EyeOff, description: 'Catches malicious image/audio inputs' },
  { id: 'rag_sandbox', name: 'RAG Sandbox', icon: Database, description: 'Protects RAG vector databases from poisoning' },
  { id: 'llm_dos_preventer', name: 'LLM DoS Preventer', icon: Shield, description: 'Prevents denial-of-service through excessive token generation' },
  { id: 'supply_chain', name: 'Supply Chain', icon: AlertTriangle, description: 'Catches malicious model supply chain attacks' },
  { id: 'oracle_detector', name: 'Oracle Detector', icon: Brain, description: 'Catches attempts to use the LLM as an oracle' },
  { id: 'sponge_detector', name: 'Sponge Detector', icon: Shield, description: 'Catches resource-exhaustion sponge attacks' },
  { id: 'intent_validator', name: 'Intent Validator', icon: MessageSquare, description: 'Validates user intent against allowed actions' },
  { id: 'output_inspector', name: 'Output Inspector', icon: EyeOff, description: 'Inspects generated output for policy violations' },
  { id: 'tokenizer_shield', name: 'Tokenizer Shield', icon: Shield, description: 'Protects against tokenizer-level manipulation' },
  { id: 'external_content_inspector', name: 'External Content Inspector', icon: Database, description: 'Inspects externally fetched content' },
  { id: 'hallucination_detector', name: 'Hallucination Detector', icon: Brain, description: 'Detects generated hallucinations and confabulations' },
  { id: 'model_weight_scanner', name: 'Model Weight Scanner', icon: Database, description: 'Scans model weights for backdoors' },
  { id: 'hardware_side_channel', name: 'Hardware Side-Channel', icon: Shield, description: 'Detects timing and power side-channel attacks' },
  { id: 'attacker_profiler', name: 'Attacker Profiler', icon: Users, description: 'Profiles and fingerprints persistent attackers' },
  
  // Pack Hunt & Multi-Agent Security (Layers 32-33)
  { id: 'pack_hunt_detector', name: 'Pack Hunt Defense', icon: Crosshair, description: 'Detects multi-request fragmentation attacks — judges the ASSEMBLY, not individual fragments' },
  { id: 'multi_agent_guard', name: 'Multi-Agent Guard', icon: Users, description: 'Agent Trust Registry, inter-agent injection defense, orchestrator protection' },
  { id: 'cross_lingual_vector', name: 'Cross-Lingual Detector', icon: Shield, description: 'Detects prompt injection in non-English languages' },
];

export default function PoliciesView() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);

  // Form State
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    policy_type: 'custom',
    priority: 100,
    rules: [] as PolicyRule[]
  });

  const fetchPolicies = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(`/api/v1/policies`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setPolicies(data);
      }
    } catch (err) {
      console.error('Failed to fetch policies:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleToggle = async (policyId: string) => {
    try {
      setPolicies(prev => prev.map(p => p.id === policyId ? { ...p, is_active: !p.is_active } : p));
      const token = localStorage.getItem('access_token');
      await fetch(`/api/v1/policies/${policyId}/toggle`, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (err) {
      console.error('Failed to toggle policy:', err);
    }
  };

  const handleDelete = async (policyId: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) return;
    try {
      const token = localStorage.getItem('access_token');
      await fetch(`/api/v1/policies/${policyId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setPolicies(prev => prev.filter(p => p.id !== policyId));
    } catch (err) {
      console.error('Failed to delete policy:', err);
    }
  };

  const openCreateModal = () => {
    setEditingPolicy(null);
    setFormData({
      name: '',
      description: '',
      policy_type: 'custom',
      priority: 100,
      rules: []
    });
    setIsModalOpen(true);
  };

  const openEditModal = (policy: Policy) => {
    setEditingPolicy(policy);
    setFormData({
      name: policy.name,
      description: policy.description || '',
      policy_type: policy.policy_type,
      priority: policy.priority,
      rules: policy.rules.map(r => ({ ...r }))
    });
    setIsModalOpen(true);
  };

  const handleAddRule = (detectorId: string) => {
    const detectorInfo = DETECTORS.find(d => d.id === detectorId);
    if (!detectorInfo) return;

    setFormData(prev => ({
      ...prev,
      rules: [...prev.rules, {
        name: `${detectorInfo.name} Rule`,
        description: `Enforces ${detectorInfo.name} checks`,
        rule_type: detectorId,
        detector: detectorId,
        threshold: 0.7,
        action: 'block',
        severity: 'high',
        is_active: true,
        priority: 100,
        parameters: {}
      }]
    }));
  };

  const handleRemoveRule = (index: number) => {
    setFormData(prev => ({
      ...prev,
      rules: prev.rules.filter((_, i) => i !== index)
    }));
  };

  const handleUpdateRule = (index: number, field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      rules: prev.rules.map((rule, i) => i === index ? { ...rule, [field]: value } : rule)
    }));
  };

  const handleSave = async () => {
    try {
      const method = editingPolicy ? 'PUT' : 'POST';
      const url = editingPolicy 
        ? `${API_URL}/api/v1/policies/${editingPolicy.id}`
        : `${API_URL}/api/v1/policies`;

      const token = localStorage.getItem('access_token');
      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          ...formData,
          applies_to: ['all']
        })
      });

      if (res.ok) {
        setIsModalOpen(false);
        fetchPolicies();
      } else {
        alert('Failed to save policy');
      }
    } catch (err) {
      console.error('Save error:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Security Policies</h2>
          <p className="text-sm text-gray-500 mt-1">Configure and manage AI Firewall protection rules</p>
        </div>
        <button onClick={openCreateModal} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Create Policy
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-4 border-emerald-500 border-t-transparent rounded-xl animate-spin" />
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="glass-card p-6 border-t-2 border-emerald-500/50">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-emerald-500/10"><Shield className="w-5 h-5 text-emerald-400" /></div>
                <h3 className="text-gray-400 font-medium">Active Policies</h3>
              </div>
              <p className="text-3xl font-bold text-white">{policies.filter(p => p.is_active).length}</p>
            </div>
            <div className="glass-card p-6 border-t-2 border-blue-500/50">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-blue-500/10"><Database className="w-5 h-5 text-blue-400" /></div>
                <h3 className="text-gray-400 font-medium">Total Rules</h3>
              </div>
              <p className="text-3xl font-bold text-white">{policies.reduce((acc, p) => acc + p.rules.length, 0)}</p>
            </div>
            <div className="glass-card p-6 border-t-2 border-purple-500/50">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-purple-500/10"><Activity className="w-5 h-5 text-purple-400" /></div>
                <h3 className="text-gray-400 font-medium">System Health</h3>
              </div>
              <p className="text-3xl font-bold text-white">100%</p>
            </div>
          </div>

          <div className="grid gap-4">
          {policies.map((policy) => (
            <div key={policy.id} className="glass-card p-6 border-l-4" style={{ borderLeftColor: policy.is_active ? '#34d399' : '#4b5563' }}>
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-3">
                    <h3 className="text-lg font-semibold text-white">{policy.name}</h3>
                    <span className="text-[10px] px-2 py-0.5 rounded-xl bg-surface-2 text-gray-400 uppercase tracking-wider">
                      {policy.policy_type}
                    </span>
                    {!policy.is_active && (
                      <span className="text-[10px] px-2 py-0.5 rounded-xl bg-red-500/10 text-red-400 uppercase tracking-wider">
                        Disabled
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{policy.description}</p>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleToggle(policy.id)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-xl transition-colors ${policy.is_active ? 'bg-ghost-500' : 'bg-gray-600'}`}
                  >
                    <span className={`inline-block h-3 w-3 transform rounded-xl bg-white transition-transform ${policy.is_active ? 'translate-x-5' : 'translate-x-1'}`} />
                  </button>
                  <button onClick={() => openEditModal(policy)} className="btn-ghost px-3 py-1.5 text-sm">
                    Edit
                  </button>
                  <button onClick={() => handleDelete(policy.id)} className="p-1.5 rounded-xl text-gray-500 hover:text-red-400 hover:bg-red-400/10 transition-colors">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="mt-6 flex flex-wrap gap-2">
                {policy.rules.map((rule) => {
                  const detectorInfo = DETECTORS.find(d => d.id === rule.detector);
                  const Icon = detectorInfo?.icon || Shield;
                  return (
                    <div key={rule.id} className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-surface-2/50 border border-white/5 text-sm text-gray-300">
                      <Icon className="w-3.5 h-3.5 text-white" />
                      <span>{detectorInfo?.name || rule.detector}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase ${
                        rule.action === 'block' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                      }`}>
                        {rule.action}
                      </span>
                    </div>
                  );
                })}
              </div>
              <div className="mt-4 pt-4 border-t border-white/5 flex justify-between items-center text-xs text-gray-500">
                <span>Priority: P{policy.priority}</span>
                <span>Last updated: {format(new Date(policy.created_at), 'MMM d, yyyy HH:mm')}</span>
              </div>
            </div>
          ))}
        </div>
        </>
      )}

      {/* Policy Modal */}
      <AnimatePresence>
        {isModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-surface-0/60 backdrop-blur-sm"
              onClick={() => setIsModalOpen(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#111111] border border-white/10 rounded-xl shadow-2xl overflow-hidden"
            >
              <div className="flex items-center justify-between p-6 border-b border-white/10 bg-surface-0">
                <h3 className="text-xl font-bold text-white">
                  {editingPolicy ? 'Edit Policy' : 'Create New Policy'}
                </h3>
                <button onClick={() => setIsModalOpen(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6 space-y-8">
                {/* Basic Info */}
                <div className="space-y-4">
                  <h4 className="text-sm font-semibold text-white uppercase tracking-wider">General Information</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-sm text-gray-400">Policy Name</label>
                      <input
                        type="text"
                        value={formData.name}
                        onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                        className="w-full bg-surface-2 border border-white/10 rounded-xl px-4 py-2 text-white focus:outline-none focus:border-emerald-500"
                        placeholder="e.g., Strict PII Protection"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-sm text-gray-400">Priority (1-1000)</label>
                      <input
                        type="number"
                        value={formData.priority}
                        onChange={(e) => setFormData(prev => ({ ...prev, priority: parseInt(e.target.value) }))}
                        className="w-full bg-surface-2 border border-white/10 rounded-xl px-4 py-2 text-white focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm text-gray-400">Description</label>
                    <input
                      type="text"
                      value={formData.description}
                      onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                      className="w-full bg-surface-2 border border-white/10 rounded-xl px-4 py-2 text-white focus:outline-none focus:border-emerald-500"
                      placeholder="What does this policy do?"
                    />
                  </div>
                </div>

                {/* Rules Section */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-semibold text-white uppercase tracking-wider">Detection Rules</h4>
                    
                    <div className="relative group">
                      <button className="btn-secondary text-xs flex items-center gap-2">
                        <Plus className="w-3 h-3" /> Add Detector
                      </button>
                      <div className="absolute right-0 top-full mt-2 w-64 bg-surface-2 border border-white/10 rounded-xl shadow-xl overflow-hidden opacity-0 pointer-events-none group-hover:opacity-100 group-hover:pointer-events-auto transition-opacity z-10">
                        <div className="max-h-64 overflow-y-auto py-2">
                          {DETECTORS.map(d => (
                            <button
                              key={d.id}
                              onClick={() => handleAddRule(d.id)}
                              disabled={formData.rules.some(r => r.detector === d.id)}
                              className="w-full text-left px-4 py-2 hover:bg-white/5 disabled:opacity-30 flex items-center gap-3 text-sm text-gray-200"
                            >
                              <d.icon className="w-4 h-4 text-white" />
                              {d.name}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  {formData.rules.length === 0 ? (
                    <div className="text-center py-10 bg-surface-0/50 border border-white/5 rounded-xl border-dashed">
                      <Shield className="w-8 h-8 text-gray-500 mx-auto mb-3" />
                      <p className="text-gray-400 text-sm">No rules configured for this policy.</p>
                      <p className="text-gray-500 text-xs mt-1">Hover "Add Detector" to add protection engines.</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {formData.rules.map((rule, idx) => {
                        const detectorInfo = DETECTORS.find(d => d.id === rule.detector);
                        const Icon = detectorInfo?.icon || Shield;
                        return (
                          <div key={idx} className="bg-surface-2/30 border border-white/10 rounded-xl p-4">
                            <div className="flex items-start justify-between mb-4">
                              <div className="flex items-center gap-3">
                                <div className="w-8 h-8 rounded-xl bg-surface-3 flex items-center justify-center">
                                  <Icon className="w-4 h-4 text-white" />
                                </div>
                                <div>
                                  <h5 className="text-sm font-semibold text-white">{detectorInfo?.name}</h5>
                                  <p className="text-xs text-gray-400">{detectorInfo?.description}</p>
                                </div>
                              </div>
                              <button onClick={() => handleRemoveRule(idx)} className="text-gray-500 hover:text-red-400 transition-colors">
                                <X className="w-4 h-4" />
                              </button>
                            </div>
                            
                            <div className="grid grid-cols-3 gap-4">
                              <div className="space-y-1.5">
                                <label className="text-xs text-gray-400">Action on Detect</label>
                                <select 
                                  value={rule.action}
                                  onChange={(e) => handleUpdateRule(idx, 'action', e.target.value)}
                                  className="w-full bg-surface-0 border border-white/10 rounded-xl px-3 py-1.5 text-sm text-white focus:outline-none focus:border-emerald-500"
                                >
                                  <option value="block">Block Request</option>
                                  <option value="flag">Flag / Allow</option>
                                  <option value="sanitize">Sanitize (Redact)</option>
                                </select>
                              </div>
                              <div className="space-y-1.5">
                                <label className="text-xs text-gray-400">Threat Severity</label>
                                <select 
                                  value={rule.severity}
                                  onChange={(e) => handleUpdateRule(idx, 'severity', e.target.value)}
                                  className="w-full bg-surface-0 border border-white/10 rounded-xl px-3 py-1.5 text-sm text-white focus:outline-none focus:border-emerald-500"
                                >
                                  <option value="critical">Critical</option>
                                  <option value="high">High</option>
                                  <option value="medium">Medium</option>
                                  <option value="low">Low</option>
                                </select>
                              </div>
                              <div className="space-y-1.5">
                                <label className="text-xs text-gray-400">Confidence Threshold</label>
                                <div className="flex items-center gap-2">
                                  <input 
                                    type="range" 
                                    min="0" max="1" step="0.05"
                                    value={rule.threshold}
                                    onChange={(e) => handleUpdateRule(idx, 'threshold', parseFloat(e.target.value))}
                                    className="flex-1 accent-emerald-500"
                                  />
                                  <span className="text-xs text-white font-mono w-8">
                                    {rule.threshold.toFixed(2)}
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              <div className="p-6 border-t border-white/10 bg-surface-0 flex justify-end gap-3">
                <button onClick={() => setIsModalOpen(false)} className="btn-ghost">
                  Cancel
                </button>
                <button onClick={handleSave} className="btn-primary flex items-center gap-2" disabled={!formData.name}>
                  <Save className="w-4 h-4" />
                  Save Policy
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
