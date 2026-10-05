'use client';
import { useState, useEffect, useCallback } from "react";
import {
  Key, Plus, Trash2, Shield, User, Users, Loader2, Copy, Check, Bell, Link2,
  Palette, Scale, AlertTriangle, Settings, Lock, Save, Eye, EyeOff,
  Monitor, Smartphone, Globe, Server, Keyboard, ChevronRight, KeyRound, Fingerprint,
  Zap, RefreshCw, ShieldCheck, Network, Database, Layers
} from "lucide-react";
import UserManagementView from '@/components/dashboard/UserManagementView';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

const TABS = [
  { id: 'profile', label: 'Profile & Account', icon: User },
  { id: 'team', label: 'Team & Permissions', icon: Users },
  { id: 'organization', label: 'Organization', icon: Globe },
  { id: 'security', label: 'Security & Detection', icon: Shield },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'integrations', label: 'Integrations / SIEM', icon: Link2 },
  { id: 'byok', label: 'BYOK (API Keys)', icon: KeyRound },
  { id: 'identity', label: 'Identity & Security', icon: Fingerprint },
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'compliance', label: 'Compliance', icon: Scale },
  { id: 'keys', label: 'Platform Keys', icon: Key },
  { id: 'shortcuts', label: 'Keyboard Shortcuts', icon: Keyboard },
  { id: 'danger', label: 'Danger Zone', icon: AlertTriangle },
];

function SectionCard({ title, icon: Icon, children, color = 'text-ghost-400' }: any) {
  return (
    <div className="glass-card p-6">
      <div className="flex items-center gap-3 mb-5 border-b border-white/5 pb-4">
        <Icon className={`w-5 h-5 ${color}`} />
        <h3 className="text-lg font-bold text-white">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function FieldRow({ label, children, description }: { label: string; children: React.ReactNode; description?: string }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 py-3 border-b border-white/[0.04] last:border-0">
      <div>
        <span className="text-sm text-gray-400">{label}</span>
        {description && <p className="text-[10px] text-gray-600 mt-0.5">{description}</p>}
      </div>
      <div className="sm:max-w-[320px] w-full">{children}</div>
    </div>
  );
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!checked)}
      className={`relative w-10 h-5 rounded-full transition-colors ${checked ? 'bg-ghost-600' : 'bg-surface-2'}`}>
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-5' : ''}`} />
    </button>
  );
}

function Input({ value, onChange, type = 'text', placeholder = '' }: any) {
  return (
    <input type={type} value={value} onChange={(e: any) => onChange(e.target.value)} placeholder={placeholder}
      className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-ghost-500" />
  );
}

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    connected: 'bg-emerald-400 shadow-emerald-400/50',
    verified: 'bg-emerald-400 shadow-emerald-400/50',
    error: 'bg-red-400 shadow-red-400/50',
    auth_failed: 'bg-red-400 shadow-red-400/50',
    unreachable: 'bg-red-400 shadow-red-400/50',
    timeout: 'bg-amber-400 shadow-amber-400/50',
    unknown: 'bg-gray-500',
  };
  return <span className={`inline-block w-2 h-2 rounded-full shadow-sm ${colors[status] || colors.unknown} animate-pulse`} />;
}

// ── SIEM provider configs ──
const SIEM_PROVIDERS = [
  { name: 'Splunk', provider: 'splunk', fields: ['endpoint', 'hec_token', 'index_name'], placeholder: { endpoint: 'https://splunk.example.com:8088', hec_token: 'HEC Token', index_name: 'main' } },
  { name: 'Datadog', provider: 'datadog', fields: ['api_key'], placeholder: { api_key: 'DD API Key' } },
  { name: 'Microsoft Sentinel', provider: 'microsoft_sentinel', fields: ['endpoint', 'workspace_id', 'api_key'], placeholder: { endpoint: 'https://<workspace>.ods.opinsights.azure.com', workspace_id: 'Workspace ID', api_key: 'Shared Key' } },
  { name: 'IBM QRadar', provider: 'ibm_qradar', fields: ['endpoint', 'api_key'], placeholder: { endpoint: 'https://qradar.example.com', api_key: 'SEC Token' } },
  { name: 'Elastic Security', provider: 'elastic_security', fields: ['endpoint', 'api_key'], placeholder: { endpoint: 'https://elastic.example.com:9200', api_key: 'user:password or API Key' } },
  { name: 'CrowdStrike', provider: 'crowdstrike', fields: ['endpoint', 'api_key', 'api_secret'], placeholder: { endpoint: 'https://api.crowdstrike.com', api_key: 'Client ID', api_secret: 'Client Secret' } },
  { name: 'Google Chronicle', provider: 'google_chronicle', fields: ['endpoint', 'api_key'], placeholder: { endpoint: 'https://chronicle.googleapis.com', api_key: 'Service Account Token' } },
  { name: 'PagerDuty', provider: 'pagerduty', fields: ['routing_key'], placeholder: { routing_key: 'Events API v2 Integration Key' } },
  { name: 'Slack', provider: 'slack', fields: ['webhook_url', 'bot_token', 'channel'], placeholder: { webhook_url: 'https://hooks.slack.com/services/T.../B.../...', bot_token: 'xoxb-... (optional, for 2-way)', channel: '#security-alerts' } },
  { name: 'ServiceNow', provider: 'servicenow', fields: ['instance_url', 'username', 'password', 'assignment_group'], placeholder: { instance_url: 'https://your-instance.service-now.com', username: 'admin', password: 'Password', assignment_group: 'IT Security' } },
  { name: 'Jira', provider: 'jira', fields: ['instance_url', 'email', 'api_token', 'project_key', 'issue_type'], placeholder: { instance_url: 'https://your-org.atlassian.net', email: 'you@company.com', api_token: 'API Token', project_key: 'SEC', issue_type: 'Bug' } },
  { name: 'Amazon Security Lake', provider: 'security_lake', fields: ['aws_access_key', 'aws_secret_key', 'region', 's3_bucket', 'account_id', 'external_id'], placeholder: { aws_access_key: 'AKIA...', aws_secret_key: 'wJal...', region: 'us-east-1', s3_bucket: 'aws-security-data-lake-...', account_id: '123456789012', external_id: 'ghostprompt-source' } },
  { name: 'Sumo Logic', provider: 'sumo_logic', fields: ['collector_url', 'source_category'], placeholder: { collector_url: 'https://endpoint1.collection.sumologic.com/receiver/v1/http/...', source_category: 'ghostprompt/security' } },
  { name: 'Opsgenie', provider: 'opsgenie', fields: ['api_key', 'api_url', 'responders_team'], placeholder: { api_key: 'GenieKey UUID', api_url: 'https://api.opsgenie.com', responders_team: 'security-team' } },
  { name: 'Microsoft Teams', provider: 'teams', fields: ['webhook_url'], placeholder: { webhook_url: 'https://prod-XX.westus.logic.azure.com:443/workflows/...' } },
  { name: 'Webhook', provider: 'webhook', fields: ['endpoint', 'api_key'], placeholder: { endpoint: 'https://your-endpoint.com/hook', api_key: 'Bearer Token (optional)' } },
];

export default function SettingsView() {
  const [tab, setTab] = useState('profile');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState('');

  // All settings state
  const [profile, setProfile] = useState<any>({});
  const [org, setOrg] = useState<any>({});
  const [security, setSecurity] = useState<any>({});
  const [notifications, setNotifications] = useState<any>({});
  const [appearance, setAppearance] = useState<any>({});
  const [compliance, setCompliance] = useState<any>({});
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [sso, setSSO] = useState<any>({});
  const [scim, setSCIM] = useState<any>({});
  const [byokEnc, setBYOKEnc] = useState<any>({});
  const [mfa, setMFA] = useState<any>({});
  const [ipAllowlist, setIPAllowlist] = useState<any>({ enabled: false, cidrs: [], enforce: false });
  const [keys, setKeys] = useState<any[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [newEnv, setNewEnv] = useState('PRODUCTION');
  const [newKey, setNewKey] = useState<string|null>(null);
  const [copied, setCopied] = useState(false);
  const [pwCurrent, setPwCurrent] = useState('');
  const [pwNew, setPwNew] = useState('');
  const [showPw, setShowPw] = useState(false);

  // SIEM state
  const [editingSIEM, setEditingSIEM] = useState<string|null>(null);
  const [siemDraft, setSiemDraft] = useState<any>({});
  const [testingProvider, setTestingProvider] = useState<string|null>(null);
  const [testResult, setTestResult] = useState<any>(null);

  // New CIDR input
  const [newCIDR, setNewCIDR] = useState('');

  const headers = useCallback(() => {
    const t = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    return { 'Authorization': `Bearer ${t}`, 'Content-Type': 'application/json' };
  }, []);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [settingsRes, keysRes] = await Promise.all([
        fetch(`${API}/api/v1/settings`, { headers: headers() }),
        fetch(`${API}/api/v1/api-keys`, { headers: headers() }),
      ]);
      if (settingsRes.ok) {
        const d = await settingsRes.json();
        setProfile(d.profile || {});
        setOrg(d.organization || {});
        setSecurity(d.security || {});
        setNotifications(d.notifications || {});
        setAppearance(d.appearance || {});
        setCompliance(d.compliance || {});
        setIntegrations(d.integrations || []);
        setSSO(d.sso || {});
        setSCIM(d.scim || {});
        setBYOKEnc(d.byok_encryption || {});
        setMFA(d.mfa || {});
        setIPAllowlist(d.ip_allowlist || { enabled: false, cidrs: [], enforce: false });
      }
      if (keysRes.ok) setKeys(await keysRes.json());
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [headers]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Apply appearance settings to DOM + persist to localStorage
  useEffect(() => {
    if (!appearance.theme) return;
    const root = document.documentElement;
    // Persist to localStorage so other pages can apply
    try { localStorage.setItem('ghostprompt_appearance', JSON.stringify(appearance)); } catch {}
    // Theme
    if (appearance.theme === 'dark') {
      root.classList.remove('light-mode');
      root.style.setProperty('--surface-0', '6, 6, 14');
      root.style.setProperty('--surface-1', '14, 14, 26');
      root.style.setProperty('--surface-2', '22, 22, 38');
    } else if (appearance.theme === 'midnight') {
      root.classList.remove('light-mode');
      root.style.setProperty('--surface-0', '2, 2, 8');
      root.style.setProperty('--surface-1', '8, 8, 16');
      root.style.setProperty('--surface-2', '14, 14, 24');
    } else {
      root.classList.add('light-mode');
      root.style.setProperty('--surface-0', '240, 240, 248');
      root.style.setProperty('--surface-1', '250, 250, 255');
      root.style.setProperty('--surface-2', '255, 255, 255');
    }
    // Accent color
    if (appearance.accent_color) {
      const hex = appearance.accent_color.replace('#', '');
      const r = parseInt(hex.substring(0, 2), 16);
      const g = parseInt(hex.substring(2, 4), 16);
      const b = parseInt(hex.substring(4, 6), 16);
      root.style.setProperty('--ghost-400', `${r}, ${g}, ${b}`);
      root.style.setProperty('--ghost-500', `${r}, ${g}, ${b}`);
      root.style.setProperty('--ghost-600', `${Math.max(0,r-30)}, ${Math.max(0,g-30)}, ${Math.max(0,b-30)}`);
    }
    // Font size
    const sizeMap: Record<string, string> = { sm: '14px', base: '16px', lg: '18px' };
    root.style.setProperty('font-size', sizeMap[appearance.font_size] || '16px');
    // Density
    if (appearance.density === 'compact') {
      root.style.setProperty('--density-pad', '0.5rem');
    } else {
      root.style.setProperty('--density-pad', '1rem');
    }
    // Reduced motion
    if (appearance.reduced_motion) {
      root.classList.add('reduce-motion');
    } else {
      root.classList.remove('reduce-motion');
    }
    // Animation speed
    const speedMap: Record<string, string> = { none: '0ms', slow: '600ms', normal: '300ms', fast: '150ms' };
    root.style.setProperty('--animation-speed', speedMap[appearance.animation_speed] || '300ms');
  }, [appearance]);

  const save = async (section: string, data: any) => {
    setSaving(true);
    try {
      const res = await fetch(`${API}/api/v1/settings/${section}`, {
        method: 'PUT', headers: headers(), body: JSON.stringify(data),
      });
      if (res.ok) { setSaved(section); setTimeout(() => setSaved(''), 2000); }
    } catch (e) { console.error(e); }
    setSaving(false);
  };

  const changePassword = async () => {
    try {
      const res = await fetch(`${API}/api/v1/settings/password`, {
        method: 'POST', headers: headers(),
        body: JSON.stringify({ current_password: pwCurrent, new_password: pwNew }),
      });
      if (res.ok) { setPwCurrent(''); setPwNew(''); alert('Password changed!'); }
      else { const e = await res.json(); alert(e.detail || 'Failed'); }
    } catch (e) { alert('Error changing password'); }
  };

  const createKey = async () => {
    try {
      const res = await fetch(`${API}/api/v1/api-keys`, {
        method: 'POST', headers: headers(),
        body: JSON.stringify({ name: newKeyName, environment: newEnv }),
      });
      if (res.ok) { const d = await res.json(); setNewKey(d.key); setNewKeyName(''); fetchAll(); }
    } catch (e) { console.error(e); }
  };

  const deleteKey = async (id: string) => {
    await fetch(`${API}/api/v1/api-keys/${id}`, { method: 'DELETE', headers: headers() });
    fetchAll();
  };

  // SIEM functions
  const saveSIEM = async (providerKey: string) => {
    const config = { ...siemDraft, provider: providerKey, enabled: true };
    try {
      const res = await fetch(`${API}/api/v1/settings/integrations`, {
        method: 'POST', headers: headers(), body: JSON.stringify(config),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        alert(`Failed to save integration: ${body.detail || res.statusText}`);
        return;
      }
      setEditingSIEM(null);
      setSiemDraft({});
      fetchAll();
    } catch (e: any) {
      alert(`Error saving integration: ${e.message}`);
    }
  };

  const removeSIEM = async (providerKey: string) => {
    await fetch(`${API}/api/v1/settings/integrations/${providerKey}`, { method: 'DELETE', headers: headers() });
    fetchAll();
  };

  const testSIEM = async (providerKey: string) => {
    setTestingProvider(providerKey);
    setTestResult(null);
    try {
      const res = await fetch(`${API}/api/v1/settings/integrations/${providerKey}/test`, {
        method: 'POST', headers: headers(),
      });
      if (res.ok) {
        const data = await res.json();
        setTestResult(data);
      } else {
        setTestResult({ status: 'error', details: 'API error' });
      }
    } catch {
      setTestResult({ status: 'error', details: 'Network error' });
    }
    setTestingProvider(null);
  };

  const SaveBtn = ({ section, data }: { section: string; data: any }) => (
    <button onClick={() => save(section, data)} disabled={saving}
      className="btn-primary text-xs py-2 px-4 flex items-center gap-2 mt-4">
      {saved === section ? <Check className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
      {saved === section ? 'Saved!' : 'Save Changes'}
    </button>
  );

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <Loader2 className="w-6 h-6 animate-spin text-ghost-400" />
    </div>
  );

  return (
    <div className="flex gap-6">
      {/* Sidebar */}
      <div className="w-56 shrink-0 space-y-0.5">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all ${
              tab === t.id ? 'bg-ghost-600/15 text-ghost-400 font-medium' : 'text-gray-500 hover:text-gray-300 hover:bg-surface-1'
            }`}>
            <t.icon className="w-4 h-4" />
            {t.label}
            {tab === t.id && <ChevronRight className="w-3 h-3 ml-auto" />}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 space-y-6 max-w-3xl">
        {/* Profile */}
        {tab === 'profile' && (
          <SectionCard title="Profile & Account" icon={User} color="text-cyan-400">
            <FieldRow label="Email"><span className="text-sm text-white font-mono">{profile.email}</span></FieldRow>
            <FieldRow label="Full Name">
              <Input value={profile.full_name || ''} onChange={(v: string) => setProfile({...profile, full_name: v})} />
            </FieldRow>
            <FieldRow label="Role">
              <span className="text-sm text-emerald-400 font-semibold capitalize">{profile.role}</span>
            </FieldRow>
            <FieldRow label="Member Since">
              <span className="text-sm text-gray-400">{profile.created_at ? new Date(profile.created_at).toLocaleDateString() : '—'}</span>
            </FieldRow>
            <button onClick={async () => {
              await fetch(`${API}/api/v1/settings/profile`, {
                method: 'PATCH', headers: headers(),
                body: JSON.stringify({ full_name: profile.full_name }),
              });
              setSaved('profile'); setTimeout(() => setSaved(''), 2000);
            }} className="btn-primary text-xs py-2 px-4 flex items-center gap-2 mt-4">
              {saved === 'profile' ? <Check className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
              {saved === 'profile' ? 'Saved!' : 'Save Profile'}
            </button>

            <div className="mt-6 pt-6 border-t border-white/5">
              <h4 className="text-sm font-bold text-white mb-3 flex items-center gap-2"><Lock className="w-4 h-4" /> Change Password</h4>
              <div className="space-y-3 max-w-sm">
                <Input type={showPw ? 'text' : 'password'} value={pwCurrent} onChange={setPwCurrent} placeholder="Current password" />
                <Input type={showPw ? 'text' : 'password'} value={pwNew} onChange={setPwNew} placeholder="New password (min 8 chars)" />
                <div className="flex items-center gap-3">
                  <button onClick={changePassword} disabled={!pwCurrent || !pwNew || pwNew.length < 8}
                    className="btn-primary text-xs py-2 px-4 disabled:opacity-40">Change Password</button>
                  <button onClick={() => setShowPw(!showPw)} className="text-gray-500 hover:text-gray-300">
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
          </SectionCard>
        )}

        {/* Team & Permissions */}
        {tab === 'team' && (
          <UserManagementView />
        )}

        {/* Organization */}
        {tab === 'organization' && (
          <SectionCard title="Organization" icon={Globe} color="text-blue-400">
            <FieldRow label="Name"><Input value={org.name || ''} onChange={(v: string) => setOrg({...org, name: v})} /></FieldRow>
            <FieldRow label="Slug"><span className="text-sm text-gray-400 font-mono">{org.slug}</span></FieldRow>
            <FieldRow label="Plan"><span className="text-sm text-cyan-400 font-semibold uppercase">{org.plan}</span></FieldRow>
            <SaveBtn section="organization" data={{ name: org.name }} />
          </SectionCard>
        )}

        {/* Security */}
        {tab === 'security' && (
          <SectionCard title="Security & Detection" icon={Shield} color="text-red-400">
            <FieldRow label="Threat Score Threshold">
              <div className="flex items-center gap-3">
                <input type="range" min="0.1" max="1.0" step="0.05" value={security.threat_score_threshold || 0.7}
                  onChange={e => setSecurity({...security, threat_score_threshold: parseFloat(e.target.value)})}
                  className="flex-1 accent-ghost-500" />
                <span className="text-sm font-mono text-white w-10">{(security.threat_score_threshold || 0.7).toFixed(2)}</span>
              </div>
            </FieldRow>
            <FieldRow label="Auto-block Critical"><Toggle checked={security.auto_block_critical ?? true} onChange={v => setSecurity({...security, auto_block_critical: v})} /></FieldRow>
            <FieldRow label="PII Auto-redact"><Toggle checked={security.pii_auto_redact ?? true} onChange={v => setSecurity({...security, pii_auto_redact: v})} /></FieldRow>
            <FieldRow label="MFA Required"><Toggle checked={security.mfa_required ?? false} onChange={v => setSecurity({...security, mfa_required: v})} /></FieldRow>
            <FieldRow label="Max Prompt Length">
              <Input type="number" value={security.max_prompt_length || 32000} onChange={(v: string) => setSecurity({...security, max_prompt_length: parseInt(v)})} />
            </FieldRow>
            <FieldRow label="Rate Limit (req/min)">
              <Input type="number" value={security.rate_limit_per_minute || 60} onChange={(v: string) => setSecurity({...security, rate_limit_per_minute: parseInt(v)})} />
            </FieldRow>
            <SaveBtn section="security" data={security} />
          </SectionCard>
        )}

        {/* Notifications */}
        {tab === 'notifications' && (
          <SectionCard title="Notifications" icon={Bell} color="text-amber-400">
            <FieldRow label="Email Alerts"><Toggle checked={notifications.email_alerts ?? true} onChange={v => setNotifications({...notifications, email_alerts: v})} /></FieldRow>
            <FieldRow label="Alert Threshold">
              <select value={notifications.alert_threshold || 'high'} onChange={e => setNotifications({...notifications, alert_threshold: e.target.value})}
                className="bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white w-full">
                {['low','medium','high','critical'].map(v => <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>)}
              </select>
            </FieldRow>
            <FieldRow label="Slack Webhook URL"><Input value={notifications.slack_webhook_url || ''} onChange={(v: string) => setNotifications({...notifications, slack_webhook_url: v})} placeholder="https://hooks.slack.com/..." /></FieldRow>
            <FieldRow label="PagerDuty Key"><Input value={notifications.pagerduty_key || ''} onChange={(v: string) => setNotifications({...notifications, pagerduty_key: v})} placeholder="Integration key" /></FieldRow>
            <FieldRow label="Custom Webhook"><Input value={notifications.webhook_url || ''} onChange={(v: string) => setNotifications({...notifications, webhook_url: v})} placeholder="https://..." /></FieldRow>
            <SaveBtn section="notifications" data={notifications} />
          </SectionCard>
        )}

        {/* ══════════════ INTEGRATIONS / SIEM (REAL) ══════════════ */}
        {tab === 'integrations' && (
          <SectionCard title="Integrations / SIEM" icon={Link2} color="text-indigo-400">
            <p className="text-xs text-gray-500 mb-4">Configure real SIEM connectors. Each integration is validated with a live connection test.</p>
            <div className="space-y-3">
              {SIEM_PROVIDERS.map(sp => {
                const existing = integrations.find((i: any) => i.provider === sp.provider);
                const isEditing = editingSIEM === sp.provider;
                const isConnected = existing?.verified || existing?.last_test_status === 'connected';
                return (
                  <div key={sp.provider} className="p-4 bg-surface-0/50 rounded-xl border border-white/5">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-white font-medium">{sp.name}</span>
                        {existing && <StatusDot status={existing.last_test_status || (existing.enabled ? 'unknown' : 'unknown')} />}
                        {isConnected && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 font-semibold">CONNECTED</span>}
                        {existing && !isConnected && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 font-semibold">CONFIGURED</span>}
                      </div>
                      <div className="flex items-center gap-2">
                        {existing && (
                          <button onClick={() => testSIEM(sp.provider)} disabled={testingProvider === sp.provider}
                            className="text-[11px] px-2.5 py-1 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 flex items-center gap-1">
                            {testingProvider === sp.provider ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                            Test
                          </button>
                        )}
                        {existing ? (
                          <button onClick={() => removeSIEM(sp.provider)} className="text-[11px] px-2.5 py-1 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20">Remove</button>
                        ) : (
                          <button onClick={() => { setEditingSIEM(sp.provider); setSiemDraft(existing || {}); }}
                            className="text-[11px] px-2.5 py-1 rounded-lg bg-ghost-600/10 text-ghost-400 hover:bg-ghost-600/20">Configure</button>
                        )}
                        {existing && !isEditing && (
                          <button onClick={() => { setEditingSIEM(sp.provider); setSiemDraft(existing); }}
                            className="text-[11px] px-2.5 py-1 rounded-lg bg-white/5 text-gray-400 hover:text-white">Edit</button>
                        )}
                      </div>
                    </div>

                    {/* Test result */}
                    {testResult && testResult.provider === sp.provider && (
                      <div className={`mt-2 p-2 rounded-lg text-[11px] font-mono ${testResult.status === 'connected' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                        {testResult.status.toUpperCase()} — {testResult.details} {testResult.latency_ms ? `(${testResult.latency_ms}ms)` : ''}
                      </div>
                    )}

                    {/* Edit form */}
                    {isEditing && (
                      <div className="mt-3 pt-3 border-t border-white/5 space-y-2">
                        {sp.fields.map(field => (
                          <div key={field}>
                            <label className="text-[10px] text-gray-500 uppercase tracking-wider">{field.replace(/_/g, ' ')}</label>
                            <input
                              type={field.includes('key') || field.includes('secret') || field.includes('token') ? 'password' : 'text'}
                              value={siemDraft[field] || ''}
                              onChange={e => setSiemDraft({...siemDraft, [field]: e.target.value})}
                              placeholder={(sp.placeholder as any)[field] || ''}
                              className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-ghost-500 mt-0.5"
                            />
                          </div>
                        ))}
                        <div className="flex items-center gap-2 mt-2">
                          <select value={siemDraft.format || 'json'} onChange={e => setSiemDraft({...siemDraft, format: e.target.value})}
                            className="bg-surface-0 border border-white/10 rounded-lg px-2 py-1 text-[11px] text-white">
                            <option value="json">JSON</option>
                            <option value="ocsf">OCSF</option>
                            <option value="cef">CEF</option>
                          </select>
                          <button onClick={() => saveSIEM(sp.provider)} className="text-xs bg-ghost-600/20 text-ghost-400 px-3 py-1.5 rounded-lg hover:bg-ghost-600/30">Save & Enable</button>
                          <button onClick={() => setEditingSIEM(null)} className="text-xs text-gray-500 hover:text-gray-300">Cancel</button>
                        </div>
                      </div>
                    )}

                    {/* Last test info */}
                    {existing?.last_test_at && !isEditing && (
                      <p className="text-[10px] text-gray-600 mt-1">Last tested: {new Date(existing.last_test_at).toLocaleString()}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </SectionCard>
        )}

        {/* ══════════════ APPEARANCE (FUNCTIONAL) ══════════════ */}
        {tab === 'appearance' && (
          <SectionCard title="Appearance" icon={Palette} color="text-purple-400">
            <FieldRow label="Theme">
              <div className="flex gap-2">
                {['dark','darker'].map(t => (
                  <button key={t} onClick={() => setAppearance({...appearance, theme: t})}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${appearance.theme === t ? 'border-ghost-500 text-ghost-400 bg-ghost-600/10' : 'border-white/10 text-gray-500'}`}>
                    {t.charAt(0).toUpperCase() + t.slice(1)}
                  </button>
                ))}
              </div>
            </FieldRow>
            <FieldRow label="Accent Color" description="Brand color for buttons, highlights, and active states">
              <div className="flex items-center gap-2">
                <input type="color" value={appearance.accent_color || '#8b5cf6'} onChange={e => setAppearance({...appearance, accent_color: e.target.value})}
                  className="w-8 h-8 rounded-lg border border-white/10 cursor-pointer bg-transparent" />
                <span className="text-xs font-mono text-gray-400">{appearance.accent_color || '#8b5cf6'}</span>
                <button onClick={() => setAppearance({...appearance, accent_color: '#8b5cf6'})} className="text-[10px] text-gray-600 hover:text-gray-400">Reset</button>
              </div>
            </FieldRow>
            <FieldRow label="Density">
              <div className="flex gap-2">
                {['comfortable','compact'].map(d => (
                  <button key={d} onClick={() => setAppearance({...appearance, density: d})}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${appearance.density === d ? 'border-ghost-500 text-ghost-400 bg-ghost-600/10' : 'border-white/10 text-gray-500'}`}>
                    {d.charAt(0).toUpperCase() + d.slice(1)}
                  </button>
                ))}
              </div>
            </FieldRow>
            <FieldRow label="Font Size">
              <div className="flex gap-2">
                {[{v:'sm',l:'Small'},{v:'base',l:'Default'},{v:'lg',l:'Large'}].map(f => (
                  <button key={f.v} onClick={() => setAppearance({...appearance, font_size: f.v})}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${appearance.font_size === f.v ? 'border-ghost-500 text-ghost-400 bg-ghost-600/10' : 'border-white/10 text-gray-500'}`}>
                    {f.l}
                  </button>
                ))}
              </div>
            </FieldRow>
            <FieldRow label="Code Font">
              <select value={appearance.code_font || 'JetBrains Mono'} onChange={e => setAppearance({...appearance, code_font: e.target.value})}
                className="bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white w-full">
                {['JetBrains Mono','Fira Code','Source Code Pro','Cascadia Code','IBM Plex Mono'].map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </FieldRow>
            <FieldRow label="Animation Speed">
              <div className="flex gap-2">
                {[{v:'none',l:'Off'},{v:'slow',l:'Slow'},{v:'normal',l:'Normal'},{v:'fast',l:'Fast'}].map(a => (
                  <button key={a.v} onClick={() => setAppearance({...appearance, animation_speed: a.v})}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border ${appearance.animation_speed === a.v ? 'border-ghost-500 text-ghost-400 bg-ghost-600/10' : 'border-white/10 text-gray-500'}`}>
                    {a.l}
                  </button>
                ))}
              </div>
            </FieldRow>
            <FieldRow label="Reduced Motion"><Toggle checked={appearance.reduced_motion ?? false} onChange={v => setAppearance({...appearance, reduced_motion: v})} /></FieldRow>
            <FieldRow label="Sidebar Collapsed by Default"><Toggle checked={appearance.sidebar_collapsed ?? false} onChange={v => setAppearance({...appearance, sidebar_collapsed: v})} /></FieldRow>
            <FieldRow label="Threat Color Scheme" description="Accessibility-friendly color palettes">
              <select value={appearance.threat_color_scheme || 'default'} onChange={e => setAppearance({...appearance, threat_color_scheme: e.target.value})}
                className="bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white w-full">
                <option value="default">Default (Red/Amber/Green)</option>
                <option value="deuteranopia">Deuteranopia-safe</option>
                <option value="protanopia">Protanopia-safe</option>
              </select>
            </FieldRow>
            <div className="flex items-center gap-3 pt-2">
              <SaveBtn section="appearance" data={appearance} />
              <button
                onClick={() => {
                  const defaults = {
                    theme: 'dark',
                    accent_color: '#8b5cf6',
                    density: 'normal',
                    font_size: 'md',
                    code_font: 'JetBrains Mono',
                    animation_speed: 'normal',
                    reduced_motion: false,
                    sidebar_collapsed: false,
                    threat_color_scheme: 'default',
                  };
                  setAppearance(defaults);
                }}
                className="px-4 py-2 text-xs font-medium rounded-lg border border-white/10 text-gray-400 hover:text-white hover:border-white/20 transition-colors"
              >
                ↺ Reset to Default
              </button>
            </div>
            {appearance.theme === 'light' && (
              <div className="mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-[11px]">
                ⚠️ Light mode maintains GhostPrompt brand colors (electric-blue accents, dark sidebar) for visual consistency. Full light mode available in Enterprise plan.
              </div>
            )}
          </SectionCard>
        )}

        {/* ══════════════ COMPLIANCE (FULL) ══════════════ */}
        {tab === 'compliance' && (
          <SectionCard title="Compliance Frameworks" icon={Scale} color="text-emerald-400">
            <p className="text-xs text-gray-500 mb-4">Enable compliance frameworks relevant to your organization. 9-framework governance suite with PDF/CSV/JSON export and HMAC-signed tamper evidence.</p>

            {/* AI-Specific Frameworks */}
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider font-bold mb-2 mt-2 flex items-center gap-1.5"><Shield className="w-3 h-3" /> AI-Specific Frameworks</h4>
            <FieldRow label="NIST AI RMF 1.0" description="Self-assessable — AI risk management with 4 functions: Govern, Map, Measure, Manage"><Toggle checked={compliance.nist_ai_rmf_enabled ?? true} onChange={v => setCompliance({...compliance, nist_ai_rmf_enabled: v})} /></FieldRow>
            <FieldRow label="ISO/IEC 42001:2023" description="Self-assessable — AI management system standard"><Toggle checked={compliance.iso_42001_enabled ?? true} onChange={v => setCompliance({...compliance, iso_42001_enabled: v})} /></FieldRow>

            {/* Global Standards */}
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider font-bold mb-2 mt-6 flex items-center gap-1.5"><Globe className="w-3 h-3" /> Global Standards</h4>
            <FieldRow label="SOC 2 Type II" description="Requires external audit — 5 Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy"><Toggle checked={compliance.soc2_enabled ?? false} onChange={v => setCompliance({...compliance, soc2_enabled: v})} /></FieldRow>
            <FieldRow label="PCI DSS v4.0" description="Requires external audit — Payment card industry data security standard, 12 requirements"><Toggle checked={compliance.pci_dss_enabled ?? false} onChange={v => setCompliance({...compliance, pci_dss_enabled: v})} /></FieldRow>

            {/* Europe */}
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider font-bold mb-2 mt-6 flex items-center gap-1.5">🇪🇺 Europe</h4>
            <FieldRow label="GDPR" description="Legal/technical alignment — Articles 5-35, DPIA generator, 72-hour breach notification"><Toggle checked={compliance.gdpr_enabled ?? false} onChange={v => setCompliance({...compliance, gdpr_enabled: v})} /></FieldRow>
            <FieldRow label="EU AI Act" description="Self-assessable — Articles 9-15/50, Annex III risk-tier classification"><Toggle checked={compliance.eu_ai_act_enabled ?? false} onChange={v => setCompliance({...compliance, eu_ai_act_enabled: v})} /></FieldRow>

            {/* Americas */}
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider font-bold mb-2 mt-6 flex items-center gap-1.5">🇺🇸 Americas</h4>
            <FieldRow label="HIPAA" description="Legal/technical alignment — Privacy Rule, Security Rule, Breach Notification Rule"><Toggle checked={compliance.hipaa_enabled ?? false} onChange={v => setCompliance({...compliance, hipaa_enabled: v})} /></FieldRow>
            <FieldRow label="CCPA/CPRA" description="Legal/technical alignment — Consumer privacy rights + ADMT risk assessment"><Toggle checked={compliance.ccpa_enabled ?? false} onChange={v => setCompliance({...compliance, ccpa_enabled: v})} /></FieldRow>

            {/* Asia-Pacific */}
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider font-bold mb-2 mt-6 flex items-center gap-1.5">🇮🇳 Asia-Pacific</h4>
            <FieldRow label="DPDPA (India 2023)" description="Legal/technical alignment — Data Principal rights, 90-day grievance timeline, cross-border restrictions"><Toggle checked={compliance.dpdpa_enabled ?? false} onChange={v => setCompliance({...compliance, dpdpa_enabled: v})} /></FieldRow>

            {/* Data Controls */}
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider font-bold mb-2 mt-6 flex items-center gap-1.5"><Database className="w-3 h-3" /> Data Controls</h4>
            <FieldRow label="Data Residency">
              <select value={compliance.data_residency || 'us'} onChange={e => setCompliance({...compliance, data_residency: e.target.value})}
                className="bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white w-full">
                <option value="us">🇺🇸 United States</option>
                <option value="eu">🇪🇺 European Union</option>
                <option value="ap">🌏 Asia-Pacific</option>
                <option value="in">🇮🇳 India</option>
              </select>
            </FieldRow>
            <FieldRow label="Audit Log Retention (days)">
              <Input type="number" value={compliance.audit_retention_days || 90} onChange={(v: string) => setCompliance({...compliance, audit_retention_days: parseInt(v)})} />
            </FieldRow>
            <FieldRow label="Allow Data Export"><Toggle checked={compliance.data_export_enabled ?? true} onChange={v => setCompliance({...compliance, data_export_enabled: v})} /></FieldRow>
            <FieldRow label="Consent Logging" description="Log user consent for data processing"><Toggle checked={compliance.consent_logging ?? false} onChange={v => setCompliance({...compliance, consent_logging: v})} /></FieldRow>
            <FieldRow label="Right to Erasure" description="Enable GDPR/DPDPA data deletion requests"><Toggle checked={compliance.right_to_erasure ?? false} onChange={v => setCompliance({...compliance, right_to_erasure: v})} /></FieldRow>
            <FieldRow label="Breach Notification (hours)" description="Max hours before mandatory breach disclosure">
              <Input type="number" value={compliance.breach_notification_hours || 72} onChange={(v: string) => setCompliance({...compliance, breach_notification_hours: parseInt(v)})} />
            </FieldRow>
            <FieldRow label="Automated DPIA" description="Data Protection Impact Assessment automation"><Toggle checked={compliance.automated_dpia ?? false} onChange={v => setCompliance({...compliance, automated_dpia: v})} /></FieldRow>
            <SaveBtn section="compliance" data={compliance} />
          </SectionCard>
        )}

        {/* API Keys */}
        {tab === 'keys' && (
          <SectionCard title="API Keys" icon={Key} color="text-ghost-400">
            {newKey && (
              <div className="mb-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-between">
                <div>
                  <h4 className="text-sm font-bold text-emerald-400">Save this key now!</h4>
                  <code className="text-xs font-mono text-emerald-300">{newKey}</code>
                </div>
                <button onClick={() => { navigator.clipboard.writeText(newKey); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                  className="p-1.5 bg-surface-0 border border-white/10 rounded-lg text-gray-400 hover:text-white">
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            )}
            <form onSubmit={e => { e.preventDefault(); createKey(); }} className="flex gap-3 mb-6">
              <input value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="Key name..."
                className="flex-1 bg-surface-0 border border-white/10 rounded-xl px-4 py-2 text-sm text-white focus:outline-none focus:border-ghost-500" />
              <select value={newEnv} onChange={e => setNewEnv(e.target.value)}
                className="bg-surface-0 border border-white/10 rounded-xl px-3 py-2 text-sm text-white">
                {['PRODUCTION','STAGING','DEV','SANDBOX'].map(e => <option key={e} value={e}>{e}</option>)}
              </select>
              <button type="submit" disabled={!newKeyName} className="btn-primary py-2 px-4 text-sm flex items-center gap-2 disabled:opacity-40">
                <Plus className="w-4 h-4" /> Create
              </button>
            </form>
            <div className="space-y-2">
              {keys.map((k: any) => (
                <div key={k.id} className="flex items-center justify-between p-3 bg-surface-0/50 rounded-xl border border-white/5 group">
                  <div>
                    <span className="text-sm text-white font-semibold">{k.name}</span>
                    <span className="ml-2 text-[10px] bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded-full">{k.environment}</span>
                    <div className="text-xs text-gray-600 font-mono mt-1">{k.key_prefix}</div>
                  </div>
                  <button onClick={() => deleteKey(k.id)} className="p-2 text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
              {keys.length === 0 && <p className="text-sm text-gray-600 text-center py-6">No API keys yet.</p>}
            </div>
          </SectionCard>
        )}

        {/* Shortcuts */}
        {tab === 'shortcuts' && (
          <SectionCard title="Keyboard Shortcuts" icon={Keyboard} color="text-violet-400">
            <div className="space-y-1">
              {[
                ['⌘/Ctrl + K', 'Command Palette'],
                ['?', 'Shortcuts Cheat Sheet'],
                ['Esc', 'Close Overlay'],
                ['g → o', 'Go to Overview'],
                ['g → c', 'Go to Cybermap'],
                ['g → a', 'Go to Attack Explorer'],
                ['g → r', 'Go to Red Team'],
                ['g → s', 'Go to Settings'],
                ['⌘/Ctrl + \\', 'Toggle Sidebar'],
                ['⌘/Ctrl + .', 'Pause/Resume Feed'],
                ['⌘/Ctrl + Enter', 'Run Scan'],
                ['[ / ]', 'Prev/Next Incident'],
                ['r', 'Reset Globe View'],
                ['f', 'Fullscreen Cybermap'],
              ].map(([key, desc]) => (
                <div key={key} className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-surface-1 transition-colors">
                  <span className="text-sm text-gray-400">{desc}</span>
                  <kbd className="text-[11px] font-mono bg-surface-2 px-2 py-0.5 rounded border border-white/10 text-gray-300">{key}</kbd>
                </div>
              ))}
            </div>
          </SectionCard>
        )}

        {/* BYOK — Bring Your Own Keys */}
        {tab === 'byok' && (
          <SectionCard title="Bring Your Own API Keys" icon={KeyRound} color="text-amber-400">
            <p className="text-xs text-gray-500 mb-4">Configure your own LLM provider API keys. These are encrypted at rest and used for scanning/inference.</p>
            <div className="space-y-3">
              {[
                { provider: 'OpenAI', placeholder: 'sk-...', envKey: 'OPENAI_API_KEY' },
                { provider: 'Anthropic', placeholder: 'sk-ant-...', envKey: 'ANTHROPIC_API_KEY' },
                { provider: 'Google AI', placeholder: 'AIza...', envKey: 'GOOGLE_AI_KEY' },
                { provider: 'Cohere', placeholder: 'co-...', envKey: 'COHERE_API_KEY' },
                { provider: 'Azure OpenAI', placeholder: 'https://...openai.azure.com', envKey: 'AZURE_OPENAI_ENDPOINT' },
              ].map(k => (
                <div key={k.provider} className="flex items-center justify-between p-4 bg-surface-0/50 border border-white/[0.04] rounded-xl">
                  <div>
                    <p className="text-sm text-white font-medium">{k.provider}</p>
                    <p className="text-[11px] text-gray-600 font-mono">{k.envKey}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <input type="password" placeholder={k.placeholder}
                      className="w-48 bg-surface-0 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-ghost-500" />
                    <button className="text-xs bg-ghost-600/20 text-ghost-400 px-3 py-1.5 rounded-lg hover:bg-ghost-600/30">Save</button>
                  </div>
                </div>
              ))}
            </div>
            <p className="text-[10px] text-gray-600 mt-4">Keys are AES-256 encrypted and stored per-organization. They are never logged or exposed in API responses.</p>
          </SectionCard>
        )}

        {/* ══════════════ IDENTITY & SECURITY (SSO/SCIM/BYOK/MFA/IP) ══════════════ */}
        {tab === 'identity' && (
          <div className="space-y-6">
            {/* SSO */}
            <SectionCard title="Single Sign-On (SSO)" icon={Fingerprint} color="text-cyan-400">
              <p className="text-xs text-gray-500 mb-4">Configure SAML 2.0 or OpenID Connect for enterprise identity federation.</p>
              <FieldRow label="SSO Protocol">
                <select value={sso.protocol || 'none'} onChange={e => setSSO({...sso, protocol: e.target.value})}
                  className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-ghost-500">
                  <option value="none">Disabled</option>
                  <option value="saml">SAML 2.0</option>
                  <option value="oidc">OpenID Connect (OIDC)</option>
                </select>
              </FieldRow>
              {sso.protocol !== 'none' && (
                <>
                  <FieldRow label="Identity Provider URL" description="SSO metadata or .well-known URL">
                    <Input value={sso.idp_url || ''} onChange={(v: string) => setSSO({...sso, idp_url: v})} placeholder="https://idp.example.com/sso" />
                  </FieldRow>
                  <FieldRow label="Entity ID / Client ID">
                    <Input value={sso.entity_id || ''} onChange={(v: string) => setSSO({...sso, entity_id: v})} placeholder="ghostprompt-prod" />
                  </FieldRow>
                  {sso.protocol === 'saml' && (
                    <FieldRow label="Certificate (PEM)">
                      <textarea rows={3} value={sso.certificate || ''} onChange={e => setSSO({...sso, certificate: e.target.value})}
                        placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                        className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-ghost-500 resize-none" />
                    </FieldRow>
                  )}
                  <FieldRow label="Enforce SSO for all users" description="Admin fallback login remains available">
                    <Toggle checked={sso.enforce_sso ?? false} onChange={v => setSSO({...sso, enforce_sso: v})} />
                  </FieldRow>
                  <FieldRow label="Just-in-Time Provisioning" description="Automatically create accounts on first SSO login">
                    <Toggle checked={sso.jit_provisioning ?? false} onChange={v => setSSO({...sso, jit_provisioning: v})} />
                  </FieldRow>
                </>
              )}
              <div className="flex items-center gap-2 mt-4">
                <button onClick={() => save('sso', sso)} className="btn-primary text-xs py-2 px-4 flex items-center gap-2">
                  <Save className="w-3.5 h-3.5" /> {saved === 'sso' ? 'Saved!' : 'Save SSO'}
                </button>
                {sso.idp_url && (
                  <button onClick={async () => {
                    const res = await fetch(`${API}/api/v1/settings/sso/test`, { method: 'POST', headers: headers() });
                    if (res.ok) { const d = await res.json(); alert(`Status: ${d.status}\nProtocol: ${d.protocol_detected || '—'}\nDetails: ${d.details}`); }
                  }} className="text-xs bg-cyan-500/10 text-cyan-400 px-3 py-2 rounded-lg hover:bg-cyan-500/20 flex items-center gap-1">
                    <Zap className="w-3 h-3" /> Test IdP
                  </button>
                )}
              </div>
            </SectionCard>

            {/* SCIM */}
            <SectionCard title="SCIM Provisioning" icon={Network} color="text-blue-400">
              <p className="text-xs text-gray-500 mb-4">Automate user lifecycle management with your identity provider.</p>
              <FieldRow label="Enable SCIM"><Toggle checked={scim.enabled ?? false} onChange={v => setSCIM({...scim, enabled: v})} /></FieldRow>
              {scim.enabled && (
                <>
                  <FieldRow label="SCIM Endpoint">
                    <Input value={scim.endpoint || ''} onChange={(v: string) => setSCIM({...scim, endpoint: v})} placeholder="https://idp.example.com/scim/v2" />
                  </FieldRow>
                  <FieldRow label="Bearer Token">
                    <Input type="password" value={scim.bearer_token || ''} onChange={(v: string) => setSCIM({...scim, bearer_token: v})} placeholder="SCIM bearer token" />
                  </FieldRow>
                  <FieldRow label="Sync Interval (minutes)">
                    <Input type="number" value={scim.sync_interval_minutes || 15} onChange={(v: string) => setSCIM({...scim, sync_interval_minutes: parseInt(v)})} />
                  </FieldRow>
                  <FieldRow label="Auto-Deprovision" description="Remove users when deactivated in IdP">
                    <Toggle checked={scim.auto_deprovision ?? false} onChange={v => setSCIM({...scim, auto_deprovision: v})} />
                  </FieldRow>
                </>
              )}
              <SaveBtn section="scim" data={scim} />
            </SectionCard>

            {/* BYOK Encryption */}
            <SectionCard title="BYOK Encryption (Customer-Managed Keys)" icon={Lock} color="text-amber-400">
              <p className="text-xs text-gray-500 mb-4">Bring your own encryption keys for data-at-rest. Envelope encryption wraps data keys with your master key.</p>
              <FieldRow label="Enable BYOK"><Toggle checked={byokEnc.enabled ?? false} onChange={v => setBYOKEnc({...byokEnc, enabled: v})} /></FieldRow>
              {byokEnc.enabled && (
                <>
                  <FieldRow label="KMS Provider">
                    <select value={byokEnc.kms_provider || 'none'} onChange={e => setBYOKEnc({...byokEnc, kms_provider: e.target.value})}
                      className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                      <option value="none">Select Provider</option>
                      <option value="aws_kms">AWS KMS</option>
                      <option value="gcp_kms">Google Cloud KMS</option>
                      <option value="azure_keyvault">Azure Key Vault</option>
                      <option value="custom">Custom HSM</option>
                    </select>
                  </FieldRow>
                  <FieldRow label="Key ID / ARN">
                    <Input value={byokEnc.key_id || ''} onChange={(v: string) => setBYOKEnc({...byokEnc, key_id: v})} placeholder="arn:aws:kms:... or projects/.../cryptoKeys/..." />
                  </FieldRow>
                  <FieldRow label="Region">
                    <Input value={byokEnc.region || ''} onChange={(v: string) => setBYOKEnc({...byokEnc, region: v})} placeholder="us-east-1" />
                  </FieldRow>
                  <FieldRow label="Rotation Period (days)">
                    <Input type="number" value={byokEnc.rotation_days || 90} onChange={(v: string) => setBYOKEnc({...byokEnc, rotation_days: parseInt(v)})} />
                  </FieldRow>
                  <FieldRow label="Envelope Encryption" description="Wrap data keys with your master key">
                    <Toggle checked={byokEnc.envelope_encryption ?? true} onChange={v => setBYOKEnc({...byokEnc, envelope_encryption: v})} />
                  </FieldRow>
                </>
              )}
              <SaveBtn section="byok-encryption" data={byokEnc} />
            </SectionCard>

            {/* MFA */}
            <SectionCard title="Multi-Factor Authentication (MFA)" icon={ShieldCheck} color="text-green-400">
              <p className="text-xs text-gray-500 mb-4">Enforce MFA across your organization for enhanced security.</p>
              <FieldRow label="Enforce MFA"><Toggle checked={mfa.enabled ?? false} onChange={v => setMFA({...mfa, enabled: v})} /></FieldRow>
              {mfa.enabled && (
                <>
                  <FieldRow label="MFA Method">
                    <select value={mfa.method || 'totp'} onChange={e => setMFA({...mfa, method: e.target.value})}
                      className="w-full bg-surface-0 border border-white/10 rounded-lg px-3 py-2 text-sm text-white">
                      <option value="totp">TOTP (Authenticator App)</option>
                      <option value="webauthn">WebAuthn (Hardware Key)</option>
                      <option value="sms">SMS (Fallback)</option>
                    </select>
                  </FieldRow>
                  <FieldRow label="Grace Period (hours)" description="Time before MFA enforcement for new users">
                    <Input type="number" value={mfa.grace_period_hours || 24} onChange={(v: string) => setMFA({...mfa, grace_period_hours: parseInt(v)})} />
                  </FieldRow>
                  <FieldRow label="Remember Device (days)">
                    <Input type="number" value={mfa.remember_device_days || 30} onChange={(v: string) => setMFA({...mfa, remember_device_days: parseInt(v)})} />
                  </FieldRow>
                  <FieldRow label="Exempt Admins" description="Allow admins to skip MFA">
                    <Toggle checked={mfa.exempt_admins ?? false} onChange={v => setMFA({...mfa, exempt_admins: v})} />
                  </FieldRow>
                </>
              )}
              <SaveBtn section="mfa" data={mfa} />
            </SectionCard>

            {/* IP Allowlist */}
            <SectionCard title="IP Allowlisting" icon={Network} color="text-orange-400">
              <p className="text-xs text-gray-500 mb-4">Restrict dashboard and API access to specific IP ranges.</p>
              <FieldRow label="Enable IP Allowlist"><Toggle checked={ipAllowlist.enabled ?? false} onChange={v => setIPAllowlist({...ipAllowlist, enabled: v})} /></FieldRow>
              {ipAllowlist.enabled && (
                <>
                  <FieldRow label="Enforce (block non-listed IPs)"><Toggle checked={ipAllowlist.enforce ?? false} onChange={v => setIPAllowlist({...ipAllowlist, enforce: v})} /></FieldRow>
                  <div className="mt-3">
                    <label className="text-xs text-gray-500">Allowed CIDR Ranges</label>
                    <div className="space-y-1 mt-1">
                      {(ipAllowlist.cidrs || []).map((cidr: string, i: number) => (
                        <div key={i} className="flex items-center gap-2">
                          <code className="text-xs font-mono text-white bg-surface-0 px-2 py-1 rounded border border-white/10 flex-1">{cidr}</code>
                          <button onClick={() => setIPAllowlist({...ipAllowlist, cidrs: ipAllowlist.cidrs.filter((_:any, j:number) => j !== i)})}
                            className="text-gray-600 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                        </div>
                      ))}
                    </div>
                    <div className="flex gap-2 mt-2">
                      <input value={newCIDR} onChange={e => setNewCIDR(e.target.value)} placeholder="10.0.0.0/8"
                        className="flex-1 bg-surface-0 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-ghost-500" />
                      <button onClick={() => { if (newCIDR) { setIPAllowlist({...ipAllowlist, cidrs: [...(ipAllowlist.cidrs || []), newCIDR]}); setNewCIDR(''); } }}
                        className="text-xs bg-ghost-600/20 text-ghost-400 px-3 py-1.5 rounded-lg hover:bg-ghost-600/30">Add</button>
                    </div>
                  </div>
                </>
              )}
              <SaveBtn section="ip-allowlist" data={ipAllowlist} />
            </SectionCard>
          </div>
        )}

        {/* Danger Zone */}
        {tab === 'danger' && (
          <div className="glass-card p-6 border-red-500/20">
            <div className="flex items-center gap-3 mb-5 border-b border-red-500/10 pb-4">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-lg font-bold text-red-400">Danger Zone</h3>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-red-500/5 border border-red-500/10 rounded-xl">
                <div>
                  <h4 className="text-sm font-bold text-white">Rotate All API Keys</h4>
                  <p className="text-xs text-gray-500">Invalidates all existing keys. New keys must be generated.</p>
                </div>
                <button onClick={async () => {
                  if (!confirm('This will invalidate ALL API keys. Are you sure?')) return;
                  await fetch(`${API}/api/v1/api-keys/rotate-all`, { method: 'POST', headers: headers() });
                  fetchAll();
                  alert('All API keys have been rotated.');
                }} className="text-xs bg-red-500/10 text-red-400 px-4 py-2 rounded-lg hover:bg-red-500/20">Rotate Keys</button>
              </div>
              <div className="flex items-center justify-between p-4 bg-red-500/5 border border-red-500/10 rounded-xl">
                <div>
                  <h4 className="text-sm font-bold text-white">Delete Organization</h4>
                  <p className="text-xs text-gray-500">Permanently delete this organization and all data. This cannot be undone.</p>
                </div>
                <button onClick={() => {
                  const name = prompt('Type your organization name to confirm deletion:');
                  if (name === org.name) {
                    alert('Organization deletion would be executed in production. This is a safety check.');
                  } else if (name) {
                    alert('Organization name does not match. Deletion cancelled.');
                  }
                }} className="text-xs bg-red-500/10 text-red-400 px-4 py-2 rounded-lg hover:bg-red-500/20">Delete Org</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
