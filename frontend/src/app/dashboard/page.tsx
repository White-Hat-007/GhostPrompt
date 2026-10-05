'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Shield, Search } from 'lucide-react';
import { useRouter, useSearchParams } from 'next/navigation';
import Sidebar from '@/components/layout/Sidebar';
import StatsGrid from '@/components/dashboard/StatsGrid';
import ThreatChart from '@/components/dashboard/ThreatChart';
import LiveAttackFeed from '@/components/dashboard/LiveAttackFeed';
import IncidentForensicsModal from '@/components/dashboard/IncidentForensicsModal';
import ThreatDistribution from '@/components/dashboard/ThreatDistribution';
import GlobalThreatMap from '@/components/dashboard/GlobalThreatMap';
import CommandPalette from '@/components/dashboard/CommandPalette';
import IncidentDrawer from '@/components/dashboard/IncidentDrawer';
import AtlasMatrixLive from '@/components/dashboard/AtlasMatrixLive';
import TopCategories from '@/components/dashboard/TopCategories';
import ModelActivity from '@/components/dashboard/ModelActivity';
import ScanTester from '@/components/dashboard/ScanTester';
import PoliciesView from '@/components/dashboard/PoliciesView';
import SettingsView from '@/components/dashboard/SettingsView';
import MultimodalAnalytics from '@/components/dashboard/MultimodalAnalytics';
import SupplyChainPanel from '@/components/dashboard/SupplyChainPanel';
import TokenAbuseChart from '@/components/dashboard/TokenAbuseChart';
import CrossLingualHeatmap from '@/components/dashboard/CrossLingualHeatmap';
import OracleAttackChart from '@/components/dashboard/OracleAttackChart';
import BusinessLogicChart from '@/components/dashboard/BusinessLogicChart';
import MemorizationChart from '@/components/dashboard/MemorizationChart';
import TokenizerChart from '@/components/dashboard/TokenizerChart';
import IndirectInjectionChart from '@/components/dashboard/IndirectInjectionChart';
import CyberGrid from '@/components/ui/CyberGrid';
import AttributionView from '@/components/dashboard/attribution/AttributionView';
import ComplianceView from '@/components/dashboard/ComplianceView';
import RedTeamOpsView from '@/components/dashboard/RedTeamOpsView';
import ProvidersView from '@/components/dashboard/ProvidersView';
import HallucinationView from '@/components/dashboard/HallucinationView';
import ModelWeightScanView from '@/components/dashboard/ModelWeightScanView';
import HardwareSecurityView from '@/components/dashboard/HardwareSecurityView';
import RoutingEngineView from '@/components/dashboard/RoutingEngineView';
import CacheAnalyticsView from '@/components/dashboard/CacheAnalyticsView';
import KeyVaultView from '@/components/dashboard/KeyVaultView';
import ObservabilityView from '@/components/dashboard/ObservabilityView';
import PromptStudioView from '@/components/dashboard/PromptStudioView';
import MCPGatewayView from '@/components/dashboard/MCPGatewayView';
import IntegrationsView from '@/components/dashboard/IntegrationsView';
import DataControlsView from '@/components/dashboard/DataControlsView';
import BudgetControlsView from '@/components/dashboard/BudgetControlsView';
import NetworkGuardsView from '@/components/dashboard/NetworkGuardsView';
import FederatedIntelView from '@/components/dashboard/FederatedIntelView';
import AdaptiveMLView from '@/components/dashboard/AdaptiveMLView';
import CustomModelsView from '@/components/dashboard/CustomModelsView';
import SaaSBillingView from '@/components/dashboard/SaaSBillingView';
import AttackFlowCanvas from '@/components/dashboard/AttackFlowCanvas';
import DataFlowSankey from '@/components/dashboard/DataFlowSankey';
import ThreatKnowledgeGraph from '@/components/dashboard/ThreatKnowledgeGraph';
import AnalyticsDashboard from '@/components/dashboard/AnalyticsDashboard';
import ShortcutsCheatSheet from '@/components/dashboard/ShortcutsCheatSheet';
import TrainingDashboard from '@/components/dashboard/TrainingDashboard';
import PlaybookBuilderView from '@/components/dashboard/PlaybookBuilderView';
import DailyBriefingView from '@/components/dashboard/DailyBriefingView';
import AttackSurfaceView from '@/components/dashboard/AttackSurfaceView';
import ServiceCatalogView from '@/components/dashboard/ServiceCatalogView';
import FirewallBansView from '@/components/dashboard/FirewallBansView';
import dynamic from 'next/dynamic';
const CyberMap = dynamic(() => import('@/components/dashboard/CyberMap'), { ssr: false });


const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:8000';

interface ScanEvent {
  id: string;
  request_id: string;
  threat_level: string;
  threat_score: number;
  action: string;
  scan_type: string;
  model: string;
  created_at: string;
  category?: string;
  prompt?: string;
  detections?: Array<{ category: string; detector: string; severity: string; confidence: number; description: string }>;
  scan_duration_ms?: number;
  attacker_profile?: any;
  lat?: number;
  lng?: number;
  city?: string;
  country?: string;
  ip?: string;
  asn?: string;
  isp?: string;
  timezone?: string;
  postal_code?: string;
  browser?: string;
  browser_full?: string;
  os?: string;
  user_agent?: string;
  provider?: string;
  primary_category?: string;
  detections_count?: number;
}

interface LiveStats {
  total_scans: number;
  blocked: number;
  flagged: number;
  allowed: number;
  threat_categories: Record<string, number>;
}

export default function DashboardPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialSection = searchParams.get('section') || 'overview';
  const [activeSection, setActiveSectionState] = useState(initialSection);

  // Sync URL when section changes
  const setActiveSection = useCallback((section: string) => {
    setActiveSectionState(section);
    const url = section === 'overview' ? '/dashboard' : `/dashboard?section=${section}`;
    window.history.replaceState(null, '', url);
  }, []);

  // Lock body scroll on dashboard — prevents double vertical scrollbar
  // Also load persisted appearance settings
  useEffect(() => {
    document.documentElement.style.overflow = 'hidden';
    document.body.style.overflow = 'hidden';
    // Apply persisted appearance from localStorage
    try {
      const saved = localStorage.getItem('ghostprompt_appearance');
      if (saved) {
        const a = JSON.parse(saved);
        const root = document.documentElement;
        if (a.theme === 'midnight') {
          root.style.setProperty('--surface-0', '2, 2, 8');
          root.style.setProperty('--surface-1', '8, 8, 16');
          root.style.setProperty('--surface-2', '14, 14, 24');
        } else if (a.theme === 'light') {
          root.classList.add('light-mode');
          root.style.setProperty('--surface-0', '240, 240, 248');
          root.style.setProperty('--surface-1', '250, 250, 255');
          root.style.setProperty('--surface-2', '255, 255, 255');
        }
        if (a.accent_color) {
          const hex = a.accent_color.replace('#', '');
          const r = parseInt(hex.substring(0, 2), 16);
          const g = parseInt(hex.substring(2, 4), 16);
          const b = parseInt(hex.substring(4, 6), 16);
          root.style.setProperty('--ghost-400', `${r}, ${g}, ${b}`);
          root.style.setProperty('--ghost-500', `${r}, ${g}, ${b}`);
        }
        const sizeMap: Record<string, string> = { sm: '14px', base: '16px', lg: '18px' };
        if (a.font_size) root.style.setProperty('font-size', sizeMap[a.font_size] || '16px');
        if (a.density === 'compact') root.style.setProperty('--density-pad', '0.5rem');
        if (a.reduced_motion) root.classList.add('reduce-motion');
        const speedMap: Record<string, string> = { none: '0ms', slow: '600ms', normal: '300ms', fast: '150ms' };
        if (a.animation_speed) root.style.setProperty('--animation-speed', speedMap[a.animation_speed] || '300ms');
      }
    } catch {}
    return () => {
      document.documentElement.style.overflow = '';
      document.body.style.overflow = '';
    };
  }, []);

  // Keyboard shortcut: ? toggles shortcuts cheat sheet
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (e.key === '?') {
        e.preventDefault();
        setShortcutsOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const [isConnected, setIsConnected] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [activePoliciesCount, setActivePoliciesCount] = useState(0);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isSuperadmin, setIsSuperadmin] = useState(false);
  const [userPlan, setUserPlan] = useState('starter');
  const [userEmail, setUserEmail] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [liveStats, setLiveStats] = useState<LiveStats>({
    total_scans: 0,
    blocked: 0,
    flagged: 0,
    allowed: 0,
    threat_categories: {},
  });
  const [recentScans, setRecentScans] = useState<ScanEvent[]>([]);
  const [threatMapData, setThreatMapData] = useState<any[]>([]);
  const [hourlyData, setHourlyData] = useState<Array<{ hour: string; scans: number; blocked: number; flagged: number }>>([]);
  const [selectedMapAttack, setSelectedMapAttack] = useState<any | null>(null);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // ⌘K / Ctrl+K shortcut for command palette
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Build hourly chart data from recent scans
  const buildHourlyData = useCallback((scans: ScanEvent[]) => {
    const hours: Record<string, { scans: number; blocked: number; flagged: number }> = {};
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
      const h = new Date(now.getTime() - i * 3600000);
      const key = h.getHours().toString().padStart(2, '0') + ':00';
      hours[key] = { scans: 0, blocked: 0, flagged: 0 };
    }
    scans.forEach((scan) => {
      const d = new Date(scan.created_at);
      const key = d.getHours().toString().padStart(2, '0') + ':00';
      if (hours[key]) {
        hours[key].scans++;
        if (scan.action === 'blocked') hours[key].blocked++;
        if (scan.action === 'flagged') hours[key].flagged++;
      }
    });
    return Object.entries(hours).map(([hour, data]) => ({ hour, ...data }));
  }, []);

  // Connect to WebSocket
  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const token = localStorage.getItem('access_token');
      const wsUrlWithToken = token ? `${WS_URL}/ws/events?token=${token}` : `${WS_URL}/ws/events`;
      const ws = new WebSocket(wsUrlWithToken);

      ws.onopen = () => {
        setIsConnected(true);
        console.log('[GhostPrompt] WebSocket connected');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          if (msg.type === 'init') {
            // Initial state from server
            setLiveStats(msg.stats);
            const scans = (msg.recent_scans || []).map((s: Record<string, unknown>, i: number) => ({
              id: (s.id as string) || String(i),
              request_id: s.request_id || `req_${i}`,
              threat_level: s.threat_level || 'safe',
              threat_score: (s.threat_score as number) || 0,
              action: s.action || 'allowed',
              scan_type: s.scan_type as string || 'prompt',
              model: s.model as string || 'unknown',
              created_at: s.created_at as string || new Date().toISOString(),
              category: (s.detections as Array<{ category: string }> || [])[0]?.category,
              prompt: s.prompt as string,
              detections: s.detections as ScanEvent['detections'],
              scan_duration_ms: s.scan_duration_ms as number,
              attacker_profile: s.attacker_profile as any,
              lat: s.lat as number,
              lng: s.lng as number,
              city: s.city as string,
              country: s.country as string,
              ip: s.ip as string,
              asn: s.asn as string,
              isp: s.isp as string,
              timezone: s.timezone as string,
              postal_code: s.postal_code as string,
              browser: s.browser as string,
              browser_full: s.browser_full as string,
              os: s.os as string,
              user_agent: s.user_agent as string,
              provider: s.provider as string,
              primary_category: s.primary_category as string || ((s.detections as Array<{ category: string }>) || [])[0]?.category,
            }));
            setRecentScans(scans);
            setHourlyData(buildHourlyData(scans));
          }

          if (msg.type === 'scan_event') {
            const s = msg.data;
            const scanEvent: ScanEvent = {
              id: s.id || String(Date.now()),
              request_id: s.request_id || `req_${Date.now().toString(36).slice(-4)}`,
              threat_level: s.threat_level || 'safe',
              threat_score: s.threat_score || 0,
              action: s.action || 'allowed',
              scan_type: s.scan_type || 'prompt',
              model: s.model || 'playground',
              created_at: s.created_at || new Date().toISOString(),
              category: (s.detections || [])[0]?.category,
              prompt: s.prompt,
              detections: s.detections,
              scan_duration_ms: s.scan_duration_ms,
              attacker_profile: s.attacker_profile || s.metadata?.attacker_profile,
              lat: s.lat,
              lng: s.lng,
              city: s.city,
              country: s.country,
              ip: s.ip,
              asn: s.asn,
              isp: s.isp,
              timezone: s.timezone,
              postal_code: s.postal_code,
              browser: s.browser,
              browser_full: s.browser_full,
              os: s.os,
              user_agent: s.user_agent,
              provider: s.provider,
              primary_category: s.primary_category || (s.detections || [])[0]?.category,
            };

            setRecentScans((prev) => [scanEvent, ...prev].slice(0, 100));
            setLiveStats(msg.stats);
            setHourlyData((prev) => {
              const updated = [...prev];
              const nowHour = new Date().getHours().toString().padStart(2, '0') + ':00';
              const idx = updated.findIndex((h) => h.hour === nowHour);
              if (idx >= 0) {
                updated[idx] = {
                  ...updated[idx],
                  scans: updated[idx].scans + 1,
                  blocked: updated[idx].blocked + (scanEvent.action === 'blocked' ? 1 : 0),
                  flagged: updated[idx].flagged + (scanEvent.action === 'flagged' ? 1 : 0),
                };
              }
              return updated;
            });
          }
        } catch (err) {
          console.error('[GhostPrompt] Failed to parse WS message:', err);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        console.log('[GhostPrompt] WebSocket disconnected, reconnecting in 3s...');
        reconnectTimeoutRef.current = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };

      wsRef.current = ws;
    } catch {
      reconnectTimeoutRef.current = setTimeout(connectWebSocket, 3000);
    }
  }, [buildHourlyData]);

  useEffect(() => {
    // Initialize hourly chart with empty data
    const hours = [];
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
      const h = new Date(now.getTime() - i * 3600000);
      hours.push({ hour: h.getHours().toString().padStart(2, '0') + ':00', scans: 0, blocked: 0, flagged: 0 });
    }
    setHourlyData(hours);

    // Check auth, billing, and policies
    const initDashboard = async () => {
      const token = localStorage.getItem('access_token');
      if (!token) {
        router.push('/auth/login');
        return;
      }
      setAuthToken(token);

      try {
        // Fetch User
        const meRes = await fetch(`${API_URL}/api/v1/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!meRes.ok) throw new Error('Unauthorized');
        const user = await meRes.json();
        setUserPlan(user.organization_plan || 'starter');
        setUserEmail(user.email || '');

        // Fetch Billing Status
        const billRes = await fetch(`${API_URL}/api/v1/billing/status`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const billing = billRes.ok ? await billRes.json() : null;

        // Admin and Superadmin definitions
        const userIsSuperadmin = user.email === 'admin@ghostprompt.dev';
        const userIsAdmin = user.role === 'owner' || user.role === 'admin' || userIsSuperadmin;
        setIsAdmin(userIsAdmin);
        setIsSuperadmin(userIsSuperadmin);

        // Only Superadmin bypasses the billing check.
        // The backend now defaults to starter, but we check if they are disabled.
        if (!userIsSuperadmin && user.is_active === false) {
          router.push('/pricing');
          return;
        }

        // Fetch active policies count
        try {
          const polRes = await fetch(`${API_URL}/api/v1/policies`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (polRes.ok) {
            const polData = await polRes.json();
            const policyList = Array.isArray(polData) ? polData : (polData.policies || []);
            setActivePoliciesCount(policyList.filter((p: any) => p.is_active).length);
          }
        } catch (e) {
          console.error("Failed to fetch policies count");
        }

        setIsCheckingAuth(false);
        // Connect WebSocket after auth checks pass
        connectWebSocket();

        // HTTP fallback: fetch recent scan events in case WS is slow or disconnected
        try {
          const evtRes = await fetch(`${API_URL}/api/v1/dashboard/events?page=1&page_size=100`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (evtRes.ok) {
            const evtData = await evtRes.json();
            const events = (evtData.events || []).map((s: any, i: number) => ({
              id: s.id || String(i),
              request_id: s.request_id || `req_${i}`,
              threat_level: s.threat_level || 'safe',
              threat_score: s.threat_score || 0,
              action: s.action || 'allowed',
              scan_type: s.scan_type || 'prompt',
              model: s.model || 'unknown',
              created_at: s.created_at || new Date().toISOString(),
              category: s.category || (s.detections || [])[0]?.category,
              prompt: s.prompt,
              detections: s.detections,
              scan_duration_ms: s.scan_duration_ms,
              attacker_profile: s.attacker_profile,
              lat: s.lat, lng: s.lng,
              city: s.city, country: s.country,
              ip: s.ip || s.source_ip,
            }));
            // Only use if WS hasn't already populated
            setRecentScans(prev => prev.length > 0 ? prev : events);
          }
        } catch (e) {
          console.error('[GhostPrompt] Failed to fetch events fallback:', e);
        }

        // Fetch threat map data (all blocked/flagged events)
        try {
          const mapRes = await fetch(`${API_URL}/api/v1/dashboard/threat-map?days=365&limit=2000`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (mapRes.ok) {
            const mapData = await mapRes.json();
            setThreatMapData(mapData.markers || []);
          }
        } catch (e) {
          console.error('[GhostPrompt] Failed to fetch threat map data:', e);
        }
      } catch (err) {
        localStorage.removeItem('access_token');
        router.push('/auth/login');
      }
    };

    initDashboard();

    return () => {
      wsRef.current?.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, [connectWebSocket]);

  // Build stats object for components
  const dashboardStats = {
    total_scans: liveStats.total_scans,
    blocked_attacks: liveStats.blocked,
    threat_events: liveStats.blocked + liveStats.flagged,
    active_policies: activePoliciesCount,
    scans_today: liveStats.total_scans,
    blocks_today: liveStats.blocked,
    avg_threat_score: liveStats.total_scans > 0
      ? recentScans.reduce((sum, s) => sum + s.threat_score, 0) / Math.max(recentScans.length, 1)
      : 0,
    evasion_caught: Object.entries(liveStats.threat_categories)
      .filter(([k]) => k.includes('encoded') || k.includes('evasion') || k.includes('obfuscation'))
      .reduce((sum, [, v]) => sum + v, 0),
    pliny_attacks: Object.entries(liveStats.threat_categories)
      .filter(([k]) => k.includes('pliny_'))
      .reduce((sum, [, v]) => sum + v, 0),
    zero_day_flags: Object.entries(liveStats.threat_categories)
      .filter(([k]) => k.includes('zero_day'))
      .reduce((sum, [, v]) => sum + v, 0),
    top_threat_categories: Object.entries(liveStats.threat_categories)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([category, count]) => ({
        category,
        count,
        percentage: liveStats.total_scans > 0 ? Math.round((count / liveStats.total_scans) * 1000) / 10 : 0,
      })),
    recent_attacks: recentScans
      .filter((s) => s.threat_level !== 'safe')
      .slice(0, 20),
    scans_over_time: hourlyData,
    threat_level_distribution: {
      safe: recentScans.filter((s) => s.threat_level === 'safe').length,
      low: recentScans.filter((s) => s.threat_level === 'low').length,
      medium: recentScans.filter((s) => s.threat_level === 'medium').length,
      high: recentScans.filter((s) => s.threat_level === 'high').length,
      critical: recentScans.filter((s) => s.threat_level === 'critical').length,
    },
  };

  if (isCheckingAuth) {
    return (
      <div className="flex h-screen items-center justify-center bg-surface-0">
        <div className="w-8 h-8 rounded-full border-2 border-ghost-500 border-t-transparent animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden bg-surface-0 relative">
      {/* Background image — pinned and heavily overlaid to prevent visual scrolling */}
      <div className="fixed inset-0 z-0 pointer-events-none" aria-hidden="true">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{ backgroundImage: "url('/bg/hacker.jpg')", opacity: 1.0 }}
        />
        <div className="absolute inset-0 bg-surface-0/10" />
        <div className="absolute inset-0 bg-gradient-to-b from-surface-0/40 via-surface-0/20 to-surface-0/60" />
      </div>
      <CyberGrid opacity={0.03} />

      <Sidebar
        activeSection={activeSection}
        onSectionChange={setActiveSection}
        liveStats={{
          scansToday: liveStats.total_scans,
          blockedToday: liveStats.blocked,
        }}
        isAdmin={isAdmin}
        isSuperadmin={isSuperadmin}
        userPlan={userPlan}
        userEmail={userEmail}
        isConnected={isConnected}
        className="relative z-10"
      />

      <main className="flex-1 overflow-y-auto relative z-10 bg-surface-0/50 backdrop-blur-xl">
        {/* ── COMMAND BAR — ELITE ── */}
        <header className="command-bar">
          <div className="flex items-center justify-between px-6 h-full">
            {/* Left: Section title + breadcrumb */}
            <div className="flex items-center gap-4">
              <motion.div
                className="flex items-center justify-center w-10 h-10 rounded-xl bg-surface-1 border border-white/[0.04] text-ghost-400 relative overflow-hidden"
                whileHover={{ scale: 1.05, borderColor: 'rgba(59,130,246,0.2)' }}
                transition={{ type: 'spring', stiffness: 400, damping: 20 }}
              >
                <div className="absolute inset-0 bg-gradient-to-br from-ghost-500/10 to-transparent" />
                <Terminal className="w-5 h-5 relative z-10" />
              </motion.div>
              <div className="flex flex-col justify-center h-full">
                <div className="flex items-center gap-2 mb-0.5 opacity-80">
                  <span className="text-[10px] font-mono text-gray-400 uppercase tracking-widest">GhostPrompt</span>
                  <span className="text-[10px] text-gray-600">/</span>
                  <span className="text-[10px] font-mono text-ghost-400 uppercase tracking-wider font-bold">Runtime_Security_&Operations</span>
                </div>
                <div className="flex items-center gap-3">
                  <motion.h1
                    key={activeSection}
                    className="text-[17px] font-bold text-white tracking-tight leading-none"
                    initial={{ opacity: 0, y: 8, filter: 'blur(4px)' }}
                    animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
                    transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                  >
                    {{
                      overview: 'Security Overview',
                      attacks: 'Attack Explorer',
                      scanner: 'Live Scanner',
                      policies: 'Security Policies',
                      models: 'Model Activity',
                      settings: 'Settings',
                      compliance: 'Compliance & Governance',
                      redteamops: 'Red Team Operations',
                      providers: 'AI Provider Gateway',
                      hallucination: 'Hallucination Detection',
                      weightscan: 'Model Weight Scanner',
                      hardware: 'Hardware Security',
                      routing: 'Routing Engine',
                      cache: 'Cache Analytics',
                      keyvault: 'Key Vault',
                      observability: 'Observability',
                      promptstudio: 'Prompt Studio',
                      mcpgateway: 'MCP Gateway',
                      integrations: 'Integrations',
                      training: 'ML Training Pipeline',
                      compliancectrl: 'Data Controls',
                      budget: 'Budget Controls',
                      network: 'Network Guardrails',
                      attribution: 'Threat Attribution',
                      analytics: 'Analytics',
                      cybermap: 'Cybermap',
                      attackflow: 'Attack Flow',
                      datasankey: 'Data Flow Sankey',
                      knowledgegraph: 'Knowledge Graph',
                      federation: 'Federated Intel',
                      adaptiveml: 'Adaptive ML',
                      custommodels: 'Models & Training',
                      billing: 'Usage & Billing',
                      playbooks: 'Playbooks',
                      briefing: 'Daily Briefing',
                      attacksurface: 'Attack Surface',
                      servicecatalog: 'Service Catalog',
                      firewallbans: 'Firewall Bans',
                      dataflowsankey: 'Data Flow Sankey',
                    }[activeSection] || activeSection}
                  </motion.h1>
                  <motion.span
                    className="w-1.5 h-1.5 rounded-full bg-ghost-500"
                    animate={{ opacity: [0.3, 1, 0.3], scale: [0.8, 1, 0.8] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                </div>
              </div>
            </div>

            {/* Right: Threat Level + Throughput + Connection */}
            <div className="flex items-center gap-2.5">
              {/* Live Throughput Ticker */}
              <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-1/60 border border-white/[0.04]">
                <span className="text-mono-xs text-gray-600 uppercase">Scans</span>
                <span className="text-xs font-mono font-bold text-white tabular-nums">{liveStats.total_scans.toLocaleString()}</span>
                <span className="text-gray-700">│</span>
                <span className="text-mono-xs text-gray-600 uppercase">Blocked</span>
                <span className="text-xs font-mono font-bold text-red-400 tabular-nums">{liveStats.blocked.toLocaleString()}</span>
              </div>

              {/* Threat Level Pill */}
              <div
                className="threat-pill"
                data-level={liveStats.blocked > 50 ? 'critical' : liveStats.blocked > 20 ? 'high' : liveStats.blocked > 5 ? 'medium' : liveStats.blocked > 0 ? 'low' : 'safe'}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${liveStats.blocked > 50 ? 'bg-red-400 animate-pulse' : liveStats.blocked > 20 ? 'bg-orange-400' : liveStats.blocked > 5 ? 'bg-amber-400' : liveStats.blocked > 0 ? 'bg-blue-400' : 'bg-emerald-400'}`} />
                {liveStats.blocked > 50 ? 'CRITICAL' : liveStats.blocked > 20 ? 'HIGH' : liveStats.blocked > 5 ? 'ELEVATED' : liveStats.blocked > 0 ? 'GUARDED' : 'NOMINAL'}
              </div>

              {/* Connection Status */}
              <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border transition-all duration-300 ${isConnected
                  ? 'bg-ghost-600/8 border-ghost-500/15'
                  : 'bg-red-500/8 border-red-500/15'
                }`}>
                <motion.span
                  className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-ghost-400' : 'bg-red-400'}`}
                  style={isConnected ? { boxShadow: '0 0 6px rgba(59,130,246,0.5)' } : {}}
                  animate={isConnected ? { scale: [1, 1.3, 1] } : {}}
                  transition={{ duration: 2, repeat: Infinity }}
                />
                <span className={`text-mono-xs uppercase ${isConnected ? 'text-ghost-400' : 'text-red-400'}`}>
                  {isConnected ? 'Live' : 'Offline'}
                </span>
              </div>

              {/* ⌘K Search */}
              <button
                onClick={() => setCommandPaletteOpen(true)}
                className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-1/60 border border-white/[0.04] hover:border-ghost-500/20 hover:shadow-glow-blue transition-all duration-300 text-gray-500 hover:text-gray-300"
              >
                <Search className="w-3.5 h-3.5" />
                <span className="text-xs">Search</span>
                <kbd className="ml-1 px-1.5 py-0.5 rounded bg-surface-2 border border-white/[0.08] text-[9px] font-mono text-gray-600">⌘K</kbd>
              </button>

              {/* Firewall Active */}
              <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-500/8 border border-emerald-500/15">
                <motion.span
                  className="w-1.5 h-1.5 rounded-full bg-emerald-400"
                  style={{ boxShadow: '0 0 6px rgba(16,185,129,0.4)' }}
                  animate={{ opacity: [1, 0.5, 1] }}
                  transition={{ duration: 3, repeat: Infinity }}
                />
                <span className="text-mono-xs text-emerald-400 uppercase">Firewall</span>
              </div>
            </div>
          </div>
        </header>

        {/* Content */}
        <div className="p-6">
            <AnimatePresence mode="wait">
              {activeSection === 'overview' && (
                <motion.div
                  key="overview"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                  className="space-y-6"
                >
                  <StatsGrid stats={dashboardStats} />
                  <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    <div className="xl:col-span-2">
                      <ThreatChart data={dashboardStats.scans_over_time} />
                    </div>
                    <div>
                      <ThreatDistribution data={dashboardStats.threat_level_distribution} />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    <div className="xl:col-span-2">
                      <GlobalThreatMap attacks={recentScans} isDashboard={true} onAttackClick={setSelectedMapAttack} />
                    </div>
                    <div className="space-y-6">
                      <TopCategories data={dashboardStats.top_threat_categories} />
                    </div>
                  </div>

                  {/* ADVANCED AI SECURITY PANELS (ROW 1) */}
                  <div className="grid grid-cols-1 xl:grid-cols-4 gap-5">
                    <div className="xl:col-span-1">
                      <MultimodalAnalytics scans={recentScans} />
                    </div>
                    <div className="xl:col-span-1">
                      <CrossLingualHeatmap scans={recentScans} />
                    </div>
                    <div className="xl:col-span-1">
                      <SupplyChainPanel scans={recentScans} />
                    </div>
                    <div className="xl:col-span-1">
                      <TokenAbuseChart scans={recentScans} />
                    </div>
                  </div>

                  {/* ADVANCED THREAT VECTORS (ROW 2 - 5 NEW MODULES) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-5">
                    <OracleAttackChart scans={recentScans} />
                    <BusinessLogicChart scans={recentScans} />
                    <MemorizationChart scans={recentScans} />
                    <TokenizerChart scans={recentScans} />
                    <IndirectInjectionChart scans={recentScans} />
                  </div>

                  {/* ATLAS MATRIX — LIVE HEAT MAP */}
                  <AtlasMatrixLive scans={recentScans} />

                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    <LiveAttackFeed attacks={dashboardStats.recent_attacks} />
                    <ModelActivity scans={recentScans} />
                  </div>
                </motion.div>
              )}

              {activeSection === 'attacks' && (
                <motion.div
                  key="attacks"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <LiveAttackFeed attacks={recentScans.filter((s) => s.threat_level !== 'safe')} fullView />
                </motion.div>
              )}

              {activeSection === 'attribution' && (
                <AttributionView recentScans={recentScans} />
              )}

              {activeSection === 'scanner' && (
                <motion.div
                  key="scanner"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ScanTester />
                </motion.div>
              )}

              {activeSection === 'policies' && (
                <motion.div
                  key="policies"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                  className="space-y-6"
                >
                  <PoliciesView />
                </motion.div>
              )}

              {activeSection === 'models' && (
                <motion.div
                  key="models"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ModelActivity fullView scans={recentScans} />
                </motion.div>
              )}

              {activeSection === 'settings' && (
                <motion.div
                  key="settings"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <SettingsView />
                </motion.div>
              )}

              {activeSection === 'compliance' && (
                <motion.div
                  key="compliance"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ComplianceView />
                </motion.div>
              )}

              {activeSection === 'providers' && (
                <motion.div
                  key="providers"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ProvidersView />
                </motion.div>
              )}

              {activeSection === 'redteamops' && (
                <motion.div
                  key="redteamops"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <RedTeamOpsView />
                </motion.div>
              )}

              {activeSection === 'hallucination' && (
                <motion.div
                  key="hallucination"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <HallucinationView />
                </motion.div>
              )}

              {activeSection === 'weightscan' && (
                <motion.div
                  key="weightscan"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ModelWeightScanView />
                </motion.div>
              )}

              {activeSection === 'hardware' && (
                <motion.div key="hardware" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <HardwareSecurityView scans={recentScans as any} />
                </motion.div>
              )}

              {activeSection === 'routing' && (
                <motion.div key="routing" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <RoutingEngineView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'cache' && (
                <motion.div key="cache" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <CacheAnalyticsView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'keyvault' && (
                <motion.div key="keyvault" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <KeyVaultView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'observability' && (
                <motion.div key="observability" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <ObservabilityView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'promptstudio' && (
                <motion.div key="promptstudio" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <PromptStudioView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'mcpgateway' && (
                <motion.div key="mcpgateway" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <MCPGatewayView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'integrations' && (
                <motion.div key="integrations" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <IntegrationsView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'compliancectrl' && (
                <motion.div key="compliancectrl" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <DataControlsView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'budget' && (
                <motion.div key="budget" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <BudgetControlsView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'network' && (
                <motion.div key="network" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <NetworkGuardsView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'federation' && (
                <motion.div key="federation" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <FederatedIntelView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'adaptiveml' && (
                <motion.div key="adaptiveml" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <AdaptiveMLView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'custommodels' && (
                <motion.div key="custommodels" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <CustomModelsView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'training' && (
                <motion.div key="training" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <TrainingDashboard token={authToken} />
                </motion.div>
              )}

              {activeSection === 'billing' && (
                <motion.div key="billing" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <SaaSBillingView token={authToken} />
                </motion.div>
              )}

              {activeSection === 'attackflow' && (
                <motion.div key="attackflow" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }} className="h-[calc(100vh-140px)]">
                  <AttackFlowCanvas recentScans={recentScans} />
                </motion.div>
              )}

              {activeSection === 'datasankey' && (
                <motion.div key="datasankey" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }} className="h-[calc(100vh-140px)]">
                  <DataFlowSankey recentScans={recentScans} />
                </motion.div>
              )}

              {activeSection === 'knowledgegraph' && (
                <motion.div key="knowledgegraph" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }} className="h-[calc(100vh-140px)]">
                  <ThreatKnowledgeGraph recentScans={recentScans} />
                </motion.div>
              )}

              {activeSection === 'analytics' && (
                <motion.div key="analytics" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <AnalyticsDashboard />
                </motion.div>
              )}

              {activeSection === 'cybermap' && (
                <motion.div key="cybermap" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.5 }} className="h-[calc(100vh-80px)] -mx-6 -mt-4">
                  <CyberMap recentScans={recentScans} liveStats={{ total_scans: liveStats.total_scans, blocked: liveStats.blocked }} />
                </motion.div>
              )}

              {activeSection === 'playbooks' && (
                <motion.div key="playbooks" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }} className="h-[calc(100vh-140px)]">
                  <PlaybookBuilderView />
                </motion.div>
              )}

              {activeSection === 'briefing' && (
                <motion.div key="briefing" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <DailyBriefingView />
                </motion.div>
              )}

              {activeSection === 'attacksurface' && (
                <motion.div key="attacksurface" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <AttackSurfaceView />
                </motion.div>
              )}

              {activeSection === 'servicecatalog' && (
                <motion.div key="servicecatalog" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <ServiceCatalogView />
                </motion.div>
              )}

              {activeSection === 'firewallbans' && (
                <motion.div key="firewallbans" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} transition={{ duration: 0.3 }}>
                  <FirewallBansView />
                </motion.div>
              )}
            </AnimatePresence>
        </div>

        <AnimatePresence>
          {selectedMapAttack && (
            <IncidentDrawer
              isOpen={true}
              attack={selectedMapAttack}
              onClose={() => setSelectedMapAttack(null)}
            />
          )}
        </AnimatePresence>

        {/* ⌘K Command Palette */}
        <CommandPalette
          isOpen={commandPaletteOpen}
          onClose={() => setCommandPaletteOpen(false)}
          onNavigate={setActiveSection}
          activeSection={activeSection}
        />

        {/* Keyboard Shortcuts Cheat Sheet */}
        <ShortcutsCheatSheet
          open={shortcutsOpen}
          onClose={() => setShortcutsOpen(false)}
        />
      </main>
    </div>
  );
}
