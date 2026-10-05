'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { Activity, Shield, AlertTriangle, Search, Settings, BarChart3, FileText, Cpu, ShieldAlert, Plug, Brain, HardDrive, Lock, Route, Database, KeyRound, Eye, Pen, Server, Link2, FileCheck, IndianRupee, Network, ChevronDown, ChevronLeft, ChevronRight, Zap, Radio, Globe, Globe2, CreditCard, Sliders, GitBranch, BarChart, Share2, LogOut, Crosshair, BookOpen, FolderOpen, Workflow, ShieldOff } from 'lucide-react';
import GhostLogo from '@/components/ui/GhostLogo';
import NotificationBell from '@/components/dashboard/NotificationBell';

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
  liveStats?: {
    scansToday: number;
    blockedToday: number;
  };
  className?: string;
  isAdmin?: boolean;
  isSuperadmin?: boolean;
  userPlan?: string;
  userEmail?: string;
  isConnected?: boolean;
}

/* ─── Unified navigation grouped by FUNCTION, not plan ─── */
const NAV_GROUPS = [
  {
    id: 'command',
    label: 'Command Center',
    accentColor: 'from-blue-500 to-indigo-600',
    items: [
      { id: 'overview', label: 'Overview', icon: BarChart3 },
      { id: 'analytics', label: 'Analytics', icon: Activity },
      { id: 'cybermap', label: 'Cybermap', icon: Globe2 },
      { id: 'scanner', label: 'Live Scanner', icon: Search },
      { id: 'attacks', label: 'Attack Explorer', icon: AlertTriangle },
      { id: 'attribution', label: 'Threat Attribution', icon: Shield },
    ],
  },
  {
    id: 'security',
    label: 'Security Engines',
    accentColor: 'from-red-500 to-rose-600',
    items: [
      { id: 'policies', label: 'Policies', icon: FileText },
      { id: 'redteamops', label: 'Red Team Ops', icon: ShieldAlert },
      { id: 'hallucination', label: 'Hallucination Det.', icon: Brain },
      { id: 'weightscan', label: 'Model Scanner', icon: HardDrive },
      { id: 'federation', label: 'Federated Intel', icon: Globe },
      { id: 'adaptiveml', label: 'Adaptive ML', icon: Sliders },
      { id: 'attackflow', label: 'Attack Flow', icon: GitBranch },
      { id: 'datasankey', label: 'Data Flow Sankey', icon: BarChart },
      { id: 'knowledgegraph', label: 'Knowledge Graph', icon: Share2 },
      { id: 'attacksurface', label: 'Attack Surface', icon: Crosshair },
    ],
  },
  {
    id: 'platform',
    label: 'AI Gateway',
    accentColor: 'from-cyan-500 to-blue-600',
    items: [
      { id: 'routing', label: 'Routing Engine', icon: Route },
      { id: 'cache', label: 'Cache Analytics', icon: Database },
      { id: 'observability', label: 'Observability', icon: Eye },
      { id: 'promptstudio', label: 'Prompt Studio', icon: Pen },
      { id: 'mcpgateway', label: 'MCP Gateway', icon: Server },
      { id: 'providers', label: 'AI Providers', icon: Plug },
      { id: 'integrations', label: 'Integrations', icon: Link2 },
      { id: 'custommodels', label: 'Models & Training', icon: Cpu },
      { id: 'servicecatalog', label: 'Service Catalog', icon: FolderOpen },
    ],
  },
  {
    id: 'governance',
    label: 'Governance',
    accentColor: 'from-emerald-500 to-teal-600',
    items: [
      { id: 'compliance', label: 'Compliance & Governance', icon: FileCheck },
      { id: 'keyvault', label: 'Key Vault', icon: KeyRound },
      { id: 'budget', label: 'Budget Controls', icon: IndianRupee },
      { id: 'network', label: 'Network Guards', icon: Network },
      { id: 'compliancectrl', label: 'Data Controls', icon: FileCheck },
      { id: 'billing', label: 'Usage & Billing', icon: CreditCard },
    ],
  },
  {
    id: 'ops',
    label: 'Operations',
    accentColor: 'from-amber-500 to-orange-600',
    items: [
      { id: 'playbooks', label: 'Playbooks', icon: Workflow },
      { id: 'briefing', label: 'Daily Briefing', icon: BookOpen },
      { id: 'firewallbans', label: 'Firewall Bans', icon: ShieldOff },
    ],
  },
  {
    id: 'system',
    label: 'System',
    accentColor: 'from-gray-500 to-gray-600',
    items: [
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

function formatNumber(n: number): string {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n.toString();
}

export default function Sidebar({ activeSection, onSectionChange, liveStats, className = '', isAdmin = false, isSuperadmin = false, userPlan = 'starter', userEmail = '', isConnected = false }: SidebarProps) {
  const router = useRouter();
  const scans = liveStats?.scansToday ?? 0;
  const blocked = liveStats?.blockedToday ?? 0;
  const [collapsed, setCollapsed] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    router.push('/auth/login');
  };

  // Find which group contains the active section so it auto-opens
  const activeGroupId = NAV_GROUPS.find(g => g.items.some(i => i.id === activeSection))?.id || 'command';
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    command: true,
    security: activeGroupId === 'security',
    platform: activeGroupId === 'platform',
    governance: activeGroupId === 'governance',
  });

  const toggleGroup = (groupId: string) => {
    if (collapsed) return; // Don't toggle in collapsed mode
    setOpenGroups(prev => ({ ...prev, [groupId]: !prev[groupId] }));
  };

  // Auto-open group when a section inside it is clicked
  const handleSectionChange = (sectionId: string) => {
    const group = NAV_GROUPS.find(g => g.items.some(i => i.id === sectionId));
    if (group && !openGroups[group.id]) {
      setOpenGroups(prev => ({ ...prev, [group.id]: true }));
    }
    onSectionChange(sectionId);
  };

  // Keyboard shortcut: [ to toggle sidebar
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === '[' && !e.ctrlKey && !e.metaKey && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) {
        setCollapsed(prev => !prev);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const sidebarWidth = collapsed ? 'w-[64px]' : 'w-[250px]';

  return (
    <aside className={`${sidebarWidth} flex-shrink-0 border-r border-white/[0.06] bg-surface-0/98 backdrop-blur-2xl flex flex-col transition-all duration-300 ease-expo-out relative ${className}`}>
      {/* Subtle gradient overlay for depth */}
      <div className="absolute inset-0 bg-gradient-to-b from-ghost-600/[0.02] via-transparent to-transparent pointer-events-none" />
      
      {/* Scanline texture */}
      <div className="scanline-overlay opacity-[0.01]" />

      {/* Animated gradient line on left edge */}
      <div className="absolute top-0 left-0 bottom-0 w-px overflow-hidden">
        <motion.div
          className="w-full h-20 bg-gradient-to-b from-transparent via-ghost-500/30 to-transparent"
          animate={{ y: ['-100%', '500%'] }}
          transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
        />
      </div>

      {/* Collapse Toggle */}
      <button
        onClick={() => setCollapsed(prev => !prev)}
        className="absolute -right-3 top-20 z-20 w-6 h-6 rounded-full bg-surface-2 border border-white/[0.08] flex items-center justify-center text-gray-500 hover:text-white hover:border-ghost-500/30 transition-all duration-200 shadow-enterprise-sm hover:shadow-glow-blue"
        title={collapsed ? 'Expand sidebar [' : 'Collapse sidebar ['}
      >
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
      </button>

      {/* Logo */}
      <div className={`px-4 py-4 border-b border-white/[0.06] ${collapsed ? 'flex justify-center' : ''} relative`}>
        <Link href="/" className="flex flex-col gap-0.5 group cursor-pointer">
          {collapsed ? (
            <motion.div
              className="w-8 h-8 rounded-lg bg-gradient-to-br from-ghost-500 to-cyber-600 flex items-center justify-center shadow-neon-blue"
              whileHover={{ scale: 1.1, rotate: 5 }}
              transition={{ type: 'spring', stiffness: 400, damping: 15 }}
            >
              <Shield className="w-4 h-4 text-white" />
            </motion.div>
          ) : (
            <>
              <GhostLogo className="text-base transition-opacity group-hover:opacity-80" />
              <p className="text-[9px] uppercase tracking-[0.2em] text-white/30 font-semibold ml-11 group-hover:text-white/50 transition-colors font-mono">Security & Operations</p>
            </>
          )}
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-2 space-y-0.5 overflow-y-auto scrollbar-none relative z-10">
        {NAV_GROUPS.map((group) => {
          const isOpen = openGroups[group.id] ?? false;
          const hasActiveChild = group.items.some(i => i.id === activeSection);

          return (
            <div key={group.id} className="mb-0.5">
              {/* Group Header — collapsible */}
              {!collapsed && (
                <button
                  onClick={() => toggleGroup(group.id)}
                  className={`w-full flex items-center justify-between px-3 py-1.5 rounded-md text-label-sm uppercase tracking-[0.12em] transition-all duration-200 group/header ${hasActiveChild ? 'text-ghost-400' : 'text-gray-600 hover:text-gray-400'}`}
                >
                  <div className="flex items-center gap-2">
                    <motion.div
                      className={`w-1 h-1 rounded-full bg-gradient-to-r ${group.accentColor}`}
                      animate={{ opacity: hasActiveChild ? 1 : 0.3, scale: hasActiveChild ? 1 : 0.8 }}
                    />
                    <span>{group.label}</span>
                  </div>
                  <motion.div
                    animate={{ rotate: isOpen ? 0 : -90 }}
                    transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
                  >
                    <ChevronDown className="w-3 h-3" />
                  </motion.div>
                </button>
              )}

              {/* Group Items */}
              <AnimatePresence initial={false}>
                {(collapsed || isOpen) && (
                  <motion.div
                    initial={collapsed ? false : { height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                    className="overflow-hidden"
                  >
                    {group.items.map((item) => {
                      const Icon = item.icon;
                      const isActive = activeSection === item.id;

                      if (collapsed) {
                        return (
                          <button
                            key={item.id}
                            onClick={() => handleSectionChange(item.id)}
                            className={`w-full flex items-center justify-center py-2.5 rounded-lg transition-all duration-200 group/item relative ${
                              isActive
                                ? 'text-ghost-400 bg-ghost-600/10'
                                : 'text-gray-500 hover:text-gray-300 hover:bg-white/[0.03]'
                            }`}
                            title={item.label}
                            style={isActive ? { boxShadow: 'inset 2px 0 0 0 #3b82f6' } : {}}
                          >
                            <Icon className="w-4 h-4" />
                            {/* Tooltip */}
                            <div className="absolute left-full ml-2 px-2 py-1 bg-surface-2 border border-white/10 rounded text-xs text-white whitespace-nowrap opacity-0 group-hover/item:opacity-100 transition-opacity pointer-events-none z-50 shadow-enterprise-md">
                              {item.label}
                            </div>
                          </button>
                        );
                      }

                      return (
                        <motion.button
                          key={item.id}
                          onClick={() => handleSectionChange(item.id)}
                          className={`w-full nav-link ${isActive ? 'nav-link-active' : ''}`}
                          whileHover={{ x: 2 }}
                          whileTap={{ scale: 0.98 }}
                          transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                        >
                          <Icon className={`w-[15px] h-[15px] flex-shrink-0 transition-colors duration-200 ${isActive ? 'text-ghost-400' : ''}`} />
                          <span className="truncate">{item.label}</span>
                          {item.id === 'attacks' && blocked > 0 && (
                            <motion.span
                              className="ml-auto text-mono-xs px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-mono font-semibold"
                              initial={{ scale: 0.8 }}
                              animate={{ scale: 1 }}
                              transition={{ type: 'spring', stiffness: 500 }}
                            >
                              {blocked}
                            </motion.span>
                          )}
                        </motion.button>
                      );
                    })}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </nav>

      {/* Bottom: Uplink Indicator + Stats + User */}
      {!collapsed && (
        <div className="relative z-10">
          {/* Uplink / Connection Status */}
          <div className="px-3 py-2">
            <div className="uplink-indicator" data-connected={isConnected ? 'true' : 'false'}>
              <motion.span
                className={`uplink-dot w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-ghost-400' : 'bg-red-400'}`}
                style={isConnected ? { boxShadow: '0 0 6px rgba(59,130,246,0.5)' } : {}}
                animate={isConnected ? { scale: [1, 1.3, 1], opacity: [1, 0.6, 1] } : {}}
                transition={{ duration: 2, repeat: Infinity }}
              />
              <span className={isConnected ? 'text-ghost-400/80' : 'text-red-400/80'}>
                {isConnected ? '● SECURE' : '○ OFFLINE'}
              </span>
              {isConnected && scans > 0 && (
                <span className="ml-auto text-gray-600">{formatNumber(scans)} evt</span>
              )}
            </div>
          </div>

          {/* Live Stats */}
          <div className="px-3 py-2 border-t border-white/[0.04]">
            <div className="glass-card p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-label-sm uppercase tracking-wider text-gray-600">Live Telemetry</span>
                <motion.div
                  animate={{ opacity: [0.3, 1, 0.3] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <Activity className="w-3 h-3 text-ghost-400/50" />
                </motion.div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <p className="text-lg font-bold text-white font-mono tracking-tight">{formatNumber(scans)}</p>
                  <p className="text-mono-xs text-gray-600 uppercase">Scans</p>
                </div>
                <div>
                  <p className="text-lg font-bold text-red-400 font-mono tracking-tight">{formatNumber(blocked)}</p>
                  <p className="text-mono-xs text-gray-600 uppercase">Blocked</p>
                </div>
              </div>
            </div>
          </div>

          {/* User */}
          <div className="px-3 py-3 border-t border-white/[0.04]">
            <div className="flex items-center gap-2.5">
              <motion.div
                className="w-7 h-7 rounded-lg bg-gradient-to-br from-ghost-500 to-cyber-600 flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0 relative"
                whileHover={{ scale: 1.1 }}
                transition={{ type: 'spring', stiffness: 400 }}
              >
                {userEmail.slice(0, 2).toUpperCase()}
                {/* Online ring */}
                <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-surface-0" />
              </motion.div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-gray-300 truncate capitalize">{userPlan}</p>
                <p className="text-mono-xs text-gray-600 truncate">{userEmail}</p>
              </div>
              <NotificationBell />
              <button onClick={handleLogout} className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-white/5 rounded-lg transition-colors" title="Log Out">
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          </div>
          
          {/* Super Admin Switch */}
          {isSuperadmin && (
            <div className="px-3 pb-3">
              <a href="/superadmin" className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-red-500/8 hover:bg-red-500/15 text-red-400 border border-red-500/20 rounded-lg transition-all text-xs font-bold tracking-wide font-mono uppercase">
                <ShieldAlert className="w-3.5 h-3.5" />
                Super Admin
              </a>
            </div>
          )}
        </div>
      )}

      {/* Collapsed bottom: minimal icons */}
      {collapsed && (
        <div className="px-2 py-3 border-t border-white/[0.04] flex flex-col items-center gap-2 relative z-10">
          {/* Connection dot */}
          <motion.div
            className={`w-2 h-2 rounded-full ${isConnected ? 'bg-ghost-400' : 'bg-red-400'}`}
            style={isConnected ? { boxShadow: '0 0 6px rgba(59,130,246,0.5)' } : {}}
            animate={isConnected ? { scale: [1, 1.3, 1] } : {}}
            transition={{ duration: 2, repeat: Infinity }}
          />
          {/* Notifications */}
          <NotificationBell />
          {/* User avatar */}
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-ghost-500 to-cyber-600 flex items-center justify-center text-[10px] font-bold text-white">
            {userEmail.slice(0, 2).toUpperCase()}
          </div>
          {isSuperadmin && (
            <a href="/superadmin" className="w-7 h-7 flex items-center justify-center rounded-lg bg-red-500/10 border border-red-500/20 text-red-400" title="Super Admin">
              <ShieldAlert className="w-3.5 h-3.5" />
            </a>
          )}
          {/* Logout button */}
          <div className="mt-1 pt-2 border-t border-white/10 w-full flex justify-center">
            <button onClick={handleLogout} className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-white/5 text-gray-500 hover:text-red-400 transition-colors" title="Log Out">
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}
