'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, BarChart3, AlertTriangle, Shield, FileText, ShieldAlert, Brain,
  HardDrive, FileCheck, Route, Database, Eye, Pen, Server, Plug, Link2,
  KeyRound, IndianRupee, Network, Settings, Cpu, Command, ArrowRight,
  Zap, Globe, Activity
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (section: string) => void;
  activeSection: string;
}

const COMMANDS = [
  { id: 'overview', label: 'Security Overview', icon: BarChart3, group: 'Navigation', keywords: 'dashboard home stats' },
  { id: 'scanner', label: 'Live Scanner', icon: Search, group: 'Navigation', keywords: 'scan test prompt' },
  { id: 'attacks', label: 'Attack Explorer', icon: AlertTriangle, group: 'Navigation', keywords: 'threats incidents logs' },
  { id: 'attribution', label: 'Threat Attribution', icon: Shield, group: 'Navigation', keywords: 'actors campaigns' },
  { id: 'policies', label: 'Security Policies', icon: FileText, group: 'Security', keywords: 'rules config' },
  { id: 'redteamops', label: 'Red Team Operations', icon: ShieldAlert, group: 'Security', keywords: 'pentest simulate attack' },
  { id: 'hallucination', label: 'Hallucination Detection', icon: Brain, group: 'Security', keywords: 'factual accuracy' },
  { id: 'weightscan', label: 'Model Weight Scanner', icon: HardDrive, group: 'Security', keywords: 'integrity verify' },
  { id: 'compliance', label: 'Compliance Reports', icon: FileCheck, group: 'Security', keywords: 'soc2 hipaa gdpr eu' },
  { id: 'routing', label: 'Routing Engine', icon: Route, group: 'Platform', keywords: 'loadbalancer failover' },
  { id: 'cache', label: 'Cache Analytics', icon: Database, group: 'Platform', keywords: 'semantic cache ttl' },
  { id: 'observability', label: 'Observability', icon: Eye, group: 'Platform', keywords: 'traces metrics latency' },
  { id: 'promptstudio', label: 'Prompt Studio', icon: Pen, group: 'Platform', keywords: 'template version ab test' },
  { id: 'mcpgateway', label: 'MCP Gateway', icon: Server, group: 'Platform', keywords: 'model context protocol' },
  { id: 'providers', label: 'AI Providers', icon: Plug, group: 'Platform', keywords: 'openai anthropic google' },
  { id: 'integrations', label: 'Integrations', icon: Link2, group: 'Platform', keywords: 'langchain llamaindex sdk' },
  { id: 'keyvault', label: 'Key Vault', icon: KeyRound, group: 'Governance', keywords: 'api keys secrets' },
  { id: 'budget', label: 'Budget Controls', icon: IndianRupee, group: 'Governance', keywords: 'cost spend limits' },
  { id: 'network', label: 'Network Guardrails', icon: Network, group: 'Governance', keywords: 'ip firewall geo' },
  { id: 'settings', label: 'Settings', icon: Settings, group: 'Governance', keywords: 'account preferences' },
];

export default function CommandPalette({ isOpen, onClose, onNavigate, activeSection }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showTooltip, setShowTooltip] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Filter commands
  const filtered = useMemo(() => {
    if (!query.trim()) return COMMANDS;
    const q = query.toLowerCase();
    return COMMANDS.filter(
      c => c.label.toLowerCase().includes(q) ||
           c.group.toLowerCase().includes(q) ||
           c.keywords.includes(q) ||
           c.id.includes(q)
    );
  }, [query]);

  // Group by category
  const grouped = useMemo(() => {
    const groups: Record<string, typeof COMMANDS> = {};
    filtered.forEach(cmd => {
      if (!groups[cmd.group]) groups[cmd.group] = [];
      groups[cmd.group].push(cmd);
    });
    return groups;
  }, [filtered]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);

      // First run tooltip
      const hasSeen = localStorage.getItem('ghostprompt_cmd_tooltip_seen');
      if (!hasSeen) {
        setShowTooltip(true);
        localStorage.setItem('ghostprompt_cmd_tooltip_seen', 'true');
        setTimeout(() => setShowTooltip(false), 6000);
      }
    } else {
      setShowTooltip(false);
    }
  }, [isOpen]);

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return;

    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => Math.min(prev + 1, filtered.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filtered[selectedIndex]) {
          onNavigate(filtered[selectedIndex].id);
          onClose();
        }
      } else if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, filtered, selectedIndex, onNavigate, onClose]);

  // Scroll selected item into view
  useEffect(() => {
    if (listRef.current) {
      const selectedEl = listRef.current.querySelector(`[data-index="${selectedIndex}"]`);
      selectedEl?.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  // Reset index when query changes
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  if (!isOpen) return null;

  let flatIndex = 0;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.15 }}
        className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]"
        onClick={onClose}
      >
        {/* Backdrop */}
        <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

        {/* Palette */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: -10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: -10 }}
          transition={{ duration: 0.2, ease: [0.25, 0.46, 0.45, 0.94] }}
          className="relative w-full max-w-lg rounded-xl overflow-hidden"
          style={{
            background: 'rgba(10, 16, 32, 0.95)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            boxShadow: '0 25px 50px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(59, 130, 246, 0.1), inset 0 1px 0 rgba(255,255,255,0.05)',
          }}
          onClick={e => e.stopPropagation()}
        >
          {/* First Run Tooltip */}
          <AnimatePresence>
            {showTooltip && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="absolute -top-12 left-1/2 -translate-x-1/2 bg-ghost-600 text-white text-xs font-semibold px-4 py-2 rounded shadow-2xl whitespace-nowrap flex items-center gap-2 border border-ghost-500/50 z-50"
              >
                <Zap className="w-3 h-3 text-amber-300" />
                Pro Tip: Press <kbd className="px-1 py-0.5 rounded bg-white/20 text-[10px] font-mono">⌘K</kbd> or <kbd className="px-1 py-0.5 rounded bg-white/20 text-[10px] font-mono">Ctrl+K</kbd> anywhere to open
                <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 border-4 border-transparent border-t-ghost-600" />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Search Input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-white/[0.06]">
            <Search className="w-4 h-4 text-gray-500 flex-shrink-0" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search commands..."
              className="flex-1 bg-transparent text-sm text-white placeholder-gray-500 outline-none"
            />
            <kbd className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface-2 border border-white/[0.08] text-[10px] text-gray-500 font-mono">
              ESC
            </kbd>
          </div>

          {/* Results */}
          <div ref={listRef} className="max-h-[360px] overflow-y-auto py-2 scrollbar-none">
            {filtered.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <p className="text-sm text-gray-500">No commands found</p>
                <p className="text-xs text-gray-600 mt-1">Try a different search term</p>
              </div>
            ) : (
              Object.entries(grouped).map(([group, items]) => (
                <div key={group}>
                  <div className="px-4 py-1.5">
                    <span className="text-[10px] font-semibold text-gray-600 uppercase tracking-wider">{group}</span>
                  </div>
                  {items.map(cmd => {
                    const idx = flatIndex++;
                    const Icon = cmd.icon;
                    const isSelected = idx === selectedIndex;
                    const isActive = cmd.id === activeSection;

                    return (
                      <button
                        key={cmd.id}
                        data-index={idx}
                        onClick={() => {
                          onNavigate(cmd.id);
                          onClose();
                        }}
                        onMouseEnter={() => setSelectedIndex(idx)}
                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                          isSelected
                            ? 'bg-ghost-600/15 text-white'
                            : 'text-gray-400 hover:text-gray-200'
                        }`}
                      >
                        <Icon className={`w-4 h-4 flex-shrink-0 ${isSelected ? 'text-ghost-400' : 'text-gray-500'}`} />
                        <span className="text-sm flex-1">{cmd.label}</span>
                        {isActive && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-ghost-600/20 text-ghost-400 font-mono font-bold">
                            ACTIVE
                          </span>
                        )}
                        {isSelected && (
                          <ArrowRight className="w-3 h-3 text-ghost-400" />
                        )}
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t border-white/[0.06] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-surface-2 border border-white/[0.08] text-[9px] text-gray-500 font-mono">↑↓</kbd>
                <span className="text-[10px] text-gray-600">Navigate</span>
              </div>
              <div className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 rounded bg-surface-2 border border-white/[0.08] text-[9px] text-gray-500 font-mono">↵</kbd>
                <span className="text-[10px] text-gray-600">Select</span>
              </div>
            </div>
            <span className="text-[10px] text-gray-600 font-mono">{filtered.length} commands</span>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
