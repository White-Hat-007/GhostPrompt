'use client';

import { useRef, useEffect, useState, useCallback } from 'react';
import { Shield, AlertTriangle, Activity, BarChart3, Terminal, TrendingUp, Zap, Lock } from 'lucide-react';
import StatusPulse from '../ui/StatusPulse';

/* ─── Panel data — preserved from original ─── */
interface PanelData {
  id: string;
  title: string;
  subtitle: string;
  type: 'threat-feed' | 'policy-dashboard' | 'attack-explorer' | 'metrics' | 'agent-log';
}

const CAROUSEL_PANELS: PanelData[] = [
  { id: 'threat-feed', title: 'Threat Detection', subtitle: 'Real-Time Feed', type: 'threat-feed' },
  { id: 'policy-dashboard', title: 'Policy Engine', subtitle: '19 Active Policies', type: 'policy-dashboard' },
  { id: 'attack-explorer', title: 'Attack Explorer', subtitle: 'Campaign Forensics', type: 'attack-explorer' },
  { id: 'metrics', title: 'Security Metrics', subtitle: 'Global Overview', type: 'metrics' },
  { id: 'agent-log', title: 'Agent Activity', subtitle: 'Tool Call Monitor', type: 'agent-log' },
];

/* ─── Main Component: Infinite Auto-Scrolling Marquee ─── */
export default function HeroCarousel() {
  const trackRef = useRef<HTMLDivElement>(null);
  const animationRef = useRef<number>(0);
  const offsetRef = useRef(0);
  const speedRef = useRef(0.35); // px per frame — silky slow
  const isPausedRef = useRef(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const wheelVelocityRef = useRef(0);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  useEffect(() => {
    setPrefersReducedMotion(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);

  // Infinite marquee animation loop — also applies wheel velocity when paused
  useEffect(() => {
    if (prefersReducedMotion) return;

    const track = trackRef.current;
    if (!track) return;

    const animate = () => {
      const singleSetWidth = track.scrollWidth / 2;

      if (!isPausedRef.current) {
        // Auto-scroll when not hovered
        offsetRef.current -= speedRef.current;
      } else {
        // Apply wheel velocity when hovered (user scrolling)
        offsetRef.current += wheelVelocityRef.current;
        wheelVelocityRef.current *= 0.92; // friction decay

        // Stop tiny residual movement
        if (Math.abs(wheelVelocityRef.current) < 0.05) {
          wheelVelocityRef.current = 0;
        }
      }

      // Wrap offset for seamless infinite loop in both directions
      if (offsetRef.current <= -singleSetWidth) {
        offsetRef.current += singleSetWidth;
      } else if (offsetRef.current > 0) {
        offsetRef.current -= singleSetWidth;
      }

      track.style.transform = `translate3d(${offsetRef.current}px, 0, 0)`;
      animationRef.current = requestAnimationFrame(animate);
    };

    animationRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationRef.current);
  }, [prefersReducedMotion]);

  // Wheel handler — converts vertical scroll into horizontal carousel movement
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const handleWheel = (e: WheelEvent) => {
      if (!isPausedRef.current) return; // only when hovering

      // Prevent the page from scrolling vertically
      e.preventDefault();

      // Scroll up (negative deltaY) → move track left (reveal right panels)
      // Scroll down (positive deltaY) → move track right (reveal left panels)
      wheelVelocityRef.current -= e.deltaY * 0.8;
    };

    container.addEventListener('wheel', handleWheel, { passive: false });
    return () => container.removeEventListener('wheel', handleWheel);
  }, []);

  // Pause on hover, resume on leave
  const handleMouseEnter = useCallback(() => {
    isPausedRef.current = true;
  }, []);

  const handleMouseLeave = useCallback(() => {
    isPausedRef.current = false;
    wheelVelocityRef.current = 0;
    setHoveredIndex(null);
  }, []);

  // Duplicate panels for seamless infinite loop
  const allPanels = [...CAROUSEL_PANELS, ...CAROUSEL_PANELS];

  return (
    <div
      ref={containerRef}
      className="w-full relative overflow-hidden"
      role="region"
      aria-roledescription="carousel"
      aria-label="Product feature panels"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {/* Edge fade masks — premium gradient dissolve */}
      <div className="pointer-events-none absolute left-0 top-0 bottom-0 w-32 z-20"
        style={{ background: 'linear-gradient(to right, rgba(2,6,23,1) 0%, transparent 100%)' }}
      />
      <div className="pointer-events-none absolute right-0 top-0 bottom-0 w-32 z-20"
        style={{ background: 'linear-gradient(to left, rgba(2,6,23,1) 0%, transparent 100%)' }}
      />

      {/* Scrolling track */}
      <div
        ref={trackRef}
        className="flex gap-5 py-4 will-change-transform"
        style={{ width: 'max-content' }}
      >
        {allPanels.map((panel, i) => (
          <CarouselCard
            key={`${panel.id}-${i}`}
            panel={panel}
            index={i}
            isHovered={hoveredIndex === i}
            onHover={() => setHoveredIndex(i)}
          />
        ))}
      </div>

      {/* Subtle glow line beneath the carousel */}
      <div className="absolute bottom-0 left-[10%] right-[10%] h-px z-10"
        style={{
          background: 'linear-gradient(90deg, transparent, rgba(59,130,246,0.25) 30%, rgba(6,182,212,0.2) 70%, transparent)',
        }}
      />
    </div>
  );
}

/* ─── Individual Carousel Card ─── */
interface CarouselCardProps {
  panel: PanelData;
  index: number;
  isHovered: boolean;
  onHover: () => void;
}

function CarouselCard({ panel, index, isHovered, onHover }: CarouselCardProps) {
  return (
    <div
      className="flex-shrink-0 w-[380px] group cursor-default"
      onMouseEnter={onHover}
      style={{
        transform: isHovered ? 'translateY(-6px) scale(1.02)' : 'translateY(0) scale(1)',
        transition: 'transform 500ms cubic-bezier(0.16, 1, 0.3, 1)',
      }}
    >
      <div
        className="h-[260px] rounded-2xl overflow-hidden select-none relative"
        style={{
          background: 'linear-gradient(160deg, rgba(15, 23, 42, 0.95) 0%, rgba(2, 6, 23, 0.98) 100%)',
          border: isHovered
            ? '1px solid rgba(59, 130, 246, 0.2)'
            : '1px solid rgba(255, 255, 255, 0.06)',
          boxShadow: isHovered
            ? '0 20px 60px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(59, 130, 246, 0.08) inset, 0 0 40px rgba(59, 130, 246, 0.04)'
            : '0 4px 24px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.03) inset',
          transition: 'border-color 500ms ease, box-shadow 500ms ease',
        }}
      >
        {/* Ambient corner glow on hover */}
        <div
          className="absolute -top-20 -right-20 w-40 h-40 rounded-full pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 70%)',
            opacity: isHovered ? 1 : 0,
            transition: 'opacity 500ms ease',
          }}
        />

        {/* Panel header — enterprise chrome bar */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.04] relative z-10">
          <div className="flex items-center gap-2.5">
            <PanelIcon type={panel.type} />
            <span className="text-[11px] font-semibold text-white/90 tracking-wide">{panel.title}</span>
          </div>
          <div className="flex items-center gap-2">
            <StatusPulse color="hacker" size={5} />
            <span className="text-[9px] font-mono text-white/30 uppercase tracking-widest">{panel.subtitle}</span>
          </div>
        </div>

        {/* Panel content */}
        <div className="p-4 h-[calc(100%-44px)] relative z-10">
          <PanelContent type={panel.type} />
        </div>
      </div>
    </div>
  );
}

/* ─── Icons ─── */
function PanelIcon({ type }: { type: PanelData['type'] }) {
  const base = 'w-3.5 h-3.5';
  switch (type) {
    case 'threat-feed': return <AlertTriangle className={`${base} text-red-400`} />;
    case 'policy-dashboard': return <Shield className={`${base} text-ghost-400`} />;
    case 'attack-explorer': return <Activity className={`${base} text-amber-400`} />;
    case 'metrics': return <BarChart3 className={`${base} text-cyber-400`} />;
    case 'agent-log': return <Terminal className={`${base} text-hacker`} />;
  }
}

/* ─── Panel Content: Realistic Product Surfaces (preserved) ─── */
function PanelContent({ type }: { type: PanelData['type'] }) {
  switch (type) {
    case 'threat-feed': return <ThreatFeedContent />;
    case 'policy-dashboard': return <PolicyDashboardContent />;
    case 'attack-explorer': return <AttackExplorerContent />;
    case 'metrics': return <MetricsContent />;
    case 'agent-log': return <AgentLogContent />;
  }
}

/* ─── Threat Feed ─── */
function ThreatFeedContent() {
  const threats = [
    { time: '00:03s', type: 'prompt_injection', severity: 'critical', action: 'BLOCKED' },
    { time: '00:07s', type: 'jailbreak_attempt', severity: 'high', action: 'BLOCKED' },
    { time: '00:12s', type: 'pii_leak', severity: 'medium', action: 'REDACTED' },
    { time: '00:18s', type: 'base64_payload', severity: 'high', action: 'BLOCKED' },
    { time: '00:24s', type: 'role_play_exploit', severity: 'critical', action: 'BLOCKED' },
  ];
  return (
    <div className="space-y-[6px] text-[10px] font-mono">
      <div className="flex items-center gap-2 mb-2 px-1">
        <div className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
        <span className="text-[9px] text-red-400/70 uppercase tracking-widest font-semibold">Live Feed</span>
      </div>
      {threats.map((t, i) => (
        <div key={i} className="flex items-center gap-2 px-3 py-[6px] rounded-lg bg-white/[0.02] border border-white/[0.03] hover:bg-white/[0.04] transition-colors">
          <span className="text-white/20 w-10 tabular-nums">{t.time}</span>
          <span className="text-white/60 flex-1 truncate">{t.type}</span>
          <SeverityBadge severity={t.severity} />
          <span className={`text-[9px] font-bold ${t.action === 'BLOCKED' ? 'text-red-400' : 'text-amber-400'}`}>
            {t.action}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ─── Policy Dashboard ─── */
function PolicyDashboardContent() {
  const policies = [
    { name: 'Injection Detection', triggers: 847, active: true },
    { name: 'Jailbreak Prevention', triggers: 312, active: true },
    { name: 'PII Redaction', triggers: 1204, active: true },
    { name: 'Rate Limiting', triggers: 56, active: true },
    { name: 'Content Filtering', triggers: 423, active: true },
  ];
  return (
    <div className="space-y-[6px] text-[10px]">
      <div className="flex items-center justify-between px-1 mb-2">
        <span className="text-[9px] text-white/30 uppercase tracking-widest font-semibold">Active Rules</span>
        <span className="text-[9px] font-mono text-hacker tabular-nums">{policies.length}/{policies.length}</span>
      </div>
      {policies.map((p, i) => (
        <div key={i} className="flex items-center gap-2.5 px-3 py-[6px] rounded-lg bg-white/[0.02] border border-white/[0.03]">
          <div className="w-1.5 h-1.5 rounded-full bg-hacker flex-shrink-0 shadow-[0_0_6px_rgba(0,255,100,0.3)]" />
          <span className="text-white/60 flex-1 font-medium">{p.name}</span>
          <div className="flex items-center gap-1">
            <TrendingUp className="w-2.5 h-2.5 text-hacker/40" />
            <span className="text-white/25 font-mono tabular-nums text-[9px]">{p.triggers.toLocaleString()}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Attack Explorer ─── */
function AttackExplorerContent() {
  return (
    <div className="h-full flex flex-col gap-2.5">
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/[0.06] border border-red-500/10">
        <div className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
        <span className="text-[10px] font-mono text-red-300/80 font-semibold">Campaign: SHADOW-PROMPT-7</span>
        <span className="ml-auto text-[8px] font-mono text-red-400/40 uppercase">Active</span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        <MetricBox label="Sessions" value="23" />
        <MetricBox label="Vectors" value="7" />
        <MetricBox label="Duration" value="4h 12m" />
      </div>
      <div className="flex-1 px-3 py-2 rounded-lg bg-white/[0.02] border border-white/[0.03] text-[9px] font-mono text-white/25 leading-relaxed">
        <div className="text-white/40 mb-1">Attack Chain:</div>
        <span className="text-amber-400/50">semantic_grooming</span>
        <span className="text-white/15"> → </span>
        <span className="text-amber-400/50">role_play</span>
        <span className="text-white/15"> → </span>
        <span className="text-red-400/50">authority_escalation</span>
        <span className="text-white/15"> → </span>
        <span className="text-red-400/60">payload_delivery</span>
      </div>
    </div>
  );
}

/* ─── Metrics Dashboard ─── */
function MetricsContent() {
  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-2.5">
        <MetricCard label="Scans Today" value="14,847" trend="+12%" positive />
        <MetricCard label="Threats Blocked" value="342" trend="+8%" positive />
        <MetricCard label="Avg Latency" value="8.2ms" trend="-3%" positive={false} />
        <MetricCard label="Detection Rate" value="99.7%" trend="+0.1%" positive />
      </div>
      {/* Mini sparkline bar */}
      <div className="flex items-end gap-[2px] px-2 h-5">
        {[35, 42, 38, 55, 48, 62, 70, 58, 75, 68, 82, 90, 78, 85, 92, 88, 95].map((h, i) => (
          <div
            key={i}
            className="flex-1 rounded-sm"
            style={{
              height: `${h}%`,
              background: `linear-gradient(to top, rgba(59,130,246,0.4), rgba(6,182,212,0.2))`,
              opacity: 0.4 + (i / 17) * 0.6,
            }}
          />
        ))}
      </div>
    </div>
  );
}

/* ─── Agent Log ─── */
function AgentLogContent() {
  const logs = [
    { agent: 'research-bot', tool: 'web_search', status: '✓', risk: 'low' },
    { agent: 'code-agent', tool: 'exec_python', status: '⚠', risk: 'elevated' },
    { agent: 'data-pipeline', tool: 'db_query', status: '✓', risk: 'low' },
    { agent: 'support-bot', tool: 'send_email', status: '✗', risk: 'blocked' },
    { agent: 'deploy-bot', tool: 'shell_exec', status: '✓', risk: 'low' },
  ];
  return (
    <div className="space-y-[6px] text-[10px] font-mono">
      <div className="flex items-center gap-2 mb-2 px-1">
        <Terminal className="w-3 h-3 text-hacker/50" />
        <span className="text-[9px] text-hacker/50 uppercase tracking-widest font-semibold">Agent Monitor</span>
      </div>
      {logs.map((l, i) => (
        <div key={i} className="flex items-center gap-2.5 px-3 py-[6px] rounded-lg bg-white/[0.02] border border-white/[0.03]">
          <span className="text-white/25 w-[72px] truncate">{l.agent}</span>
          <span className="text-white/40 flex-1 truncate">{l.tool}</span>
          <span className={`text-xs font-bold ${
            l.risk === 'blocked' ? 'text-red-400' :
            l.risk === 'elevated' ? 'text-amber-400' :
            'text-hacker'
          }`}>
            {l.status}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ─── Shared Sub-components ─── */
function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-400 border-red-500/10',
    high: 'bg-amber-500/10 text-amber-400 border-amber-500/10',
    medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/10',
    low: 'bg-blue-500/10 text-blue-400 border-blue-500/10',
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase border ${colors[severity] || colors.low}`}>
      {severity}
    </span>
  );
}

function MetricBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-white/[0.02] border border-white/[0.03] rounded-lg px-3 py-2 text-center">
      <div className="text-white font-mono font-bold text-sm tabular-nums">{value}</div>
      <div className="text-white/20 text-[8px] uppercase tracking-widest mt-0.5">{label}</div>
    </div>
  );
}

function MetricCard({ label, value, trend, positive }: { label: string; value: string; trend: string; positive: boolean }) {
  return (
    <div className="bg-white/[0.02] border border-white/[0.03] rounded-lg px-3 py-2.5">
      <div className="text-[9px] text-white/25 uppercase tracking-widest mb-1">{label}</div>
      <div className="flex items-baseline gap-1.5">
        <span className="text-white font-mono font-bold text-[13px] tabular-nums">{value}</span>
        <span className={`text-[8px] font-mono font-semibold ${positive ? 'text-hacker/70' : 'text-cyber-400/70'}`}>{trend}</span>
      </div>
    </div>
  );
}

export { CAROUSEL_PANELS };
export type { PanelData };
