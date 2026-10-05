'use client';

import { useState, useCallback } from 'react';
import { motion, useMotionValue, useTransform, useSpring } from 'framer-motion';
import { Shield, AlertTriangle, Zap, Activity, TrendingUp, Crosshair, Radar, Layers } from 'lucide-react';

interface StatsGridProps {
  stats: {
    total_scans: number;
    blocked_attacks: number;
    threat_events: number;
    active_policies: number;
    scans_today: number;
    blocks_today: number;
    avg_threat_score: number;
    evasion_caught: number;
    pliny_attacks?: number;
    zero_day_flags?: number;
    detection_layers?: number;
  };
}

const formatNumber = (num: number): string => {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
};

/* ── 3D Tilt Card ── */
function Stat3DCard({
  card,
  index,
}: {
  card: {
    title: string;
    value: string;
    subtext: string;
    icon: any;
    gradient: string;
    iconGradient: string;
    accentColor: string;
    borderGlow: string;
  };
  index: number;
}) {
  const Icon = card.icon;
  const [hovered, setHovered] = useState(false);

  // 3D tilt tracking
  const mouseX = useMotionValue(0.5);
  const mouseY = useMotionValue(0.5);
  const rotateX = useSpring(useTransform(mouseY, [0, 1], [6, -6]), { stiffness: 300, damping: 30 });
  const rotateY = useSpring(useTransform(mouseX, [0, 1], [-6, 6]), { stiffness: 300, damping: 30 });
  const glareX = useTransform(mouseX, [0, 1], ['-50%', '150%']);
  const glareY = useTransform(mouseY, [0, 1], ['-50%', '150%']);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const rect = e.currentTarget.getBoundingClientRect();
      mouseX.set((e.clientX - rect.left) / rect.width);
      mouseY.set((e.clientY - rect.top) / rect.height);
    },
    [mouseX, mouseY]
  );

  const handleMouseLeave = useCallback(() => {
    mouseX.set(0.5);
    mouseY.set(0.5);
    setHovered(false);
  }, [mouseX, mouseY]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay: index * 0.06, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={handleMouseLeave}
      style={{
        rotateX,
        rotateY,
        transformStyle: 'preserve-3d',
        perspective: '800px',
      }}
      className="group relative rounded-xl overflow-hidden cursor-default"
    >
      {/* Card background */}
      <div
        className="absolute inset-0 transition-all duration-500"
        style={{
          background: 'rgba(10, 16, 32, 0.6)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          borderRadius: '0.75rem',
        }}
      />

      {/* Top accent line — animated shimmer */}
      <motion.div
        className="absolute top-0 left-0 right-0 h-[2px] z-10"
        style={{
          background: `linear-gradient(90deg, transparent 20%, ${card.accentColor}, transparent 80%)`,
        }}
        animate={{ opacity: hovered ? 1 : 0.5 }}
      />

      {/* Holographic glare on hover */}
      <motion.div
        className="absolute inset-0 pointer-events-none z-10 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
        style={{
          background: `radial-gradient(circle at ${glareX} ${glareY}, rgba(255,255,255,0.06) 0%, transparent 60%)`,
        } as any}
      />

      {/* Ambient glow on hover */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse at top right, ${card.borderGlow}, transparent 70%)`,
        }}
      />

      {/* Inner glow line */}
      <div className="absolute inset-0 pointer-events-none" style={{ boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.04)' }} />

      {/* Content */}
      <div className="relative z-10 p-5" style={{ transform: 'translateZ(20px)', transformStyle: 'preserve-3d' }}>
        <div className="flex items-start justify-between mb-4">
          <motion.div
            className={`w-10 h-10 rounded-xl bg-gradient-to-br ${card.iconGradient} flex items-center justify-center shadow-lg`}
            style={{ boxShadow: `0 4px 14px ${card.borderGlow}`, transform: 'translateZ(10px)' }}
            animate={{ rotate: hovered ? [0, -5, 5, 0] : 0 }}
            transition={{ duration: 0.5 }}
          >
            <Icon className="w-5 h-5 text-white" />
          </motion.div>
          {/* Mini sparkline decoration */}
          <div className="flex items-end gap-[2px] h-5 opacity-40 group-hover:opacity-70 transition-opacity">
            {[3, 5, 4, 7, 6, 8, 5, 9, 7, 8].map((h, i) => (
              <motion.div
                key={i}
                className="w-[3px] rounded-full"
                style={{
                  background: card.accentColor,
                  opacity: 0.3 + (i / 10) * 0.7,
                }}
                initial={{ height: 0 }}
                animate={{ height: `${h * 2}px` }}
                transition={{ delay: index * 0.06 + i * 0.03 + 0.3, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
              />
            ))}
          </div>
        </div>

        <div>
          <motion.p
            className="text-2xl font-bold text-white tracking-tight font-mono tabular-nums"
            style={{ transform: 'translateZ(15px)' }}
          >
            {card.value}
          </motion.p>
          <div className="flex items-center justify-between mt-1.5">
            <p className="text-[11px] font-medium text-gray-400">{card.title}</p>
            <p className="text-[10px] text-gray-600 font-mono">{card.subtext}</p>
          </div>
        </div>
      </div>

      {/* Hover border glow */}
      <motion.div
        className="absolute inset-0 rounded-xl pointer-events-none z-20"
        animate={{
          boxShadow: hovered
            ? `inset 0 0 0 1px ${card.accentColor}30, 0 0 25px ${card.borderGlow}`
            : 'inset 0 0 0 1px transparent, 0 0 0px transparent',
        }}
        transition={{ duration: 0.4 }}
      />
    </motion.div>
  );
}

export default function StatsGrid({ stats }: StatsGridProps) {
  const cards = [
    {
      title: 'Total Scans',
      value: formatNumber(stats.total_scans),
      subtext: `${formatNumber(stats.scans_today)} today`,
      icon: Activity,
      gradient: 'from-blue-500/20 via-indigo-500/10 to-transparent',
      iconGradient: 'from-blue-500 to-indigo-600',
      accentColor: '#3b82f6',
      borderGlow: 'rgba(59, 130, 246, 0.15)',
    },
    {
      title: 'Attacks Blocked',
      value: formatNumber(stats.blocked_attacks),
      subtext: `${stats.blocks_today} today`,
      icon: Shield,
      gradient: 'from-red-500/20 via-rose-500/10 to-transparent',
      iconGradient: 'from-red-500 to-rose-600',
      accentColor: '#ef4444',
      borderGlow: 'rgba(239, 68, 68, 0.15)',
    },
    {
      title: 'Threat Events',
      value: formatNumber(stats.threat_events),
      subtext: 'Last 30 days',
      icon: AlertTriangle,
      gradient: 'from-amber-500/20 via-orange-500/10 to-transparent',
      iconGradient: 'from-amber-500 to-orange-600',
      accentColor: '#f59e0b',
      borderGlow: 'rgba(245, 158, 11, 0.15)',
    },
    {
      title: 'Active Policies',
      value: stats.active_policies.toString(),
      subtext: 'Enforcing rules',
      icon: Zap,
      gradient: 'from-emerald-500/20 via-teal-500/10 to-transparent',
      iconGradient: 'from-emerald-500 to-teal-600',
      accentColor: '#10b981',
      borderGlow: 'rgba(16, 185, 129, 0.15)',
    },
    {
      title: 'Evasion Caught',
      value: formatNumber(stats.evasion_caught),
      subtext: 'Normalized attacks',
      icon: TrendingUp,
      gradient: 'from-cyan-500/20 via-blue-500/10 to-transparent',
      iconGradient: 'from-cyan-500 to-blue-600',
      accentColor: '#06b6d4',
      borderGlow: 'rgba(6, 182, 212, 0.15)',
    },
    {
      title: 'Pliny-Class Attacks',
      value: formatNumber(stats.pliny_attacks ?? 0),
      subtext: 'L1B3RT4S / OBLITERATUS',
      icon: Crosshair,
      gradient: 'from-fuchsia-500/20 via-purple-500/10 to-transparent',
      iconGradient: 'from-fuchsia-500 to-purple-600',
      accentColor: '#d946ef',
      borderGlow: 'rgba(217, 70, 239, 0.15)',
    },
    {
      title: 'Zero-Day Flags',
      value: formatNumber(stats.zero_day_flags ?? 0),
      subtext: 'Novel attack patterns',
      icon: Radar,
      gradient: 'from-rose-500/20 via-pink-500/10 to-transparent',
      iconGradient: 'from-rose-500 to-pink-600',
      accentColor: '#f43f5e',
      borderGlow: 'rgba(244, 63, 94, 0.15)',
    },
    {
      title: 'Detection Layers',
      value: (stats.detection_layers ?? 31).toString(),
      subtext: 'Active defense systems',
      icon: Layers,
      gradient: 'from-violet-500/20 via-indigo-500/10 to-transparent',
      iconGradient: 'from-violet-500 to-indigo-600',
      accentColor: '#8b5cf6',
      borderGlow: 'rgba(139, 92, 246, 0.15)',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4" style={{ perspective: '1200px' }}>
      {cards.map((card, index) => (
        <Stat3DCard key={card.title} card={card} index={index} />
      ))}
    </div>
  );
}
