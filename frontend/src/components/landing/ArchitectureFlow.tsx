'use client';

import { useRef, useState } from 'react';
import { motion, useInView } from 'framer-motion';
import {
  Shield, AlertTriangle, Zap, CheckCircle, XCircle,
  Eye, Cpu, Lock, Database, Terminal, Globe, GitBranch,
  ArrowRight, Radio
} from 'lucide-react';

/* ─── Architecture Flow Data ─── */
interface FlowNode {
  id: string;
  label: string;
  sublabel: string;
  icon: any;
  color: string; // tailwind gradient
  glowColor: string; // rgba
  x: number; // percent
  y: number; // percent
  type: 'input' | 'process' | 'decision' | 'output';
}

interface FlowEdge {
  from: string;
  to: string;
  label?: string;
  color?: string;
  dashed?: boolean;
}

const NODES: FlowNode[] = [
  { id: 'input', label: 'AI Request', sublabel: 'prompt / completion / tool_call', icon: Terminal, color: 'from-blue-500 to-indigo-600', glowColor: 'rgba(59,130,246,0.3)', x: 8, y: 53, type: 'input' },
  { id: 'proxy', label: 'GhostPrompt Proxy', sublabel: 'OpenAI-compatible endpoint', icon: Globe, color: 'from-cyan-500 to-blue-600', glowColor: 'rgba(6,182,212,0.3)', x: 22, y: 53, type: 'process' },
  { id: 'firewall', label: 'Firewall Engine', sublabel: '33 detection engines', icon: Shield, color: 'from-violet-500 to-purple-600', glowColor: 'rgba(139,92,246,0.3)', x: 38, y: 53, type: 'process' },
  { id: 'regex', label: 'Regex Patterns', sublabel: '50+ rules', icon: Eye, color: 'from-blue-400 to-blue-600', glowColor: 'rgba(96,165,250,0.2)', x: 24, y: 20, type: 'process' },
  { id: 'ml', label: 'ML Classifier', sublabel: 'binary gate', icon: Cpu, color: 'from-purple-400 to-purple-600', glowColor: 'rgba(192,132,252,0.2)', x: 38, y: 20, type: 'process' },
  { id: 'semantic', label: 'Semantic Analysis', sublabel: 'cosine sim', icon: Database, color: 'from-indigo-400 to-indigo-600', glowColor: 'rgba(129,140,248,0.2)', x: 52, y: 20, type: 'process' },
  { id: 'packhunt', label: 'Pack Hunt', sublabel: 'multi-request', icon: GitBranch, color: 'from-fuchsia-400 to-fuchsia-600', glowColor: 'rgba(232,121,249,0.2)', x: 24, y: 86, type: 'process' },
  { id: 'zeroday', label: 'Zero-Day', sublabel: 'anomaly detect', icon: AlertTriangle, color: 'from-amber-400 to-orange-600', glowColor: 'rgba(251,146,60,0.2)', x: 38, y: 86, type: 'process' },
  { id: 'constitutional', label: 'Constitutional AI', sublabel: 'guardrails', icon: Lock, color: 'from-teal-400 to-emerald-600', glowColor: 'rgba(45,212,191,0.2)', x: 52, y: 86, type: 'process' },
  { id: 'policy', label: 'Policy Engine', sublabel: 'org rules + RBAC', icon: Zap, color: 'from-amber-500 to-yellow-600', glowColor: 'rgba(245,158,11,0.3)', x: 54, y: 53, type: 'decision' },
  { id: 'allow', label: 'Allow', sublabel: 'forwarded to LLM', icon: CheckCircle, color: 'from-emerald-500 to-green-600', glowColor: 'rgba(16,185,129,0.3)', x: 68, y: 35, type: 'output' },
  { id: 'block', label: 'Block & Escalate', sublabel: 'logged, alerted', icon: XCircle, color: 'from-red-500 to-rose-600', glowColor: 'rgba(239,68,68,0.3)', x: 68, y: 72, type: 'output' },
  { id: 'llm', label: 'LLM Provider', sublabel: 'OpenAI / Anthropic', icon: Radio, color: 'from-emerald-400 to-cyan-600', glowColor: 'rgba(52,211,153,0.3)', x: 82, y: 35, type: 'output' },
];

const EDGES: FlowEdge[] = [
  { from: 'input', to: 'proxy', label: 'intercept' },
  { from: 'proxy', to: 'firewall', label: 'analyze' },
  { from: 'firewall', to: 'regex', dashed: true },
  { from: 'firewall', to: 'ml', dashed: true },
  { from: 'firewall', to: 'semantic', dashed: true },
  { from: 'firewall', to: 'packhunt', dashed: true },
  { from: 'firewall', to: 'zeroday', dashed: true },
  { from: 'firewall', to: 'constitutional', dashed: true },
  { from: 'firewall', to: 'policy', label: 'verdict' },
  { from: 'policy', to: 'allow', label: 'safe', color: '#10b981' },
  { from: 'policy', to: 'block', label: 'threat', color: '#ef4444' },
  { from: 'allow', to: 'llm', label: 'forward', color: '#10b981' },
];

/* ─── Animated Flow Edge (SVG line between nodes) ─── */
function FlowEdgeLine({
  x1, y1, x2, y2, color = 'rgba(255,255,255,0.18)', dashed = false, delay = 0
}: {
  x1: number; y1: number; x2: number; y2: number;
  color?: string; dashed?: boolean; delay?: number;
}) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const path = Math.abs(dy) > 10
    ? `M ${x1} ${y1} C ${x1 + dx/2} ${y1} ${x1 + dx/2} ${y2} ${x2} ${y2}`
    : `M ${x1} ${y1} L ${x2} ${y2}`;

  // Dashed lines: use opacity animation only (pathLength conflicts with strokeDasharray)
  // Solid lines: use pathLength draw animation
  if (dashed) {
    return (
      <motion.path
        d={path}
        stroke={color}
        strokeWidth={1.5}
        fill="none"
        strokeDasharray="6 4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8, delay: delay + 0.5, ease: 'easeOut' }}
      />
    );
  }

  return (
    <motion.path
      d={path}
      stroke={color}
      strokeWidth={2}
      fill="none"
      initial={{ pathLength: 0, opacity: 0 }}
      animate={{ pathLength: 1, opacity: 1 }}
      transition={{ duration: 1.2, delay: delay + 0.5, ease: [0.16, 1, 0.3, 1] }}
    />
  );
}

/* ─── Flow Node Card ─── */
function FlowNodeCard({ node, index }: { node: FlowNode; index: number }) {
  const [hovered, setHovered] = useState(false);
  const Icon = node.icon;

  const isSubEngine = node.type === 'process' && (node.id === 'regex' || node.id === 'ml' || node.id === 'semantic' || node.id === 'packhunt' || node.id === 'zeroday' || node.id === 'constitutional');
  const sizeClass = isSubEngine ? 'w-[145px]' : 'w-[175px]';

  return (
    <motion.div
      className={`absolute ${sizeClass}`}
      style={{ left: `${node.x}%`, top: `${node.y}%`, transform: 'translate(-50%, -50%)' }}
      initial={{ opacity: 0, scale: 0.8, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.6, delay: index * 0.08 + 0.3, ease: [0.16, 1, 0.3, 1] }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <motion.div
        className="glass-card px-3 py-2.5 rounded-xl flex items-center gap-2.5 cursor-default relative overflow-visible"
        animate={{
          scale: hovered ? 1.06 : 1,
          boxShadow: hovered
            ? `0 8px 32px rgba(0,0,0,0.5), 0 0 30px ${node.glowColor}`
            : '0 4px 16px rgba(0,0,0,0.3)',
        }}
        transition={{ type: 'spring', stiffness: 400, damping: 25 }}
      >
        {/* Icon */}
        <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${node.color} flex items-center justify-center flex-shrink-0 shadow-lg`}>
          <Icon className="w-4 h-4 text-white" />
        </div>

        {/* Text */}
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-bold text-white leading-tight">{node.label}</p>
          <p className="text-[9px] text-gray-500 leading-tight mt-0.5 font-mono">{node.sublabel}</p>
        </div>

        {/* Glow ring on hover */}
        <motion.div
          className="absolute -inset-px rounded-xl pointer-events-none"
          style={{ border: `1px solid ${node.glowColor}` }}
          animate={{ opacity: hovered ? 0.6 : 0 }}
          transition={{ duration: 0.3 }}
        />
      </motion.div>
    </motion.div>
  );
}

/* ─── Stats Badge ─── */
function StatsBadge({ label, value, color, delay }: { label: string; value: string; color: string; delay: number }) {
  return (
    <motion.div
      className="glass-card px-4 py-3 rounded-xl text-center"
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ delay, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
    >
      <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-[10px] text-gray-500 uppercase tracking-wider mt-1">{label}</p>
    </motion.div>
  );
}


/* ─── Main Component ─── */
export default function ArchitectureFlow() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-100px' });

  // Calculate node positions for edge drawing (in a 1000x500 coordinate space)
  const W = 1000;
  const H = 580;
  const getPos = (id: string) => {
    const n = NODES.find(n => n.id === id);
    return n ? { x: (n.x / 100) * W, y: (n.y / 100) * H } : { x: 0, y: 0 };
  };

  return (
    <section ref={ref} className="py-24 px-6 relative z-10">
      <div className="max-w-7xl mx-auto">
        {/* Section Header */}
        <div className="text-center mb-16">
          <motion.div
            className="section-eyebrow mb-4 mx-auto"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
          >
            <Shield className="w-3 h-3" />
            The Architecture
          </motion.div>
          <motion.h2
            className="text-3xl md:text-5xl font-bold text-white font-display mb-4"
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          >
            How GhostPrompt{' '}
            <span className="text-gradient-premium">Intercepts Threats</span>
          </motion.h2>
          <motion.p
            className="text-gray-400 text-lg max-w-3xl mx-auto"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            Every AI request passes through our 33-engine detection pipeline. From regex pattern matching
            to zero-day ML heuristics — every attack vector is analyzed, classified, and neutralized
            before reaching your LLM.
          </motion.p>
        </div>

        {/* Architecture Flow Diagram */}
        <div className="w-full overflow-x-auto pb-8 -mx-6 px-6 md:mx-0 md:px-0">
          <motion.div
            className="relative glass-card rounded-2xl overflow-hidden min-w-[1200px]"
            style={{ minHeight: 580 }}
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            {/* Background grid */}
            <div className="absolute inset-0 opacity-[0.03] bg-hex-grid" />

            {/* SVG Connector Lines */}
            <svg
              className="absolute inset-0 w-full h-full pointer-events-none"
              viewBox={`0 0 ${W} ${H}`}
              preserveAspectRatio="none"
            >
              {inView && EDGES.map((edge, i) => {
                const from = getPos(edge.from);
                const to = getPos(edge.to);
                return (
                  <FlowEdgeLine
                    key={i}
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    color={edge.color || 'rgba(255,255,255,0.2)'}
                    dashed={edge.dashed}
                    delay={i * 0.05}
                  />
                );
              })}

              {/* Animated particle along main path */}
              {inView && (
                <>
                  <circle r="3" fill="#3b82f6" opacity="0.8">
                    <animateMotion
                      dur="4s"
                      repeatCount="indefinite"
                      path={`M ${getPos('input').x} ${getPos('input').y} L ${getPos('proxy').x} ${getPos('proxy').y} L ${getPos('firewall').x} ${getPos('firewall').y} L ${getPos('policy').x} ${getPos('policy').y} L ${getPos('allow').x} ${getPos('allow').y} L ${getPos('llm').x} ${getPos('llm').y}`}
                    />
                  </circle>
                  <circle r="2" fill="#06b6d4" opacity="0.6">
                    <animateMotion
                      dur="4s"
                      repeatCount="indefinite"
                      begin="1s"
                      path={`M ${getPos('input').x} ${getPos('input').y} L ${getPos('proxy').x} ${getPos('proxy').y} L ${getPos('firewall').x} ${getPos('firewall').y} L ${getPos('policy').x} ${getPos('policy').y} L ${getPos('block').x} ${getPos('block').y}`}
                    />
                  </circle>
                </>
              )}
            </svg>

            {/* Render Nodes */}
            <div className="relative w-full" style={{ height: 580 }}>
              {NODES.map((node, i) => (
                <FlowNodeCard key={node.id} node={node} index={i} />
              ))}
            </div>

            {/* Flow Legend */}
            <div className="absolute bottom-4 right-4 flex items-center gap-4 text-[10px] font-mono text-gray-500 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-px bg-white/20" />
                Data Flow
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-px border-t border-dashed border-white/20" />
                Engine Link
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue-500/50" />
                Packet
              </span>
            </div>
          </motion.div>
        </div>

        {/* Bottom Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
          <StatsBadge label="Avg Scan Latency" value="<8ms" color="text-cyan-400" delay={0.1} />
          <StatsBadge label="Detection Engines" value="33" color="text-violet-400" delay={0.2} />
          <StatsBadge label="Attack Signatures" value="1,200+" color="text-amber-400" delay={0.3} />
          <StatsBadge label="Block Accuracy" value="99.97%" color="text-emerald-400" delay={0.4} />
        </div>
      </div>
    </section>
  );
}
