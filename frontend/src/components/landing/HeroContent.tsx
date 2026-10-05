'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { motion, useAnimation, useInView, useMotionValue, useTransform, useSpring } from 'framer-motion';
import { Shield, Zap, Lock, Terminal, Activity, Crosshair, ArrowRight, Eye } from 'lucide-react';
import MagneticButton from '../ui/MagneticButton';
import StatusPulse from '../ui/StatusPulse';

// ── GLITCH TEXT ── cinematic character-level reveal like Elliot's terminal
function GlitchReveal({ text, className = '', delay = 0, hackerColor = false }: { text: string; className?: string; delay?: number; hackerColor?: boolean }) {
  const [displayed, setDisplayed] = useState('');
  const [done, setDone] = useState(false);
  const chars = '01#$@%&*!?/<>';

  useEffect(() => {
    let frame = 0;
    const len = text.length;
    const timer = setTimeout(() => {
      const interval = setInterval(() => {
        frame++;
        const resolved = Math.floor(frame / 2);
        if (resolved >= len) {
          setDisplayed(text);
          setDone(true);
          clearInterval(interval);
          return;
        }
        let out = text.slice(0, resolved);
        for (let i = resolved; i < Math.min(resolved + 5, len); i++) {
          out += text[i] === ' ' ? ' ' : chars[Math.floor(Math.random() * chars.length)];
        }
        setDisplayed(out);
      }, 30);
      return () => clearInterval(interval);
    }, delay);
    return () => clearTimeout(timer);
  }, [text, delay]);

  const pulseColor = hackerColor ? 'text-[#00ff88]' : 'text-[#0ae0ff]';
  return <span className={className}>{displayed}<span className={`${done ? 'opacity-0' : 'animate-pulse'} ${pulseColor}`}>▊</span></span>;
}

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.06, delayChildren: 0.15 } },
};
const wordUp = {
  hidden: { opacity: 0, y: 20, filter: 'blur(6px)', rotateX: -15 },
  show: { opacity: 1, y: 0, filter: 'blur(0px)', rotateX: 0, transition: { duration: 0.7, ease: [0.16, 1, 0.3, 1] } },
};

export default function HeroContent() {
  const controls = useAnimation();
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-100px' });

  // 3D Parallax mouse tracking
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);
  const springX = useSpring(mouseX, { stiffness: 150, damping: 30 });
  const springY = useSpring(mouseY, { stiffness: 150, damping: 30 });
  const rotateX = useTransform(springY, [-0.5, 0.5], [3, -3]);
  const rotateY = useTransform(springX, [-0.5, 0.5], [-3, 3]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    mouseX.set(x);
    mouseY.set(y);
  }, [mouseX, mouseY]);

  useEffect(() => { if (inView) controls.start('show'); }, [inView, controls]);

  const headline1 = ['Hello', 'friend.'];
  const headline2 = ['We', 'are', 'the', 'AI', 'Firewall.'];

  return (
    <motion.div
      ref={ref}
      className="max-w-5xl mx-auto text-center relative preserve-3d"
      style={{ perspective: '1200px' }}
      onMouseMove={handleMouseMove}
      onMouseLeave={() => { mouseX.set(0); mouseY.set(0); }}
    >
      {/* Floating ambient particles */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {[...Array(8)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-1 h-1 rounded-full bg-ghost-500/30"
            style={{
              left: `${15 + i * 10}%`,
              top: `${20 + (i % 3) * 25}%`,
            }}
            animate={{
              y: [0, -40, 0],
              opacity: [0.2, 0.6, 0.2],
              scale: [1, 1.5, 1],
            }}
            transition={{
              duration: 3 + i * 0.5,
              repeat: Infinity,
              delay: i * 0.3,
              ease: 'easeInOut',
            }}
          />
        ))}
      </div>

      {/* 3D Parallax container */}
      <motion.div style={{ rotateX, rotateY, transformStyle: 'preserve-3d' }}>
        {/* Status Badges */}
        <motion.div
          className="flex items-center justify-center gap-3 mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <StatusPulse color="hacker" size={6} label="All systems operational" />
          <span className="text-gray-600">•</span>
          <span className="text-mono-xs text-gray-500 uppercase tracking-wider font-mono">Runtime Protection Active</span>
        </motion.div>

        {/* ── HEADLINE 1: "Hello friend." ── */}
        <motion.div
          className="flex flex-wrap justify-center gap-x-4 mb-2"
          variants={container}
          initial="hidden"
          animate={controls}
          style={{ transformStyle: 'preserve-3d' }}
        >
          {headline1.map((word, i) => (
            <motion.span
              key={i}
              variants={wordUp}
              className="text-[3rem] sm:text-[4rem] md:text-[5rem] font-black tracking-tight font-display text-white leading-none"
              style={{ transformStyle: 'preserve-3d' }}
            >
              {word}
            </motion.span>
          ))}
        </motion.div>

        {/* ── HEADLINE 2: "We are the AI Firewall." — gradient + shimmer ── */}
        <motion.div
          className="flex flex-wrap justify-center gap-x-3 mb-6"
          variants={container}
          initial="hidden"
          animate={controls}
          style={{ transformStyle: 'preserve-3d' }}
        >
          {headline2.map((word, i) => (
            <motion.span
              key={i}
              variants={wordUp}
              className={`text-[2.5rem] sm:text-[3.5rem] md:text-[4.5rem] font-black tracking-tight font-display leading-none ${
                i >= 3 ? 'text-gradient-premium' : 'text-white/80'
              }`}
              style={{ transformStyle: 'preserve-3d' }}
            >
              {word}
            </motion.span>
          ))}
        </motion.div>

        {/* ── SUBHEADLINE ── */}
        <motion.div
          initial={{ opacity: 0, y: 20, filter: 'blur(6px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 0.8, delay: 0.8 }}
          className="max-w-2xl mx-auto mb-4"
        >
          <p className="text-base md:text-lg text-gray-400 leading-relaxed">
            Enterprise AI Runtime Security & Operations Platform.{' '}
            <span className="text-gray-300">33 detection engines</span> protect every prompt, completion,
            and tool call from injection, jailbreaks, and zero-day attacks.
          </p>
        </motion.div>

        {/* ── GLITCH TAGLINE ── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2, duration: 0.5 }}
          className="mb-10"
        >
          <span className="text-mono-xs text-[#0ae0ff]/60 font-mono uppercase tracking-[0.2em]">
            <GlitchReveal text="CORTEX_CLASS // RUNTIME_DEFENSE // 33_ENGINES_ACTIVE" delay={1400} />
          </span>
        </motion.div>

        {/* ── CTAs ── */}
        <motion.div
          initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 0.7, delay: 1.0, ease: [0.16, 1, 0.3, 1] }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4"
        >
          <MagneticButton href="/auth/register" variant="primary" className="text-base px-8 py-3.5 shadow-neon-blue" id="hero-cta-signup">
            Start Protecting <ArrowRight className="w-4 h-4" />
          </MagneticButton>
          <MagneticButton href="/dashboard" variant="ghost" className="text-base px-6 py-3.5" id="hero-cta-dashboard">
            <Eye className="w-4 h-4" /> Live Dashboard
          </MagneticButton>
        </motion.div>

        {/* ── Floating Shield 3D ── */}
        <motion.div
          className="absolute -right-8 top-1/2 -translate-y-1/2 hidden xl:block"
          animate={{
            y: [0, -12, 0],
            rotateY: [0, 10, 0],
            rotateZ: [-5, 5, -5],
          }}
          transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut' }}
          style={{ transformStyle: 'preserve-3d' }}
        >
          <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-ghost-500/20 to-cyber-600/10 border border-ghost-500/20 flex items-center justify-center shadow-neon-blue backdrop-blur-xl">
            <Shield className="w-10 h-10 text-ghost-400/60" />
          </div>
        </motion.div>
      </motion.div>
    </motion.div>
  );
}
