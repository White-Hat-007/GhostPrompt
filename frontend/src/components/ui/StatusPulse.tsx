'use client';

import { useEffect, useRef } from 'react';

interface StatusPulseProps {
  /** Pulse color — maps to existing brand palette */
  color?: 'hacker' | 'ghost' | 'cyber' | 'danger';
  /** Size in pixels */
  size?: number;
  /** Optional label displayed next to the pulse */
  label?: string;
  /** Additional CSS classes */
  className?: string;
}

const COLOR_MAP: Record<string, { core: string; glow: string }> = {
  hacker: { core: 'rgb(0, 255, 136)', glow: 'rgba(0, 255, 136, 0.4)' },
  ghost: { core: 'rgb(59, 130, 246)', glow: 'rgba(59, 130, 246, 0.4)' },
  cyber: { core: 'rgb(6, 182, 212)', glow: 'rgba(6, 182, 212, 0.4)' },
  danger: { core: 'rgb(239, 68, 68)', glow: 'rgba(239, 68, 68, 0.4)' },
};

export default function StatusPulse({
  color = 'hacker',
  size = 8,
  label,
  className = '',
}: StatusPulseProps) {
  const dotRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const { core, glow } = COLOR_MAP[color] ?? COLOR_MAP.hacker;

  useEffect(() => {
    const dot = dotRef.current;
    if (!dot) return;

    // Respect reduced motion
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mq.matches) {
      dot.style.boxShadow = `0 0 ${size}px ${glow}`;
      return;
    }

    let t = 0;
    const animate = () => {
      t += 0.02;
      // Subtle sine-wave pulse: 60-100% opacity range, 2.5s period
      const pulse = 0.6 + Math.sin(t * 2.5) * 0.4;
      const shadowSize = size * (0.8 + pulse * 0.6);
      dot.style.opacity = String(pulse);
      dot.style.boxShadow = `0 0 ${shadowSize}px ${glow}`;
      animRef.current = requestAnimationFrame(animate);
    };

    animRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animRef.current);
  }, [size, glow]);

  return (
    <div className={`inline-flex items-center gap-2 ${className}`}>
      <div
        ref={dotRef}
        style={{
          width: size,
          height: size,
          borderRadius: '50%',
          backgroundColor: core,
          flexShrink: 0,
        }}
        role="presentation"
        aria-hidden="true"
      />
      {label && (
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">
          {label}
        </span>
      )}
    </div>
  );
}
