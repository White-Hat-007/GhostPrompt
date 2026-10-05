'use client';

import { useEffect, useRef, useState } from 'react';

/**
 * #6 — Orbital Threat Radar
 * A small, elegant radar sweep animation reinforcing the
 * "always scanning" narrative. Pure CSS/SVG — zero canvas overhead.
 */
export default function ThreatRadar() {
  const [isInView, setIsInView] = useState(false);
  const [blips, setBlips] = useState<{ x: number; y: number; age: number }[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsInView(true);
          observer.disconnect();
        }
      },
      { threshold: 0.3 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Generate random blips
  useEffect(() => {
    if (!isInView) return;

    const interval = setInterval(() => {
      setBlips(prev => {
        // Add a new blip at random angle/distance
        const angle = Math.random() * Math.PI * 2;
        const distance = 15 + Math.random() * 40;
        const newBlip = {
          x: 60 + Math.cos(angle) * distance,
          y: 60 + Math.sin(angle) * distance,
          age: 0,
        };

        // Age existing blips, remove old ones
        const updated = prev
          .map(b => ({ ...b, age: b.age + 1 }))
          .filter(b => b.age < 6);

        return [...updated, newBlip].slice(-8); // Max 8 blips
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isInView]);

  return (
    <div
      ref={containerRef}
      className="relative w-[120px] h-[120px] flex-shrink-0"
      aria-hidden="true"
    >
      <svg viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
        {/* Concentric rings */}
        {[20, 35, 50].map(r => (
          <circle
            key={r}
            cx="60"
            cy="60"
            r={r}
            stroke="rgba(59, 130, 246, 0.08)"
            strokeWidth="0.5"
            fill="none"
          />
        ))}

        {/* Crosshairs */}
        <line x1="60" y1="10" x2="60" y2="110" stroke="rgba(59, 130, 246, 0.06)" strokeWidth="0.5" />
        <line x1="10" y1="60" x2="110" y2="60" stroke="rgba(59, 130, 246, 0.06)" strokeWidth="0.5" />

        {/* Sweep arm */}
        {isInView && (
          <g className="origin-center animate-radar-sweep" style={{ transformOrigin: '60px 60px' }}>
            {/* Sweep gradient wedge */}
            <path
              d="M 60,60 L 60,10 A 50,50 0 0,1 103,35 Z"
              fill="url(#sweep-gradient)"
            />
            {/* Leading edge line */}
            <line x1="60" y1="60" x2="60" y2="10" stroke="rgba(6, 182, 212, 0.5)" strokeWidth="0.75" />
          </g>
        )}

        {/* Threat blips */}
        {blips.map((blip, i) => (
          <circle
            key={i}
            cx={blip.x}
            cy={blip.y}
            r="2"
            fill={blip.age < 2 ? 'rgba(239, 68, 68, 0.7)' : `rgba(239, 68, 68, ${0.5 - blip.age * 0.08})`}
            className={blip.age === 0 ? 'animate-blip-appear' : ''}
          />
        ))}

        {/* Center dot */}
        <circle cx="60" cy="60" r="2.5" fill="rgba(6, 182, 212, 0.4)" />
        <circle cx="60" cy="60" r="1" fill="rgba(6, 182, 212, 0.8)" />

        {/* Gradient definitions */}
        <defs>
          <linearGradient id="sweep-gradient" gradientTransform="rotate(0)">
            <stop offset="0%" stopColor="rgba(6, 182, 212, 0.12)" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
        </defs>
      </svg>

      {/* "SCANNING" label */}
      {isInView && (
        <div className="absolute -bottom-5 left-1/2 -translate-x-1/2">
          <span className="text-[8px] font-mono text-cyan-400/30 uppercase tracking-[0.2em]">Scanning</span>
        </div>
      )}
    </div>
  );
}
