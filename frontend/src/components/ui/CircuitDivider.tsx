'use client';

import { useEffect, useRef, useState } from 'react';

/**
 * #3 — Circuit Pulse Section Divider (ELITE)
 * Enhanced with double-pulse, glowing junction nodes,
 * and secondary ghost trail effect.
 */

interface CircuitDividerProps {
  variant?: 1 | 2 | 3;
  className?: string;
}

export default function CircuitDivider({ variant = 1, className = '' }: CircuitDividerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isInView, setIsInView] = useState(false);

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
      { threshold: 0.5 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const gradientId = `pulse-gradient-${variant}`;
  const glowId = `glow-gradient-${variant}`;

  return (
    <div
      ref={containerRef}
      className={`relative w-full h-8 overflow-hidden ${className}`}
      aria-hidden="true"
    >
      <svg
        viewBox="0 0 1200 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full"
        preserveAspectRatio="none"
      >
        {/* Circuit path — base */}
        <path
          d={CIRCUIT_PATHS[variant]}
          stroke="rgba(255, 255, 255, 0.04)"
          strokeWidth="1"
          fill="none"
        />

        {isInView && (
          <>
            {/* Ghost trail — wider, fainter, offset timing */}
            <path
              d={CIRCUIT_PATHS[variant]}
              stroke={`url(#${glowId})`}
              strokeWidth="4"
              fill="none"
              strokeDasharray="60 1140"
              className="animate-circuit-pulse"
              style={{ animationDelay: '0.3s', opacity: 0.3, filter: 'blur(3px)' }}
            />

            {/* Primary energy pulse */}
            <path
              d={CIRCUIT_PATHS[variant]}
              stroke={`url(#${gradientId})`}
              strokeWidth="1.5"
              fill="none"
              strokeDasharray="80 1120"
              className="animate-circuit-pulse"
            />

            {/* Junction nodes with glow rings */}
            {JUNCTION_POINTS[variant].map((point, i) => (
              <g key={i}>
                {/* Outer glow ring */}
                <circle
                  cx={point[0]}
                  cy={point[1]}
                  r="5"
                  fill="none"
                  stroke="rgba(59, 130, 246, 0.15)"
                  strokeWidth="0.5"
                  className={isInView ? 'animate-node-glow' : ''}
                  style={{ animationDelay: `${i * 200 + 500}ms` }}
                />
                {/* Core dot */}
                <circle
                  cx={point[0]}
                  cy={point[1]}
                  r="2"
                  fill="rgba(59, 130, 246, 0.5)"
                  className={isInView ? 'animate-node-glow' : ''}
                  style={{ animationDelay: `${i * 200 + 500}ms` }}
                />
              </g>
            ))}
          </>
        )}

        {/* Gradient definitions */}
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="transparent" />
            <stop offset="35%" stopColor="rgba(6, 182, 212, 0.5)" />
            <stop offset="50%" stopColor="rgba(59, 130, 246, 0.9)" />
            <stop offset="65%" stopColor="rgba(139, 92, 246, 0.5)" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <linearGradient id={glowId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="transparent" />
            <stop offset="40%" stopColor="rgba(59, 130, 246, 0.4)" />
            <stop offset="60%" stopColor="rgba(6, 182, 212, 0.3)" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

/* Circuit path data — 3 distinct patterns */
const CIRCUIT_PATHS: Record<number, string> = {
  1: 'M 0,16 L 200,16 L 220,8 L 400,8 L 420,16 L 500,16 L 500,24 L 600,24 L 620,16 L 780,16 L 800,8 L 980,8 L 1000,16 L 1200,16',
  2: 'M 0,16 L 100,16 L 120,24 L 300,24 L 320,16 L 550,16 L 570,8 L 650,8 L 670,16 L 900,16 L 920,24 L 1080,24 L 1100,16 L 1200,16',
  3: 'M 0,16 L 150,16 L 170,8 L 250,8 L 270,16 L 470,16 L 490,24 L 570,24 L 590,16 L 730,16 L 750,8 L 930,8 L 950,16 L 1050,16 L 1070,24 L 1150,24 L 1170,16 L 1200,16',
};

/* Junction node positions for each variant */
const JUNCTION_POINTS: Record<number, [number, number][]> = {
  1: [[220, 8], [420, 16], [500, 24], [620, 16], [800, 8], [1000, 16]],
  2: [[120, 24], [320, 16], [570, 8], [670, 16], [920, 24], [1100, 16]],
  3: [[170, 8], [270, 16], [490, 24], [590, 16], [750, 8], [950, 16], [1070, 24], [1170, 16]],
};
