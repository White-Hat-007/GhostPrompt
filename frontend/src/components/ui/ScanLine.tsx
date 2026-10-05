'use client';

import { useEffect, useRef, useState } from 'react';

/**
 * #1 — Security Scan Line Sweep (ELITE)
 * Enhanced with double-line effect and ripple trail.
 */
export default function ScanLine() {
  const lineRef = useRef<HTMLDivElement>(null);
  const trailRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const initialDelay = setTimeout(() => setIsVisible(true), 3000);
    return () => clearTimeout(initialDelay);
  }, []);

  useEffect(() => {
    if (!isVisible) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const runSweep = () => {
      const el = lineRef.current;
      const trail = trailRef.current;
      if (!el) return;

      // Reset position
      el.style.transition = 'none';
      el.style.top = '-2px';
      el.style.opacity = '1';

      if (trail) {
        trail.style.transition = 'none';
        trail.style.top = '-20px';
        trail.style.opacity = '0.8';
      }

      el.getBoundingClientRect();

      // Animate sweep down
      el.style.transition = 'top 3.5s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 3.5s ease';
      el.style.top = '100vh';
      el.style.opacity = '0.2';

      // Trail follows slightly behind
      if (trail) {
        trail.style.transition = 'top 3.5s cubic-bezier(0.25, 0.46, 0.45, 0.94) 0.05s, opacity 3.5s ease 0.05s';
        trail.style.top = '100vh';
        trail.style.opacity = '0';
      }
    };

    runSweep();
    const interval = setInterval(runSweep, 12000);

    return () => clearInterval(interval);
  }, [isVisible]);

  if (!isVisible) return null;

  return (
    <div
      className="fixed inset-0 pointer-events-none overflow-hidden"
      style={{ zIndex: 2 }}
      aria-hidden="true"
    >
      {/* Primary scan line */}
      <div
        ref={lineRef}
        className="absolute left-0 right-0"
        style={{
          height: '1px',
          top: '-2px',
          background: 'linear-gradient(90deg, transparent 5%, rgba(6, 182, 212, 0.4) 25%, rgba(59, 130, 246, 0.7) 50%, rgba(139, 92, 246, 0.4) 75%, transparent 95%)',
          boxShadow: '0 0 30px 8px rgba(59, 130, 246, 0.12), 0 0 80px 20px rgba(6, 182, 212, 0.06)',
        }}
      />
      {/* Ghost trail — wider, fainter follow */}
      <div
        ref={trailRef}
        className="absolute left-0 right-0"
        style={{
          height: '20px',
          top: '-20px',
          background: 'linear-gradient(180deg, rgba(59, 130, 246, 0.04), transparent)',
          filter: 'blur(8px)',
        }}
      />
    </div>
  );
}
