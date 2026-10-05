'use client';

import { useEffect, useRef } from 'react';

/**
 * #2 — Cursor Spotlight / Proximity Glow
 * A soft, radial light that follows the user's cursor — like inspecting
 * the interface with a flashlight in a dark SOC room.
 */
export default function CursorSpotlight() {
  const spotlightRef = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number>(0);
  const mouseRef = useRef({ x: -500, y: -500 });
  const currentRef = useRef({ x: -500, y: -500 });

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    // Detect touch device — no spotlight on mobile
    if ('ontouchstart' in window || navigator.maxTouchPoints > 0) return;

    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY };
    };

    // Smooth follow at ~30fps for performance
    let frameCount = 0;
    const animate = () => {
      frameCount++;
      if (frameCount % 2 === 0) { // Throttle to ~30fps
        const lerp = 0.12;
        currentRef.current.x += (mouseRef.current.x - currentRef.current.x) * lerp;
        currentRef.current.y += (mouseRef.current.y - currentRef.current.y) * lerp;

        if (spotlightRef.current) {
          spotlightRef.current.style.transform = `translate(${currentRef.current.x - 200}px, ${currentRef.current.y - 200}px) translateZ(0)`;
        }
      }
      rafRef.current = requestAnimationFrame(animate);
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    rafRef.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <div
      className="fixed inset-0 pointer-events-none overflow-hidden"
      style={{ zIndex: 1 }}
      aria-hidden="true"
    >
      <div
        ref={spotlightRef}
        className="absolute will-change-transform"
        style={{
          width: '400px',
          height: '400px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.06) 0%, rgba(6, 182, 212, 0.03) 40%, transparent 70%)',
          transform: 'translate(-500px, -500px) translateZ(0)',
          mixBlendMode: 'screen',
        }}
      />
    </div>
  );
}
