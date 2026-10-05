/**
 * GhostCursor — Elliot's Targeting Reticle
 *
 * "Hello friend."
 *
 * A five-layer GPU-accelerated intelligence reticle built around a ☠️ skull core.
 * Military HUD precision. Mr. Robot terminal menace. Blade Runner 2049 cinema.
 *
 * Layer 1 — Skull + Crosshair Core: ☠️ at center with extending reticle lines
 * Layer 2 — Segmented Tracking Arc: spring-follows with tick marks
 * Layer 3 — Outer Sweep: dashed counter-rotating perimeter
 * Layer 4 — HUD Terminal: boxed coordinate readout + state label
 * Layer 5 — Trail Canvas: ghosted echoes + scanline + ping + lock-on
 */

'use client';

import { useRef, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { useCursorEngine } from './useCursorEngine';
import type { CursorRefs } from './useCursorEngine';

export default function GhostCursor() {
  const [mounted, setMounted] = useState(false);
  const [isCoarse, setIsCoarse] = useState(false);

  const refs = useRef<CursorRefs>({
    reticle: null,
    ring: null,
    sweep: null,
    hud: null,
    hudCoords: null,
    hudLabel: null,
    canvas: null,
  });

  useEffect(() => {
    setMounted(true);
    if (window.matchMedia('(pointer: coarse)').matches) {
      setIsCoarse(true);
    }
  }, []);

  useCursorEngine(refs);

  if (!mounted || isCoarse) return null;

  // ── Shared inline style constants ──
  const CYAN = '#00D4FF';
  const GREEN = '#00FF88';
  const FIXED_BASE: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    pointerEvents: 'none',
  };

  return createPortal(
    <div
      style={{
        ...FIXED_BASE,
        width: '100%',
        height: '100%',
        zIndex: 2147483647,
        overflow: 'hidden',
      }}
    >
      {/* ━━━ Layer 5: Trail + Effects Canvas ━━━ */}
      <canvas
        ref={(el) => { refs.current.canvas = el; }}
        style={{
          ...FIXED_BASE,
          width: '100%',
          height: '100%',
          willChange: 'contents',
        }}
      />

      {/* ━━━ Layer 3: Outer Sweep Ring ━━━ */}
      <div
        ref={(el) => { refs.current.sweep = el; }}
        style={{
          ...FIXED_BASE,
          width: 52,
          height: 52,
          marginLeft: -26,
          marginTop: -26,
          willChange: 'transform, opacity',
          opacity: 0,
        }}
      >
        <svg width="52" height="52" viewBox="0 0 52 52" fill="none" style={{ display: 'block' }}>
          {/* Dashed outer perimeter */}
          <circle
            cx="26" cy="26" r="24"
            stroke={CYAN}
            strokeWidth="1"
            strokeDasharray="6 4"
            fill="none"
            opacity="0.3"
          />
        </svg>
      </div>

      {/* ━━━ Layer 2: Segmented Tracking Ring with Tick Marks ━━━ */}
      <div
        ref={(el) => { refs.current.ring = el; }}
        style={{
          ...FIXED_BASE,
          width: 36,
          height: 36,
          marginLeft: -18,
          marginTop: -18,
          willChange: 'transform, opacity',
          opacity: 0,
        }}
      >
        <svg width="36" height="36" viewBox="0 0 36 36" fill="none" style={{ display: 'block' }}>
          {/* Four segmented arcs (90° each with 8° gaps) */}
          <circle
            cx="18" cy="18" r="16"
            stroke={CYAN}
            strokeWidth="1"
            strokeDasharray="20 5"
            fill="none"
            opacity="0.7"
          />
          {/* Cardinal tick marks — N, E, S, W */}
          <line x1="18" y1="0" x2="18" y2="4" stroke={CYAN} strokeWidth="1" opacity="0.5" />
          <line x1="36" y1="18" x2="32" y2="18" stroke={CYAN} strokeWidth="1" opacity="0.5" />
          <line x1="18" y1="36" x2="18" y2="32" stroke={CYAN} strokeWidth="1" opacity="0.5" />
          <line x1="0" y1="18" x2="4" y2="18" stroke={CYAN} strokeWidth="1" opacity="0.5" />
        </svg>
      </div>

      {/* ━━━ Layer 1: Skull + Crosshair Core ━━━ */}
      <div
        ref={(el) => { refs.current.reticle = el; }}
        style={{
          ...FIXED_BASE,
          width: 40,
          height: 40,
          marginLeft: -20,
          marginTop: -20,
          willChange: 'transform, opacity',
          opacity: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {/* Crosshair lines extending from center */}
        <svg
          width="40" height="40" viewBox="0 0 40 40"
          style={{ position: 'absolute', top: 0, left: 0 }}
          fill="none"
        >
          {/* Top reticle line */}
          <line x1="20" y1="2" x2="20" y2="10" stroke="#E8FAFF" strokeWidth="1" opacity="0.6" />
          {/* Bottom reticle line */}
          <line x1="20" y1="30" x2="20" y2="38" stroke="#E8FAFF" strokeWidth="1" opacity="0.6" />
          {/* Left reticle line */}
          <line x1="2" y1="20" x2="10" y2="20" stroke="#E8FAFF" strokeWidth="1" opacity="0.6" />
          {/* Right reticle line */}
          <line x1="30" y1="20" x2="38" y2="20" stroke="#E8FAFF" strokeWidth="1" opacity="0.6" />

          {/* Corner brackets — targeting frame */}
          {/* Top-left */}
          <path d="M 4 10 L 4 4 L 10 4" stroke={CYAN} strokeWidth="1" opacity="0.4" />
          {/* Top-right */}
          <path d="M 30 4 L 36 4 L 36 10" stroke={CYAN} strokeWidth="1" opacity="0.4" />
          {/* Bottom-left */}
          <path d="M 4 30 L 4 36 L 10 36" stroke={CYAN} strokeWidth="1" opacity="0.4" />
          {/* Bottom-right */}
          <path d="M 30 36 L 36 36 L 36 30" stroke={CYAN} strokeWidth="1" opacity="0.4" />
        </svg>

        {/* ☠️ Skull — the brand identity at dead center */}
        <span
          style={{
            fontSize: 14,
            lineHeight: 1,
            userSelect: 'none',
            display: 'block',
            position: 'relative',
            zIndex: 1,
            filter: `drop-shadow(0 0 4px ${CYAN}) drop-shadow(0 0 10px rgba(0, 212, 255, 0.35))`,
          }}
        >
          ☠️
        </span>
      </div>


    </div>,
    document.body
  );
}
