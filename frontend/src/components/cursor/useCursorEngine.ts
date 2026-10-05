/**
 * useCursorEngine — RAF loop, spring physics, state machine
 *
 * Core animation engine for the GhostPrompt ☠️ targeting reticle.
 * Writes directly to DOM refs inside the RAF loop — zero React state
 * for cursor position. Locked 60fps.
 *
 * Layer 1: Skull + crosshair (instant follow)
 * Layer 2: Segmented arc ring (spring-lagged, rotating)
 * Layer 3: Outer sweep ring (spring-lagged, counter-rotating, breathing)
 * Layer 4: HUD terminal readout (offset, edge-flipping)
 * Layer 5: Canvas (trails, scanline, ping, lock-on)
 */

import { useEffect, useRef, useCallback } from 'react';
import type { CursorState, SpringState, CursorEngineState } from './types';
import { resolveElementContext } from './useElementContext';
import { CursorCanvas } from './cursorCanvas';

// ── Spring Configuration ──
const RING_STIFFNESS = 0.18;
const RING_DAMPING = 0.78;
const SWEEP_STIFFNESS = 0.10;
const SWEEP_DAMPING = 0.82;

// ── Timing ──
const IDLE_THRESHOLD_MS = 2500;
const PING_INTERVAL_MS = 3000;
const SCANLINE_DURATION_MS = 220;

// ── FPS Monitor ──
const FPS_SAMPLE_INTERVAL = 30;
const FPS_MIN_THRESHOLD = 50;

// ── Scramble Glyphs for DECRYPT state ──
const SCRAMBLE_GLYPHS = '▓▒░█▄▀╬╠╣║═╗╝╚╔';

function springStep(
  spring: SpringState,
  targetX: number,
  targetY: number,
  stiffness: number,
  damping: number,
): void {
  spring.vx += (targetX - spring.x) * stiffness;
  spring.vy += (targetY - spring.y) * stiffness;
  spring.vx *= damping;
  spring.vy *= damping;
  spring.x += spring.vx;
  spring.y += spring.vy;
}

function pad4(n: number): string {
  const i = Math.round(Math.abs(n));
  if (i >= 10000) return String(i).slice(0, 4);
  return String(i).padStart(4, '0');
}

function scrambleText(length: number): string {
  let s = '';
  for (let i = 0; i < length; i++) {
    s += SCRAMBLE_GLYPHS[Math.floor(Math.random() * SCRAMBLE_GLYPHS.length)];
  }
  return s;
}

const STATE_LABELS: Record<CursorState, string> = {
  scanning: '> SCANNING',
  interact: '> INTERACT',
  input: '> INPUT',
  analyze: '> ANALYZE',
  caution: '> CAUTION',
  decrypt: '> DECRYPT',
  idle: '> IDLE',
};

export interface CursorRefs {
  reticle: HTMLDivElement | null;
  ring: HTMLDivElement | null;
  sweep: HTMLDivElement | null;
  hud: HTMLDivElement | null;
  hudCoords: HTMLSpanElement | null;
  hudLabel: HTMLSpanElement | null;
  canvas: HTMLCanvasElement | null;
}

export function useCursorEngine(refs: React.MutableRefObject<CursorRefs>) {
  const state = useRef<CursorEngineState>({
    mouse: { x: -100, y: -100 },
    ring: { x: -100, y: -100, vx: 0, vy: 0 },
    sweep: { x: -100, y: -100, vx: 0, vy: 0 },
    context: { state: 'scanning', element: null, rect: null },
    isVisible: false,
    isPressed: false,
    isIdle: false,
    reducedMotion: false,
    coarsePointer: false,
    timestamp: 0,
    lastMoveTime: 0,
    frameCount: 0,
    fps: 60,
    trailEnabled: true,
  });

  const canvasRenderer = useRef<CursorCanvas | null>(null);
  const rafId = useRef<number>(0);
  const scanlineState = useRef({ active: false, y: 0, startTime: 0 });
  const pingState = useRef({ lastPing: 0 });
  const prevState = useRef<CursorState>('scanning');
  const fpsFrameTimes = useRef<number[]>([]);
  const decryptTimer = useRef(0);

  // Smooth animation values
  const ringOpacity = useRef(0.7);
  const ringTargetOpacity = useRef(0.7);
  const sweepOpacity = useRef(0.3);
  const sweepTargetOpacity = useRef(0.3);
  const lockOnOpacity = useRef(0);
  const lockOnTarget = useRef(0);
  const skullScale = useRef(1.0);
  const skullTargetScale = useRef(1.0);

  const tick = useCallback((now: number) => {
    const s = state.current;
    const r = refs.current;
    s.timestamp = now;

    // ── FPS monitoring ──
    fpsFrameTimes.current.push(now);
    if (fpsFrameTimes.current.length > FPS_SAMPLE_INTERVAL) {
      const oldest = fpsFrameTimes.current.shift()!;
      s.fps = Math.round((FPS_SAMPLE_INTERVAL * 1000) / (now - oldest));
      s.trailEnabled = s.fps >= FPS_MIN_THRESHOLD;
    }

    // ── Idle detection ──
    const wasIdle = s.isIdle;
    s.isIdle = now - s.lastMoveTime > IDLE_THRESHOLD_MS && s.isVisible;
    if (s.isIdle && !wasIdle) {
      s.context = { ...s.context, state: 'idle' };
    } else if (!s.isIdle && wasIdle && s.context.state === 'idle') {
      s.context = resolveElementContext(s.mouse.x, s.mouse.y);
    }

    // ── State change ──
    if (s.context.state !== prevState.current) {
      prevState.current = s.context.state;
    }

    // ── Colors ──
    const isCaution = s.context.state === 'caution';
    const primaryColor = isCaution ? '#FF3B47' : '#00D4FF';
    const accentColor = '#00FF88';
    const curState = s.context.state;

    // ── State-driven targets ──
    switch (curState) {
      case 'interact':
        ringTargetOpacity.current = 1.0;
        sweepTargetOpacity.current = 0.35;
        lockOnTarget.current = 0;
        skullTargetScale.current = 1.12;
        break;
      case 'input':
        ringTargetOpacity.current = 0.15;
        sweepTargetOpacity.current = 0;
        lockOnTarget.current = 0;
        skullTargetScale.current = 0.8;
        break;
      case 'analyze':
        ringTargetOpacity.current = 0.7;
        sweepTargetOpacity.current = 0.6;
        lockOnTarget.current = 0.7;
        skullTargetScale.current = 1.0;
        break;
      case 'caution':
        ringTargetOpacity.current = 0.9;
        sweepTargetOpacity.current = 0.5;
        lockOnTarget.current = 0;
        skullTargetScale.current = 1.08;
        break;
      case 'idle':
        ringTargetOpacity.current = 0.3;
        sweepTargetOpacity.current = 0.12;
        lockOnTarget.current = 0;
        skullTargetScale.current = 0.85;
        break;
      default: // scanning
        ringTargetOpacity.current = 0.7;
        sweepTargetOpacity.current = 0.3;
        lockOnTarget.current = 0;
        skullTargetScale.current = 1.0;
        break;
    }

    // Smooth interpolation (exponential ease)
    ringOpacity.current += (ringTargetOpacity.current - ringOpacity.current) * 0.1;
    sweepOpacity.current += (sweepTargetOpacity.current - sweepOpacity.current) * 0.1;
    lockOnOpacity.current += (lockOnTarget.current - lockOnOpacity.current) * 0.08;
    skullScale.current += (skullTargetScale.current - skullScale.current) * 0.12;

    // ── Spring physics ──
    springStep(s.ring, s.mouse.x, s.mouse.y, RING_STIFFNESS, RING_DAMPING);
    springStep(s.sweep, s.mouse.x, s.mouse.y, SWEEP_STIFFNESS, SWEEP_DAMPING);

    const visMul = s.isVisible ? 1 : 0;

    // ━━━ Layer 1: Skull + Crosshair Core ━━━
    if (r.reticle) {
      const sc = skullScale.current;
      r.reticle.style.transform = `translate3d(${s.mouse.x}px, ${s.mouse.y}px, 0) scale(${sc})`;
      r.reticle.style.opacity = String(0.95 * visMul);

      // State-driven glow
      if (isCaution) {
        r.reticle.style.filter = 'drop-shadow(0 0 5px #FF3B47) drop-shadow(0 0 12px rgba(255,59,71,0.45))';
      } else if (curState === 'interact') {
        r.reticle.style.filter = 'drop-shadow(0 0 6px #00D4FF) drop-shadow(0 0 16px rgba(0,212,255,0.45))';
      } else if (curState === 'input') {
        r.reticle.style.filter = 'drop-shadow(0 0 4px #00FF88) drop-shadow(0 0 10px rgba(0,255,136,0.35))';
      } else if (curState === 'idle') {
        r.reticle.style.filter = 'drop-shadow(0 0 2px #00D4FF) drop-shadow(0 0 5px rgba(0,212,255,0.15))';
      } else {
        r.reticle.style.filter = 'drop-shadow(0 0 4px #00D4FF) drop-shadow(0 0 10px rgba(0,212,255,0.3))';
      }

      // Update SVG stroke colors inside the reticle for caution state
      const svgEl = r.reticle.querySelector('svg');
      if (svgEl) {
        const lines = svgEl.querySelectorAll('line');
        const paths = svgEl.querySelectorAll('path');
        const lineColor = isCaution ? '#FFD0D3' : '#E8FAFF';
        const bracketColor = isCaution ? '#FF3B47' : '#00D4FF';
        lines.forEach(l => l.setAttribute('stroke', lineColor));
        paths.forEach(p => p.setAttribute('stroke', bracketColor));
      }
    }

    // ━━━ Layer 2: Segmented Tracking Ring ━━━
    if (r.ring) {
      const rotation = s.reducedMotion ? 0 : (now * 0.045) % 360; // 8s revolution
      r.ring.style.transform = `translate3d(${s.ring.x}px, ${s.ring.y}px, 0) rotate(${rotation}deg)`;

      let opacity = ringOpacity.current * visMul;
      if (curState === 'caution') {
        opacity = (Math.sin(now * 0.0105) * 0.3 + 0.7) * visMul;
      }
      r.ring.style.opacity = String(opacity);

      // Update SVG stroke color
      const svgCircle = r.ring.querySelector('circle');
      const svgLines = r.ring.querySelectorAll('line');
      if (svgCircle) svgCircle.setAttribute('stroke', primaryColor);
      svgLines.forEach(l => l.setAttribute('stroke', primaryColor));
    }

    // ━━━ Layer 3: Outer Sweep ━━━
    if (r.sweep) {
      if (s.reducedMotion) {
        r.sweep.style.display = 'none';
      } else {
        r.sweep.style.display = '';
        const sweepSpeed = curState === 'interact' ? -0.0514 : -0.0257;
        const rotation = (now * sweepSpeed) % 360;
        const breathe = 1.0 + Math.sin(now * 0.00157) * 0.02;
        r.sweep.style.transform = `translate3d(${s.sweep.x}px, ${s.sweep.y}px, 0) rotate(${rotation}deg) scale(${breathe})`;

        let opacity = sweepOpacity.current * visMul;
        if (curState === 'caution') {
          opacity = (Math.sin(now * 0.0105) * 0.2 + 0.4) * visMul;
        }
        r.sweep.style.opacity = String(opacity);

        // Update SVG stroke color and dash pattern
        const svgCircle = r.sweep.querySelector('circle');
        if (svgCircle) {
          svgCircle.setAttribute('stroke', primaryColor);
          svgCircle.setAttribute('stroke-dasharray', curState === 'caution' ? '0' : '6 4');
          svgCircle.setAttribute('opacity', curState === 'caution' ? '0.5' : '0.3');
        }
      }
    }

    // ━━━ Layer 4: HUD Terminal ━━━
    if (r.hud) {
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const flipX = s.mouse.x > vw - 160;
      const flipY = s.mouse.y > vh - 60;
      const offsetX = flipX ? -130 : 32;
      const offsetY = flipY ? -50 : 32;

      r.hud.style.transform = `translate3d(${Math.round(s.mouse.x + offsetX)}px, ${Math.round(s.mouse.y + offsetY)}px, 0)`;
      r.hud.style.opacity = String(0.75 * visMul);

      // Border color for caution
      r.hud.style.borderLeftColor = isCaution ? '#FF3B47' : accentColor;
    }

    if (r.hudCoords) {
      r.hudCoords.textContent = `X:${pad4(s.mouse.x)}  Y:${pad4(s.mouse.y)}`;
    }

    if (r.hudLabel) {
      if (curState === 'decrypt') {
        decryptTimer.current += 16.67;
        if (decryptTimer.current % 500 < 250) {
          r.hudLabel.textContent = scrambleText(9);
        } else {
          r.hudLabel.textContent = STATE_LABELS[curState];
        }
      } else {
        decryptTimer.current = 0;
        r.hudLabel.textContent = STATE_LABELS[curState];
      }
      r.hudLabel.style.color = isCaution ? '#FF3B47' : accentColor;
    }

    // ━━━ Layer 5: Canvas Effects ━━━
    if (canvasRenderer.current) {
      canvasRenderer.current.pushPosition(s.mouse.x, s.mouse.y);

      const trailColor = isCaution ? '#FF3B47' : '#E8FAFF';
      canvasRenderer.current.renderTrails(trailColor, s.trailEnabled && !s.reducedMotion && s.isVisible);

      // Lock-on brackets
      if (curState === 'analyze' && s.context.rect) {
        canvasRenderer.current.renderLockOn(s.context.rect, primaryColor, lockOnOpacity.current);
      }

      // Click scanline
      if (scanlineState.current.active) {
        const elapsed = now - scanlineState.current.startTime;
        const progress = elapsed / SCANLINE_DURATION_MS;
        if (progress >= 1) {
          scanlineState.current.active = false;
        } else {
          canvasRenderer.current.renderScanline(scanlineState.current.y, progress, primaryColor);
        }
      }

      // Idle ping ring
      if (s.isIdle && !s.reducedMotion) {
        const timeSinceLastPing = now - pingState.current.lastPing;
        if (timeSinceLastPing > PING_INTERVAL_MS) {
          pingState.current.lastPing = now;
        }
        const pingElapsed = now - pingState.current.lastPing;
        const pingProgress = Math.min(1, pingElapsed / 1500);
        canvasRenderer.current.renderPingRing(s.mouse.x, s.mouse.y, pingProgress, primaryColor);
      }
    }

    s.frameCount++;
    rafId.current = requestAnimationFrame(tick);
  }, [refs]);

  useEffect(() => {
    const reducedMotionMQ = window.matchMedia('(prefers-reduced-motion: reduce)');
    const coarsePointerMQ = window.matchMedia('(pointer: coarse)');

    state.current.reducedMotion = reducedMotionMQ.matches;
    state.current.coarsePointer = coarsePointerMQ.matches;

    if (state.current.coarsePointer) return;

    const onReducedMotionChange = (e: MediaQueryListEvent) => {
      state.current.reducedMotion = e.matches;
    };
    reducedMotionMQ.addEventListener('change', onReducedMotionChange);

    if (refs.current.canvas) {
      canvasRenderer.current = new CursorCanvas(refs.current.canvas);
    }

    const onMouseMove = (e: MouseEvent) => {
      const s = state.current;
      s.mouse.x = e.clientX;
      s.mouse.y = e.clientY;
      s.lastMoveTime = performance.now();
      if (!s.isVisible) s.isVisible = true;
      if (!s.isIdle) {
        s.context = resolveElementContext(e.clientX, e.clientY);
      }
    };

    const onMouseDown = (e: MouseEvent) => {
      state.current.isPressed = true;
      if (!state.current.reducedMotion) {
        scanlineState.current = { active: true, y: e.clientY, startTime: performance.now() };
      }
    };

    const onMouseUp = () => { state.current.isPressed = false; };
    const onMouseLeave = () => { state.current.isVisible = false; };

    const onMouseEnter = (e: MouseEvent) => {
      const s = state.current;
      s.isVisible = true;
      s.mouse.x = e.clientX;
      s.mouse.y = e.clientY;
      s.ring.x = e.clientX; s.ring.y = e.clientY; s.ring.vx = 0; s.ring.vy = 0;
      s.sweep.x = e.clientX; s.sweep.y = e.clientY; s.sweep.vx = 0; s.sweep.vy = 0;
      s.lastMoveTime = performance.now();
    };

    const onResize = () => { canvasRenderer.current?.resize(); };

    document.addEventListener('mousemove', onMouseMove, { passive: true });
    document.addEventListener('mousedown', onMouseDown, { passive: true });
    document.addEventListener('mouseup', onMouseUp, { passive: true });
    document.documentElement.addEventListener('mouseleave', onMouseLeave);
    document.documentElement.addEventListener('mouseenter', onMouseEnter);
    window.addEventListener('resize', onResize, { passive: true });

    state.current.lastMoveTime = performance.now();
    rafId.current = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(rafId.current);
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mousedown', onMouseDown);
      document.removeEventListener('mouseup', onMouseUp);
      document.documentElement.removeEventListener('mouseleave', onMouseLeave);
      document.documentElement.removeEventListener('mouseenter', onMouseEnter);
      window.removeEventListener('resize', onResize);
      reducedMotionMQ.removeEventListener('change', onReducedMotionChange);
      canvasRenderer.current?.destroy();
    };
  }, [tick, refs]);
}
