/**
 * GhostPrompt Cursor System — Type Definitions
 *
 * Precision targeting reticle for the AI Firewall interface.
 * "Hello friend." — Elliot Alderson
 */

export type CursorState =
  | 'scanning'   // Default — background / nothing special
  | 'interact'   // <a>, <button>, [role=button]
  | 'input'      // <input>, <textarea>, [contenteditable]
  | 'analyze'    // <img>, <video>, <canvas>
  | 'caution'    // [data-cursor="threat"]
  | 'decrypt'    // [data-cursor="encrypted"]
  | 'idle';      // No movement > 2.5s

export interface CursorPosition {
  x: number;
  y: number;
}

export interface SpringState {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

export interface TrailParticle {
  x: number;
  y: number;
  opacity: number;
  scale: number;
}

export interface ElementContext {
  state: CursorState;
  element: Element | null;
  rect: DOMRect | null;
}

export interface CursorEngineState {
  mouse: CursorPosition;
  ring: SpringState;
  sweep: SpringState;
  context: ElementContext;
  isVisible: boolean;
  isPressed: boolean;
  isIdle: boolean;
  reducedMotion: boolean;
  coarsePointer: boolean;
  timestamp: number;
  lastMoveTime: number;
  frameCount: number;
  fps: number;
  trailEnabled: boolean;
}
