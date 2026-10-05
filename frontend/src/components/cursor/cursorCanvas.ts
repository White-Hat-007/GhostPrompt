/**
 * cursorCanvas — Trail particle + lock-on bracket renderer
 *
 * Renders to a single <canvas> element. No DOM node spawning for trails.
 * Auto-disables if FPS drops below 50.
 */

import type { TrailParticle } from './types';

const TRAIL_COUNT = 6;
const TRAIL_OPACITY_START = 0.4;
const TRAIL_OPACITY_END = 0.05;
const TRAIL_SCALE_START = 1.0;
const TRAIL_SCALE_END = 0.6;

export class CursorCanvas {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private trails: TrailParticle[];
  private dpr: number;

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d', { alpha: true })!;
    this.dpr = window.devicePixelRatio || 1;
    this.trails = [];

    for (let i = 0; i < TRAIL_COUNT; i++) {
      const t = i / (TRAIL_COUNT - 1);
      this.trails.push({
        x: 0,
        y: 0,
        opacity: TRAIL_OPACITY_START + t * (TRAIL_OPACITY_END - TRAIL_OPACITY_START),
        scale: TRAIL_SCALE_START + t * (TRAIL_SCALE_END - TRAIL_SCALE_START),
      });
    }

    this.resize();
  }

  resize() {
    this.dpr = window.devicePixelRatio || 1;
    this.canvas.width = window.innerWidth * this.dpr;
    this.canvas.height = window.innerHeight * this.dpr;
    this.canvas.style.width = window.innerWidth + 'px';
    this.canvas.style.height = window.innerHeight + 'px';
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
  }

  /**
   * Push a new position into the trail buffer (FIFO shift).
   */
  pushPosition(x: number, y: number) {
    // Shift all trails back by one
    for (let i = this.trails.length - 1; i > 0; i--) {
      this.trails[i].x = this.trails[i - 1].x;
      this.trails[i].y = this.trails[i - 1].y;
    }
    // First trail matches current position
    if (this.trails.length > 0) {
      this.trails[0].x = x;
      this.trails[0].y = y;
    }
  }

  /**
   * Render trail particles as ghosted ☠️ skull echoes.
   */
  renderTrails(color: string, visible: boolean) {
    this.ctx.clearRect(0, 0, this.canvas.width / this.dpr, this.canvas.height / this.dpr);

    if (!visible) return;

    // Skip the first trail (it's the current position — Layer 1 draws that)
    for (let i = 1; i < this.trails.length; i++) {
      const t = this.trails[i];
      if (t.opacity < 0.01) continue;

      this.ctx.save();
      this.ctx.globalAlpha = t.opacity;
      this.ctx.translate(t.x, t.y);
      this.ctx.scale(t.scale, t.scale);

      // Draw skull echo
      this.ctx.font = '16px serif';
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'middle';
      this.ctx.fillText('☠️', 0, 0);

      this.ctx.restore();
    }
  }

  /**
   * Render lock-on corner brackets around a target element.
   */
  renderLockOn(rect: DOMRect | null, color: string, opacity: number) {
    if (!rect || opacity < 0.01) return;

    const pad = 4;
    const bracketLen = Math.min(12, rect.width * 0.2, rect.height * 0.2);
    const x = rect.left - pad;
    const y = rect.top - pad;
    const w = rect.width + pad * 2;
    const h = rect.height + pad * 2;

    this.ctx.save();
    this.ctx.globalAlpha = opacity;
    this.ctx.strokeStyle = color;
    this.ctx.lineWidth = 1;

    // Top-left
    this.ctx.beginPath();
    this.ctx.moveTo(x, y + bracketLen);
    this.ctx.lineTo(x, y);
    this.ctx.lineTo(x + bracketLen, y);
    this.ctx.stroke();

    // Top-right
    this.ctx.beginPath();
    this.ctx.moveTo(x + w - bracketLen, y);
    this.ctx.lineTo(x + w, y);
    this.ctx.lineTo(x + w, y + bracketLen);
    this.ctx.stroke();

    // Bottom-left
    this.ctx.beginPath();
    this.ctx.moveTo(x, y + h - bracketLen);
    this.ctx.lineTo(x, y + h);
    this.ctx.lineTo(x + bracketLen, y + h);
    this.ctx.stroke();

    // Bottom-right
    this.ctx.beginPath();
    this.ctx.moveTo(x + w - bracketLen, y + h);
    this.ctx.lineTo(x + w, y + h);
    this.ctx.lineTo(x + w, y + h - bracketLen);
    this.ctx.stroke();

    this.ctx.restore();
  }

  /**
   * Render the click scanline effect.
   */
  renderScanline(y: number, progress: number, color: string) {
    if (progress <= 0 || progress >= 1) return;

    const width = window.innerWidth;
    const alpha = 1 - progress;

    this.ctx.save();
    this.ctx.globalAlpha = alpha * 0.6;

    // Main line
    const gradient = this.ctx.createLinearGradient(0, y, width, y);
    gradient.addColorStop(0, 'transparent');
    gradient.addColorStop(0.3, color);
    gradient.addColorStop(0.7, color);
    gradient.addColorStop(1, 'transparent');

    this.ctx.strokeStyle = gradient;
    this.ctx.lineWidth = 1;
    this.ctx.beginPath();
    this.ctx.moveTo(0, y);
    this.ctx.lineTo(width, y);
    this.ctx.stroke();

    this.ctx.restore();
  }

  /**
   * Render the idle ping ring.
   */
  renderPingRing(x: number, y: number, progress: number, color: string) {
    if (progress <= 0 || progress >= 1) return;

    const radius = 40 * progress;
    const alpha = (1 - progress) * 0.3;

    this.ctx.save();
    this.ctx.globalAlpha = alpha;
    this.ctx.strokeStyle = color;
    this.ctx.lineWidth = 1;
    this.ctx.beginPath();
    this.ctx.arc(x, y, radius, 0, Math.PI * 2);
    this.ctx.stroke();
    this.ctx.restore();
  }

  destroy() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
  }
}
