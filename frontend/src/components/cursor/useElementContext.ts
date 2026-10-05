/**
 * useElementContext — Throttled elementFromPoint + attribute parsing
 *
 * Reads the DOM element under the cursor at 60fps (skipped when velocity
 * is below 0.5px/frame to save cycles) and resolves a CursorState.
 *
 * This runs OUTSIDE React render — no setState, pure ref mutation.
 */

import type { CursorState, ElementContext } from './types';

const INTERACTIVE_SELECTORS = 'a, button, [role="button"], [role="link"], [type="submit"]';
const INPUT_SELECTORS = 'input, textarea, select, [contenteditable="true"], [contenteditable=""]';
const MEDIA_SELECTORS = 'img, video, canvas, svg';

/**
 * Resolve the CursorState for an element under the pointer.
 * Walks up the tree (max 8 levels) to catch wrapper patterns like
 * <div><button><span>Click</span></button></div>.
 */
export function resolveElementContext(x: number, y: number): ElementContext {
  // Guard against non-finite values (NaN, Infinity) that cause elementFromPoint to throw
  if (!Number.isFinite(x) || !Number.isFinite(y)) {
    return { state: 'scanning', element: null, rect: null };
  }
  const el = document.elementFromPoint(x, y);
  if (!el) return { state: 'scanning', element: null, rect: null };

  // Walk up to 8 ancestors
  let node: Element | null = el;
  let depth = 0;

  while (node && depth < 8) {
    // Explicit data-cursor attribute takes highest priority
    const dataCursor = node.getAttribute('data-cursor');
    if (dataCursor === 'threat') {
      return { state: 'caution', element: node, rect: node.getBoundingClientRect() };
    }
    if (dataCursor === 'encrypted') {
      return { state: 'decrypt', element: node, rect: node.getBoundingClientRect() };
    }

    // Input elements
    if (node.matches(INPUT_SELECTORS)) {
      return { state: 'input', element: node, rect: node.getBoundingClientRect() };
    }

    // Interactive elements
    if (node.matches(INTERACTIVE_SELECTORS)) {
      return { state: 'interact', element: node, rect: node.getBoundingClientRect() };
    }

    // Media elements
    if (node.matches(MEDIA_SELECTORS)) {
      return { state: 'analyze', element: node, rect: node.getBoundingClientRect() };
    }

    // Check for cursor:pointer in computed style (catches styled divs acting as buttons)
    // Only check at depth 0 to avoid perf hit
    if (depth === 0) {
      try {
        const computed = window.getComputedStyle(node);
        if (computed.cursor === 'pointer') {
          return { state: 'interact', element: node, rect: node.getBoundingClientRect() };
        }
      } catch {
        // getComputedStyle can throw on pseudo-elements
      }
    }

    node = node.parentElement;
    depth++;
  }

  return { state: 'scanning', element: el, rect: null };
}
