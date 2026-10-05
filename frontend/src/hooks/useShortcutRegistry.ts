'use client';

import { useEffect, useCallback, useRef, useMemo } from 'react';

// ── Types ──────────────────────────────────────────────────────────────
export interface Shortcut {
  /** Unique identifier */
  id: string;
  /** Display label */
  label: string;
  /** Category for grouping in cheat-sheet */
  category: 'navigation' | 'actions' | 'view' | 'scanner' | 'global';
  /** Key combo: modifier keys + final key */
  keys: string[];
  /** Human-readable key display (auto-generated if not provided) */
  display?: string;
  /** Description shown in cheat-sheet */
  description: string;
  /** Handler function */
  handler: () => void;
  /** Whether this is a sequence (e.g., g then o) */
  isSequence?: boolean;
  /** Whether shortcut requires modifier (Cmd/Ctrl) */
  requiresMod?: boolean;
}

// ── OS Detection ───────────────────────────────────────────────────────
const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.userAgent);
export const MOD_KEY = isMac ? '⌘' : 'Ctrl';
export const MOD_KEY_CODE = isMac ? 'metaKey' : 'ctrlKey';

/**
 * Format key combo for display.
 * Converts ['mod', 'k'] → '⌘K' on Mac, 'Ctrl+K' on Windows.
 */
export function formatKeys(keys: string[]): string {
  return keys
    .map((k) => {
      if (k === 'mod') return MOD_KEY;
      if (k === 'shift') return '⇧';
      if (k === 'alt') return isMac ? '⌥' : 'Alt';
      if (k === 'enter') return '↵';
      if (k === 'escape') return 'Esc';
      if (k === 'backslash') return '\\';
      if (k === 'bracketleft') return '[';
      if (k === 'bracketright') return ']';
      if (k === 'period') return '.';
      return k.toUpperCase();
    })
    .join(isMac ? '' : '+');
}

// ── Registry ───────────────────────────────────────────────────────────
const _registry: Map<string, Shortcut> = new Map();
let _sequenceBuffer: string | null = null;
let _sequenceTimer: ReturnType<typeof setTimeout> | null = null;
const SEQUENCE_TIMEOUT = 800; // ms to wait for second key in sequence

/**
 * Central keyboard shortcut hook.
 *
 * Usage:
 * ```tsx
 * useShortcutRegistry([
 *   { id: 'nav-overview', label: 'Overview', category: 'navigation',
 *     keys: ['g', 'o'], isSequence: true,
 *     description: 'Go to Overview', handler: () => router.push('/dashboard') },
 * ]);
 * ```
 */
export function useShortcutRegistry(shortcuts: Shortcut[]) {
  const handlersRef = useRef<Shortcut[]>(shortcuts);
  handlersRef.current = shortcuts;

  // Register on mount, deregister on unmount
  useEffect(() => {
    for (const s of shortcuts) {
      _registry.set(s.id, { ...s, display: s.display || formatKeys(s.keys) });
    }
    return () => {
      for (const s of shortcuts) {
        _registry.delete(s.id);
      }
    };
  }, [shortcuts]);

  // Global keydown listener
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // ── Guard: don't fire while typing in inputs ──
      const tag = (e.target as HTMLElement)?.tagName;
      const isEditable =
        tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' ||
        (e.target as HTMLElement)?.isContentEditable;

      // Allow mod+key shortcuts even in inputs (they're intentional)
      const hasMod = e.metaKey || e.ctrlKey;
      if (isEditable && !hasMod) return;

      const key = e.key.toLowerCase();

      // ── Sequence handling (e.g., g then o) ──
      if (_sequenceBuffer) {
        const seqKey = _sequenceBuffer;
        _sequenceBuffer = null;
        if (_sequenceTimer) clearTimeout(_sequenceTimer);

        for (const s of handlersRef.current) {
          if (
            s.isSequence &&
            s.keys.length === 2 &&
            s.keys[0] === seqKey &&
            s.keys[1] === key
          ) {
            e.preventDefault();
            e.stopPropagation();
            s.handler();
            return;
          }
        }
        // Sequence didn't match — fall through to normal handling
      }

      // ── Check for sequence starters ──
      const isSequenceStarter = handlersRef.current.some(
        (s) => s.isSequence && s.keys[0] === key
      );
      if (isSequenceStarter && !hasMod && !isEditable) {
        _sequenceBuffer = key;
        _sequenceTimer = setTimeout(() => {
          _sequenceBuffer = null;
        }, SEQUENCE_TIMEOUT);
        return;
      }

      // ── Normal shortcuts ──
      for (const s of handlersRef.current) {
        if (s.isSequence) continue; // handled above

        const keys = s.keys;
        const needsMod = keys.includes('mod');
        const needsShift = keys.includes('shift');
        const needsAlt = keys.includes('alt');
        const finalKey = keys.filter(
          (k) => k !== 'mod' && k !== 'shift' && k !== 'alt'
        )[0];

        if (!finalKey) continue;

        const modOk = needsMod ? e[MOD_KEY_CODE] : !e[MOD_KEY_CODE];
        const shiftOk = needsShift ? e.shiftKey : true;
        const altOk = needsAlt ? e.altKey : true;

        if (key === finalKey && modOk && shiftOk && altOk) {
          // Don't prevent ? in inputs
          if (key === '?' && isEditable) continue;
          e.preventDefault();
          e.stopPropagation();
          s.handler();
          return;
        }
      }
    }

    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, []);
}

/** Get all registered shortcuts (for rendering cheat-sheet). */
export function getRegisteredShortcuts(): Shortcut[] {
  return Array.from(_registry.values());
}

/** Get shortcuts grouped by category. */
export function getShortcutsByCategory(): Record<string, Shortcut[]> {
  const grouped: Record<string, Shortcut[]> = {};
  for (const s of _registry.values()) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return grouped;
}

// ── Category labels ────────────────────────────────────────────────────
export const CATEGORY_LABELS: Record<string, string> = {
  global: 'Global',
  navigation: 'Navigation',
  actions: 'Actions',
  view: 'View Controls',
  scanner: 'Live Scanner',
};
