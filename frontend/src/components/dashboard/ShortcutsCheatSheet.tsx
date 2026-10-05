'use client';

import { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Search, Keyboard } from 'lucide-react';
import {
  getShortcutsByCategory,
  CATEGORY_LABELS,
  type Shortcut,
  formatKeys,
} from '@/hooks/useShortcutRegistry';

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function ShortcutsCheatSheet({ open, onClose }: Props) {
  const [search, setSearch] = useState('');

  // Close on Escape
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  const grouped = useMemo(() => getShortcutsByCategory(), [open]);

  const filtered = useMemo(() => {
    if (!search.trim()) return grouped;
    const q = search.toLowerCase();
    const result: Record<string, Shortcut[]> = {};
    for (const [cat, shortcuts] of Object.entries(grouped)) {
      const matches = shortcuts.filter(
        (s) =>
          s.label.toLowerCase().includes(q) ||
          s.description.toLowerCase().includes(q) ||
          s.keys.join(' ').toLowerCase().includes(q)
      );
      if (matches.length) result[cat] = matches;
    }
    return result;
  }, [grouped, search]);

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[200]"
            onClick={onClose}
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="fixed top-[10%] left-1/2 -translate-x-1/2 w-full max-w-xl max-h-[75vh] bg-surface-1 border border-white/[0.08] rounded-2xl shadow-2xl z-[201] flex flex-col overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
              <div className="flex items-center gap-2.5">
                <Keyboard className="w-4 h-4 text-ghost-400" />
                <h2 className="text-sm font-bold text-white tracking-wide">Keyboard Shortcuts</h2>
              </div>
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors"
              >
                <X className="w-4 h-4 text-gray-500" />
              </button>
            </div>

            {/* Search */}
            <div className="px-5 py-3 border-b border-white/[0.04]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-600" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search shortcuts..."
                  autoFocus
                  className="w-full pl-9 pr-4 py-2 bg-surface-0/80 border border-white/[0.06] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-ghost-500/30 transition-colors"
                />
              </div>
            </div>

            {/* Shortcuts list */}
            <div className="flex-1 overflow-y-auto px-5 py-3 space-y-5 scrollbar-thin">
              {Object.entries(filtered).map(([category, shortcuts]) => (
                <div key={category}>
                  <h3 className="text-[10px] font-mono text-gray-600 uppercase tracking-widest mb-2">
                    {CATEGORY_LABELS[category] || category}
                  </h3>
                  <div className="space-y-0.5">
                    {shortcuts.map((shortcut) => (
                      <div
                        key={shortcut.id}
                        className="flex items-center justify-between py-1.5 px-2 rounded-lg hover:bg-white/[0.03] transition-colors group"
                      >
                        <span className="text-[13px] text-gray-400 group-hover:text-gray-300 transition-colors">
                          {shortcut.description}
                        </span>
                        <div className="flex items-center gap-1 flex-shrink-0 ml-4">
                          {shortcut.keys.map((key, i) => (
                            <span key={i} className="flex items-center gap-0.5">
                              {shortcut.isSequence && i > 0 && (
                                <span className="text-[10px] text-gray-700 mx-0.5">then</span>
                              )}
                              <kbd className="min-w-[22px] h-[22px] flex items-center justify-center px-1.5 rounded bg-surface-2 border border-white/[0.08] text-[11px] font-mono text-gray-400 shadow-sm">
                                {key === 'mod'
                                  ? (typeof navigator !== 'undefined' && /Mac/.test(navigator.userAgent) ? '⌘' : 'Ctrl')
                                  : key === 'shift' ? '⇧'
                                  : key === 'enter' ? '↵'
                                  : key === 'escape' ? 'Esc'
                                  : key === 'backslash' ? '\\'
                                  : key === 'bracketleft' ? '['
                                  : key === 'bracketright' ? ']'
                                  : key === 'period' ? '.'
                                  : key.toUpperCase()}
                              </kbd>
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {Object.keys(filtered).length === 0 && (
                <div className="text-center py-8 text-gray-600 text-sm">
                  No shortcuts matching &quot;{search}&quot;
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="px-5 py-3 border-t border-white/[0.06] text-center">
              <p className="text-[10px] text-gray-700 font-mono">
                Press <kbd className="px-1 py-0.5 rounded bg-surface-2 border border-white/[0.06] text-[10px]">?</kbd> to toggle this panel
              </p>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
