'use client';

import { useEffect, useState, useRef, useCallback } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const POLL_INTERVAL = 10_000;

/**
 * #4 — Floating HUD Overlay (ELITE)
 * Cybersecurity operations visor with real scan counter data,
 * enhanced floating data displays and premium micro-animations.
 */
export default function HudOverlay() {
  const [isVisible, setIsVisible] = useState(false);
  const [clock, setClock] = useState('');
  const [displayCount, setDisplayCount] = useState(0);
  const [targetCount, setTargetCount] = useState(0);
  const [latency, setLatency] = useState(8.2);
  const [isLive, setIsLive] = useState(false);
  const [engineCount, setEngineCount] = useState(33);
  const animFrameRef = useRef<number | null>(null);
  const lastFetchRef = useRef(0);

  // ── Fetch real global scan count ──
  const fetchGlobalStats = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/scan/global-stats`);
      if (!res.ok) return;
      const data = await res.json();
      const total = data.total_scans ?? 0;
      setTargetCount(total);
      if (!isLive) {
        setDisplayCount(total);
        setIsLive(true);
      }
      lastFetchRef.current = Date.now();
    } catch {
      // Silently fail — keep showing last known count
    }
  }, [isLive]);

  useEffect(() => {
    fetchGlobalStats();
    const interval = setInterval(fetchGlobalStats, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchGlobalStats]);

  // Smoothly animate displayCount toward targetCount
  useEffect(() => {
    if (displayCount === targetCount) return;
    
    const diff = targetCount - displayCount;
    const step = Math.max(1, Math.ceil(Math.abs(diff) / 30));
    
    const tick = () => {
      setDisplayCount(prev => {
        if (prev === targetCount) return prev;
        if (Math.abs(targetCount - prev) <= step) return targetCount;
        return prev + (diff > 0 ? step : -step);
      });
      animFrameRef.current = requestAnimationFrame(tick);
    };
    
    animFrameRef.current = requestAnimationFrame(tick);
    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [targetCount, displayCount]);

  // Fade in after 2.5 seconds
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setIsVisible(true);
      return;
    }
    const timer = setTimeout(() => setIsVisible(true), 2500);
    return () => clearTimeout(timer);
  }, []);

  // Live clock in military format
  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      const day = now.getDate().toString().padStart(2, '0');
      const months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
      const month = months[now.getMonth()];
      const year = now.getFullYear();
      const h = now.getHours().toString().padStart(2, '0');
      const m = now.getMinutes().toString().padStart(2, '0');
      const s = now.getSeconds().toString().padStart(2, '0');
      setClock(`${day} ${month} ${year} | ${h}:${m}:${s} LOCAL`);
    };

    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  // Fluctuating latency
  useEffect(() => {
    const interval = setInterval(() => {
      setLatency(prev => {
        const delta = (Math.random() - 0.5) * 1.5;
        return Math.max(3.1, Math.min(12.8, prev + delta));
      });
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div
      className="fixed inset-0 pointer-events-none overflow-hidden"
      style={{
        zIndex: 40,
        opacity: isVisible ? 1 : 0,
        transition: 'opacity 1.5s ease',
      }}
      aria-hidden="true"
    >
      {/* Top-left: System clock + uptime */}
      <div className="absolute top-20 left-5 flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <div className="w-1 h-1 rounded-full bg-cyan-500/40" />
          <span className="text-[9px] font-mono text-white/20 tracking-widest uppercase">
            {clock}
          </span>
        </div>
        <div className="flex items-center gap-2 ml-3">
          <span className="text-[8px] font-mono text-white/10 tracking-widest uppercase">
            ENGINES: <span className="text-cyan-400/20 tabular-nums">{engineCount}</span> ACTIVE
          </span>
        </div>
      </div>

      {/* Top-right: Scan counter (REAL DATA) — Enhanced with glow */}
      <div className="absolute top-20 right-5 flex flex-col items-end gap-1">
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-mono text-white/20 tracking-widest uppercase">
            GLOBAL SCANS: <span className="text-cyan-400/40 tabular-nums font-bold">{displayCount.toLocaleString()}</span>
          </span>
          {isLive ? (
            <span className="text-[8px] text-hacker/40 animate-pulse">▲ LIVE</span>
          ) : (
            <span className="text-[8px] text-yellow-400/30 animate-pulse">⟳ SYNC</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[8px] font-mono text-white/10 tracking-widest uppercase">
            POLL: {(POLL_INTERVAL / 1000)}s │ SRC: API/v1
          </span>
        </div>
      </div>

      {/* Bottom-left: System status with enhanced indicator */}
      <div className="absolute bottom-5 left-5 flex items-center gap-2">
        <div className="relative">
          <div className="w-1.5 h-1.5 rounded-full bg-hacker/50" />
          <div className="absolute inset-0 w-1.5 h-1.5 rounded-full bg-hacker/30 animate-ping" />
        </div>
        <span className="text-[9px] font-mono text-white/20 tracking-widest uppercase">
          SYSTEM: <span className="text-hacker/40">NOMINAL</span>
          <span className="text-white/10 ml-2">│</span>
          <span className="text-white/15 ml-2">THREAT LVL: <span className="text-cyan-400/25">LOW</span></span>
        </span>
      </div>

      {/* Bottom-right: Latency indicator with signal bars */}
      <div className="absolute bottom-5 right-5 flex items-center gap-2">
        <span className="text-[9px] font-mono text-white/20 tracking-widest uppercase">
          P95: <span className="text-cyan-400/30 tabular-nums">{latency.toFixed(1)}ms</span>
        </span>
        <div className="flex gap-[2px] items-end">
          {[1, 2, 3, 4, 5].map(i => (
            <div
              key={i}
              className="w-[2px] rounded-full transition-all duration-500"
              style={{
                height: `${2 + i * 2}px`,
                backgroundColor: i <= (latency < 6 ? 5 : latency < 8 ? 4 : latency < 10 ? 3 : 2)
                  ? 'rgba(0, 255, 136, 0.3)'
                  : 'rgba(255, 255, 255, 0.05)',
              }}
            />
          ))}
        </div>
      </div>

      {/* Corner brackets — top-left (with subtle glow) */}
      <svg className="absolute top-16 left-3 w-5 h-5" viewBox="0 0 20 20" fill="none">
        <path d="M 0,16 L 0,0 L 16,0" stroke="rgba(59, 130, 246, 0.12)" strokeWidth="1" />
        <circle cx="0" cy="0" r="1.5" fill="rgba(59, 130, 246, 0.15)" />
      </svg>

      {/* Corner brackets — top-right */}
      <svg className="absolute top-16 right-3 w-5 h-5" viewBox="0 0 20 20" fill="none">
        <path d="M 20,16 L 20,0 L 4,0" stroke="rgba(59, 130, 246, 0.12)" strokeWidth="1" />
        <circle cx="20" cy="0" r="1.5" fill="rgba(59, 130, 246, 0.15)" />
      </svg>

      {/* Corner brackets — bottom-left */}
      <svg className="absolute bottom-3 left-3 w-5 h-5" viewBox="0 0 20 20" fill="none">
        <path d="M 0,4 L 0,20 L 16,20" stroke="rgba(59, 130, 246, 0.12)" strokeWidth="1" />
        <circle cx="0" cy="20" r="1.5" fill="rgba(59, 130, 246, 0.15)" />
      </svg>

      {/* Corner brackets — bottom-right */}
      <svg className="absolute bottom-3 right-3 w-5 h-5" viewBox="0 0 20 20" fill="none">
        <path d="M 20,4 L 20,20 L 4,20" stroke="rgba(59, 130, 246, 0.12)" strokeWidth="1" />
        <circle cx="20" cy="20" r="1.5" fill="rgba(59, 130, 246, 0.15)" />
      </svg>
    </div>
  );
}
