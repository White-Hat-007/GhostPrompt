'use client';

import { useEffect, useRef, useState } from 'react';

interface LiveMetricTickerProps {
  /** Target value to count towards */
  value: number;
  /** Duration of the count animation in ms */
  duration?: number;
  /** Prefix (e.g., '<', '$') */
  prefix?: string;
  /** Suffix (e.g., 'ms', '%', '+') */
  suffix?: string;
  /** Number of decimal places */
  decimals?: number;
  /** Whether to show subtle increment animation after reaching target */
  liveIncrement?: boolean;
  /** Increment interval in ms (for live mode) */
  incrementInterval?: number;
  /** Additional CSS classes */
  className?: string;
}

export default function LiveMetricTicker({
  value,
  duration = 2000,
  prefix = '',
  suffix = '',
  decimals = 0,
  liveIncrement = false,
  incrementInterval = 5000,
  className = '',
}: LiveMetricTickerProps) {
  const [displayValue, setDisplayValue] = useState(0);
  const [hasAnimated, setHasAnimated] = useState(false);
  const [isIncrementing, setIsIncrementing] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);

  // Initial count-up animation triggered by intersection
  useEffect(() => {
    const el = containerRef.current;
    if (!el || hasAnimated) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          observer.disconnect();

          if (prefersReducedMotion) {
            setDisplayValue(value);
            setHasAnimated(true);
            return;
          }

          const startTime = performance.now();
          const animate = (currentTime: number) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Expo-out easing: cubic-bezier(0.16, 1, 0.3, 1) approximation
            const eased = 1 - Math.pow(1 - progress, 4);
            setDisplayValue(Math.round(eased * value * Math.pow(10, decimals)) / Math.pow(10, decimals));

            if (progress < 1) {
              animRef.current = requestAnimationFrame(animate);
            } else {
              setDisplayValue(value);
              setHasAnimated(true);
            }
          };
          animRef.current = requestAnimationFrame(animate);
        }
      },
      { threshold: 0.3 },
    );

    observer.observe(el);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(animRef.current);
    };
  }, [value, duration, decimals, hasAnimated]);

  // Subtle live increment after initial animation completes
  useEffect(() => {
    if (!hasAnimated || !liveIncrement) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) return;

    const interval = setInterval(() => {
      setIsIncrementing(true);
      setDisplayValue(prev => prev + 1);
      // Brief flash on increment
      setTimeout(() => setIsIncrementing(false), 300);
    }, incrementInterval);

    return () => clearInterval(interval);
  }, [hasAnimated, liveIncrement, incrementInterval]);

  const formattedValue = displayValue.toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });

  return (
    <div
      ref={containerRef}
      className={`font-mono tabular-nums ${className}`}
      aria-live="polite"
      aria-atomic="true"
    >
      <span
        className={`transition-colors duration-300 ${
          isIncrementing ? 'text-cyber-400' : ''
        }`}
      >
        {prefix}{formattedValue}{suffix}
      </span>
    </div>
  );
}
