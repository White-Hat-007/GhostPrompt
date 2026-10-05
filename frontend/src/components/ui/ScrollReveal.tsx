'use client';

import { useEffect, useRef } from 'react';

interface ScrollRevealProps {
  children: React.ReactNode;
  /** Stagger delay between children (ms) */
  staggerDelay?: number;
  /** Animation duration (ms) */
  duration?: number;
  /** Y offset for entrance (px) */
  yOffset?: number;
  /** Intersection threshold */
  threshold?: number;
  /** Additional CSS classes */
  className?: string;
  /** Reveal variant */
  variant?: 'fade' | 'slide-3d' | 'flip' | 'perspective';
}

export default function ScrollReveal({
  children,
  staggerDelay = 80,
  duration = 700,
  yOffset = 30,
  threshold = 0.12,
  className = '',
  variant = 'slide-3d',
}: ScrollRevealProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const hasRevealedRef = useRef(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || hasRevealedRef.current) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Set initial hidden state based on variant
    const childElements = el.children;
    if (!prefersReducedMotion) {
      for (let i = 0; i < childElements.length; i++) {
        const child = childElements[i] as HTMLElement;
        child.style.opacity = '0';
        child.style.transition = 'none';

        switch (variant) {
          case 'slide-3d':
            child.style.transform = `translateY(${yOffset}px) scale(0.97)`;
            child.style.filter = 'blur(4px)';
            break;
          case 'flip':
            child.style.transform = `perspective(800px) rotateX(8deg) translateY(${yOffset}px)`;
            child.style.filter = 'blur(3px)';
            break;
          case 'perspective':
            child.style.transform = `perspective(1200px) rotateY(-4deg) translateX(-20px) translateY(${yOffset / 2}px)`;
            child.style.filter = 'blur(2px)';
            break;
          default: // 'fade'
            child.style.transform = `translateY(${yOffset}px)`;
            break;
        }
      }
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting || hasRevealedRef.current) return;
        hasRevealedRef.current = true;
        observer.disconnect();

        if (prefersReducedMotion) {
          for (let i = 0; i < childElements.length; i++) {
            (childElements[i] as HTMLElement).style.opacity = '1';
            (childElements[i] as HTMLElement).style.transform = 'none';
            (childElements[i] as HTMLElement).style.filter = 'none';
          }
          return;
        }

        // Staggered reveal with expo-out easing
        const easing = 'cubic-bezier(0.16, 1, 0.3, 1)';
        for (let i = 0; i < childElements.length; i++) {
          const child = childElements[i] as HTMLElement;
          setTimeout(() => {
            child.style.transition = `opacity ${duration}ms ${easing}, transform ${duration}ms ${easing}, filter ${duration}ms ${easing}`;
            child.style.opacity = '1';
            child.style.transform = 'translateY(0) scale(1) rotateX(0) rotateY(0) translateX(0)';
            child.style.filter = 'blur(0px)';

            // Cleanup will-change after animation
            setTimeout(() => {
              child.style.willChange = 'auto';
            }, duration + 50);
          }, i * staggerDelay);
        }
      },
      { threshold },
    );

    observer.observe(el);

    return () => observer.disconnect();
  }, [staggerDelay, duration, yOffset, threshold, variant]);

  return (
    <div ref={containerRef} className={className}>
      {children}
    </div>
  );
}
