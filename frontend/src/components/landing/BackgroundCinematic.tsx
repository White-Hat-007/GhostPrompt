'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import Image from 'next/image';

/* ─── Background image data ─── */
const BG_IMAGES = [
  '/bg/hacker.jpg',
  '/bg/elliot.jpg',
  '/bg/control.jpg',
  '/bg/hacker1.png',
  '/bg/hacker2.png',
  '/bg/hacker3.png',
];

/** Per-image Ken Burns config: [scaleStart, scaleEnd, translateXEnd, translateYEnd] */
const KEN_BURNS: [number, number, string, string][] = [
  [1.0,  1.04, '-0.5%', '-0.3%'],
  [1.03, 1.0,  '0.3%',  '0.5%'],
  [1.0,  1.03, '0.4%',  '-0.2%'],
  [1.02, 1.0,  '-0.3%', '0.3%'],
  [1.0,  1.04, '0.2%',  '-0.4%'],
  [1.03, 1.0,  '-0.4%', '0.2%'],
];

const INTERVAL_MS = 10000;
const TRANSITION_MS = 2200;

export default function BackgroundCinematic() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [nextIndex, setNextIndex] = useState<number | null>(null);
  const [isTransitioning, setIsTransitioning] = useState(false);
  const scrollProgressRef = useRef(0);
  const overlayRef = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number>(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
  const prefersReducedMotionRef = useRef(false);

  // ── Scroll-reactive overlay: creates depth variation as user scrolls ──
  useEffect(() => {
    prefersReducedMotionRef.current = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const updateScrollOverlay = () => {
      const docHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = docHeight > 0 ? window.scrollY / docHeight : 0;
      scrollProgressRef.current = progress;

      if (overlayRef.current) {
        // Dynamic overlay: slightly darker in the middle sections, lighter at top/bottom
        // Creates a "breathing" depth effect as you scroll through different sections
        const midDip = Math.sin(progress * Math.PI); // peaks at 0.5, zero at 0/1
        const baseDarkness = 0.68;
        const scrollDarkness = baseDarkness + midDip * 0.08; // 0.68 → 0.76 → 0.68

        // Subtle color temperature shift: cool blue at top → warmer at middle → cool at bottom
        const warmth = midDip * 8; // degrees of hue shift

        overlayRef.current.style.cssText = `
          background: linear-gradient(
            180deg,
            rgba(2, 6, 23, ${scrollDarkness * 0.88}) 0%,
            rgba(2, 6, 23, ${scrollDarkness * 0.72}) 25%,
            rgba(2, 6, 23, ${scrollDarkness * 0.78}) 50%,
            rgba(2, 6, 23, ${scrollDarkness * 0.82}) 75%,
            rgba(2, 6, 23, 0.92) 100%
          );
          filter: hue-rotate(${warmth}deg);
          transition: filter 0.5s ease;
        `;
      }
      rafRef.current = requestAnimationFrame(updateScrollOverlay);
    };

    rafRef.current = requestAnimationFrame(updateScrollOverlay);

    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  // ── Background image rotation (preserved 10-second interval) ──
  const advanceImage = useCallback(() => {
    const next = (currentIndex + 1) % BG_IMAGES.length;
    setNextIndex(next);
    setIsTransitioning(true);

    setTimeout(() => {
      setCurrentIndex(next);
      setNextIndex(null);
      setIsTransitioning(false);
    }, TRANSITION_MS);
  }, [currentIndex]);

  useEffect(() => {
    timerRef.current = setInterval(advanceImage, INTERVAL_MS);
    return () => clearInterval(timerRef.current);
  }, [advanceImage]);

  const reducedMotion = prefersReducedMotionRef.current;

  return (
    <div
      className="fixed inset-0 z-0 overflow-hidden"
      role="presentation"
      aria-hidden="true"
    >
      {/* ── Image layers: fixed to viewport, always visible ── */}
      <div className="absolute inset-0">
        {/* Current image */}
        <BackgroundImage
          src={BG_IMAGES[currentIndex]}
          index={currentIndex}
          state={isTransitioning ? 'exiting' : 'active'}
          reducedMotion={reducedMotion}
        />

        {/* Incoming image (during transition) */}
        {nextIndex !== null && (
          <BackgroundImage
            src={BG_IMAGES[nextIndex]}
            index={nextIndex}
            state="entering"
            reducedMotion={reducedMotion}
          />
        )}
      </div>

      {/* ── Layer 1: Scroll-reactive gradient overlay ── */}
      <div
        ref={overlayRef}
        className="absolute inset-0 z-10 pointer-events-none"
        style={{
          background: `linear-gradient(180deg,
            rgba(2, 6, 23, 0.70) 0%,
            rgba(2, 6, 23, 0.60) 25%,
            rgba(2, 6, 23, 0.65) 50%,
            rgba(2, 6, 23, 0.68) 75%,
            rgba(2, 6, 23, 0.95) 100%
          )`,
        }}
      />

      {/* ── Layer 1.5: Hacker Hex Grid & Scanline ── */}
      <div className="absolute inset-0 z-10 pointer-events-none opacity-[0.15] bg-hex-grid mix-blend-screen" />
      <div className="absolute inset-0 z-10 pointer-events-none crt-scanline opacity-[0.25]" />

      {/* ── Layer 2: Cinematic vignette — draws eye to center ── */}
      <div
        className="absolute inset-0 z-10 pointer-events-none"
        style={{
          background: `radial-gradient(
            ellipse 70% 60% at 50% 40%,
            transparent 0%,
            rgba(2, 6, 23, 0.15) 50%,
            rgba(2, 6, 23, 0.55) 100%
          )`,
        }}
      />

      {/* ── Layer 3: Film grain texture — ultra-subtle cinematic quality ── */}
      <div
        className="absolute inset-0 z-10 pointer-events-none opacity-[0.035] mix-blend-overlay"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`,
          backgroundRepeat: 'repeat',
          backgroundSize: '128px 128px',
        }}
      />

      {/* ── Layer 4: Top edge fade — nav blends seamlessly ── */}
      <div
        className="absolute top-0 left-0 right-0 h-32 z-10 pointer-events-none"
        style={{
          background: 'linear-gradient(to bottom, rgba(2, 6, 23, 0.6) 0%, transparent 100%)',
        }}
      />

      {/* ── Layer 5: Subtle branded accent glow ── */}
      <div
        className="absolute inset-0 z-10 pointer-events-none opacity-[0.06]"
        style={{
          background: `radial-gradient(
            ellipse 50% 30% at 50% 20%,
            rgba(37, 99, 235, 0.6) 0%,
            transparent 70%
          )`,
        }}
      />
    </div>
  );
}

/* ─── Individual background image layer ─── */
interface BackgroundImageProps {
  src: string;
  index: number;
  state: 'active' | 'entering' | 'exiting';
  reducedMotion: boolean;
}

function BackgroundImage({ src, index, state, reducedMotion }: BackgroundImageProps) {
  const imgRef = useRef<HTMLDivElement>(null);
  const kenBurnsRef = useRef<number>(0);
  const startTimeRef = useRef(performance.now());

  // Ken Burns pan-zoom animation — subtle, cinematic drift
  useEffect(() => {
    if (reducedMotion || state === 'exiting') return;

    const el = imgRef.current;
    if (!el) return;

    startTimeRef.current = performance.now();
    const [scaleStart, scaleEnd, txEnd, tyEnd] = KEN_BURNS[index];

    const animate = () => {
      const elapsed = performance.now() - startTimeRef.current;
      const progress = Math.min(elapsed / INTERVAL_MS, 1);
      const scale = scaleStart + (scaleEnd - scaleStart) * progress;
      const tx = parseFloat(txEnd) * progress;
      const ty = parseFloat(tyEnd) * progress;

      el.style.transform = `scale(${scale}) translate(${tx}%, ${ty}%)`;
      kenBurnsRef.current = requestAnimationFrame(animate);
    };

    kenBurnsRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(kenBurnsRef.current);
  }, [index, state, reducedMotion]);

  // Transition states
  const transitionStyle: React.CSSProperties = (() => {
    if (reducedMotion) {
      return {
        opacity: state === 'exiting' ? 0 : 1,
        transition: `opacity ${TRANSITION_MS}ms ease`,
      };
    }

    switch (state) {
      case 'active':
        return { opacity: 1 };
      case 'entering':
        return {
          opacity: 1,
          animation: `bgEnter ${TRANSITION_MS}ms cubic-bezier(0.16, 1, 0.3, 1) forwards`,
        };
      case 'exiting':
        return {
          animation: `bgExit ${TRANSITION_MS}ms cubic-bezier(0.16, 1, 0.3, 1) forwards`,
        };
    }
  })();

  return (
    <div
      ref={imgRef}
      className="absolute inset-0"
      style={{
        ...transitionStyle,
        willChange: state === 'active' ? 'transform' : 'transform, opacity, filter',
      }}
    >
      <Image
        src={src}
        alt=""
        fill
        sizes="100vw"
        quality={85}
        priority={index === 0}
        className="object-cover object-center"
        style={{
          /* Unified color-grade: cinematic desaturation with slight cool tone */
          filter: 'brightness(0.8) contrast(1.15) saturate(0.6) hue-rotate(-5deg)',
        }}
      />
    </div>
  );
}
