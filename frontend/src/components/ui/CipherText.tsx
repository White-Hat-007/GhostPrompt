'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

/**
 * #5 — Cipher-Decode Headline Reveal (ELITE)
 * Characters "decrypt" from scrambled glyphs with per-character color
 * transitions and optional holographic shimmer after resolve.
 */

interface CipherTextProps {
  text: string;
  tag?: 'h2' | 'h3' | 'span';
  className?: string;
  duration?: number;
  /** Enable gradient shimmer after decode completes */
  shimmer?: boolean;
}

const CIPHER_CHARS = '▓░▒█▄▀│─┼╬◆◇○●◐◑⊕⊗∎∷₿Ψ∞Σ∆λ';

export default function CipherText({
  text,
  tag: Tag = 'h2',
  className = '',
  duration = 800,
  shimmer = false,
}: CipherTextProps) {
  const containerRef = useRef<HTMLElement>(null);
  const [displayChars, setDisplayChars] = useState<{ char: string; resolved: boolean }[]>(
    text.split('').map(c => ({ char: c, resolved: false }))
  );
  const [hasDecoded, setHasDecoded] = useState(false);
  const [decodeComplete, setDecodeComplete] = useState(false);
  const reducedMotion = useRef(false);

  useEffect(() => {
    reducedMotion.current = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }, []);

  const decode = useCallback(() => {
    if (hasDecoded || reducedMotion.current) return;
    setHasDecoded(true);

    const chars = text.split('');
    const totalSteps = 14;
    const stepDuration = duration / totalSteps;
    let step = 0;

    const interval = setInterval(() => {
      step++;
      const progress = step / totalSteps;

      const decoded = chars.map((char, i) => {
        if (char === ' ' || char === '\n') return { char, resolved: true };

        const charProgress = (progress - (i / chars.length) * 0.5) / 0.5;

        if (charProgress >= 1) return { char, resolved: true };
        if (charProgress <= 0) {
          return {
            char: CIPHER_CHARS[Math.floor(Math.random() * CIPHER_CHARS.length)],
            resolved: false,
          };
        }

        return Math.random() < charProgress
          ? { char, resolved: true }
          : { char: CIPHER_CHARS[Math.floor(Math.random() * CIPHER_CHARS.length)], resolved: false };
      });

      setDisplayChars(decoded);

      if (step >= totalSteps) {
        clearInterval(interval);
        setDisplayChars(chars.map(c => ({ char: c, resolved: true })));
        setDecodeComplete(true);
      }
    }, stepDuration);
  }, [text, duration, hasDecoded]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    if (reducedMotion.current) {
      setDisplayChars(text.split('').map(c => ({ char: c, resolved: true })));
      setDecodeComplete(true);
      return;
    }

    // Start with scrambled text
    setDisplayChars(
      text.split('').map(c =>
        c === ' ' || c === '\n'
          ? { char: c, resolved: true }
          : { char: CIPHER_CHARS[Math.floor(Math.random() * CIPHER_CHARS.length)], resolved: false }
      )
    );

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          decode();
          observer.disconnect();
        }
      },
      { threshold: 0.25 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [text, decode]);

  // Render with per-character styling
  return (
    <Tag
      ref={containerRef as React.Ref<HTMLHeadingElement>}
      className={`${className} ${shimmer && decodeComplete ? 'text-gradient-premium' : ''}`}
      style={{ fontVariantNumeric: 'tabular-nums' }}
    >
      {displayChars.map((item, i) => (
        <span
          key={i}
          style={{
            color: item.resolved ? undefined : 'rgba(59, 130, 246, 0.4)',
            transition: 'color 0.15s ease',
            display: 'inline',
          }}
        >
          {item.char}
        </span>
      ))}
    </Tag>
  );
}
