'use client';

import { useRef, useCallback, useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';

interface MagneticButtonProps {
  children: React.ReactNode;
  href?: string;
  variant?: 'primary' | 'secondary' | 'ghost';
  magneticRadius?: number;
  magneticStrength?: number;
  className?: string;
  onClick?: () => void;
  id?: string;
}

export default function MagneticButton({
  children,
  href,
  variant = 'primary',
  magneticRadius = 60,
  magneticStrength = 4,
  className = '',
  onClick,
  id,
}: MagneticButtonProps) {
  const buttonRef = useRef<HTMLDivElement>(null);
  const innerRef = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number>(0);
  const [isPressed, setIsPressed] = useState(false);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      const btn = buttonRef.current;
      const inner = innerRef.current;
      if (!btn || !inner) return;
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

      const rect = btn.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const dx = e.clientX - centerX;
      const dy = e.clientY - centerY;
      const distance = Math.sqrt(dx * dx + dy * dy);

      if (distance < magneticRadius) {
        const pull = (1 - distance / magneticRadius) * magneticStrength;
        cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(() => {
          inner.style.transform = `translate(${dx * pull * 0.08}px, ${dy * pull * 0.08}px) translateY(-2px)`;
        });
      }
    },
    [magneticRadius, magneticStrength],
  );

  const handleMouseLeave = useCallback(() => {
    const inner = innerRef.current;
    if (!inner) return;
    cancelAnimationFrame(rafRef.current);
    inner.style.transform = 'translate(0, 0)';
  }, []);

  const variantClasses: Record<string, string> = {
    primary: `
      relative overflow-hidden text-white font-semibold
      bg-gradient-to-r from-ghost-600 to-cyber-700
      shadow-[0_2px_8px_rgba(37,99,235,0.25)]
      hover:shadow-[0_4px_24px_rgba(37,99,235,0.4)]
      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ghost-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0
    `,
    secondary: `
      text-ghost-400 border border-ghost-500/20 bg-transparent
      hover:bg-ghost-600/10 hover:text-ghost-300 hover:border-ghost-500/40
      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ghost-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0
    `,
    ghost: `
      text-gray-400 border border-white/10 bg-transparent
      hover:bg-surface-3 hover:text-white hover:border-white/20
      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ghost-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0
    `,
  };

  const baseClasses = `
    inline-flex items-center justify-center gap-2
    px-6 py-3 rounded-xl text-sm
    transition-all duration-300
    cursor-pointer select-none
  `;

  const content = (
    <div
      ref={buttonRef}
      className="relative group/magnetic"
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onMouseDown={() => setIsPressed(true)}
      onMouseUp={() => setIsPressed(false)}
    >
      <div
        ref={innerRef}
        className={`${baseClasses} ${variantClasses[variant]} ${className}`}
        style={{
          transition: 'transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.3s ease',
          transform: isPressed ? 'scale(0.97) translateY(1px)' : undefined,
        }}
      >
        {/* Animated gradient sheen on primary hover */}
        {variant === 'primary' && (
          <>
            <div
              className="absolute inset-0 rounded-xl opacity-0 hover-parent-sheen"
              style={{
                background: 'linear-gradient(105deg, transparent 40%, rgba(255,255,255,0.12) 45%, rgba(255,255,255,0.06) 50%, transparent 55%)',
                backgroundSize: '250% 100%',
                backgroundPosition: '200% 0',
              }}
              aria-hidden="true"
            />
            {/* Animated gradient border */}
            <div
              className="absolute -inset-px rounded-xl opacity-0 group-hover/magnetic:opacity-100 transition-opacity duration-500 pointer-events-none"
              style={{
                background: 'conic-gradient(from 0deg, rgba(59,130,246,0.3), rgba(6,182,212,0.2), rgba(139,92,246,0.2), rgba(59,130,246,0.3))',
                mask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
                maskComposite: 'xor',
                WebkitMaskComposite: 'xor',
                padding: '1px',
              } as any}
              aria-hidden="true"
            />
          </>
        )}
        <span className="relative z-10 flex items-center gap-2">{children}</span>
      </div>
    </div>
  );

  if (href) {
    return (
      <Link href={href} id={id} className="no-underline">
        {content}
      </Link>
    );
  }

  return (
    <button type="button" onClick={onClick} id={id} className="bg-transparent border-none p-0">
      {content}
    </button>
  );
}
