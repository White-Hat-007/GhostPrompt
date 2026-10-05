import React from 'react';
import { Shield } from 'lucide-react';

interface GhostLogoProps {
  className?: string;
  showIcon?: boolean;
}

export default function GhostLogo({ className = "text-xl", showIcon = true }: GhostLogoProps) {
  return (
    <div className={`group flex items-center gap-3 cursor-pointer ${className}`}>
      {showIcon && (
        <div className="relative">
          {/* Base shield background with neon glow */}
          <div className="w-8 h-8 bg-surface-0 border border-ghost-500/40 flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.2)] transition-all duration-500 group-hover:shadow-neon-blue group-hover:border-cyber-500/60 relative overflow-hidden rounded-sm">
            {/* Scanline overlay */}
            <div className="absolute inset-0 pointer-events-none opacity-20 bg-[repeating-linear-gradient(0deg,transparent,transparent_1px,rgba(59,130,246,0.15)_1px,rgba(59,130,246,0.15)_2px)]" />
            {/* Animated gradient sweep on hover */}
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none"
              style={{ background: 'linear-gradient(135deg, rgba(59,130,246,0.15) 0%, transparent 50%, rgba(6,182,212,0.1) 100%)' }}
            />
            <Shield className="w-4 h-4 text-ghost-400 transition-all duration-300 group-hover:scale-110 group-hover:text-cyber-400 relative z-10" />
          </div>
          {/* Status indicator dot with enhanced glow */}
          <div className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-hacker shadow-[0_0_8px_rgba(0,255,136,0.8)] animate-pulse transition-all duration-500 group-hover:bg-cyber-400 group-hover:shadow-[0_0_15px_rgba(6,182,212,1)] rounded-sm" />
        </div>
      )}
      
      <div className="relative flex items-center font-hacker font-bold tracking-wider uppercase text-[15px]">
        <span className="text-ghost-400 mr-2 opacity-80 group-hover:text-cyber-400 transition-colors duration-300">&gt;</span>
        
        {/* Main Text with enhanced hover transform */}
        <span className="text-white drop-shadow-[0_0_5px_rgba(255,255,255,0.2)] transition-all duration-300 group-hover:-translate-x-0.5 group-hover:-translate-y-0.5">
          GHOST<span className="text-cyber-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)] group-hover:text-cyber-300 group-hover:drop-shadow-[0_0_15px_rgba(6,182,212,1)]">_PROMPT</span>
        </span>

        {/* Subtle glitch line on hover */}
        <div className="absolute top-1/2 left-0 w-full h-[2px] bg-cyber-400/0 transition-all duration-300 group-hover:bg-cyber-400/60 group-hover:animate-ping mix-blend-screen" />
      </div>
    </div>
  );
}
