/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // ── Primary brand: Electric blue / deep azure (PRESERVED) ──
        ghost: {
          50:  '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#0f1d4a',
        },
        // ── Secondary: Cyber cyan (PRESERVED) ──
        cyber: {
          50:  '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
        },
        // ── Threat severity (PRESERVED) ──
        threat: {
          safe:     '#00ff88',
          low:      '#3b82f6',
          medium:   '#f59e0b',
          high:     '#ef4444',
          critical: '#dc2626',
        },
        // ── Surface: Deep navy-black tones ──
        surface: {
          0:  '#020617',
          '05': '#060B15',
          1:  '#0a1020',
          '15': '#0D1525',
          2:  '#111827',
          3:  '#1e293b',
          4:  '#293548',
          5:  '#334155',
          6:  '#475569',
        },
        // ── Terminal / hacker green (PRESERVED) ──
        hacker: '#00ff88',
        // ── ATLAS technique taxonomy colors (PRESERVED) ──
        atlas: {
          recon:      '#818cf8',
          resource:   '#a78bfa',
          access:     '#c084fc',
          staging:    '#e879f9',
          execution:  '#f472b6',
          persist:    '#fb923c',
          escalation: '#fbbf24',
          evasion:    '#34d399',
          discovery:  '#2dd4bf',
          collection: '#38bdf8',
          exfil:      '#f87171',
          impact:     '#ef4444',
        },
        // ── Enterprise neutral scale ──
        steel: {
          50:  '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['"Plus Jakarta Sans"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        hacker: ['Orbitron', 'sans-serif'],
      },
      fontSize: {
        'display-xl': ['3.5rem', { lineHeight: '1.1', letterSpacing: '-0.02em', fontWeight: '800' }],
        'display-lg': ['2.5rem', { lineHeight: '1.15', letterSpacing: '-0.02em', fontWeight: '800' }],
        'display-md': ['2rem', { lineHeight: '1.2', letterSpacing: '-0.01em', fontWeight: '700' }],
        'display-sm': ['1.5rem', { lineHeight: '1.25', letterSpacing: '-0.01em', fontWeight: '700' }],
        'label-lg':   ['0.875rem', { lineHeight: '1.25', letterSpacing: '0.01em', fontWeight: '600' }],
        'label-md':   ['0.75rem', { lineHeight: '1.25', letterSpacing: '0.02em', fontWeight: '600' }],
        'label-sm':   ['0.625rem', { lineHeight: '1.2', letterSpacing: '0.05em', fontWeight: '700' }],
        'mono-sm':    ['0.6875rem', { lineHeight: '1.4', letterSpacing: '0.03em', fontWeight: '500' }],
        'mono-xs':    ['0.5625rem', { lineHeight: '1.3', letterSpacing: '0.04em', fontWeight: '500' }],
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'slide-up': 'slide-up 0.3s ease-out',
        'slide-down': 'slide-down 0.3s ease-out',
        'fade-in': 'fade-in 0.2s ease-out',
        'scan-line': 'scan-line 6s linear infinite',
        'blink': 'blink 1s step-end infinite',
        'radar-sweep': 'radar-sweep 4s linear infinite',
        'slide-in-right': 'slide-in-right 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
        'slide-out-right': 'slide-out-right 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
        'count-up': 'count-up 1.8s ease-out',
        'marquee': 'marquee 35s linear infinite',
        'marquee-reverse': 'marquee-reverse 35s linear infinite',
        'sonar-ping': 'sonar-ping 2s ease-out infinite',
        'threat-pulse': 'threat-pulse 1.5s ease-in-out infinite',
        // ── ELITE animations ──
        'float-3d': 'float-3d 6s ease-in-out infinite',
        'neon-pulse': 'neon-pulse 2s ease-in-out infinite',
        'shimmer': 'shimmer-sweep 3s linear infinite',
        'energy-wave': 'energy-wave 3s ease-in-out infinite',
        'holo-shift': 'holo-shift 6s ease-in-out infinite',
        'gradient-shift': 'gradient-shift 4s ease-in-out infinite',
        'flow-dash': 'flow-dash 2s linear infinite',
        'border-rotate': 'border-rotate 4s linear infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'slide-down': {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'blink': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'radar-sweep': {
          '0%':   { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        'slide-in-right': {
          '0%': { transform: 'translateX(100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        'slide-out-right': {
          '0%': { transform: 'translateX(0)', opacity: '1' },
          '100%': { transform: 'translateX(100%)', opacity: '0' },
        },
        'marquee': {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        'marquee-reverse': {
          '0%': { transform: 'translateX(-50%)' },
          '100%': { transform: 'translateX(0)' },
        },
        'sonar-ping': {
          '0%': { transform: 'scale(0.5)', opacity: '0.8' },
          '100%': { transform: 'scale(2.5)', opacity: '0' },
        },
        'threat-pulse': {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(59, 130, 246, 0.4)' },
          '50%': { boxShadow: '0 0 0 8px rgba(59, 130, 246, 0)' },
        },
        // ── ELITE keyframes ──
        'float-3d': {
          '0%, 100%': { transform: 'translateY(0) rotateX(0) rotateY(0)' },
          '25%': { transform: 'translateY(-8px) rotateX(2deg) rotateY(-1deg)' },
          '75%': { transform: 'translateY(4px) rotateX(-1deg) rotateY(2deg)' },
        },
        'neon-pulse': {
          '0%, 100%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.2), 0 0 15px rgba(59, 130, 246, 0.1)' },
          '50%': { boxShadow: '0 0 15px rgba(59, 130, 246, 0.4), 0 0 40px rgba(59, 130, 246, 0.15)' },
        },
        'shimmer-sweep': {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'energy-wave': {
          '0%': { transform: 'translateX(-100%)', opacity: '0' },
          '50%': { opacity: '1' },
          '100%': { transform: 'translateX(100%)', opacity: '0' },
        },
        'holo-shift': {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        'gradient-shift': {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        'flow-dash': {
          '0%': { strokeDashoffset: '0' },
          '100%': { strokeDashoffset: '-20' },
        },
        'border-rotate': {
          '0%': { '--border-angle': '0deg' },
          '100%': { '--border-angle': '360deg' },
        },
      },
      backdropBlur: {
        xs: '2px',
        '3xl': '64px',
      },
      boxShadow: {
        'glow-blue':  '0 0 20px rgba(59,130,246,0.25), 0 0 60px rgba(59,130,246,0.08)',
        'glow-cyan':  '0 0 20px rgba(6,182,212,0.25), 0 0 60px rgba(6,182,212,0.08)',
        'glow-green': '0 0 15px rgba(0,255,136,0.25)',
        'glow-red':   '0 0 20px rgba(239,68,68,0.3), 0 0 60px rgba(239,68,68,0.1)',
        // ── Enterprise shadows ──
        'enterprise-sm': '0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.03)',
        'enterprise-md': '0 4px 12px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04)',
        'enterprise-lg': '0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05)',
        'enterprise-xl': '0 16px 48px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.05)',
        'inner-glow':    'inset 0 1px 0 rgba(255,255,255,0.04), inset 0 0 20px rgba(59,130,246,0.03)',
        'panel':         '0 0 0 1px rgba(255,255,255,0.06), 0 2px 8px rgba(0,0,0,0.4)',
        // ── 3D Depth shadows ──
        'depth-3d':      '0 20px 50px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.05)',
        'neon-blue':     '0 0 15px rgba(59,130,246,0.4), 0 0 40px rgba(59,130,246,0.15), 0 0 80px rgba(59,130,246,0.05)',
        'neon-cyan':     '0 0 15px rgba(6,182,212,0.4), 0 0 40px rgba(6,182,212,0.15), 0 0 80px rgba(6,182,212,0.05)',
        'neon-green':    '0 0 15px rgba(0,255,136,0.4), 0 0 40px rgba(0,255,136,0.15)',
      },
      borderRadius: {
        'enterprise': '0.625rem',
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '100': '25rem',
        '120': '30rem',
      },
      transitionTimingFunction: {
        'expo-out': 'cubic-bezier(0.16, 1, 0.3, 1)',
        'enterprise': 'cubic-bezier(0.25, 0.46, 0.45, 0.94)',
        'bounce-out': 'cubic-bezier(0.34, 1.56, 0.64, 1)',
      },
    },
  },
  plugins: [],
};
