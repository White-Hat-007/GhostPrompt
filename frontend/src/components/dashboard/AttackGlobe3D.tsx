'use client';

import { useEffect, useRef, useCallback, useMemo } from 'react';
import createGlobe from 'cobe';

interface AttackGlobe3DProps {
  attacks?: Array<{
    lat?: number;
    lng?: number;
    threat_level?: string;
    action?: string;
  }>;
  className?: string;
  size?: number;
}

export default function AttackGlobe3D({ attacks = [], className = '', size = 500 }: AttackGlobe3DProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pointerInteracting = useRef<{ x: number; y: number } | null>(null);
  const movementRef = useRef({ x: 0, y: 0 });
  const phiRef = useRef(0);
  const thetaRef = useRef(0.25);
  const globeRef = useRef<ReturnType<typeof createGlobe> | null>(null);
  const animFrameRef = useRef<number>(0);

  // Convert live attacks to cobe markers — reactive to data changes
  const markers = useMemo(() => {
    const liveMarkers = attacks
      .filter(a => a.lat != null && a.lng != null && a.lat !== 0 && a.lng !== 0)
      .slice(0, 250)
      .map(a => ({
        location: [a.lat!, a.lng!] as [number, number],
        size: a.threat_level === 'critical' ? 0.14 :
              a.threat_level === 'high' ? 0.1 :
              a.threat_level === 'medium' ? 0.07 : 0.05,
      }));

    // If no live data, show demo markers
    if (liveMarkers.length === 0) {
      return [
        { location: [37.77, -122.42] as [number, number], size: 0.06 },
        { location: [51.51, -0.13] as [number, number], size: 0.08 },
        { location: [35.68, 139.65] as [number, number], size: 0.07 },
        { location: [1.35, 103.82] as [number, number], size: 0.05 },
        { location: [-33.87, 151.21] as [number, number], size: 0.04 },
        { location: [52.52, 13.41] as [number, number], size: 0.06 },
        { location: [19.08, 72.88] as [number, number], size: 0.09 },
        { location: [55.76, 37.62] as [number, number], size: 0.07 },
        { location: [39.90, 116.41] as [number, number], size: 0.1 },
        { location: [-23.55, -46.63] as [number, number], size: 0.05 },
        { location: [48.86, 2.35] as [number, number], size: 0.06 },
        { location: [40.71, -74.01] as [number, number], size: 0.08 },
      ];
    }
    return liveMarkers;
  }, [attacks]);

  // Pointer handlers for full 360° drag rotation (both axes)
  const onPointerDown = useCallback((e: React.PointerEvent) => {
    pointerInteracting.current = { x: e.clientX, y: e.clientY };
    if (canvasRef.current) canvasRef.current.style.cursor = 'grabbing';
  }, []);

  const onPointerUp = useCallback(() => {
    if (pointerInteracting.current) {
      // Commit the current drag offset into the base phi/theta so rotation persists
      phiRef.current += movementRef.current.x / 150;
      thetaRef.current += movementRef.current.y / 150;
      // Clamp theta to prevent flipping
      thetaRef.current = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, thetaRef.current));
      movementRef.current = { x: 0, y: 0 };
    }
    pointerInteracting.current = null;
    if (canvasRef.current) canvasRef.current.style.cursor = 'grab';
  }, []);

  const onPointerOut = useCallback(() => {
    if (pointerInteracting.current) {
      phiRef.current += movementRef.current.x / 150;
      thetaRef.current += movementRef.current.y / 150;
      thetaRef.current = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, thetaRef.current));
      movementRef.current = { x: 0, y: 0 };
    }
    pointerInteracting.current = null;
    if (canvasRef.current) canvasRef.current.style.cursor = 'grab';
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (pointerInteracting.current) {
      movementRef.current = {
        x: e.clientX - pointerInteracting.current.x,
        y: e.clientY - pointerInteracting.current.y,
      };
    }
  }, []);

  // Create globe + animation loop
  useEffect(() => {
    if (!canvasRef.current) return;

    let width = canvasRef.current.offsetWidth;

    const globe = createGlobe(canvasRef.current, {
      devicePixelRatio: 2,
      width: width * 2,
      height: width * 2,
      phi: 0,
      theta: 0.25,
      dark: 1,
      diffuse: 1.2,
      mapSamples: 16000,
      mapBrightness: 2.5,
      baseColor: [0.15, 0.18, 0.25],
      markerColor: [0.23, 0.51, 0.96],
      glowColor: [0.08, 0.12, 0.22],
      markers,
    });

    globeRef.current = globe;

    // Animation loop — auto-rotate + live drag
    const animate = () => {
      if (!pointerInteracting.current) {
        phiRef.current += 0.003; // Auto-rotate when not dragging
      }

      const dragPhi = pointerInteracting.current ? movementRef.current.x / 150 : 0;
      const dragTheta = pointerInteracting.current ? movementRef.current.y / 150 : 0;

      globe.update({
        phi: phiRef.current + dragPhi,
        theta: Math.max(-Math.PI / 2, Math.min(Math.PI / 2, thetaRef.current + dragTheta)),
        width: width * 2,
        height: width * 2,
      });
      animFrameRef.current = requestAnimationFrame(animate);
    };
    animFrameRef.current = requestAnimationFrame(animate);

    // Fade in
    setTimeout(() => {
      if (canvasRef.current) canvasRef.current.style.opacity = '1';
    }, 100);

    const onResize = () => {
      if (canvasRef.current) width = canvasRef.current.offsetWidth;
    };
    window.addEventListener('resize', onResize);

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      globe.destroy();
      window.removeEventListener('resize', onResize);
    };
  }, []); // Only create globe once

  // Update markers reactively when attack data changes (without recreating globe)
  useEffect(() => {
    if (globeRef.current) {
      globeRef.current.update({ markers });
    }
  }, [markers]);

  return (
    <div className={`relative ${className}`}>
      {/* Atmospheric ring glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.08) 0%, transparent 60%)',
        }}
      />

      <canvas
        ref={canvasRef}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onPointerOut={onPointerOut}
        onPointerMove={onPointerMove}
        className="w-full aspect-square transition-opacity duration-1000 cursor-grab"
        style={{
          opacity: 0,
          contain: 'layout paint size',
          maxWidth: `${size}px`,
          margin: '0 auto',
        }}
      />

      {/* Bottom fade-out */}
      <div className="absolute bottom-0 left-0 right-0 h-12 bg-gradient-to-t from-surface-0 to-transparent pointer-events-none" />
    </div>
  );
}
