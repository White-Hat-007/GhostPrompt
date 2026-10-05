'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps';
import { motion, AnimatePresence } from 'framer-motion';
import { Target, RefreshCw, Activity } from 'lucide-react';

const geoUrl = "https://unpkg.com/world-atlas@2.0.2/countries-110m.json";

interface GlobalThreatMapProps {
  className?: string;
  attacks?: any[]; 
  onAttackClick?: (attack: any) => void;
  isDashboard?: boolean;
}

export default function GlobalThreatMap({ className = '', attacks = [], onAttackClick, isDashboard = false }: GlobalThreatMapProps) {
  const [selectedMarker, setSelectedMarker] = useState<any | null>(null);
  const [hoveredMarker, setHoveredMarker] = useState<any | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number, y: number } | null>(null);
  const [position, setPosition] = useState({ coordinates: [0, 20], zoom: 1 });

  const containerRef = useRef<HTMLDivElement>(null);

  // Parse backend data into map markers
  const rawMarkers = useMemo(() => {
    return attacks.map((attack, i) => {
      const threatLower = (attack.threat_level || 'low').toLowerCase();
      let color = '#3b82f6'; // low
      let glowColor = 'rgba(59, 130, 246, 0.6)';
      if (threatLower === 'medium') { color = '#06b6d4'; glowColor = 'rgba(6, 182, 212, 0.6)'; }
      if (threatLower === 'high') { color = '#f59e0b'; glowColor = 'rgba(245, 158, 11, 0.6)'; }
      if (threatLower === 'critical') { color = '#ef4444'; glowColor = 'rgba(239, 68, 68, 0.6)'; }

      return {
        id: attack.id || `att-${i}`,
        city: attack.city || 'Unknown',
        country: attack.country || 'Unknown',
        ip: attack.ip || '127.0.0.1',
        threat_level: threatLower.toUpperCase(),
        scan_type: attack.scan_type?.toUpperCase() || 'PROMPT INJECTION',
        coordinates: [
          (attack.lng || 0) + (Math.cos(i * 137.5 * (Math.PI / 180)) * ((i % 10) * 0.1)), 
          (attack.lat || 0) + (Math.sin(i * 137.5 * (Math.PI / 180)) * ((i % 10) * 0.1))
        ] as [number, number],
        isCritical: threatLower === 'critical',
        color,
        glowColor,
        rawAttack: attack
      };
    });
  }, [attacks]);

  // Geographic Grid Clustering Algorithm O(N)
  const clusteredMarkers = useMemo(() => {
    const gridSizeDegrees = 15 / position.zoom; 
    const grid = new Map<string, any[]>();

    rawMarkers.forEach(marker => {
      const x = Math.floor(marker.coordinates[0] / gridSizeDegrees);
      const y = Math.floor(marker.coordinates[1] / gridSizeDegrees);
      const key = `${x},${y}`;
      if (!grid.has(key)) grid.set(key, []);
      grid.get(key)!.push(marker);
    });

    const clusters: any[] = [];
    grid.forEach(group => {
      if (group.length === 1) {
        clusters.push({ ...group[0], isCluster: false });
      } else {
        // Compute center of mass
        const avgLng = group.reduce((sum, m) => sum + m.coordinates[0], 0) / group.length;
        const avgLat = group.reduce((sum, m) => sum + m.coordinates[1], 0) / group.length;
        
        // Inherit highest severity in cluster
        let maxColor = '#3b82f6';
        if (group.some(m => m.color === '#ef4444')) maxColor = '#ef4444';
        else if (group.some(m => m.color === '#f59e0b')) maxColor = '#f59e0b';
        else if (group.some(m => m.color === '#06b6d4')) maxColor = '#06b6d4';

        clusters.push({
          id: `cluster-${avgLng}-${avgLat}`,
          coordinates: [avgLng, avgLat],
          isCluster: true,
          count: group.length,
          color: maxColor,
          children: group
        });
      }
    });
    
    return clusters;
  }, [rawMarkers, position.zoom]);

  // Handle native scroll/touchpad wheel zooming natively
  useEffect(() => {
    const mapContainer = containerRef.current;
    if (!mapContainer) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault(); 
      setSelectedMarker(null);
      setHoveredMarker(null);

      const zoomFactor = 1.15;
      const scale = e.deltaY < 0 ? zoomFactor : 1 / zoomFactor;

      setPosition(prev => {
        const nextZoom = prev.zoom * scale;
        const clampedZoom = Math.min(Math.max(1, nextZoom), 15);
        return { ...prev, zoom: clampedZoom };
      });
    };

    mapContainer.addEventListener('wheel', handleWheel, { passive: false });
    return () => mapContainer.removeEventListener('wheel', handleWheel);
  }, []);

  const handleReset = () => {
    setPosition({ coordinates: [0, 20], zoom: 1 });
    setSelectedMarker(null);
    setHoveredMarker(null);
  };

  const handleMouseEnter = (e: React.MouseEvent, m: any) => {
    if (selectedMarker) return;
    setHoveredMarker(m);
    const rect = e.currentTarget.getBoundingClientRect();
    const containerRect = containerRef.current?.getBoundingClientRect();
    if (containerRect) {
      setTooltipPos({
        x: rect.left - containerRect.left + rect.width / 2,
        y: rect.top - containerRect.top - 10
      });
    }
  };

  const handleMouseLeave = () => {
    if (selectedMarker) return;
    setHoveredMarker(null);
  };

  const handleMarkerClick = (e: React.MouseEvent, m: any) => {
    e.stopPropagation();
    
    if (m.isCluster) {
      // Zoom into cluster
      setPosition({ coordinates: m.coordinates, zoom: Math.min(15, position.zoom * 2) });
      if (onAttackClick) {
        onAttackClick(m);
      }
      return;
    }

    setPosition({ coordinates: m.coordinates, zoom: position.zoom });
    setHoveredMarker(null);
    
    // Bubble up to parent
    if (onAttackClick && m.rawAttack) {
      onAttackClick(m.rawAttack);
    }
  };

  const activeMarker = hoveredMarker;

  return (
    <div className={`w-full rounded-2xl border border-[#1e293b] bg-[#050914] overflow-hidden flex flex-col shadow-[0_0_50px_-12px_rgba(59,130,246,0.1)] ${className}`}>
      
      {/* ELITE HACKER HEADER */}
      <div className="flex items-center justify-between p-4 border-b border-[#1e293b] bg-[#080d1e] relative overflow-hidden">
        <div className="absolute inset-0 bg-[url('/bg/scanlines.png')] opacity-10 pointer-events-none mix-blend-overlay" />
        
        <div className="flex items-center gap-4 relative z-10">
          <div className="w-10 h-10 rounded-lg bg-[#0f172a] border border-[#1e293b] flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
            <Target className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h3 className="text-white font-bold tracking-wider text-sm font-mono flex items-center gap-2">
              GLOBAL THREAT ORIGIN MAP
              <span className="px-1.5 py-0.5 rounded-sm bg-blue-500/20 text-blue-400 text-[9px] uppercase">Active</span>
            </h3>
            <p className="text-[10px] text-gray-500 font-mono mt-0.5 uppercase tracking-widest">
              Live Geospatial Telemetry // Auto-Clustering Enabled
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 relative z-10">
          <button 
            onClick={handleReset}
            className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#0f172a] hover:bg-[#1e293b] transition-all border border-[#1e293b] text-xs text-gray-400 font-mono hover:text-blue-400"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            RESET
          </button>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-red-500/50 bg-red-500/10 text-xs text-red-500 font-bold tracking-widest font-mono shadow-[0_0_10px_rgba(239,68,68,0.2)]">
            <Activity className="w-3.5 h-3.5 animate-pulse" />
            LIVE
          </div>
        </div>
      </div>

      {/* MAP VIEWPORT WITH GRIDS */}
      <div 
        ref={containerRef}
        className="relative w-full aspect-[16/9] bg-[#050a18] overflow-hidden select-none"
      >
        <div className="absolute inset-0 opacity-[0.03] pointer-events-none" 
             style={{ backgroundImage: 'linear-gradient(#3b82f6 1px, transparent 1px), linear-gradient(90deg, #3b82f6 1px, transparent 1px)', backgroundSize: '40px 40px' }} />
        
        <div className="absolute inset-0 shadow-[inset_0_0_100px_rgba(0,0,0,0.9)] pointer-events-none z-10" />

        <div className="absolute right-4 bottom-4 z-20 flex flex-col gap-2">
          <button
            onClick={() => {
              setSelectedMarker(null);
              setHoveredMarker(null);
              setPosition(pos => ({ ...pos, zoom: Math.min(15, pos.zoom * 1.5) }));
            }}
            className="w-8 h-8 flex items-center justify-center bg-[#0f172a]/90 hover:bg-[#1e293b] border border-[#1e293b] rounded-md text-white shadow-xl backdrop-blur-sm transition-all"
          >
            +
          </button>
          <button
            onClick={() => {
              setSelectedMarker(null);
              setHoveredMarker(null);
              setPosition(pos => ({ ...pos, zoom: Math.max(1, pos.zoom / 1.5) }));
            }}
            className="w-8 h-8 flex items-center justify-center bg-[#0f172a]/90 hover:bg-[#1e293b] border border-[#1e293b] rounded-md text-white shadow-xl backdrop-blur-sm transition-all"
          >
            -
          </button>
        </div>

        {/* Floating Tooltip HUD */}
        <AnimatePresence>
          {activeMarker && tooltipPos && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: -5 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.15 }}
              className="absolute z-30 pointer-events-none flex flex-col bg-[#050a18]/95 border border-[#1e293b] rounded p-3 shadow-[0_0_30px_rgba(0,0,0,0.8)] backdrop-blur-md w-[200px]"
              style={{
                left: `${tooltipPos.x}px`,
                top: `${tooltipPos.y}px`,
                transform: 'translate(-50%, -100%)',
                borderTop: `3px solid ${activeMarker.color}`
              }}
            >
              <div className="absolute inset-0 bg-[url('/bg/scanlines.png')] opacity-20 pointer-events-none rounded mix-blend-overlay" />
              
              {activeMarker.isCluster ? (
                <>
                  <div className="text-white font-bold text-sm tracking-wide text-center leading-tight">
                    THREAT CLUSTER
                  </div>
                  <div className="text-center">
                    <span className="text-[10px] text-gray-400 font-mono tracking-widest">{activeMarker.count} ATTACKS</span>
                  </div>
                  <div className="mt-2 space-y-0.5 border-t border-[#1e293b] pt-1.5 text-center">
                    <div className="text-[9px] font-mono text-gray-400">
                      {isDashboard 
                        ? "Go to Threat Attribution and click individual nodes to reveal details."
                        : "Click to reveal details."}
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="text-white font-bold text-sm tracking-wide text-center leading-tight">
                    {activeMarker.city}
                  </div>
                  <div className="text-center">
                    <span className="text-[10px] text-gray-400 font-mono tracking-widest">{activeMarker.country}</span>
                  </div>
                  
                  <div className="flex items-center justify-center gap-3 mt-1.5 text-[10px] font-mono text-blue-400 bg-blue-500/10 py-0.5 px-2 rounded-sm border border-blue-500/20">
                    <span>{activeMarker.coordinates[1].toFixed(4)}°</span>
                    <span className="text-blue-500/50">|</span>
                    <span>{activeMarker.coordinates[0].toFixed(4)}°</span>
                  </div>

                  <div className="mt-2 space-y-0.5 border-t border-[#1e293b] pt-1.5">
                    <div className="flex items-center justify-between gap-4 text-[9px] font-mono">
                      <span className="text-gray-500">IP</span>
                      <span className="text-gray-300">{activeMarker.ip}</span>
                    </div>
                    <div className="flex items-center justify-between gap-4 text-[9px] font-mono">
                      <span className="text-gray-500">BROWSER</span>
                      <span className="text-gray-300 truncate max-w-[90px] text-right" title={activeMarker.rawAttack?.browser_full || activeMarker.rawAttack?.browser}>{activeMarker.rawAttack?.browser || 'Unknown'}</span>
                    </div>
                    <div className="flex items-center justify-between gap-4 text-[9px] font-mono">
                      <span className="text-gray-500">OS</span>
                      <span className="text-gray-300 truncate max-w-[90px] text-right">{activeMarker.rawAttack?.os || 'Unknown'}</span>
                    </div>
                    <div className="flex items-center justify-between gap-4 text-[9px] font-mono">
                      <span className="text-gray-500">TYPE</span>
                      <span className="text-gray-300 truncate max-w-[90px] text-right" title={activeMarker.scan_type}>{activeMarker.scan_type}</span>
                    </div>
                    <div className="flex items-center justify-between gap-4 text-[9px] font-mono">
                      <span className="text-gray-500">THREAT</span>
                      <span style={{ color: activeMarker.color }} className="font-bold">{activeMarker.threat_level}</span>
                    </div>
                  </div>
                </>
              )}

              <div className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-3 h-3 bg-[#050a18] border-b border-r border-[#1e293b] rotate-45" />
            </motion.div>
          )}
        </AnimatePresence>

        <ComposableMap
          projectionConfig={{ scale: 130, center: [0, 0] }}
          width={800}
          height={450}
          style={{ width: "100%", height: "100%" }}
          onClick={() => setSelectedMarker(null)}
        >
          <ZoomableGroup
            zoom={position.zoom}
            center={position.coordinates as [number, number]}
            onMoveStart={() => {
              setSelectedMarker(null);
              setHoveredMarker(null);
            }}
            onMoveEnd={setPosition}
            maxZoom={15}
          >
            <Geographies geography={geoUrl}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="#0a0f1c"
                    stroke="#1e293b"
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: { fill: "#131c31", outline: "none" },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>

            {clusteredMarkers.map((m, i) => {
              
              if (m.isCluster) {
                return (
                  <Marker 
                    key={m.id} 
                    coordinates={m.coordinates}
                    onClick={(e) => handleMarkerClick(e, m)}
                    onMouseEnter={(e) => handleMouseEnter(e, m)}
                    onMouseLeave={handleMouseLeave}
                    className="cursor-pointer"
                  >
                    <motion.circle
                      r={12}
                      fill={`${m.color}33`}
                      stroke={m.color}
                      strokeWidth={1}
                      animate={{ scale: [1, 1.3, 1], opacity: [0.6, 1, 0.6] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                    <text
                      textAnchor="middle"
                      y={3}
                      style={{ fontFamily: 'monospace', fontSize: '8px', fill: '#fff', fontWeight: 'bold' }}
                    >
                      {m.count}
                    </text>
                  </Marker>
                );
              }

              const isActive = hoveredMarker?.id === m.id;
              
              return (
                <Marker 
                  key={m.id} 
                  coordinates={m.coordinates}
                  onClick={(e) => handleMarkerClick(e, m)}
                  onMouseEnter={(e) => handleMouseEnter(e, m)}
                  onMouseLeave={handleMouseLeave}
                  className="cursor-pointer"
                >
                  <motion.circle
                    r={16}
                    fill="transparent"
                    stroke={m.color}
                    strokeWidth={1}
                    initial={{ scale: 0.1, opacity: 0 }}
                    animate={{ scale: [0.1, 2], opacity: [0.9, 0] }}
                    transition={{ duration: 2, repeat: Infinity, delay: i * 0.1 }}
                  />
                  <circle r={2.5} fill={m.color} style={{ filter: `drop-shadow(0 0 4px ${m.glowColor})` }} />
                  <circle r={1} fill="#ffffff" />

                  {isActive && (
                    <g>
                      <path d="M -10 -10 L -5 -10 M -10 -10 L -10 -5" stroke={m.color} strokeWidth="1" fill="none" opacity="0.8" />
                      <path d="M 10 -10 L 5 -10 M 10 -10 L 10 -5" stroke={m.color} strokeWidth="1" fill="none" opacity="0.8" />
                      <path d="M -10 10 L -5 10 M -10 10 L -10 5" stroke={m.color} strokeWidth="1" fill="none" opacity="0.8" />
                      <path d="M 10 10 L 5 10 M 10 10 L 10 5" stroke={m.color} strokeWidth="1" fill="none" opacity="0.8" />
                      <circle r={14} fill="none" stroke={m.color} strokeWidth="0.5" strokeDasharray="2,2" className="animate-[spin_4s_linear_infinite]" opacity="0.5" />
                    </g>
                  )}
                </Marker>
              );
            })}
          </ZoomableGroup>
        </ComposableMap>
      </div>
    </div>
  );
}
