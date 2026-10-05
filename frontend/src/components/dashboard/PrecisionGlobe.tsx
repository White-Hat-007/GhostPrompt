'use client';
import React, { useRef, useEffect, useState } from 'react';
import maplibregl from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import { Layers, Mountain, Building, X } from 'lucide-react';

interface ArcDatum {
  id: string;
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  rawColor: [number, number, number, number];
  stroke: number;
  timestamp: number;
  attackType: string;
  severity: string;
  srcCountry: string;
  label: string;
}

interface RingDatum {
  lat: number;
  lng: number;
  maxR: number;
  rawColor: [number, number, number, number];
  _created: number;
}

interface PrecisionGlobeProps {
  arcs: ArcDatum[];
  rings: RingDatum[];
}

const ESRI_SATELLITE = 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}';

export default function PrecisionGlobe({ arcs, rings }: PrecisionGlobeProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const arcSourceRef = useRef<boolean>(false);
  const animFrameRef = useRef<number>(0);
  const [loaded, setLoaded] = useState(false);
  
  // Toggles
  const [showTerrain, setShowTerrain] = useState(false);
  const [showBuildings, setShowBuildings] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<ArcDatum | null>(null);

  // Initialize map
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: {
        version: 8 as const,
        glyphs: 'https://demotiles.maplibre.org/font/{fontstack}/{range}.pbf',
        sources: {
          'satellite-tiles': {
            type: 'raster',
            tiles: [ESRI_SATELLITE],
            tileSize: 256,
            maxzoom: 18,
            attribution: '&copy; Esri, Earthstar Geographics',
          },
          'terrain-tiles': {
            type: 'raster-dem',
            tiles: ['https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png'],
            encoding: 'terrarium',
            tileSize: 256,
            maxzoom: 15,
          }
        },
        layers: [
          {
            id: 'satellite-layer',
            type: 'raster',
            source: 'satellite-tiles',
            paint: {
              'raster-brightness-min': 0.05,
              'raster-brightness-max': 0.85,
              'raster-saturation': -0.1,
              'raster-contrast': 0.05,
            },
          }
        ],
        terrain: { source: 'terrain-tiles', exaggeration: 2.5 }
      } as any,
      center: [78.9, 20.6],
      zoom: 1.8,
      pitch: 15,
      bearing: 0,
      maxPitch: 85,
      renderWorldCopies: false,
      fadeDuration: 0,
    });

    map.on('style.load', () => {
      map.setProjection({ type: 'globe' } as any);
      
      try {
        map.setSky({
          'sky-color': '#020208',
          'sky-horizon-blend': 0.4,
          'horizon-color': '#050510',
          'horizon-fog-blend': 0.3,
          'fog-color': '#020208',
          'fog-ground-blend': 0.2,
        } as any);
      } catch (e) {
        console.warn('Sky/fog not fully supported:', e);
      }
    });

    map.on('load', () => {
      mapRef.current = map;
      arcSourceRef.current = false;
      setLoaded(true);

      map.addSource('attack-arcs', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });
      map.addSource('impact-points', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] },
      });

      map.addLayer({
        id: 'attack-arc-lines',
        type: 'line',
        source: 'attack-arcs',
        paint: {
          'line-color': ['get', 'color'],
          'line-width': ['get', 'width'],
          'line-opacity': 0.85,
        },
        layout: { 'line-cap': 'round', 'line-join': 'round' },
      });

      map.addLayer({
        id: 'impact-glow',
        type: 'circle',
        source: 'impact-points',
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, 6, 4, 12, 8, 20],
          'circle-color': ['get', 'color'],
          'circle-opacity': 0.6,
          'circle-blur': 0.8,
        },
      });

      map.addLayer({
        id: 'impact-core',
        type: 'circle',
        source: 'impact-points',
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, 3, 4, 6, 8, 10],
          'circle-color': ['get', 'color'],
          'circle-opacity': 0.9,
          'circle-blur': 0.3,
        },
      });

      arcSourceRef.current = true;
      
      // Click handlers
      map.on('click', 'attack-arc-lines', (e) => {
        if (!e.features || !e.features.length) return;
        const props = e.features[0].properties;
        
        // Find full arc data
        const arcId = props.id;
        // Fly to midpoint
        const coords = (e.features[0].geometry as any).coordinates;
        if (coords && coords.length > 1) {
          const mid = coords[1];
          map.flyTo({
            center: mid,
            zoom: 6,
            pitch: 45,
            duration: 2000,
            essential: true
          });
          
          // Trigger panel
          setSelectedThreat({
            id: arcId,
            startLng: coords[0][0],
            startLat: coords[0][1],
            endLng: coords[2][0],
            endLat: coords[2][1],
            rawColor: [0,0,0,0], // mock
            stroke: props.width,
            timestamp: Date.now(),
            attackType: props.attackType || 'Unknown',
            severity: props.severity || 'High',
            srcCountry: props.srcCountry || 'Unknown',
            label: props.label || 'Threat detected',
          });
        }
      });
      
      map.on('mouseenter', 'attack-arc-lines', () => {
        map.getCanvas().style.cursor = 'pointer';
      });
      map.on('mouseleave', 'attack-arc-lines', () => {
        map.getCanvas().style.cursor = '';
      });
    });

    map.addControl(new maplibregl.NavigationControl({ showCompass: true, showZoom: true }), 'bottom-right');

    let bearing = 0;
    let userInteracting = false;
    map.on('mousedown', () => { userInteracting = true; });
    map.on('mouseup', () => { userInteracting = false; });
    map.on('touchstart', () => { userInteracting = true; });
    map.on('touchend', () => { userInteracting = false; });

    function spinGlobe() {
      if (!userInteracting && map.getZoom() < 5) {
        bearing += 0.015;
        map.rotateTo(bearing, { duration: 0 });
      }
      animFrameRef.current = requestAnimationFrame(spinGlobe);
    }
    spinGlobe();

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      map.remove();
      mapRef.current = null;
      arcSourceRef.current = false;
    };
  }, []);

  // Update arcs/rings
  useEffect(() => {
    if (!mapRef.current || !arcSourceRef.current) return;
    const map = mapRef.current;

    const arcFeatures = arcs.map((a) => {
      const [r, g, b, alpha] = a.rawColor || [10, 224, 255, 200];
      const color = `rgba(${r},${g},${b},${(alpha / 255).toFixed(2)})`;
      const midLat = (a.startLat + a.endLat) / 2;
      const midLng = (a.startLng + a.endLng) / 2;
      return {
        type: 'Feature' as const,
        properties: {
          color,
          width: Math.max(a.stroke || 1.5, 1),
          id: a.id,
          attackType: a.attackType,
          severity: a.severity,
          label: a.label,
          srcCountry: a.srcCountry,
        },
        geometry: {
          type: 'LineString' as const,
          coordinates: [
            [a.startLng, a.startLat],
            [midLng, midLat],
            [a.endLng, a.endLat],
          ],
        },
      };
    });

    const impactFeatures = rings.map((r) => {
      const [red, green, blue, alpha] = r.rawColor || [10, 224, 255, 180];
      return {
        type: 'Feature' as const,
        properties: {
          color: `rgba(${red},${green},${blue},${(alpha / 255).toFixed(2)})`,
          radius: r.maxR,
        },
        geometry: { type: 'Point' as const, coordinates: [r.lng, r.lat] },
      };
    });

    const arcSource = map.getSource('attack-arcs') as maplibregl.GeoJSONSource;
    const impactSource = map.getSource('impact-points') as maplibregl.GeoJSONSource;

    if (arcSource) arcSource.setData({ type: 'FeatureCollection', features: arcFeatures });
    if (impactSource) impactSource.setData({ type: 'FeatureCollection', features: impactFeatures });
  }, [arcs, rings, loaded]);

  // Toggle Terrain
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !loaded) return;
    if (showTerrain) {
      map.setTerrain({ source: 'terrain-tiles', exaggeration: 1.5 });
    } else {
      map.setTerrain(null);
    }
  }, [showTerrain, loaded]);

  // Toggle Buildings
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !loaded) return;
    if (map.getLayer('3d-buildings')) {
      map.setLayoutProperty('3d-buildings', 'visibility', showBuildings ? 'visible' : 'none');
    }
  }, [showBuildings, loaded]);

  const starsRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = starsRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    const W = canvas.offsetWidth, H = canvas.offsetHeight;
    ctx.clearRect(0, 0, W, H);
    for (let i = 0; i < 400; i++) {
      const x = Math.random() * W, y = Math.random() * H;
      const r = Math.random() * 0.8 + 0.1;
      const brightness = 40 + Math.random() * 60;
      const alpha = 0.15 + Math.random() * 0.45;
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${brightness + 155}, ${brightness + 155}, ${brightness + 170}, ${alpha})`;
      ctx.fill();
    }
  }, []);

  return (
    <div className="absolute inset-0 z-0 overflow-hidden">
      <div className="absolute inset-0" style={{ background: 'radial-gradient(ellipse at 40% 30%, #06060f 0%, #020208 60%, #000000 100%)' }} />
      <canvas ref={starsRef} className="absolute inset-0 w-full h-full" style={{ pointerEvents: 'none' }} />
      <div ref={containerRef} className="absolute inset-0 w-full h-full" style={{ zIndex: 1 }} />

      {!loaded && (
        <div className="absolute inset-0 flex items-center justify-center z-10" style={{ background: 'radial-gradient(ellipse at center, #06060f 0%, #000000 100%)' }}>
          <div className="text-center">
            <div className="w-16 h-16 rounded-full border-2 border-[#0ae0ff]/30 border-t-[#0ae0ff] animate-spin mx-auto mb-4"/>
            <p className="text-sm font-mono text-[#0ae0ff]/60 uppercase tracking-widest">Loading Satellite Imagery</p>
          </div>
        </div>
      )}
      
      {/* Precision Controls Overlay */}
      {loaded && (
        <div className="absolute bottom-[100px] left-4 z-20 flex flex-col gap-2">
          <button 
            onClick={() => setShowTerrain(!showTerrain)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border backdrop-blur-md transition-all ${
              showTerrain ? 'bg-[#0ae0ff]/20 border-[#0ae0ff]/50 text-[#0ae0ff]' : 'bg-black/50 border-white/10 text-gray-400 hover:bg-white/10'
            }`}
          >
            <Mountain className="w-4 h-4" />
            <span className="text-xs font-mono uppercase">3D Terrain</span>
          </button>
          
          <button 
            onClick={() => setShowBuildings(!showBuildings)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border backdrop-blur-md transition-all ${
              showBuildings ? 'bg-[#0ae0ff]/20 border-[#0ae0ff]/50 text-[#0ae0ff]' : 'bg-black/50 border-white/10 text-gray-400 hover:bg-white/10'
            }`}
          >
            <Building className="w-4 h-4" />
            <span className="text-xs font-mono uppercase">3D Buildings</span>
          </button>
        </div>
      )}
      
      {/* Selected Threat Precision Panel */}
      {selectedThreat && (
        <div className="absolute top-24 left-4 z-20 w-80 backdrop-blur-xl bg-black/80 border border-[#0ae0ff]/30 rounded-xl overflow-hidden shadow-[0_0_30px_rgba(10,224,255,0.15)] animate-in slide-in-from-left-4 fade-in">
          <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between bg-gradient-to-r from-[#0ae0ff]/10 to-transparent">
            <h3 className="text-xs font-mono text-[#0ae0ff] uppercase tracking-wider">Precision Forensics</h3>
            <button onClick={() => setSelectedThreat(null)} className="text-gray-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="p-4 space-y-3">
            <div>
              <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest">Target Signature</p>
              <p className="text-sm font-bold text-white mt-0.5">{selectedThreat.label}</p>
            </div>
            
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest">Type</p>
                <p className="text-xs text-gray-300 mt-0.5">{selectedThreat.attackType}</p>
              </div>
              <div>
                <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest">Severity</p>
                <p className={`text-xs mt-0.5 ${selectedThreat.severity === 'critical' ? 'text-red-400' : 'text-yellow-400'}`}>
                  {selectedThreat.severity.toUpperCase()}
                </p>
              </div>
              <div>
                <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest">Origin</p>
                <p className="text-xs text-gray-300 mt-0.5">{selectedThreat.srcCountry}</p>
              </div>
              <div>
                <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest">Coordinates</p>
                <p className="text-[10px] font-mono text-gray-400 mt-0.5">
                  {selectedThreat.startLat.toFixed(4)}, {selectedThreat.startLng.toFixed(4)}
                </p>
              </div>
            </div>
            
            <div className="pt-3 mt-3 border-t border-white/10">
              <button 
                onClick={() => {
                  mapRef.current?.flyTo({ center: [selectedThreat.startLng, selectedThreat.startLat], zoom: 12, pitch: 60, duration: 2500 });
                }}
                className="w-full py-1.5 bg-[#0ae0ff]/10 hover:bg-[#0ae0ff]/20 text-[#0ae0ff] text-xs font-mono rounded border border-[#0ae0ff]/30 transition-colors"
              >
                Track Origin
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
