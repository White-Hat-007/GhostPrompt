'use client';

import { useMemo, useRef, useCallback, useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import {
  Shield, Brain, Maximize2, ZoomIn, ZoomOut, Lock, Unlock,
  Search, X, ChevronRight, BarChart3, Crosshair,
  Layers, GitBranch, AlertTriangle, Filter
} from 'lucide-react';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false });

// @ts-ignore
import { forceCollide, forceX, forceY } from 'd3-force-3d';

/* ═══════════════════════════════════════════════════════════════
   NODE TYPE DEFINITIONS — Elite Color Palette
   ═══════════════════════════════════════════════════════════════ */
const NODE_TYPES = {
  attack: { color: '#ff3366', glow: '#ff336680', accent: '#ff6699', size: 4, label: 'Attack', icon: '⚡' },
  detector: { color: '#00ccff', glow: '#00ccff60', accent: '#66ddff', size: 6, label: 'Detector', icon: '🛡' },
  category: { color: '#ffaa00', glow: '#ffaa0060', accent: '#ffcc55', size: 5, label: 'Category', icon: '◆' },
  model: { color: '#b466ff', glow: '#b466ff60', accent: '#cc99ff', size: 5, label: 'Model', icon: '⬡' },
  action: { color: '#00ff88', glow: '#00ff8860', accent: '#66ffaa', size: 7, label: 'Action', icon: '▶' },
  technique: { color: '#ff44cc', glow: '#ff44cc60', accent: '#ff88dd', size: 3, label: 'ATLAS Technique', icon: '◎' },
};

const ATLAS_MAP: Record<string, string> = {
  'injection': 'AML.T0051', 'jailbreak': 'AML.T0054', 'pliny': 'AML.T0054.002',
  'encoded': 'AML.T0015', 'obfuscation': 'AML.T0015', 'pii': 'AML.T0024',
  'secrets': 'AML.T0024.001', 'secret': 'AML.T0024.001', 'oracle': 'AML.T0044',
  'sponge': 'AML.T0029', 'policy': 'AML.T0048', 'content': 'AML.T0048.002',
  'agent': 'AML.T0052', 'external': 'AML.T0051.002', 'tokenizer': 'AML.T0043',
  'zero_day': 'AML.T0000', 'campaign': 'AML.T0011', 'hallucination': 'AML.T0048.001',
  'memorization': 'AML.T0024.002', 'supply_chain': 'AML.T0010', 'ml': 'AML.T0015',
  'pack_hunt': 'AML.T0011', 'intent': 'AML.T0051',
};

/* ─── Helper: extract node ID from a link endpoint (handles both string & object) ─── */
function linkEndpointId(endpoint: any): string {
  if (typeof endpoint === 'string') return endpoint;
  if (endpoint && typeof endpoint === 'object' && endpoint.id) return endpoint.id;
  return '';
}

interface GraphNode {
  id: string;
  label: string;
  type: keyof typeof NODE_TYPES;
  val: number;
  color: string;
  count?: number;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

interface GraphLink {
  source: string | any;
  target: string | any;
  value: number;
  color: string;
}

interface ThreatKnowledgeGraphProps {
  recentScans?: any[];
}

/* ═══════════════════════════════════════════════════════════════
   COMPONENT
   ═══════════════════════════════════════════════════════════════ */
export default function ThreatKnowledgeGraph({ recentScans = [] }: ThreatKnowledgeGraphProps) {
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 900, height: 600 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilters, setActiveFilters] = useState<Set<string>>(new Set(Object.keys(NODE_TYPES)));
  const [isPhysicsLocked, setIsPhysicsLocked] = useState(false);
  const [showPanel, setShowPanel] = useState(true);

  // Resize observer
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ width: Math.max(width, 400), height: Math.max(height, 300) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /* ─── Build Graph Data ─── */
  const graphData = useMemo(() => {
    const nodesMap = new Map<string, GraphNode>();
    const linksMap = new Map<string, GraphLink>();
    const threats = recentScans.filter(s => s.threat_level !== 'safe');

    const actNodes = new Map<string, GraphNode>();
    ['blocked', 'flagged', 'allowed'].forEach(act => {
      const color = act === 'blocked' ? '#ff3366' : act === 'flagged' ? '#ffaa00' : '#00ff88';
      actNodes.set(`action:${act}`, {
        id: `action:${act}`, label: act.toUpperCase(), type: 'action',
        val: 16, color, count: 0,
      });
    });

    const catCounts: Record<string, number> = {};
    const detCounts: Record<string, number> = {};
    const modelCounts: Record<string, number> = {};
    const techCounts: Record<string, number> = {};

    threats.forEach(scan => {
      const action = scan.action || 'allowed';
      const actNodeId = `action:${action}`;
      if (actNodes.has(actNodeId)) {
        const node = actNodes.get(actNodeId)!;
        node.count = (node.count || 0) + 1;
        nodesMap.set(actNodeId, node);
      }

      const model = scan.model || 'unknown';
      modelCounts[model] = (modelCounts[model] || 0) + 1;

      const detections = scan.detections || [];
      if (detections.length === 0) {
        const cat = scan.category || 'unknown';
        catCounts[cat] = (catCounts[cat] || 0) + 1;
      }

      detections.forEach((d: any) => {
        const cat = d.category || 'unknown';
        const det = d.detector || 'unknown';
        const prefix = cat.split('.')[0];
        const tech = ATLAS_MAP[cat] || ATLAS_MAP[prefix] || null;

        catCounts[cat] = (catCounts[cat] || 0) + 1;
        detCounts[det] = (detCounts[det] || 0) + 1;
        if (tech) techCounts[tech] = (techCounts[tech] || 0) + 1;

        // Category → Detector
        const cdKey = `cat:${cat}→det:${det}`;
        if (!linksMap.has(cdKey)) linksMap.set(cdKey, { source: `cat:${cat}`, target: `det:${det}`, value: 0, color: '#f59e0b20' });
        linksMap.get(cdKey)!.value++;

        // Detector → Action
        const daKey = `det:${det}→${actNodeId}`;
        if (!linksMap.has(daKey)) linksMap.set(daKey, { source: `det:${det}`, target: actNodeId, value: 0, color: '#3b82f620' });
        linksMap.get(daKey)!.value++;

        // Category → Technique
        if (tech) {
          const ctKey = `cat:${cat}→tech:${tech}`;
          if (!linksMap.has(ctKey)) linksMap.set(ctKey, { source: `cat:${cat}`, target: `tech:${tech}`, value: 0, color: '#ec489920' });
          linksMap.get(ctKey)!.value++;
        }

        // Model → Category
        const mcKey = `model:${model}→cat:${cat}`;
        if (!linksMap.has(mcKey)) linksMap.set(mcKey, { source: `model:${model}`, target: `cat:${cat}`, value: 0, color: '#8b5cf620' });
        linksMap.get(mcKey)!.value++;
      });
    });

    // Create nodes with larger values
    Object.entries(catCounts).forEach(([cat, count]) => {
      nodesMap.set(`cat:${cat}`, { id: `cat:${cat}`, label: cat.replace(/_/g, ' '), type: 'category', val: Math.min(8 + count * 1.0, 28), color: '#ffaa00', count });
    });
    Object.entries(detCounts).forEach(([det, count]) => {
      nodesMap.set(`det:${det}`, { id: `det:${det}`, label: det.replace(/_/g, ' '), type: 'detector', val: Math.min(10 + count * 0.7, 30), color: '#00ccff', count });
    });
    Object.entries(modelCounts).forEach(([model, count]) => {
      nodesMap.set(`model:${model}`, { id: `model:${model}`, label: model, type: 'model', val: Math.min(9 + count * 0.8, 28), color: '#b466ff', count });
    });
    Object.entries(techCounts).forEach(([tech, count]) => {
      nodesMap.set(`tech:${tech}`, { id: `tech:${tech}`, label: tech, type: 'technique', val: Math.min(7 + count * 0.6, 24), color: '#ff44cc', count });
    });

    const X_TIERS: Record<string, number> = {
      model: -650,
      category: -300,
      detector: 50,
      technique: 400,
      action: 750,
    };

    nodesMap.forEach(node => {
      if (node.type === 'action') node.val = Math.min(18 + (node.count || 0) * 0.4, 36);
      const baseX = X_TIERS[node.type] ?? 0;
      if (node.x === undefined) {
        node.x = baseX + (Math.random() - 0.5) * 180;
        node.y = (Math.random() - 0.5) * 160;
      }
    });

    const validLinks = Array.from(linksMap.values()).filter(
      l => nodesMap.has(linkEndpointId(l.source)) && nodesMap.has(linkEndpointId(l.target))
    );

    return { nodes: Array.from(nodesMap.values()), links: validLinks };
  }, [recentScans]);

  /* ─── Filtered graph based on active type filters and search ─── */
  const filteredGraph = useMemo(() => {
    let nodes = graphData.nodes.filter(n => activeFilters.has(n.type));
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      nodes = nodes.map(n => ({
        ...n,
        _dimmed: !n.label.toLowerCase().includes(q) && !n.id.toLowerCase().includes(q),
      }));
    }
    const nodeIds = new Set(nodes.map(n => n.id));
    // Use linkEndpointId helper to handle both string IDs and object refs (d3 mutates these in-place)
    const links = graphData.links.filter(l => nodeIds.has(linkEndpointId(l.source)) && nodeIds.has(linkEndpointId(l.target)));
    return { nodes, links };
  }, [graphData, activeFilters, searchQuery]);

  /* ─── Computed analytics for the intelligence panel ─── */
  const analytics = useMemo(() => {
    const typeBreakdown: Record<string, number> = {};
    graphData.nodes.forEach(n => { typeBreakdown[n.type] = (typeBreakdown[n.type] || 0) + 1; });

    const topCategories = graphData.nodes
      .filter(n => n.type === 'category')
      .sort((a, b) => (b.count || 0) - (a.count || 0))
      .slice(0, 6);

    const topDetectors = graphData.nodes
      .filter(n => n.type === 'detector')
      .sort((a, b) => (b.count || 0) - (a.count || 0))
      .slice(0, 5);

    const totalEvents = recentScans.filter(s => s.threat_level !== 'safe').length;
    const blockedCount = graphData.nodes.find(n => n.id === 'action:blocked')?.count || 0;
    const blockRate = totalEvents > 0 ? Math.round((blockedCount / totalEvents) * 100) : 0;

    return { typeBreakdown, topCategories, topDetectors, totalEvents, blockedCount, blockRate };
  }, [graphData, recentScans]);

  /* ─── Connected nodes for selected node ─── 
     Uses graphData.links with linkEndpointId helper so it works whether
     d3 has mutated link endpoints to objects or they're still strings. */
  const connectedNodes = useMemo(() => {
    if (!selectedNode) return [];
    return graphData.links
      .filter(l => {
        const srcId = linkEndpointId(l.source);
        const tgtId = linkEndpointId(l.target);
        return srcId === selectedNode.id || tgtId === selectedNode.id;
      })
      .map(l => {
        const srcId = linkEndpointId(l.source);
        const tgtId = linkEndpointId(l.target);
        const otherId = srcId === selectedNode.id ? tgtId : srcId;
        const otherNode = graphData.nodes.find(n => n.id === otherId);
        return otherNode ? { ...otherNode, linkValue: l.value } : null;
      })
      .filter(Boolean) as (GraphNode & { linkValue: number })[];
  }, [selectedNode, graphData]);

  /* ─── Interaction handlers ─── */
  const handleNodeClick = useCallback((node: any) => {
    setSelectedNode(node);
    setShowPanel(true);
    if (graphRef.current && Number.isFinite(node.x) && Number.isFinite(node.y)) {
      graphRef.current.centerAt(node.x, node.y, 600);
      graphRef.current.zoom(2.5, 600);
    }
  }, []);

  /* Click a node in the side panel — find the live simulation object so we get x/y coords */
  const handlePanelNodeClick = useCallback((nodeId: string) => {
    // Get the live node from the force-graph's internal data (has x/y from simulation)
    const graphInstance = graphRef.current;
    if (!graphInstance) return;
    const liveData = graphInstance.graphData?.() || filteredGraph;
    const liveNode = liveData.nodes?.find((n: any) => n.id === nodeId);
    if (liveNode) {
      handleNodeClick(liveNode);
    } else {
      // Fallback: just select the node data without zooming
      const fallback = graphData.nodes.find(n => n.id === nodeId);
      if (fallback) setSelectedNode(fallback);
    }
  }, [filteredGraph, graphData, handleNodeClick]);

  const handleZoomIn = () => graphRef.current?.zoom(graphRef.current.zoom() * 1.5, 300);
  const handleZoomOut = () => graphRef.current?.zoom(graphRef.current.zoom() / 1.5, 300);
  const handleFit = () => graphRef.current?.zoomToFit(400, 60);
  const toggleFilter = (type: string) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  };
  const togglePhysics = () => {
    setIsPhysicsLocked(!isPhysicsLocked);
    if (graphRef.current) {
      if (!isPhysicsLocked) {
        // Lock: pin all nodes
        const liveData = graphRef.current.graphData?.();
        liveData?.nodes?.forEach((n: any) => { n.fx = n.x; n.fy = n.y; });
      } else {
        // Unlock: unpin all
        const liveData = graphRef.current.graphData?.();
        liveData?.nodes?.forEach((n: any) => { n.fx = undefined; n.fy = undefined; });
        graphRef.current.d3ReheatSimulation();
      }
    }
  };

  // Configure physics on data change — includes HORIZONTAL X-AXIS SCATTER and COLLISION FORCE
  useEffect(() => {
    if (graphRef.current) {
      const X_TARGETS: Record<string, number> = {
        model: -1600,
        category: -800,
        attack: -200,
        detector: 200,
        technique: 800,
        atlas: 1200,
        action: 1600,
      };

      const physicsTimer = setTimeout(() => {
        if (!graphRef.current) return;
        
        // Use native 2D forces from the graph engine
        const chargeForce = graphRef.current.d3Force('charge');
        if (chargeForce) chargeForce.strength(-1400); // Balanced repulsion
        
        const linkForce = graphRef.current.d3Force('link');
        if (linkForce) {
          linkForce.distance(180); // Good spacing
          linkForce.strength(0.08); 
        }

        const centerForce = graphRef.current.d3Force('center');
        if (centerForce) centerForce.strength(0.008);

        // Pull nodes horizontally into distinct columns — gentle pull
        if (forceX) {
          graphRef.current.d3Force('x',
            forceX((node: any) => X_TARGETS[node.type] ?? 0).strength(0.2)
          );
        }

        // Gentle vertical gravity
        if (forceY) {
          graphRef.current.d3Force('y',
            forceY(0).strength(0.08)
          );
        }

        // Collision padding for labels
        if (forceCollide) {
          graphRef.current.d3Force('collide',
            forceCollide()
              .radius((node: any) => {
                const typeDef = NODE_TYPES[node.type as keyof typeof NODE_TYPES] || NODE_TYPES.attack;
                const baseSize = Math.max((node.val || typeDef.size) * 1.3, 8);
                return baseSize + 30; 
              })
              .iterations(6)
          );
        }

        graphRef.current.d3ReheatSimulation();
      }, 100);

      // Auto-fit camera to framed scatter layout after simulation settles
      const zoomTimer = setTimeout(() => {
        graphRef.current?.zoomToFit(400, 40);
      }, 800);
      
      return () => {
        clearTimeout(physicsTimer);
        clearTimeout(zoomTimer);
      };
    }
  }, [filteredGraph]);

  /* ═══════════════════════════════════════════════════════════════
     ELITE NODE RENDERING — Canvas
     ═══════════════════════════════════════════════════════════════ */
  const nodeCanvasObject = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    // Guard: node positions may be undefined before force simulation settles
    if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return;

    const typeDef = NODE_TYPES[node.type as keyof typeof NODE_TYPES] || NODE_TYPES.attack;
    const baseSize = Math.max((node.val || typeDef.size) * 1.15, 6);
    const isHovered = hoveredNode === node.id;
    const isSelected = selectedNode?.id === node.id;
    const isDimmed = (node as any)._dimmed;
    const isHighlighted = isHovered || isSelected;
    const pulse = Math.sin(Date.now() * 0.003) * 0.15 + 0.85;

    const alpha = isDimmed ? 0.15 : 1;
    ctx.globalAlpha = alpha;

    // ── Outer Glow Ring (for high-count or highlighted nodes) ──
    if ((node.count || 0) > 10 || isHighlighted) {
      const glowSize = baseSize + (isHighlighted ? 6 : 3);
      ctx.beginPath();
      ctx.arc(node.x, node.y, glowSize * pulse, 0, Math.PI * 2);
      const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, glowSize);
      grad.addColorStop(0, isHighlighted ? `${typeDef.color}40` : `${typeDef.color}15`);
      grad.addColorStop(1, 'transparent');
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // ── Second glow ring for selected ──
    if (isSelected) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, baseSize + 10, 0, Math.PI * 2);
      ctx.strokeStyle = `${typeDef.color}30`;
      ctx.lineWidth = 0.5;
      ctx.setLineDash([2, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // ── Hexagon Shape ──
    ctx.beginPath();
    const sides = 6;
    for (let i = 0; i < sides; i++) {
      const angle = (i * Math.PI * 2) / sides - Math.PI / 6; // Flat-top hex
      const vx = node.x + baseSize * Math.cos(angle);
      const vy = node.y + baseSize * Math.sin(angle);
      if (i === 0) ctx.moveTo(vx, vy); else ctx.lineTo(vx, vy);
    }
    ctx.closePath();

    // Gradient fill
    const fillGrad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, baseSize);
    fillGrad.addColorStop(0, isHighlighted ? `${typeDef.color}55` : `${typeDef.color}20`);
    fillGrad.addColorStop(1, isHighlighted ? `${typeDef.color}25` : `${typeDef.color}08`);
    ctx.fillStyle = fillGrad;
    ctx.fill();

    // Border
    ctx.strokeStyle = isHighlighted ? '#ffffff' : `${typeDef.color}aa`;
    ctx.lineWidth = isHighlighted ? 1.8 : 0.7;
    ctx.stroke();

    // ── Inner core dot ──
    ctx.beginPath();
    ctx.arc(node.x, node.y, Math.max(baseSize * 0.2, 1.2), 0, Math.PI * 2);
    ctx.fillStyle = isHighlighted ? '#ffffff' : typeDef.color;
    ctx.fill();

    // ── Labels ──
    const showLabel = isHighlighted || globalScale > 0.3 || node.type === 'action' || node.type === 'model' || node.type === 'atlas' || (node.count || 0) > 5;
    if (showLabel) {
      const rawLabel = node.label || '';
      const label = rawLabel.length > 24 ? rawLabel.slice(0, 22) + '…' : rawLabel;
      const fontSize = Math.max(10 / globalScale, 2.8);
      ctx.font = `600 ${fontSize}px "Inter", "JetBrains Mono", sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';

      const textWidth = ctx.measureText(label).width;
      const pad = 3 / globalScale;
      const pillY = node.y + baseSize + 3;

      // Background pill
      const pillH = fontSize + pad * 2;
      const pillW = textWidth + pad * 4;
      const pillR = pillH / 2;
      ctx.fillStyle = isHighlighted ? '#0a0e1dee' : '#050914cc';
      const rx = node.x - pillW / 2;
      const ry = pillY - pad;
      ctx.beginPath();
      if (ctx.roundRect) {
        ctx.roundRect(rx, ry, pillW, pillH, pillR);
      } else {
        ctx.rect(rx, ry, pillW, pillH);
      }
      ctx.fill();

      // Border on pill
      if (isHighlighted) {
        ctx.strokeStyle = `${typeDef.color}60`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }

      // Text
      ctx.fillStyle = isHighlighted ? '#ffffff' : `${typeDef.color}cc`;
      ctx.fillText(label, node.x, pillY);

      // Count badge for high-count nodes
      if ((node.count || 0) > 1 && (isHighlighted || globalScale > 1.5)) {
        const countStr = `${node.count}`;
        const countFontSize = Math.max(8 / globalScale, 2.2);
        ctx.font = `700 ${countFontSize}px "Inter", sans-serif`;
        const countWidth = ctx.measureText(countStr).width;
        const badgeX = node.x + baseSize + 2;
        const badgeY = node.y - baseSize - 2;

        ctx.beginPath();
        ctx.arc(badgeX, badgeY, Math.max(countWidth / 2 + 2, 4), 0, Math.PI * 2);
        ctx.fillStyle = typeDef.color;
        ctx.fill();

        ctx.fillStyle = '#000000';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(countStr, badgeX, badgeY);
      }
    }

    ctx.globalAlpha = 1;
  }, [hoveredNode, selectedNode]);

  /* ─── Link rendering ─── */
  const linkCanvasObject = useCallback((link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const srcNode = typeof link.source === 'object' ? link.source : null;
    const tgtNode = typeof link.target === 'object' ? link.target : null;
    if (!srcNode || !tgtNode) return;
    if (!Number.isFinite(srcNode.x) || !Number.isFinite(srcNode.y) || !Number.isFinite(tgtNode.x) || !Number.isFinite(tgtNode.y)) return;

    const isConnected = hoveredNode === srcNode.id || hoveredNode === tgtNode.id ||
      selectedNode?.id === srcNode.id || selectedNode?.id === tgtNode.id;
    const isDimmedSearch = (srcNode as any)._dimmed || (tgtNode as any)._dimmed;

    const width = isConnected ? Math.min(1 + link.value * 0.3, 4) : Math.min(0.3 + link.value * 0.08, 1.5);
    const alpha = isDimmedSearch ? 0.02 : isConnected ? 0.6 : 0.08;

    ctx.globalAlpha = alpha;
    ctx.beginPath();

    // Curved link
    const dx = tgtNode.x - srcNode.x;
    const dy = tgtNode.y - srcNode.y;
    const midX = (srcNode.x + tgtNode.x) / 2;
    const midY = (srcNode.y + tgtNode.y) / 2;
    const cpX = midX - dy * 0.15;
    const cpY = midY + dx * 0.15;

    ctx.moveTo(srcNode.x, srcNode.y);
    ctx.quadraticCurveTo(cpX, cpY, tgtNode.x, tgtNode.y);

    // Gradient stroke
    const grad = ctx.createLinearGradient(srcNode.x, srcNode.y, tgtNode.x, tgtNode.y);
    grad.addColorStop(0, srcNode.color || '#6366f1');
    grad.addColorStop(1, tgtNode.color || '#6366f1');
    ctx.strokeStyle = isConnected ? grad : (link.color || '#ffffff10');
    ctx.lineWidth = width;
    ctx.stroke();

    ctx.globalAlpha = 1;
  }, [hoveredNode, selectedNode]);

  /* ═══════════════════════════════════════════════════════════════
     RENDER
     ═══════════════════════════════════════════════════════════════ */
  return (
    <div className="h-full overflow-hidden bg-transparent text-gray-300">
      <div className="h-full flex flex-col">
        {/* ── Header ── */}
        <div className="px-6 pt-6 pb-3">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-pink-500/30 to-violet-500/30 border border-pink-500/40 flex items-center justify-center shadow-lg shadow-pink-500/10">
                  <Brain className="w-5 h-5 text-pink-400" />
                </div>
                Threat Knowledge Graph
              </h1>
              <p className="text-xs text-gray-500 mt-1 ml-12">
                Force-directed relationship mapping — Models → Categories → Detectors → ATLAS Techniques → Actions
              </p>
            </div>
            <div className="flex items-center gap-2">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search nodes…"
                  className="bg-surface-0/80 border border-white/[0.08] rounded-lg pl-8 pr-8 py-1.5 text-xs text-white placeholder-gray-600 w-44 focus:outline-none focus:border-pink-500/40 focus:ring-1 focus:ring-pink-500/20 transition-all"
                />
                {searchQuery && (
                  <button onClick={() => setSearchQuery('')} className="absolute right-2 top-1/2 -translate-y-1/2">
                    <X className="w-3 h-3 text-gray-500 hover:text-white" />
                  </button>
                )}
              </div>

              {/* Controls */}
              <div className="glass-card flex items-center gap-0.5 p-1">
                <button onClick={handleZoomIn} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" title="Zoom In">
                  <ZoomIn className="w-3.5 h-3.5 text-gray-400" />
                </button>
                <button onClick={handleZoomOut} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" title="Zoom Out">
                  <ZoomOut className="w-3.5 h-3.5 text-gray-400" />
                </button>
                <div className="w-px h-4 bg-white/10 mx-0.5" />
                <button onClick={handleFit} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" title="Fit View">
                  <Maximize2 className="w-3.5 h-3.5 text-gray-400" />
                </button>
                <button onClick={togglePhysics} className={`p-1.5 rounded-lg transition-colors ${isPhysicsLocked ? 'bg-amber-500/20 text-amber-400' : 'hover:bg-white/10 text-gray-400'}`} title={isPhysicsLocked ? 'Unlock Physics' : 'Lock Physics'}>
                  {isPhysicsLocked ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
                </button>
                <div className="w-px h-4 bg-white/10 mx-0.5" />
                <button onClick={() => setShowPanel(!showPanel)} className={`p-1.5 rounded-lg transition-colors ${showPanel ? 'bg-pink-500/20 text-pink-400' : 'hover:bg-white/10 text-gray-400'}`} title="Toggle Intelligence Panel">
                  <BarChart3 className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Live status badge */}
              <div className="glass-card px-3 py-1.5 flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-pink-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-pink-500" />
                </span>
                <span className="text-[10px] font-mono text-gray-400">
                  {filteredGraph.nodes.length}<span className="text-gray-600">/</span>{graphData.nodes.length} nodes • {filteredGraph.links.length} edges
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Interactive Filter Chips ── */}
        <div className="px-6 pb-3 flex items-center gap-2 flex-wrap">
          <Filter className="w-3 h-3 text-gray-600 mr-1" />
          {Object.entries(NODE_TYPES).map(([key, def]) => {
            const isActive = activeFilters.has(key);
            const count = graphData.nodes.filter(n => n.type === key).length;
            return (
              <button
                key={key}
                onClick={() => toggleFilter(key)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold uppercase tracking-wider border transition-all duration-200 ${isActive
                    ? 'border-white/15 bg-white/[0.06] text-white hover:bg-white/10'
                    : 'border-white/[0.04] bg-transparent text-gray-600 hover:text-gray-400 hover:border-white/10'
                  }`}
              >
                <div className="w-2 h-2 rounded-full transition-opacity" style={{ background: def.color, opacity: isActive ? 1 : 0.3 }} />
                {def.label}
                {count > 0 && (
                  <span className={`ml-0.5 px-1.5 py-0 rounded-full text-[9px] ${isActive ? 'bg-white/10 text-gray-300' : 'bg-white/[0.03] text-gray-600'}`}>
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* ── Main Content: Graph + Intelligence Panel ── */}
        <div className="flex-1 flex gap-0 mx-6 mb-6 overflow-hidden">
          {/* Graph Canvas */}
          <div
            className="flex-1 rounded-xl border border-white/[0.06] overflow-hidden relative"
            ref={containerRef}
            style={{
              background: 'radial-gradient(ellipse at center, #0c1222 0%, #050914 60%, #030710 100%)',
              boxShadow: 'inset 0 0 80px rgba(0, 0, 0, 0.5)',
            }}
          >
            {/* Subtle grid background */}
            <div className="absolute inset-0 pointer-events-none" style={{
              backgroundImage: `
                linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)
              `,
              backgroundSize: '40px 40px',
            }} />

            {/* Vignette overlay */}
            <div className="absolute inset-0 pointer-events-none" style={{
              background: 'radial-gradient(ellipse at center, transparent 40%, rgba(3,7,16,0.7) 100%)',
            }} />

            {/* Top scan line effect */}
            <div className="absolute top-0 left-0 right-0 h-px pointer-events-none" style={{
              background: 'linear-gradient(90deg, transparent, rgba(236,72,153,0.3), transparent)',
            }} />

            {filteredGraph.nodes.length > 0 ? (
              <ForceGraph2D
                ref={graphRef}
                graphData={filteredGraph}
                width={dimensions.width}
                height={dimensions.height}
                backgroundColor="transparent"
                nodeCanvasObjectMode={() => 'replace'}
                nodeCanvasObject={nodeCanvasObject}
                nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
                  if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return;
                  const typeDef = NODE_TYPES[node.type as keyof typeof NODE_TYPES] || NODE_TYPES.attack;
                  const baseSize = Math.max((node.val || typeDef.size) * 1.3, 8);

                  ctx.fillStyle = color;

                  // 1. Core node hit area
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, baseSize + 15, 0, 2 * Math.PI);
                  ctx.fill();

                  // 2. Tightly fitted label hit area based on string length
                  // This avoids massive invisible overlapping rectangles while still making
                  // the text clickable. We estimate 6.5px per character.
                  const rawLabel = node.label || '';
                  if (rawLabel) {
                    const displayLabel = rawLabel.length > 24 ? rawLabel.slice(0, 22) + '…' : rawLabel;
                    const approxWidth = displayLabel.length * 6.5 + 15;
                    const approxHeight = 22;

                    ctx.beginPath();
                    ctx.rect(node.x - approxWidth / 2, node.y + baseSize + 2, approxWidth, approxHeight);
                    ctx.fill();
                  }
                }}
                linkCanvasObjectMode={() => 'replace'}
                linkCanvasObject={linkCanvasObject}
                linkDirectionalParticles={3}
                linkDirectionalParticleWidth={1.2}
                linkDirectionalParticleColor={(link: any) => {
                  const src = link.source;
                  return typeof src === 'object' ? src.color : '#6366f1';
                }}
                linkDirectionalParticleSpeed={0.004}
                enableNodeDrag={true}
                onNodeHover={(node: any) => setHoveredNode(node?.id || null)}
                onNodeClick={handleNodeClick}
                onNodeDragEnd={(node: any) => {
                  // Only pin if physics is explicitly locked by user
                  if (isPhysicsLocked) {
                    node.fx = node.x;
                    node.fy = node.y;
                  }
                }}
                cooldownTicks={200}
                d3AlphaDecay={0.012}
                d3VelocityDecay={0.25}
              />
            ) : (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-pink-500/10 to-violet-500/10 border border-white/5 flex items-center justify-center mx-auto mb-4">
                    <Shield className="w-8 h-8 text-gray-700" />
                  </div>
                  <p className="text-sm text-gray-500 font-medium">Waiting for threat data…</p>
                  <p className="text-xs text-gray-600 mt-1">Run the Live Scanner or Red Team Simulator to populate the graph</p>
                </div>
              </div>
            )}
          </div>

          {/* ── Intelligence Panel (Right Side) ── */}
          {showPanel && (
            <div className="w-[310px] ml-3 flex flex-col gap-3 overflow-y-auto overflow-x-hidden custom-scrollbar">
              {/* Selected Node Deep Dive */}
              {selectedNode ? (
                <div className="glass-card p-4 border-l-2" style={{ borderLeftColor: NODE_TYPES[selectedNode.type]?.color || '#fff' }}>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[9px] uppercase tracking-[0.15em] font-bold px-2 py-0.5 rounded-full" style={{ background: `${NODE_TYPES[selectedNode.type]?.color}20`, color: NODE_TYPES[selectedNode.type]?.color }}>
                      {NODE_TYPES[selectedNode.type]?.label || selectedNode.type}
                    </span>
                    <button onClick={() => setSelectedNode(null)} className="text-gray-600 hover:text-white transition-colors">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <h3 className="text-sm font-bold text-white mb-1 break-words">{selectedNode.label}</h3>
                  {selectedNode.count !== undefined && (
                    <p className="text-xs font-mono mb-3" style={{ color: NODE_TYPES[selectedNode.type]?.color }}>
                      {selectedNode.count.toLocaleString()} events detected
                    </p>
                  )}

                  {/* Connected Nodes */}
                  {connectedNodes.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-white/[0.06]">
                      <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-2 flex items-center gap-1.5">
                        <GitBranch className="w-3 h-3" />
                        {connectedNodes.length} Connected Nodes
                      </p>
                      <div className="space-y-1 max-h-48 overflow-y-auto custom-scrollbar">
                        {connectedNodes.sort((a, b) => (b.linkValue || 0) - (a.linkValue || 0)).map(cn => (
                          <button
                            key={cn.id}
                            onClick={() => handlePanelNodeClick(cn.id)}
                            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/[0.04] transition-colors text-left group"
                          >
                            <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: NODE_TYPES[cn.type]?.color }} />
                            <span className="text-[11px] text-gray-400 group-hover:text-white transition-colors truncate flex-1">
                              {cn.label}
                            </span>
                            <span className="text-[9px] font-mono text-gray-600 flex-shrink-0">{cn.linkValue}</span>
                            <ChevronRight className="w-2.5 h-2.5 text-gray-700 group-hover:text-gray-400 flex-shrink-0" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="glass-card p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Crosshair className="w-3.5 h-3.5 text-gray-500" />
                    <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Node Inspector</span>
                  </div>
                  <p className="text-xs text-gray-600">Click any node in the graph to inspect its relationships, event counts, and connected entities.</p>
                </div>
              )}

              {/* Graph Statistics */}
              <div className="glass-card p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Layers className="w-3.5 h-3.5 text-pink-400" />
                  <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Graph Composition</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(NODE_TYPES).map(([key, def]) => {
                    const count = analytics.typeBreakdown[key] || 0;
                    if (count === 0) return null;
                    return (
                      <div key={key} className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-white/[0.02]">
                        <div className="w-1.5 h-1.5 rounded-full" style={{ background: def.color }} />
                        <span className="text-[10px] text-gray-500 flex-1">{def.label}</span>
                        <span className="text-[11px] font-mono font-bold text-white">{count}</span>
                      </div>
                    );
                  })}
                </div>

                {/* Block rate mini stat */}
                <div className="mt-3 pt-3 border-t border-white/[0.06]">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-gray-500">Block Rate</span>
                    <span className="text-sm font-bold text-emerald-400">{analytics.blockRate}%</span>
                  </div>
                  <div className="mt-1.5 h-1.5 rounded-full bg-white/[0.04] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700" style={{
                      width: `${analytics.blockRate}%`,
                      background: `linear-gradient(90deg, #ef4444, #f59e0b, #10b981)`,
                    }} />
                  </div>
                </div>
              </div>

              {/* Top Attack Categories */}
              {analytics.topCategories.length > 0 && (
                <div className="glass-card p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Top Attack Categories</span>
                  </div>
                  <div className="space-y-2">
                    {analytics.topCategories.map((cat) => {
                      const maxCount = analytics.topCategories[0]?.count || 1;
                      const pct = Math.round(((cat.count || 0) / maxCount) * 100);
                      return (
                        <button
                          key={cat.id}
                          onClick={() => handlePanelNodeClick(cat.id)}
                          className="w-full group"
                        >
                          <div className="flex items-center justify-between mb-0.5">
                            <span className="text-[11px] text-gray-400 group-hover:text-white transition-colors truncate">
                              {cat.label}
                            </span>
                            <span className="text-[10px] font-mono text-amber-400 ml-2 flex-shrink-0">{cat.count}</span>
                          </div>
                          <div className="h-1 rounded-full bg-white/[0.04] overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-500" style={{
                              width: `${pct}%`,
                              background: `linear-gradient(90deg, #f59e0b, #ef4444)`,
                            }} />
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Top Detectors */}
              {analytics.topDetectors.length > 0 && (
                <div className="glass-card p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Shield className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Top Detectors</span>
                  </div>
                  <div className="space-y-2">
                    {analytics.topDetectors.map(det => {
                      const maxCount = analytics.topDetectors[0]?.count || 1;
                      const pct = Math.round(((det.count || 0) / maxCount) * 100);
                      return (
                        <button
                          key={det.id}
                          onClick={() => handlePanelNodeClick(det.id)}
                          className="w-full group"
                        >
                          <div className="flex items-center justify-between mb-0.5">
                            <span className="text-[11px] text-gray-400 group-hover:text-white transition-colors truncate">
                              {det.label}
                            </span>
                            <span className="text-[10px] font-mono text-cyan-400 ml-2 flex-shrink-0">{det.count}</span>
                          </div>
                          <div className="h-1 rounded-full bg-white/[0.04] overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-500" style={{
                              width: `${pct}%`,
                              background: `linear-gradient(90deg, #06b6d4, #3b82f6)`,
                            }} />
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
