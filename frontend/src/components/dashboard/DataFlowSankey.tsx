'use client';

import { useMemo, useRef, useEffect, useState } from 'react';
import { sankey, sankeyLinkHorizontal, sankeyCenter, type SankeyGraph } from 'd3-sankey';
import { Activity, Shield, Zap } from 'lucide-react';

/* ─── Category → Node Mapping ─── */
const SOURCE_NODES = [
  { id: 'src_injection', label: 'Prompt Injection', color: '#ef4444' },
  { id: 'src_jailbreak', label: 'Jailbreak', color: '#f97316' },
  { id: 'src_encoded', label: 'Encoded Payload', color: '#eab308' },
  { id: 'src_pii', label: 'PII / Secrets', color: '#8b5cf6' },
  { id: 'src_policy', label: 'Policy Violation', color: '#ec4899' },
  { id: 'src_oracle', label: 'Oracle / Sponge', color: '#06b6d4' },
  { id: 'src_agent', label: 'Agent Hijack', color: '#10b981' },
  { id: 'src_campaign', label: 'Campaign / Pack', color: '#6366f1' },
  { id: 'src_other', label: 'Other Threats', color: '#64748b' },
];

const DETECTOR_NODES = [
  { id: 'det_ml', label: 'ML Ensemble', color: '#3b82f6' },
  { id: 'det_signature', label: 'Signature Engine', color: '#f59e0b' },
  { id: 'det_semantic', label: 'Semantic Classifier', color: '#8b5cf6' },
  { id: 'det_campaign', label: 'Campaign Detector', color: '#ec4899' },
  { id: 'det_policy', label: 'Content Policy', color: '#ef4444' },
  { id: 'det_other', label: 'Other Detectors', color: '#64748b' },
];

const ACTION_NODES = [
  { id: 'act_blocked', label: 'BLOCKED', color: '#ef4444' },
  { id: 'act_flagged', label: 'FLAGGED', color: '#f59e0b' },
  { id: 'act_allowed', label: 'ALLOWED', color: '#10b981' },
];

function mapCategoryToSource(category: string): string {
  if (!category) return 'src_other';
  const c = category.toLowerCase();
  if (c.includes('injection') || c.includes('intent')) return 'src_injection';
  if (c.includes('jailbreak') || c.includes('pliny')) return 'src_jailbreak';
  if (c.includes('encoded') || c.includes('obfuscation') || c.includes('tokenizer')) return 'src_encoded';
  if (c.includes('pii') || c.includes('secret')) return 'src_pii';
  if (c.includes('policy') || c.includes('content') || c.includes('hallucination')) return 'src_policy';
  if (c.includes('oracle') || c.includes('sponge')) return 'src_oracle';
  if (c.includes('agent') || c.includes('tool')) return 'src_agent';
  if (c.includes('campaign') || c.includes('pack_hunt') || c.includes('velocity')) return 'src_campaign';
  if (c.includes('ml') || c.includes('embedding') || c.includes('zero_day')) return 'src_campaign';
  return 'src_other';
}

function mapDetectorToNode(detector: string): string {
  if (!detector) return 'det_other';
  const d = detector.toLowerCase();
  if (d.includes('ml_ensemble') || d.includes('ml')) return 'det_ml';
  if (d.includes('prompt_injection') || d.includes('jailbreak') || d.includes('encoded') || d.includes('secret') || d.includes('pii')) return 'det_signature';
  if (d.includes('semantic') || d.includes('intent')) return 'det_semantic';
  if (d.includes('campaign') || d.includes('pack_hunt')) return 'det_campaign';
  if (d.includes('policy') || d.includes('content')) return 'det_policy';
  return 'det_other';
}

interface DataFlowSankeyProps {
  recentScans?: any[];
}

export default function DataFlowSankey({ recentScans = [] }: DataFlowSankeyProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 1200, height: 600 });
  const [hoveredLink, setHoveredLink] = useState<string | null>(null);

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

  const sankeyData = useMemo(() => {
    const threats = recentScans.filter(s => s.threat_level !== 'safe');

    // Build flow counts
    const srcToDetLinks: Record<string, number> = {};
    const detToActLinks: Record<string, number> = {};

    threats.forEach(scan => {
      const detections = scan.detections || [];
      const action = scan.action || 'allowed';
      const actNode = action === 'blocked' ? 'act_blocked' : action === 'flagged' ? 'act_flagged' : 'act_allowed';

      if (detections.length === 0) {
        const src = mapCategoryToSource(scan.category || '');
        const det = 'det_other';
        const key1 = `${src}→${det}`;
        srcToDetLinks[key1] = (srcToDetLinks[key1] || 0) + 1;
        const key2 = `${det}→${actNode}`;
        detToActLinks[key2] = (detToActLinks[key2] || 0) + 1;
      } else {
        detections.forEach((d: any) => {
          const src = mapCategoryToSource(d.category || '');
          const det = mapDetectorToNode(d.detector || '');
          const key1 = `${src}→${det}`;
          srcToDetLinks[key1] = (srcToDetLinks[key1] || 0) + 1;
          const key2 = `${det}→${actNode}`;
          detToActLinks[key2] = (detToActLinks[key2] || 0) + 1;
        });
      }
    });

    // Build nodes array with only used nodes
    const usedNodeIds = new Set<string>();
    [...Object.keys(srcToDetLinks), ...Object.keys(detToActLinks)].forEach(key => {
      key.split('→').forEach(id => usedNodeIds.add(id));
    });

    const allNodeDefs = [...SOURCE_NODES, ...DETECTOR_NODES, ...ACTION_NODES];
    const nodesList = allNodeDefs.filter(n => usedNodeIds.has(n.id));
    const nodeIndex: Record<string, number> = {};
    nodesList.forEach((n, i) => { nodeIndex[n.id] = i; });

    const links: { source: number; target: number; value: number }[] = [];

    Object.entries(srcToDetLinks).forEach(([key, val]) => {
      const [src, tgt] = key.split('→');
      if (nodeIndex[src] !== undefined && nodeIndex[tgt] !== undefined) {
        links.push({ source: nodeIndex[src], target: nodeIndex[tgt], value: val });
      }
    });

    Object.entries(detToActLinks).forEach(([key, val]) => {
      const [src, tgt] = key.split('→');
      if (nodeIndex[src] !== undefined && nodeIndex[tgt] !== undefined) {
        links.push({ source: nodeIndex[src], target: nodeIndex[tgt], value: val });
      }
    });

    if (nodesList.length === 0 || links.length === 0) return null;

    const { width, height } = dimensions;
    const margin = { top: 30, right: 20, bottom: 30, left: 20 };

    try {
      const sankeyGen = sankey<{ label: string; color: string }, {}>()
        .nodeId((d: any) => d.index)
        .nodeAlign(sankeyCenter)
        .nodeWidth(20)
        .nodePadding(16)
        .extent([[margin.left, margin.top], [width - margin.right, height - margin.bottom]]);

      const graph = sankeyGen({
        nodes: nodesList.map((n, i) => ({ ...n, index: i })) as any,
        links: links as any,
      });

      return graph;
    } catch {
      return null;
    }
  }, [recentScans, dimensions]);

  const totalThreats = recentScans.filter(s => s.threat_level !== 'safe').length;
  const allNodeDefs = [...SOURCE_NODES, ...DETECTOR_NODES, ...ACTION_NODES];

  return (
    <div className="h-full overflow-hidden bg-transparent text-gray-300">
      <div className="h-full flex flex-col">
        {/* Header */}
        <div className="px-8 pt-8 pb-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                  <Activity className="w-5 h-5 text-emerald-400" />
                </div>
                Data Flow Sankey
              </h1>
              <p className="text-xs text-gray-500 mt-1 ml-12">
                Threat category → Detection engine → Action outcome flow visualization
              </p>
            </div>
            <div className="flex items-center gap-4">
              <div className="glass-card px-4 py-2 flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                </span>
                <span className="text-xs font-mono text-gray-400">
                  {totalThreats} threats flowing through {sankeyData?.nodes?.length || 0} nodes
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Legend */}
        <div className="px-8 pb-3 flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm bg-red-500/60" />
            <span className="text-[10px] text-gray-500 uppercase tracking-wider">Threat Sources</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm bg-blue-500/60" />
            <span className="text-[10px] text-gray-500 uppercase tracking-wider">Detection Engines</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm bg-emerald-500/60" />
            <span className="text-[10px] text-gray-500 uppercase tracking-wider">Actions</span>
          </div>
        </div>

        {/* Sankey Diagram */}
        <div
          ref={containerRef}
          className="flex-1 mx-8 mb-8 rounded-xl border border-white/[0.06] overflow-hidden relative"
          style={{ background: '#050914' }}
        >
          {sankeyData ? (
            <svg ref={svgRef} width={dimensions.width} height={dimensions.height} className="w-full h-full">
              <defs>
                {(sankeyData.links as any[]).map((link: any, i: number) => {
                  const srcNode = allNodeDefs.find(n => n.label === link.source?.label);
                  const tgtNode = allNodeDefs.find(n => n.label === link.target?.label);
                  return (
                    <linearGradient key={`grad-${i}`} id={`grad-${i}`} gradientUnits="userSpaceOnUse"
                      x1={link.source?.x1} x2={link.target?.x0}>
                      <stop offset="0%" stopColor={srcNode?.color || '#6366f1'} stopOpacity={0.5} />
                      <stop offset="100%" stopColor={tgtNode?.color || '#6366f1'} stopOpacity={0.5} />
                    </linearGradient>
                  );
                })}
              </defs>

              {/* Links */}
              <g>
                {(sankeyData.links as any[]).map((link: any, i: number) => {
                  const linkId = `link-${i}`;
                  const isHovered = hoveredLink === linkId;
                  return (
                    <path
                      key={linkId}
                      d={sankeyLinkHorizontal()(link) || ''}
                      fill="none"
                      stroke={`url(#grad-${i})`}
                      strokeWidth={Math.max(link.width || 1, 2)}
                      strokeOpacity={isHovered ? 0.8 : 0.35}
                      onMouseEnter={() => setHoveredLink(linkId)}
                      onMouseLeave={() => setHoveredLink(null)}
                      className="transition-all duration-200 cursor-pointer"
                    />
                  );
                })}
              </g>

              {/* Nodes */}
              <g>
                {(sankeyData.nodes as any[]).map((node: any, i: number) => {
                  const nodeDef = allNodeDefs.find(n => n.label === node.label);
                  const color = nodeDef?.color || '#6366f1';
                  const nodeHeight = Math.max((node.y1 || 0) - (node.y0 || 0), 4);
                  return (
                    <g key={`node-${i}`}>
                      <rect
                        x={node.x0}
                        y={node.y0}
                        width={(node.x1 || 0) - (node.x0 || 0)}
                        height={nodeHeight}
                        fill={color}
                        rx={4}
                        ry={4}
                        className="transition-all duration-200"
                        style={{ filter: `drop-shadow(0 0 8px ${color}40)` }}
                      />
                      <text
                        x={node.x0! < dimensions.width / 2 ? (node.x1 || 0) + 8 : (node.x0 || 0) - 8}
                        y={((node.y0 || 0) + (node.y1 || 0)) / 2}
                        textAnchor={node.x0! < dimensions.width / 2 ? 'start' : 'end'}
                        dominantBaseline="central"
                        className="text-[11px] font-mono"
                        fill="#9ca3af"
                      >
                        {node.label} ({node.value || 0})
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Shield className="w-12 h-12 text-gray-700 mx-auto mb-3" />
                <p className="text-sm text-gray-500">Waiting for threat data to build flow diagram...</p>
                <p className="text-xs text-gray-600 mt-1">Run the Live Scanner or trigger live-fire to populate</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
