'use client';

import React, { useMemo, useCallback, useState, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Handle,
  Position,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Shield, Zap, AlertTriangle, XCircle, Activity, Target, Radio, Bug } from 'lucide-react';

/* ─── MITRE ATLAS Kill Chain Stages ─── */
const KILL_CHAIN_STAGES = [
  { id: 'recon', label: 'Reconnaissance', icon: Radio, color: '#6366f1', x: 50 },
  { id: 'weaponize', label: 'Weaponization', icon: Bug, color: '#f59e0b', x: 300 },
  { id: 'delivery', label: 'Delivery', icon: Zap, color: '#ef4444', x: 550 },
  { id: 'exploit', label: 'Exploitation', icon: Target, color: '#dc2626', x: 800 },
  { id: 'install', label: 'Installation', icon: AlertTriangle, color: '#f97316', x: 1050 },
  { id: 'c2', label: 'Command & Control', icon: Activity, color: '#8b5cf6', x: 1300 },
  { id: 'action', label: 'Actions on Objective', icon: XCircle, color: '#ec4899', x: 1550 },
];

const CATEGORY_TO_STAGE: Record<string, string> = {
  'injection': 'delivery',
  'injection.direct_override': 'delivery',
  'injection.instruction_bypass': 'delivery',
  'jailbreak': 'exploit',
  'jailbreak.persona_switch': 'exploit',
  'jailbreak.hypothetical': 'exploit',
  'pliny': 'exploit',
  'encoded': 'weaponize',
  'obfuscation': 'weaponize',
  'pii': 'action',
  'secrets': 'action',
  'secret': 'action',
  'oracle': 'recon',
  'sponge': 'c2',
  'policy': 'install',
  'content': 'install',
  'tokenizer': 'weaponize',
  'zero_day': 'exploit',
  'agent': 'c2',
  'external': 'delivery',
  'memorization': 'action',
  'supply_chain': 'install',
  'hallucination': 'action',
  'campaign': 'recon',
  'ml': 'recon',
  'pack_hunt': 'recon',
  'intent': 'delivery',
};

function mapCategory(category: string): string {
  if (!category) return 'delivery';
  const prefix = category.split('.')[0];
  return CATEGORY_TO_STAGE[category] || CATEGORY_TO_STAGE[prefix] || 'delivery';
}

/* ─── Custom Node Components ─── */
function StageNode({ data }: { data: any }) {
  const Icon = data.icon;
  return (
    <div
      className="relative group"
      style={{ minWidth: 180 }}
    >
      <Handle type="target" position={Position.Left} className="!bg-transparent !border-0 !w-0 !h-0" />
      <div
        className="rounded-xl border px-5 py-4 backdrop-blur-md transition-all duration-300 hover:scale-105"
        style={{
          background: `linear-gradient(135deg, ${data.color}15, ${data.color}08)`,
          borderColor: `${data.color}40`,
          boxShadow: `0 0 20px ${data.color}15, inset 0 1px 0 ${data.color}20`,
        }}
      >
        <div className="flex items-center gap-3 mb-2">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: `${data.color}25`, border: `1px solid ${data.color}50` }}
          >
            <Icon className="w-4 h-4" style={{ color: data.color }} />
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-widest font-mono" style={{ color: `${data.color}99` }}>
              Stage {data.stageIndex + 1}
            </p>
            <h3 className="text-sm font-bold text-white leading-tight">{data.label}</h3>
          </div>
        </div>
        <div className="flex items-center justify-between mt-3 pt-3 border-t" style={{ borderColor: `${data.color}20` }}>
          <span className="text-xs font-mono" style={{ color: data.color }}>
            {data.count} events
          </span>
          <div className="flex gap-1">
            {data.techniques.slice(0, 3).map((t: string, i: number) => (
              <span
                key={i}
                className="text-[8px] px-1.5 py-0.5 rounded font-mono"
                style={{ background: `${data.color}20`, color: `${data.color}cc` }}
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-transparent !border-0 !w-0 !h-0" />
    </div>
  );
}

function AttackNode({ data }: { data: any }) {
  return (
    <div className="relative">
      <Handle type="target" position={Position.Top} className="!bg-transparent !border-0 !w-0 !h-0" />
      <div
        className="rounded-lg border px-3 py-2 backdrop-blur-sm max-w-[160px] transition-all hover:scale-105"
        style={{
          background: `${data.color}10`,
          borderColor: `${data.color}30`,
        }}
      >
        <p className="text-[9px] font-mono truncate" style={{ color: `${data.color}dd` }}>
          {data.label}
        </p>
        <p className="text-[8px] text-gray-500 truncate mt-0.5">{data.sub}</p>
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-transparent !border-0 !w-0 !h-0" />
    </div>
  );
}

const nodeTypes = {
  stageNode: StageNode,
  attackNode: AttackNode,
};

interface AttackFlowCanvasProps {
  recentScans?: any[];
}

export default function AttackFlowCanvas({ recentScans = [] }: AttackFlowCanvasProps) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const stageCounts: Record<string, { count: number; techniques: Set<string>; attacks: any[] }> = {};
    KILL_CHAIN_STAGES.forEach(s => {
      stageCounts[s.id] = { count: 0, techniques: new Set(), attacks: [] };
    });

    // Process live scan data into kill chain stages
    const threats = recentScans.filter(s => s.threat_level !== 'safe');
    threats.forEach(scan => {
      const detections = scan.detections || [];
      const cats = detections.map((d: any) => d.category || '').filter(Boolean);
      if (cats.length === 0) cats.push(scan.category || 'injection');

      cats.forEach((cat: string) => {
        const stage = mapCategory(cat);
        if (stageCounts[stage]) {
          stageCounts[stage].count++;
          stageCounts[stage].techniques.add(cat.split('.')[0]);
          if (stageCounts[stage].attacks.length < 4) {
            stageCounts[stage].attacks.push(scan);
          }
        }
      });
    });

    const nodes: Node[] = [];
    const edges: Edge[] = [];

    // Create stage nodes
    KILL_CHAIN_STAGES.forEach((stage, i) => {
      const data = stageCounts[stage.id];
      nodes.push({
        id: stage.id,
        type: 'stageNode',
        position: { x: stage.x, y: 200 },
        data: {
          label: stage.label,
          icon: stage.icon,
          color: stage.color,
          stageIndex: i,
          count: data.count,
          techniques: Array.from(data.techniques),
        },
      });

      // Create attack detail nodes below each stage
      data.attacks.slice(0, 3).forEach((attack, ai) => {
        const attackId = `${stage.id}-attack-${ai}`;
        nodes.push({
          id: attackId,
          type: 'attackNode',
          position: { x: stage.x + (ai * 60 - 60), y: 380 + ai * 60 },
          data: {
            label: attack.prompt?.slice(0, 30) || attack.category || 'Unknown',
            sub: `${attack.model || 'unknown'} • ${attack.threat_score ? (attack.threat_score * 100).toFixed(0) + '%' : ''}`,
            color: stage.color,
          },
        });
        edges.push({
          id: `e-${stage.id}-${attackId}`,
          source: stage.id,
          target: attackId,
          type: 'smoothstep',
          animated: true,
          style: { stroke: `${stage.color}40`, strokeWidth: 1 },
        });
      });

      // Connect stages in sequence
      if (i > 0) {
        const prevStage = KILL_CHAIN_STAGES[i - 1];
        const hasFlow = data.count > 0 || stageCounts[prevStage.id].count > 0;
        edges.push({
          id: `e-${prevStage.id}-${stage.id}`,
          source: prevStage.id,
          target: stage.id,
          type: 'smoothstep',
          animated: hasFlow,
          style: {
            stroke: hasFlow ? `${stage.color}80` : '#ffffff10',
            strokeWidth: hasFlow ? 2 : 1,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: hasFlow ? `${stage.color}80` : '#ffffff10',
            width: 15,
            height: 12,
          },
        });
      }
    });

    return { nodes, edges };
  }, [recentScans]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync state when props/memo change
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const totalThreats = recentScans.filter(s => s.threat_level !== 'safe').length;

  return (
    <div className="h-full overflow-hidden bg-transparent text-gray-300">
      <div className="h-full flex flex-col">
        {/* Header */}
        <div className="px-8 pt-8 pb-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center">
                  <Zap className="w-5 h-5 text-indigo-400" />
                </div>
                Attack Flow Canvas
              </h1>
              <p className="text-xs text-gray-500 mt-1 ml-12">
                MITRE ATLAS kill chain visualization — real-time attack progression mapping
              </p>
            </div>
            <div className="flex items-center gap-4">
              <div className="glass-card px-4 py-2 flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
                </span>
                <span className="text-xs font-mono text-gray-400">
                  {totalThreats} active threats across {KILL_CHAIN_STAGES.length} stages
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Flow Canvas */}
        <div className="flex-1 mx-8 mb-8 rounded-xl border border-white/[0.06] overflow-hidden" style={{ background: '#050914', position: 'relative' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.3 }}
            proOptions={{ hideAttribution: true }}
            minZoom={0.3}
            maxZoom={2}
            style={{ width: '100%', height: '100%' }}
          >
            <Background color="#ffffff08" gap={20} size={1} />
            <Controls
              className="!bg-[#0a0f1a] !border-white/10 !rounded-lg !shadow-xl [&>button]:!bg-[#0a0f1a] [&>button]:!border-white/10 [&>button]:!text-gray-400 [&>button:hover]:!bg-white/5"
            />
            <MiniMap
              nodeColor={(node) => {
                const data = node.data as any;
                return data?.color || '#6366f1';
              }}
              maskColor="#050914dd"
              className="!bg-[#0a0f1a] !border-white/10 !rounded-lg"
            />
          </ReactFlow>
        </div>
      </div>
    </div>
  );
}
