import React, { useState, useCallback, useEffect } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

// ── Node type definitions ──
const NODE_TYPES = [
  { type: 'trigger', label: 'Trigger', icon: '⚡', color: '#EF4444', desc: 'Entry point — starts the playbook' },
  { type: 'condition', label: 'Condition', icon: '🔀', color: '#F59E0B', desc: 'Branch based on field value' },
  { type: 'osint_enrich', label: 'OSINT Enrich', icon: '🔍', color: '#06B6D4', desc: 'Run OSINT enrichment on source IP' },
  { type: 'firewall_ban', label: 'Firewall Ban', icon: '🛡️', color: '#DC2626', desc: 'Ban IP at OS firewall level' },
  { type: 'create_ticket', label: 'Create Ticket', icon: '🎫', color: '#8B5CF6', desc: 'Create Jira/ServiceNow ticket' },
  { type: 'send_notification', label: 'Notify', icon: '📣', color: '#10B981', desc: 'Send Slack/Teams/PagerDuty alert' },
  { type: 'wait', label: 'Wait', icon: '⏱️', color: '#6B7280', desc: 'Pause for N seconds' },
  { type: 'webhook', label: 'Webhook', icon: '🌐', color: '#3B82F6', desc: 'Call external HTTP endpoint' },
  { type: 'ai_summarize', label: 'AI Summary', icon: '🤖', color: '#A855F7', desc: 'Generate AI incident summary' },
  { type: 'update_policy', label: 'Update Policy', icon: '📋', color: '#F97316', desc: 'Push BIOC policy rule' },
];

const TRIGGER_TYPES = [
  { value: 'severity', label: 'Severity Threshold', desc: 'Trigger when threat level meets minimum' },
  { value: 'category', label: 'Attack Category', desc: 'Trigger on specific attack types' },
  { value: 'blocked', label: 'Blocked Request', desc: 'Trigger when request is blocked' },
];

// ── Node Component ──
function PlaybookNode({ node, isSelected, onSelect, onDelete, onDragStart }: any) {
  const typeDef = NODE_TYPES.find(t => t.type === node.type) || NODE_TYPES[0];
  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, node.id)}
      onClick={() => onSelect(node.id)}
      style={{
        position: 'absolute',
        left: node.position?.x || 0,
        top: node.position?.y || 0,
        width: 200,
        padding: '14px 16px',
        background: isSelected ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.03)',
        border: `1px solid ${isSelected ? typeDef.color : 'rgba(255,255,255,0.08)'}`,
        borderRadius: 10,
        cursor: 'grab',
        zIndex: isSelected ? 10 : 1,
        transition: 'all 0.15s ease',
        boxShadow: isSelected ? `0 0 20px ${typeDef.color}22` : 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 18 }}>{typeDef.icon}</span>
        <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: 13 }}>{node.label || typeDef.label}</span>
        <button
          onClick={(e) => { e.stopPropagation(); onDelete(node.id); }}
          style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#64748B', cursor: 'pointer', fontSize: 14 }}
        >✕</button>
      </div>
      <div style={{ fontSize: 10, color: '#64748B', fontFamily: 'JetBrains Mono, monospace' }}>
        {typeDef.desc}
      </div>
      {/* Connection dots */}
      <div style={{ position: 'absolute', bottom: -6, left: '50%', transform: 'translateX(-50%)', width: 10, height: 10, borderRadius: '50%', background: typeDef.color, border: '2px solid #0F1419' }} />
      <div style={{ position: 'absolute', top: -6, left: '50%', transform: 'translateX(-50%)', width: 10, height: 10, borderRadius: '50%', background: '#334155', border: '2px solid #0F1419' }} />
    </div>
  );
}

// ── Edge Component ──
function PlaybookEdge({ from, to, nodes }: any) {
  const fromNode = nodes.find((n: any) => n.id === from);
  const toNode = nodes.find((n: any) => n.id === to);
  if (!fromNode || !toNode) return null;

  const x1 = (fromNode.position?.x || 0) + 100;
  const y1 = (fromNode.position?.y || 0) + 70;
  const x2 = (toNode.position?.x || 0) + 100;
  const y2 = (toNode.position?.y || 0);

  return (
    <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 0 }}>
      <path
        d={`M ${x1} ${y1} C ${x1} ${y1 + 40}, ${x2} ${y2 - 40}, ${x2} ${y2}`}
        stroke="rgba(100,116,139,0.4)"
        strokeWidth={2}
        fill="none"
        strokeDasharray="6,4"
      />
      <polygon
        points={`${x2-4},${y2-8} ${x2+4},${y2-8} ${x2},${y2}`}
        fill="rgba(100,116,139,0.6)"
      />
    </svg>
  );
}

// ── Config Panel ──
function NodeConfigPanel({ node, onUpdate }: any) {
  if (!node) return (
    <div style={{ padding: 24, color: '#64748B', textAlign: 'center', fontSize: 13 }}>
      Select a node to configure
    </div>
  );

  const typeDef = NODE_TYPES.find(t => t.type === node.type) || NODE_TYPES[0];

  return (
    <div style={{ padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <span style={{ fontSize: 20 }}>{typeDef.icon}</span>
        <span style={{ fontWeight: 600, color: '#F1F5F9', fontSize: 15 }}>{typeDef.label}</span>
      </div>

      {/* Label */}
      <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: 1 }}>Label</label>
      <input
        value={node.label || ''}
        onChange={(e) => onUpdate({ ...node, label: e.target.value })}
        style={{ width: '100%', padding: '8px 12px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 16, outline: 'none', boxSizing: 'border-box' }}
      />

      {/* Type-specific configs */}
      {node.type === 'condition' && (
        <>
          <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace' }}>CONDITION FIELD</label>
          <select
            value={node.data?.config?.field || 'threat_score'}
            onChange={(e) => onUpdate({ ...node, data: { ...node.data, config: { ...(node.data?.config || {}), field: e.target.value } } })}
            style={{ width: '100%', padding: '8px 12px', background: '#0F1419', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 12, outline: 'none' }}
          >
            <option value="threat_score">Threat Score</option>
            <option value="threat_level">Threat Level</option>
            <option value="is_blocked">Is Blocked</option>
            <option value="source_ip">Source IP</option>
          </select>
          <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace' }}>THRESHOLD VALUE</label>
          <input
            type="number"
            step="0.1"
            value={node.data?.config?.value || 0.8}
            onChange={(e) => onUpdate({ ...node, data: { ...node.data, config: { ...(node.data?.config || {}), value: parseFloat(e.target.value) } } })}
            style={{ width: '100%', padding: '8px 12px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 12, outline: 'none', boxSizing: 'border-box' }}
          />
        </>
      )}

      {node.type === 'send_notification' && (
        <>
          <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace' }}>PROVIDER</label>
          <select
            value={node.data?.config?.provider || 'slack'}
            onChange={(e) => onUpdate({ ...node, data: { ...node.data, config: { ...(node.data?.config || {}), provider: e.target.value } } })}
            style={{ width: '100%', padding: '8px 12px', background: '#0F1419', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 12, outline: 'none' }}
          >
            <option value="slack">Slack</option>
            <option value="teams">Microsoft Teams</option>
            <option value="pagerduty">PagerDuty</option>
            <option value="opsgenie">Opsgenie</option>
          </select>
        </>
      )}

      {node.type === 'create_ticket' && (
        <>
          <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace' }}>TICKETING SYSTEM</label>
          <select
            value={node.data?.config?.provider || 'jira'}
            onChange={(e) => onUpdate({ ...node, data: { ...node.data, config: { ...(node.data?.config || {}), provider: e.target.value } } })}
            style={{ width: '100%', padding: '8px 12px', background: '#0F1419', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 12, outline: 'none' }}
          >
            <option value="jira">Jira</option>
            <option value="servicenow">ServiceNow</option>
          </select>
        </>
      )}

      {node.type === 'wait' && (
        <>
          <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace' }}>WAIT (SECONDS)</label>
          <input
            type="number"
            value={node.data?.config?.seconds || 5}
            onChange={(e) => onUpdate({ ...node, data: { ...node.data, config: { ...(node.data?.config || {}), seconds: parseInt(e.target.value) } } })}
            style={{ width: '100%', padding: '8px 12px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 12, outline: 'none', boxSizing: 'border-box' }}
          />
        </>
      )}

      {node.type === 'webhook' && (
        <>
          <label style={{ display: 'block', fontSize: 11, color: '#94A3B8', marginBottom: 4, fontFamily: 'JetBrains Mono, monospace' }}>WEBHOOK URL</label>
          <input
            value={node.data?.config?.url || ''}
            placeholder="https://your-endpoint.com/hook"
            onChange={(e) => onUpdate({ ...node, data: { ...node.data, config: { ...(node.data?.config || {}), url: e.target.value } } })}
            style={{ width: '100%', padding: '8px 12px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: '#F1F5F9', fontSize: 13, marginBottom: 12, outline: 'none', boxSizing: 'border-box' }}
          />
        </>
      )}
    </div>
  );
}

// ── Main Playbook Builder ──
export default function PlaybookBuilderView() {
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [activePlaybook, setActivePlaybook] = useState<any>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [connectingFrom, setConnectingFrom] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newTriggerType, setNewTriggerType] = useState('severity');
  const [saving, setSaving] = useState(false);
  const [execHistory, setExecHistory] = useState<any[]>([]);

  const token = localStorage.getItem('access_token');
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };

  const fetchPlaybooks = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/v1/playbooks/`, { headers });
      if (r.ok) {
        const data = await r.json();
        if (data.length > 0) {
          setPlaybooks(data);
          if (!activePlaybook) setActivePlaybook(data[0]);
        }
      }
    } catch {}
    // If no playbooks loaded and none active, auto-create a starter playbook client-side
    if (!activePlaybook && playbooks.length === 0) {
      const starter = {
        id: `pb-local-${Date.now()}`,
        name: 'Starter Playbook',
        status: 'draft',
        trigger_type: 'severity',
        trigger_conditions: { min_severity: 'high' },
        total_runs: 0,
        nodes: [{ id: 'trigger-1', type: 'trigger', label: 'Trigger', position: { x: 280, y: 40 }, data: {} }],
        edges: [],
      };
      setPlaybooks([starter]);
      setActivePlaybook(starter);
    }
  }, []);

  useEffect(() => { fetchPlaybooks(); }, []);

  const createPlaybook = async () => {
    const newPb = {
      id: `pb-${Date.now()}`,
      name: newName || 'New Playbook',
      status: 'draft',
      trigger_type: newTriggerType,
      trigger_conditions: newTriggerType === 'severity' ? { min_severity: 'high' } : {},
      total_runs: 0,
      nodes: [{ id: 'trigger-1', type: 'trigger', label: 'Trigger', position: { x: 280, y: 40 }, data: {} }],
      edges: [],
    };

    // Try API first
    try {
      const r = await fetch(`${API}/api/v1/playbooks/`, {
        method: 'POST', headers,
        body: JSON.stringify(newPb),
      });
      if (r.ok) {
        const pb = await r.json();
        setActivePlaybook(pb);
        setPlaybooks(prev => [...prev, pb]);
        setShowCreate(false);
        setNewName('');
        return;
      }
    } catch {}

    // Fallback: create client-side
    setActivePlaybook(newPb);
    setPlaybooks(prev => [...prev, newPb]);
    setShowCreate(false);
    setNewName('');
  };

  const savePlaybook = async () => {
    if (!activePlaybook) return;
    setSaving(true);
    await fetch(`/api/v1/playbooks/${activePlaybook.id}`, {
      method: 'PUT', headers,
      body: JSON.stringify({ nodes: activePlaybook.nodes, edges: activePlaybook.edges, name: activePlaybook.name, status: activePlaybook.status }),
    });
    setSaving(false);
    fetchPlaybooks();
  };

  const addNode = (type: string) => {
    if (!activePlaybook) return;
    const typeDef = NODE_TYPES.find(t => t.type === type)!;
    const newNode = {
      id: `${type}-${Date.now()}`,
      type,
      label: typeDef.label,
      position: { x: 200 + Math.random() * 200, y: 100 + (activePlaybook.nodes?.length || 0) * 100 },
      data: { config: {} },
    };
    setActivePlaybook({ ...activePlaybook, nodes: [...(activePlaybook.nodes || []), newNode] });
  };

  const deleteNode = (nodeId: string) => {
    if (!activePlaybook) return;
    setActivePlaybook({
      ...activePlaybook,
      nodes: activePlaybook.nodes.filter((n: any) => n.id !== nodeId),
      edges: activePlaybook.edges.filter((e: any) => e.source !== nodeId && e.target !== nodeId),
    });
    if (selectedNodeId === nodeId) setSelectedNodeId(null);
  };

  const updateNode = (updated: any) => {
    if (!activePlaybook) return;
    setActivePlaybook({
      ...activePlaybook,
      nodes: activePlaybook.nodes.map((n: any) => n.id === updated.id ? updated : n),
    });
  };

  const handleCanvasDrop = (e: React.DragEvent) => {
    const nodeId = e.dataTransfer.getData('nodeId');
    if (!nodeId || !activePlaybook) return;
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const x = e.clientX - rect.left - 100;
    const y = e.clientY - rect.top - 35;
    setActivePlaybook({
      ...activePlaybook,
      nodes: activePlaybook.nodes.map((n: any) => n.id === nodeId ? { ...n, position: { x, y } } : n),
    });
  };

  const handleNodeDragStart = (e: React.DragEvent, nodeId: string) => {
    e.dataTransfer.setData('nodeId', nodeId);
  };

  const toggleConnect = (nodeId: string) => {
    if (connectingFrom) {
      if (connectingFrom !== nodeId) {
        const newEdge = { id: `edge-${Date.now()}`, source: connectingFrom, target: nodeId };
        setActivePlaybook({
          ...activePlaybook,
          edges: [...(activePlaybook.edges || []), newEdge],
        });
      }
      setConnectingFrom(null);
    } else {
      setConnectingFrom(nodeId);
    }
  };

  const executePlaybook = async () => {
    if (!activePlaybook) return;
    const r = await fetch(`${API}/api/v1/playbooks/${activePlaybook.id}/execute`, { method: 'POST', headers });
    if (r.ok) {
      const result = await r.json();
      setExecHistory(prev => [result, ...prev]);
    }
  };

  const activatePlaybook = async () => {
    if (!activePlaybook) return;
    const newStatus = activePlaybook.status === 'active' ? 'paused' : 'active';
    setActivePlaybook({ ...activePlaybook, status: newStatus });
    await fetch(`/api/v1/playbooks/${activePlaybook.id}`, {
      method: 'PUT', headers,
      body: JSON.stringify({ status: newStatus }),
    });
    fetchPlaybooks();
  };

  const selectedNode = activePlaybook?.nodes?.find((n: any) => n.id === selectedNodeId);

  return (
    <div style={{ display: 'flex', height: '100%', color: '#CBD5E1' }}>
      {/* Left sidebar — playbook list + node palette */}
      <div style={{ width: 260, borderRight: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column' }}>
        {/* Playbook list */}
        <div style={{ padding: '16px 16px 8px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#F1F5F9' }}>📋 Playbooks</span>
            <button onClick={() => setShowCreate(true)} style={{ background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, color: '#00D4FF', padding: '4px 10px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>+ New</button>
          </div>
          {showCreate && (
            <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: 12, marginBottom: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
              <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Playbook name" style={{ width: '100%', padding: '6px 10px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4, color: '#F1F5F9', fontSize: 12, marginBottom: 8, outline: 'none', boxSizing: 'border-box' }} />
              <select value={newTriggerType} onChange={e => setNewTriggerType(e.target.value)} style={{ width: '100%', padding: '6px 10px', background: '#0F1419', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4, color: '#F1F5F9', fontSize: 12, marginBottom: 8, outline: 'none' }}>
                {TRIGGER_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={createPlaybook} style={{ flex: 1, padding: '6px 0', background: 'rgba(0,212,255,0.15)', border: '1px solid rgba(0,212,255,0.3)', borderRadius: 4, color: '#00D4FF', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>Create</button>
                <button onClick={() => setShowCreate(false)} style={{ flex: 1, padding: '6px 0', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4, color: '#64748B', fontSize: 11, cursor: 'pointer' }}>Cancel</button>
              </div>
            </div>
          )}
          <div style={{ maxHeight: 160, overflowY: 'auto' }}>
            {playbooks.map((pb: any) => (
              <div
                key={pb.id}
                onClick={() => { setActivePlaybook(pb); setSelectedNodeId(null); }}
                style={{
                  padding: '8px 10px', borderRadius: 6, cursor: 'pointer', marginBottom: 4,
                  background: activePlaybook?.id === pb.id ? 'rgba(0,212,255,0.06)' : 'transparent',
                  border: `1px solid ${activePlaybook?.id === pb.id ? 'rgba(0,212,255,0.15)' : 'transparent'}`,
                }}
              >
                <div style={{ fontSize: 12, fontWeight: 600, color: '#F1F5F9' }}>{pb.name}</div>
                <div style={{ fontSize: 10, color: pb.status === 'active' ? '#10B981' : '#64748B', marginTop: 2 }}>
                  {pb.status === 'active' ? '● Active' : pb.status === 'draft' ? '○ Draft' : '◌ Paused'} — {pb.total_runs || 0} runs
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Node palette */}
        <div style={{ padding: '12px 16px', flex: 1, overflowY: 'auto' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#64748B', marginBottom: 8, fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1, textTransform: 'uppercase' }}>Node Palette</div>
          {NODE_TYPES.map(nt => (
            <div
              key={nt.type}
              onClick={() => addNode(nt.type)}
              style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', borderRadius: 6, cursor: 'pointer', marginBottom: 4, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', transition: 'all 0.1s' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.05)'; (e.currentTarget as HTMLElement).style.borderColor = `${nt.color}33`; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.02)'; (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.04)'; }}
            >
              <span style={{ fontSize: 16 }}>{nt.icon}</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#F1F5F9' }}>{nt.label}</div>
                <div style={{ fontSize: 9, color: '#64748B' }}>{nt.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Center — Canvas */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Toolbar */}
        {activePlaybook && (
          <div style={{ display: 'flex', alignItems: 'center', padding: '8px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', gap: 8 }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: '#F1F5F9', flex: 1 }}>{activePlaybook.name}</span>
            <button onClick={savePlaybook} disabled={saving} style={{ padding: '6px 14px', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, color: '#00D4FF', fontSize: 11, cursor: 'pointer', fontWeight: 600, opacity: saving ? 0.5 : 1 }}>
              {saving ? 'Saving...' : '💾 Save'}
            </button>
            <button onClick={activatePlaybook} style={{ padding: '6px 14px', background: activePlaybook.status === 'active' ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)', border: `1px solid ${activePlaybook.status === 'active' ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'}`, borderRadius: 6, color: activePlaybook.status === 'active' ? '#EF4444' : '#10B981', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
              {activePlaybook.status === 'active' ? '⏸ Pause' : '▶ Activate'}
            </button>
            <button onClick={executePlaybook} style={{ padding: '6px 14px', background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.2)', borderRadius: 6, color: '#A855F7', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
              🧪 Test Run
            </button>
            {connectingFrom && (
              <span style={{ fontSize: 10, color: '#F59E0B', fontFamily: 'JetBrains Mono, monospace' }}>
                🔗 Click target node to connect
              </span>
            )}
          </div>
        )}

        {/* Canvas */}
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleCanvasDrop}
          style={{ flex: 1, position: 'relative', overflow: 'hidden', background: 'radial-gradient(circle at 50% 50%, rgba(0,212,255,0.02) 0%, transparent 70%)', backgroundImage: 'radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)', backgroundSize: '24px 24px' }}
        >
          {!activePlaybook && (
            <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center' }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>📋</div>
              <div style={{ fontSize: 16, fontWeight: 600, color: '#F1F5F9', marginBottom: 8 }}>Playbook Builder</div>
              <div style={{ fontSize: 13, color: '#64748B' }}>Select a playbook or create a new one to start building</div>
            </div>
          )}

          {activePlaybook?.edges?.map((edge: any) => (
            <PlaybookEdge key={edge.id} from={edge.source} to={edge.target} nodes={activePlaybook.nodes || []} />
          ))}

          {activePlaybook?.nodes?.map((node: any) => (
            <PlaybookNode
              key={node.id}
              node={node}
              isSelected={selectedNodeId === node.id}
              onSelect={(id: string) => { setSelectedNodeId(id); if (connectingFrom) toggleConnect(id); }}
              onDelete={deleteNode}
              onDragStart={handleNodeDragStart}
            />
          ))}
        </div>
      </div>

      {/* Right panel — config */}
      <div style={{ width: 280, borderLeft: '1px solid rgba(255,255,255,0.06)', overflowY: 'auto' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: '#64748B', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1, textTransform: 'uppercase' }}>Node Config</span>
        </div>
        <NodeConfigPanel node={selectedNode} onUpdate={updateNode} />

        {/* Connection tools */}
        {selectedNodeId && (
          <div style={{ padding: '12px 16px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <button
              onClick={() => toggleConnect(selectedNodeId)}
              style={{
                width: '100%', padding: '8px 0',
                background: connectingFrom === selectedNodeId ? 'rgba(245,158,11,0.1)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${connectingFrom === selectedNodeId ? 'rgba(245,158,11,0.3)' : 'rgba(255,255,255,0.08)'}`,
                borderRadius: 6, color: connectingFrom === selectedNodeId ? '#F59E0B' : '#94A3B8',
                fontSize: 11, cursor: 'pointer', fontWeight: 600
              }}
            >
              {connectingFrom === selectedNodeId ? '🔗 Connecting... (click target)' : '🔗 Connect to Another Node'}
            </button>
          </div>
        )}

        {/* Execution history */}
        {execHistory.length > 0 && (
          <div style={{ padding: '12px 16px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#64748B', marginBottom: 8, fontFamily: 'JetBrains Mono, monospace' }}>EXECUTION LOG</div>
            {execHistory.slice(0, 5).map((ex: any, i: number) => (
              <div key={i} style={{ padding: '6px 8px', background: 'rgba(255,255,255,0.02)', borderRadius: 4, marginBottom: 4, fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}>
                <span style={{ color: ex.status === 'completed' ? '#10B981' : '#EF4444' }}>{ex.status}</span>
                <span style={{ color: '#64748B' }}> — {ex.duration_ms?.toFixed(0)}ms — {ex.node_results?.length || 0} nodes</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
