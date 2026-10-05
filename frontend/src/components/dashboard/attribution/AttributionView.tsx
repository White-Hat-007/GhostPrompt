"use client";

import { useEffect, useState } from "react";
import { 
  Shield, Users, GitMerge, Brain, Crosshair, Network, Clock, Database, Eye, Activity, TriangleAlert, BugPlay, Box
} from "lucide-react";
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, AreaChart, Area, CartesianGrid, PieChart, Pie
} from "recharts";
import GlobalThreatMap from "../GlobalThreatMap";
import ThreatSidePanel from "./ThreatSidePanel";

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
const WS_URL = API_URL.replace('http://', 'ws://').replace('https://', 'wss://');

export default function AttributionView({ recentScans = [] }: { recentScans?: any[] }) {
  const [stats, setStats] = useState<any>(null);
  const [actors, setActors] = useState<any[]>([]);
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [grooming, setGrooming] = useState<any[]>([]);
  const [integrity, setIntegrity] = useState<any[]>([]);
  const [exfiltration, setExfiltration] = useState<any[]>([]);
  const [media, setMedia] = useState<any[]>([]);
  const [tokenizer, setTokenizer] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const [selectedAttack, setSelectedAttack] = useState<any | null>(null);

  useEffect(() => {
    async function fetchData() {
      const token = localStorage.getItem("access_token");
      if (!token) return;

      const headers = { Authorization: `Bearer ${token}` };

      try {
        const [
          resStats, resActors, resCampaigns, resGrooming, resIntegrity, resExfiltration, resMedia, resTokenizer
        ] = await Promise.all([
          fetch(`/api/v1/attribution/dashboard`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/actors?limit=5`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/campaigns?limit=5`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/grooming?limit=5`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/model-integrity?limit=5`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/exfiltration?limit=5`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/adversarial-media?limit=5`, { headers }).then(r => r.json()),
          fetch(`/api/v1/attribution/tokenizer-threats?limit=5`, { headers }).then(r => r.json()),
        ]);

        setStats(resStats || {});
        setActors(Array.isArray(resActors) ? resActors : []);
        setCampaigns(Array.isArray(resCampaigns) ? resCampaigns : []);
        setGrooming(Array.isArray(resGrooming) ? resGrooming : []);
        setIntegrity(Array.isArray(resIntegrity) ? resIntegrity : []);
        setExfiltration(Array.isArray(resExfiltration) ? resExfiltration : []);
        setMedia(Array.isArray(resMedia) ? resMedia : []);
        setTokenizer(Array.isArray(resTokenizer) ? resTokenizer : []);
      } catch (err) {
        console.error("Failed to fetch attribution data", err);
        setActors([]);
        setCampaigns([]);
        setGrooming([]);
        setIntegrity([]);
        setExfiltration([]);
        setMedia([]);
        setTokenizer([]);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  // Internal WebSocket removed in favor of parent's recentScans prop

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-8 h-8 border-2 border-ghost-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto bg-transparent text-gray-300 p-8">
      <div className="max-w-[1600px] mx-auto space-y-8">
        
        {/* HEADER */}
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-500" />
            Threat Attribution Center
          </h1>
          <p className="text-sm text-gray-500 mt-2">
            Advanced correlation, residual attack defense, and long-horizon telemetry.
          </p>
        </div>

        {/* METRICS ROW */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-4">
          <StatBox icon={Users} label="Threat Actors" value={stats?.threat_actors} color="text-blue-400" />
          <StatBox icon={Network} label="Campaigns" value={stats?.active_campaigns} color="text-red-400" />
          <StatBox icon={GitMerge} label="Attack Clusters" value={stats?.attack_clusters} color="text-orange-400" />
          <StatBox icon={Database} label="Integrity Events" value={stats?.model_integrity_events} color="text-emerald-400" />
          <StatBox icon={Clock} label="Grooming Sessions" value={stats?.grooming_timelines} color="text-purple-400" />
          <StatBox icon={Activity} label="Covert Channels" value={stats?.exfiltration_events} color="text-yellow-400" />
          <StatBox icon={Eye} label="Adversarial Media" value={stats?.adversarial_media_events} color="text-pink-400" />
          <StatBox icon={BugPlay} label="Tokenizer Threats" value={stats?.tokenizer_threats} color="text-cyan-400" />
        </div>

        {/* GLOBAL THREAT MAP */}
        <div className="glass-card p-6 border-l-4 border-l-indigo-500">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400" />
              <h2 className="text-lg font-bold text-white">Global Threat Map (Real-Time)</h2>
            </div>
            <div className="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full font-semibold">
              <Activity className="w-3 h-3" />
              Live Scanning
            </div>
          </div>
          <div className="flex items-center justify-center bg-[#050914] rounded-xl overflow-hidden border border-white/5 relative">
            <GlobalThreatMap 
              attacks={recentScans} 
              onAttackClick={(attack) => setSelectedAttack(attack)} 
            />
          </div>
        </div>

        {/* MAIN SPLIT */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          
          {/* CAMPAIGN EXPLORER */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-2 mb-6">
              <Network className="w-5 h-5 text-red-500" />
              <h2 className="text-lg font-bold text-white">Campaign Explorer</h2>
            </div>
            <div className="space-y-4">
              {campaigns.map((c: any) => (
                <div key={c.id} className="p-4 rounded-xl bg-white/5 border border-white/10 hover:border-red-500/30 transition-colors">
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <h3 className="font-semibold text-red-400">{c.name}</h3>
                      <p className="text-xs text-gray-500">{c.campaign_id} • {c.threat_family}</p>
                    </div>
                    <span className={`text-[10px] uppercase px-2 py-1 rounded-full font-bold ${c.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                      {c.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-4">{c.description}</p>
                  <div className="grid grid-cols-3 gap-4 text-xs">
                    <div>
                      <span className="text-gray-500 block">Total Events</span>
                      <span className="text-white font-mono">{c.total_events}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block">Actors</span>
                      <span className="text-white font-mono">{c.total_actors}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block">Attack Types</span>
                      <span className="text-white">{c.attack_types?.join(', ')}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* THREAT ACTOR PROFILES */}
          <div className="glass-card p-6">
            <div className="flex items-center gap-2 mb-6">
              <Users className="w-5 h-5 text-blue-500" />
              <h2 className="text-lg font-bold text-white">Threat Actor Profiles</h2>
            </div>
            <div className="space-y-4">
              {actors.map((a: any) => (
                <div key={a.id} className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10 hover:border-blue-500/30">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-blue-500/20 border border-blue-500/50 flex items-center justify-center">
                      <Crosshair className="w-5 h-5 text-blue-400" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{a.alias || a.actor_id}</h3>
                      <p className="text-xs text-gray-500">
                        {a.actor_type.toUpperCase()} • {a.primary_country || 'Unknown Geo'}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-blue-400 font-mono">Risk: {(a.risk_score * 100).toFixed(0)}%</p>
                    <div className="flex gap-1 mt-1">
                      {a.is_vpn && <span className="text-[9px] px-1.5 py-0.5 bg-yellow-500/20 text-yellow-500 rounded">VPN</span>}
                      {a.is_tor && <span className="text-[9px] px-1.5 py-0.5 bg-purple-500/20 text-purple-500 rounded">TOR</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* LONG-HORIZON GROOMING & INTEGRITY */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          
          <div className="glass-card p-6 border-t-4 border-t-purple-500">
            <div className="flex items-center gap-2 mb-6">
              <Clock className="w-5 h-5 text-purple-500" />
              <h2 className="text-lg font-bold text-white">Long-Horizon Grooming</h2>
            </div>
            <div className="space-y-4">
              {grooming.map((g: any) => (
                <div key={g.id} className="p-4 rounded-xl bg-purple-500/5 border border-purple-500/20">
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-sm font-semibold text-purple-300">Session: {g.session_id.slice(0, 12)}...</span>
                    <span className="text-xs text-purple-400 bg-purple-500/10 px-2 py-1 rounded">{g.stage.toUpperCase()}</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-2">Duration: {g.span_days} days • Interactions: {g.interaction_count}</p>
                  <div className="flex flex-wrap gap-2">
                    {g.manipulation_indicators?.map((i: string) => (
                      <span key={i} className="text-[10px] bg-white/5 text-gray-300 px-2 py-1 rounded-full">{i.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card p-6 border-t-4 border-t-emerald-500">
            <div className="flex items-center gap-2 mb-6">
              <Database className="w-5 h-5 text-emerald-500" />
              <h2 className="text-lg font-bold text-white">Training Integrity Monitor</h2>
            </div>
            <div className="space-y-4">
              {integrity.map((i: any) => (
                <div key={i.id} className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
                  <div className="flex justify-between items-start mb-2">
                    <h3 className="text-sm font-bold text-emerald-400">{i.event_type.replace(/_/g, ' ').toUpperCase()}</h3>
                    <span className="text-[10px] text-gray-500 font-mono">{i.model_name}</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">{i.description}</p>
                  {i.indicators?.length > 0 && (
                    <div className="text-[10px] font-mono text-emerald-500/70">
                      &gt; {i.indicators.join(' | ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* COVERT CHANNELS, ADVERSARIAL MEDIA, TOKENIZER */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          
          <div className="glass-card p-6 border-l-2 border-l-yellow-500">
            <h3 className="text-sm font-bold text-yellow-500 mb-4 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Authorized Side-Effect Exfiltration
            </h3>
            <div className="space-y-4">
              {exfiltration.map((e: any) => (
                <div key={e.id} className="text-xs border-b border-white/5 pb-3 last:border-0">
                  <div className="flex justify-between text-gray-300 mb-1">
                    <span className="font-semibold">{e.channel_type}</span>
                    <span className="text-yellow-500/70">{e.source_ip}</span>
                  </div>
                  <p className="text-gray-500 leading-relaxed">{e.description}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card p-6 border-l-2 border-l-pink-500">
            <h3 className="text-sm font-bold text-pink-500 mb-4 flex items-center gap-2">
              <Eye className="w-4 h-4" /> Adversarial Media (Continuous-Space)
            </h3>
            <div className="space-y-4">
              {media.map((m: any) => (
                <div key={m.id} className="text-xs border-b border-white/5 pb-3 last:border-0">
                  <div className="flex justify-between text-gray-300 mb-1">
                    <span className="font-semibold uppercase">{m.media_type}: {m.attack_type}</span>
                    <span className="text-pink-500/70">{m.confidence_score}%</span>
                  </div>
                  <p className="text-gray-500 leading-relaxed">{m.description}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card p-6 border-l-2 border-l-cyan-500">
            <h3 className="text-sm font-bold text-cyan-500 mb-4 flex items-center gap-2">
              <BugPlay className="w-4 h-4" /> Tokenizer Intelligence
            </h3>
            <div className="space-y-4">
              {tokenizer.map((t: any) => (
                <div key={t.id} className="text-xs border-b border-white/5 pb-3 last:border-0">
                  <div className="flex justify-between text-gray-300 mb-1">
                    <span className="font-semibold">{t.threat_type}</span>
                    <span className="text-cyan-500/70">{t.affected_tokenizer}</span>
                  </div>
                  <p className="text-gray-500 leading-relaxed">{t.description}</p>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>

      <ThreatSidePanel 
        attack={selectedAttack} 
        onClose={() => setSelectedAttack(null)} 
      />
    </div>
  );
}

function StatBox({ icon: Icon, label, value, color }: any) {
  return (
    <div className="glass-card p-4 flex flex-col items-center justify-center text-center">
      <Icon className={`w-6 h-6 mb-2 ${color}`} />
      <span className="text-2xl font-bold text-white">{value ?? '-'}</span>
      <span className="text-[10px] uppercase tracking-wider text-gray-500 mt-1">{label}</span>
    </div>
  );
}
