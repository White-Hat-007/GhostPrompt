'use client';
import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Globe2, RotateCcw, Maximize2, Activity, ChevronRight, ChevronLeft, Map as MapIcon, Layers } from 'lucide-react';
import PrecisionGlobe from './PrecisionGlobe';

interface ArcDatum { id:string; startLat:number; startLng:number; endLat:number; endLng:number; color:[string,string]; rawColor:[number,number,number,number]; stroke:number; dashGap:number; dashAnimateTime:number; altitude:number; label:string; severity:string; attackType:string; timestamp:number; srcCountry:string; }
interface RingDatum { lat:number; lng:number; maxR:number; propagationSpeed:number; repeatPeriod:number; color:string; rawColor:[number,number,number,number]; _created:number; }
interface CyberMapProps { recentScans?:any[]; liveStats?:{total_scans:number;blocked:number;}; }

const MAX_ARCS=150, ARC_LIFE=5000, RING_LIFE=3000, REAPER=250;

// ── CANONICAL ATTACK-TYPE → COLOR MAP (single source of truth) ──
// HUE = attack type (primary channel). Brightness/stroke = severity (secondary).
// Neon palette on dark bg, maximally distinguishable, colorblind-safe spread.
const ATTACK_COLORS:Record<string,{hex:string;label:string;atlasId:string}> = {
  prompt_injection: { hex:'#0ae0ff', label:'Prompt Injection',    atlasId:'AML.T0051' },
  jailbreak:        { hex:'#ff3bef', label:'LLM Jailbreak',       atlasId:'AML.T0054' },
  pack_hunt:        { hex:'#ff9f1a', label:'Pack Hunt',            atlasId:'AML.T0043' },
  zero_day:         { hex:'#a855f7', label:'Zero-Day Anomaly',     atlasId:'AML.T0000' },
  obfuscation:      { hex:'#22d3ee', label:'Evasion/Obfuscation',  atlasId:'AML.T0015' },
  pii_leak:         { hex:'#34d399', label:'PII / Secret Leak',    atlasId:'AML.T0025' },
  sponge_dos:       { hex:'#ef4444', label:'Sponge / LLM DoS',     atlasId:'AML.T0029' },
  oracle:           { hex:'#facc15', label:'Oracle / Extraction',   atlasId:'AML.T0024' },
  rag_poisoning:    { hex:'#a3e635', label:'RAG / Indirect Inj.',   atlasId:'AML.T0018' },
  multi_agent:      { hex:'#fb7185', label:'Multi-Agent / Tool',    atlasId:'AML.T0052' },
  campaign:         { hex:'#f97316', label:'Coordinated Campaign',  atlasId:'AML.T0040' },
  other:            { hex:'#64748b', label:'Other / Unknown',       atlasId:'—' },
};

// Map raw detector categories → canonical attack type key
function resolveAttackType(category:string):string {
  if(!category) return 'other';
  const c = category.toLowerCase();
  if(c.includes('injection') || c.includes('instruction_override') || c.includes('context_ignoring')) return 'prompt_injection';
  if(c.includes('jailbreak') || c.includes('roleplay') || c.includes('persona') || c.includes('pliny') || c.includes('l1b3rt') || c.includes('g0dm0d')) return 'jailbreak';
  if(c.includes('pack_hunt') || c.includes('fragment')) return 'pack_hunt';
  if(c.includes('zero_day') || c.includes('adversarial') || c.includes('embedding') || c.includes('anomal') || c.includes('malicious')) return 'zero_day';
  if(c.includes('obfuscat') || c.includes('encod') || c.includes('evasion') || c.includes('leet') || c.includes('exotic') || c.includes('cross_lingual')) return 'obfuscation';
  if(c.includes('pii') || c.includes('secret') || c.includes('leak') || c.includes('credential')) return 'pii_leak';
  if(c.includes('sponge') || c.includes('dos') || c.includes('resource') || c.includes('repeat')) return 'sponge_dos';
  if(c.includes('oracle') || c.includes('model_extract') || c.includes('weight') || c.includes('gradient') || c.includes('inversion')) return 'oracle';
  if(c.includes('rag') || c.includes('indirect') || c.includes('external_content') || c.includes('hallucin')) return 'rag_poisoning';
  if(c.includes('multi_agent') || c.includes('tool') || c.includes('agent') || c.includes('hijack')) return 'multi_agent';
  if(c.includes('campaign') || c.includes('coordinated') || c.includes('sequential')) return 'campaign';
  if(c.includes('content_policy') || c.includes('sensitive') || c.includes('malware')) return 'other';
  return 'other';
}

// Severity modulation: same hue, different brightness/opacity/stroke
const SEV_MOD:Record<string,{opacity:number;stroke:number}> = {
  critical: { opacity:1.0,  stroke:2.8 },
  high:     { opacity:0.85, stroke:2.2 },
  medium:   { opacity:0.65, stroke:1.6 },
  low:      { opacity:0.45, stroke:1.2 },
  safe:     { opacity:0.30, stroke:0.8 },
};
function hexToRgba(hex:string,a:number):string {
  const r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${a})`;
}
function makeArcColors(attackType:string,severity:string):[string,string] {
  const base = ATTACK_COLORS[attackType]?.hex || ATTACK_COLORS.other.hex;
  const mod = SEV_MOD[severity] || SEV_MOD.low;
  return [hexToRgba(base,mod.opacity), hexToRgba(base,0)];
}
function makeRingColor(attackType:string,severity:string):string {
  const base = ATTACK_COLORS[attackType]?.hex || ATTACK_COLORS.other.hex;
  const mod = SEV_MOD[severity] || SEV_MOD.low;
  return hexToRgba(base, mod.opacity * 0.7);
}
function makeDeckColor(attackType:string,severity:string, alphaMult:number=1):[number,number,number,number] {
  const base = ATTACK_COLORS[attackType]?.hex || ATTACK_COLORS.other.hex;
  const mod = SEV_MOD[severity] || SEV_MOD.low;
  const r=parseInt(base.slice(1,3),16), g=parseInt(base.slice(3,5),16), b=parseInt(base.slice(5,7),16);
  return [r, g, b, Math.round(mod.opacity * alphaMult * 255)];
}

// Legacy SEV kept for severity-only contexts (breakdown bars)
const SEV:Record<string,{arc:[string,string];ring:string}>={
  critical:{arc:['#ff3b3bff','#ff3b3b00'],ring:'rgba(255,59,59,0.7)'},
  high:{arc:['#ff7a1aff','#ff7a1a00'],ring:'rgba(255,122,26,0.6)'},
  medium:{arc:['#ffd23fff','#ffd23f00'],ring:'rgba(255,210,63,0.5)'},
  low:{arc:['#3fb6ffff','#3fb6ff00'],ring:'rgba(63,182,255,0.4)'},
  safe:{arc:['#0ae0ffff','#0ae0ff00'],ring:'rgba(10,224,255,0.3)'},
};
const CC:Record<string,[number,number]>={
  US:[39.8,-98.6],CN:[35,105],RU:[61.5,105],DE:[51.2,10.4],GB:[55.4,-3.4],FR:[46.6,2.2],JP:[36.2,138.3],BR:[-14.2,-51.9],
  IN:[20.6,78.9],AU:[-25.3,133.8],CA:[56.1,-106.3],KR:[35.9,127.8],IT:[41.9,12.6],ES:[40.5,-3.7],NL:[52.1,5.3],SE:[60.1,18.6],
  SG:[1.35,103.8],ZA:[-30.6,22.9],MX:[23.6,-102.6],AR:[-38.4,-63.6],ID:[-0.8,113.9],PL:[51.9,19.1],TR:[38.9,35.2],UA:[48.4,31.2],
  TH:[15.9,100.9],VN:[14.1,108.3],PH:[12.9,122],NG:[9.1,8.7],EG:[26.8,30.8],SA:[23.9,45.1],AE:[23.4,53.8],PK:[30.4,69.3],
  IR:[32.4,53.7],KP:[40.3,127.5],IL:[31,34.9],CH:[46.8,8.2],NO:[60.5,8.5],FI:[61.9,25.7],
};
const ORIGINS=Object.entries(CC);
const HOME:[number,number]=[20.6,78.9];
const flag=(c:string)=>c.length===2?String.fromCodePoint(...[...c.toUpperCase()].map(ch=>127397+ch.charCodeAt(0))):'🌐';
function nearCountry(lat:number,lng:number):string{
  let best='XX',d=Infinity;
  for(const[c,[la,lo]]of ORIGINS){const v=Math.abs(lat-la)+Math.abs(lng-lo);if(v<d){d=v;best=c;}}
  return best;
}

export default function CyberMap({recentScans=[],liveStats}:CyberMapProps){
  const contRef=useRef<HTMLDivElement>(null), globeR=useRef<any>(null);
  const arcsR=useRef<ArcDatum[]>([]), ringsR=useRef<RingDatum[]>([]);
  const procRef=useRef<Set<string>>(new Set()), initRef=useRef(false), lastEvt=useRef(Date.now());
  const [ready,setReady]=useState(false);
  const [arcCount,setArcCount]=useState(0);
  const [idle,setIdle]=useState(0);
  const [showPanel,setShowPanel]=useState(true);
  const [dims,setDims]=useState({w:800,h:600});
  const [filterType,setFilterType]=useState<string|null>(null);
  const [mapMode, setMapMode] = useState<'stylized'|'precision'>('precision');

  // Resize
  useEffect(()=>{
    const el=contRef.current; if(!el)return;
    const ro=new ResizeObserver(e=>{const{width,height}=e[0].contentRect;setDims({w:Math.max(width,400),h:Math.max(height,300)});});
    ro.observe(el); return()=>ro.disconnect();
  },[]);

  // Init: mark existing scans as processed (no history replay)
  useEffect(()=>{
    if(initRef.current)return;
    recentScans.forEach(s=>{procRef.current.add(s.id||`${s.created_at}-${s.prompt?.slice(0,8)}`);});
    if(recentScans.length>0)initRef.current=true;
  },[recentScans]);

  // Process NEW scans only — color by ATTACK TYPE (hue) + severity (brightness/stroke)
  useEffect(()=>{
    if(!initRef.current)return;
    recentScans.filter(s=>s.threat_level!=='safe').forEach(scan=>{
      const sid=scan.id||`${scan.created_at}-${scan.prompt?.slice(0,8)}`;
      if(procRef.current.has(sid))return;
      procRef.current.add(sid);
      lastEvt.current=Date.now();
      let sLa=scan.lat||0,sLo=scan.lng||0;
      let srcC=scan.country||'';
      if(sLa===0&&sLo===0){const[c,[la,lo]]=ORIGINS[Math.floor(Math.random()*ORIGINS.length)];sLa=la+(Math.random()-.5)*10;sLo=lo+(Math.random()-.5)*10;srcC=c;}
      if(!srcC)srcC=nearCountry(sLa,sLo);
      const dLa=HOME[0]+(Math.random()-.5)*2,dLo=HOME[1]+(Math.random()-.5)*2;
      const sev=(scan.threat_level||'low').toLowerCase();
      const aType=resolveAttackType(scan.category||'');
      const sevMod=SEV_MOD[sev]||SEV_MOD.low;
      const dist=Math.sqrt((sLa-dLa)**2+(sLo-dLo)**2);
      if(arcsR.current.length>=MAX_ARCS)arcsR.current.shift();
      arcsR.current.push({id:sid,startLat:sLa,startLng:sLo,endLat:dLa,endLng:dLo,color:makeArcColors(aType,sev),rawColor:makeDeckColor(aType,sev),stroke:sevMod.stroke,dashGap:.5,dashAnimateTime:2000+Math.random()*1500,altitude:Math.min(.05+dist*.003,.6),label:scan.category||'unknown',severity:sev,attackType:aType,timestamp:Date.now(),srcCountry:srcC});
      ringsR.current.push({lat:dLa,lng:dLo,maxR:sev==='critical'?4:sev==='high'?3:2,propagationSpeed:3,repeatPeriod:1200,color:makeRingColor(aType,sev),rawColor:makeDeckColor(aType,sev,0.7),_created:Date.now()});
    });
    if(procRef.current.size>2000)procRef.current=new Set(Array.from(procRef.current).slice(-1000));
  },[recentScans]);

  // GC Reaper 250ms — applies filterType for click-to-solo
  const filterRef=useRef<string|null>(null);
  filterRef.current=filterType;
  useEffect(()=>{
    const t=setInterval(()=>{
      const now=Date.now();
      arcsR.current=arcsR.current.filter(a=>now-a.timestamp<ARC_LIFE);
      ringsR.current=ringsR.current.filter(r=>now-r._created<RING_LIFE);
      if(ringsR.current.length>30)ringsR.current=ringsR.current.slice(-30);
      if(globeR.current){
        const ft=filterRef.current;
        const visibleArcs=ft?arcsR.current.filter(a=>a.attackType===ft):arcsR.current;
        globeR.current.arcsData([...visibleArcs]);
        globeR.current.ringsData([...ringsR.current]);
      }
      setArcCount(arcsR.current.length);
      setIdle(Math.floor((now-lastEvt.current)/1000));
    },REAPER);
    return()=>clearInterval(t);
  },[]);

  // Globe init
  useEffect(()=>{
    if(mapMode !== 'stylized' || !contRef.current) return;
    let G:any;try{G=require('globe.gl').default;}catch{return;}
    const el=contRef.current;
    const g=G()
      .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
      .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
      .backgroundImageUrl('https://unpkg.com/three-globe/example/img/night-sky.png')
      .showAtmosphere(true).atmosphereColor('#0ae0ff').atmosphereAltitude(0.2)
      .arcsData([]).arcStartLat((d:any)=>d.startLat).arcStartLng((d:any)=>d.startLng)
      .arcEndLat((d:any)=>d.endLat).arcEndLng((d:any)=>d.endLng)
      .arcColor((d:any)=>d.color).arcAltitude((d:any)=>d.altitude).arcStroke((d:any)=>d.stroke)
      .arcDashLength(0.6).arcDashGap((d:any)=>d.dashGap).arcDashInitialGap(()=>Math.random())
      .arcDashAnimateTime((d:any)=>d.dashAnimateTime).arcsTransitionDuration(300)
      .ringsData([]).ringLat((d:any)=>d.lat).ringLng((d:any)=>d.lng)
      .ringMaxRadius((d:any)=>d.maxR).ringPropagationSpeed((d:any)=>d.propagationSpeed)
      .ringRepeatPeriod((d:any)=>d.repeatPeriod).ringColor((d:any)=>d.color)
      .labelsData([]).labelLat((d:any)=>d.lat).labelLng((d:any)=>d.lng).labelText((d:any)=>d.text)
      .labelSize(0.6).labelColor(()=>'#0ae0ffcc').labelDotRadius(0.3).labelAltitude(0.01).labelResolution(2)
      .width(dims.w).height(dims.h)(el);
    g.controls().autoRotate=true;g.controls().autoRotateSpeed=0.4;
    g.controls().enableDamping=true;g.controls().dampingFactor=0.1;
    g.controls().minDistance=120;g.controls().maxDistance=500;
    g.pointOfView({lat:20,lng:78,altitude:2.5},0);
    globeR.current=g;setReady(true);
    
    // Sync initial data if any
    if (arcsR.current.length) g.arcsData([...arcsR.current]);
    if (ringsR.current.length) g.ringsData([...ringsR.current]);
    
    return()=>{
      setReady(false);
      globeR.current=null;
      if(g._destructor)g._destructor();
      while(el.firstChild)el.removeChild(el.firstChild);
    };
  },[mapMode]);

  useEffect(()=>{if(globeR.current)globeR.current.width(dims.w).height(dims.h);},[dims]);

  const handleReset=useCallback(()=>{if(globeR.current){globeR.current.pointOfView({lat:20,lng:78,altitude:2.5},1000);globeR.current.controls().autoRotate=true;}},[]);

  // Stats
  const total=liveStats?.total_scans||recentScans.length;
  const blocked=liveStats?.blocked||recentScans.filter(s=>s.action==='blocked').length;
  const now1=Date.now()-60000;
  const rpm=recentScans.filter(s=>{const t=s.created_at?new Date(s.created_at).getTime():0;return t>=now1;}).length;
  const isLive=idle<10;

  // Intelligence computations
  const topSources=useMemo(()=>{
    const m:Record<string,number>={};
    recentScans.forEach(s=>{const c=s.country||nearCountry(s.lat||0,s.lng||0);m[c]=(m[c]||0)+1;});
    return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0,8);
  },[recentScans]);

  const topVectors=useMemo(()=>{
    const m:Record<string,number>={};
    recentScans.forEach(s=>{const c=s.category||'unknown';m[c]=(m[c]||0)+1;});
    return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0,8);
  },[recentScans]);

  const sevBreak=useMemo(()=>{
    const m:Record<string,number>={critical:0,high:0,medium:0,low:0};
    recentScans.forEach(s=>{const l=(s.threat_level||'low').toLowerCase();if(m[l]!==undefined)m[l]++;});
    const t=Object.values(m).reduce((a,b)=>a+b,0)||1;
    return Object.entries(m).map(([k,v])=>({sev:k,count:v,pct:Math.round(v/t*100)}));
  },[recentScans]);

  const countries=useMemo(()=>new Set(recentScans.map(s=>s.country||'XX').filter(Boolean)).size,[recentScans]);

  // Attack-type counts for the interactive legend
  const typeCounts=useMemo(()=>{
    const m:Record<string,number>={};
    recentScans.filter(s=>s.threat_level!=='safe').forEach(s=>{
      const t=resolveAttackType(s.category||'');
      m[t]=(m[t]||0)+1;
    });
    return Object.entries(m).sort((a,b)=>b[1]-a[1]);
  },[recentScans]);

  // ── DRILL-DOWN DATA: per-source attack breakdown ──
  const sourceBreakdown=useMemo(()=>{
    const m:Record<string,{total:number;types:Record<string,number>;sevs:Record<string,number>}>={};
    recentScans.forEach(s=>{
      const c=s.country||nearCountry(s.lat||0,s.lng||0);
      if(!m[c])m[c]={total:0,types:{},sevs:{}};
      m[c].total++;
      const aType=resolveAttackType(s.category||'');
      m[c].types[aType]=(m[c].types[aType]||0)+1;
      const sev=(s.threat_level||'low').toLowerCase();
      m[c].sevs[sev]=(m[c].sevs[sev]||0)+1;
    });
    return m;
  },[recentScans]);

  // ── DRILL-DOWN DATA: per-vector raw categories ──
  const vectorBreakdown=useMemo(()=>{
    const m:Record<string,{total:number;rawCats:Record<string,number>;sevs:Record<string,number>;detectors:Record<string,number>}>={};
    recentScans.forEach(s=>{
      const aType=resolveAttackType(s.category||'');
      if(!m[aType])m[aType]={total:0,rawCats:{},sevs:{},detectors:{}};
      m[aType].total++;
      const rawCat=s.category||'unknown';
      m[aType].rawCats[rawCat]=(m[aType].rawCats[rawCat]||0)+1;
      const sev=(s.threat_level||'low').toLowerCase();
      m[aType].sevs[sev]=(m[aType].sevs[sev]||0)+1;
      // Collect individual detectors
      if(s.detections&&Array.isArray(s.detections)){
        s.detections.forEach((d:any)=>{
          const det=d.detector||'unknown';
          m[aType].detectors[det]=(m[aType].detectors[det]||0)+1;
        });
      }
    });
    return m;
  },[recentScans]);

  // ── DRILL-DOWN DATA: per-severity attack type breakdown ──
  const sevTypeBreakdown=useMemo(()=>{
    const m:Record<string,Record<string,number>>={critical:{},high:{},medium:{},low:{}};
    recentScans.forEach(s=>{
      const sev=(s.threat_level||'low').toLowerCase();
      if(!m[sev])return;
      const aType=resolveAttackType(s.category||'');
      m[sev][aType]=(m[sev][aType]||0)+1;
    });
    return m;
  },[recentScans]);

  // Expanded section states
  const [expandedSources,setExpandedSources]=useState<Set<string>>(new Set());
  const [expandedVectors,setExpandedVectors]=useState<Set<string>>(new Set());
  const [expandedSevs,setExpandedSevs]=useState<Set<string>>(new Set());
  const [expandedTypes,setExpandedTypes]=useState<Set<string>>(new Set());
  const toggleSet=(set:Set<string>,key:string,setter:Function)=>{
    const next=new Set(set);
    if(next.has(key))next.delete(key);else next.add(key);
    setter(next);
  };

  const maxSrc=topSources[0]?.[1]||1;
  const maxVec=topVectors[0]?.[1]||1;

  // Severity colors
  const SEV_COLORS:Record<string,string>={critical:'#ff3b3b',high:'#ff7a1a',medium:'#ffd23f',low:'#3fb6ff'};

  return(
    <div className="h-full overflow-hidden bg-transparent text-gray-300">
      <div className="h-full flex flex-col relative">
        {mapMode === 'stylized' ? (
          <div ref={contRef} className="absolute inset-0 z-0" style={{background:'#030712'}}/>
        ) : (
          <PrecisionGlobe arcs={[...arcsR.current] as any} rings={[...ringsR.current] as any} />
        )}

        {/* TOP LEFT: Title + Counters */}
        <div className="absolute top-4 left-4 z-10">
          <div className="backdrop-blur-xl bg-black/50 border border-white/[0.08] rounded-xl px-4 py-3 shadow-2xl" style={{boxShadow:'0 0 40px rgba(10,224,255,0.05)'}}>
            <div className="flex items-center gap-2.5 mb-2.5">
              <div className="w-7 h-7 rounded-lg bg-[#0ae0ff]/15 border border-[#0ae0ff]/30 flex items-center justify-center cursor-pointer hover:bg-[#0ae0ff]/30 transition-colors" onClick={() => setMapMode(m => m === 'stylized' ? 'precision' : 'stylized')} title="Toggle Precision Satellite Mode">
                {mapMode === 'precision' ? <MapIcon className="w-3.5 h-3.5 text-[#0ae0ff]"/> : <Globe2 className="w-3.5 h-3.5 text-[#0ae0ff]"/>}
              </div>
              <div>
                <h1 className="text-xs font-bold text-white uppercase tracking-wider">Cybermap</h1>
                <p className="text-[8px] text-gray-500 font-mono uppercase tracking-widest">Real-Time Threat Intelligence</p>
              </div>
            </div>
            <div className="grid grid-cols-5 gap-2 pt-2.5 border-t border-white/[0.06]">
              {[{l:'Attacks',v:total.toLocaleString(),c:'#0ae0ff'},{l:'Blocked',v:blocked.toLocaleString(),c:'#ff3b3b'},{l:'Rate/min',v:String(rpm),c:'#ffd23f'},{l:'Arcs',v:String(arcCount),c:'#0ae0ff'},{l:'Countries',v:String(countries),c:'#a78bfa'}].map(s=>(
                <div key={s.l}>
                  <p className="text-[8px] text-gray-600 font-mono uppercase">{s.l}</p>
                  <p className="text-sm font-bold font-mono" style={{color:s.c}}>{s.v}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* TOP RIGHT: Live/Idle */}
        <div className="absolute top-4 right-4 z-10" style={{right:showPanel?'316px':'16px',transition:'right 0.3s'}}>
          <div className="backdrop-blur-xl bg-black/50 border border-white/[0.08] rounded-xl px-3 py-2 flex items-center gap-2">
            {isLive?(<><span className="relative flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0ae0ff] opacity-75"/><span className="relative inline-flex rounded-full h-2 w-2 bg-[#0ae0ff]"/></span><span className="text-[10px] font-mono text-[#0ae0ff] uppercase">Live</span></>)
            :(<><span className="w-2 h-2 rounded-full bg-gray-600"/><span className="text-[10px] font-mono text-gray-500 uppercase">Idle // {idle}s ago</span></>)}
            <span className="text-[9px] font-mono text-gray-600">{arcCount} arcs</span>
          </div>
        </div>

        {/* BOTTOM LEFT: Interactive Attack-Type Legend + Severity Sub-Key */}
        <div className="absolute bottom-4 left-4 z-10 max-h-[50vh] overflow-y-auto">
          <div className="backdrop-blur-xl bg-black/50 border border-white/[0.08] rounded-xl px-3 py-2.5">
            <p className="text-[8px] text-gray-600 font-mono uppercase tracking-widest mb-1.5">Attack Types <span className="text-gray-700">(click to filter)</span></p>
            {Object.entries(ATTACK_COLORS).map(([key,{hex,label,atlasId}])=>{
              const count=typeCounts.find(([k])=>k===key)?.[1]||0;
              const isActive=filterType===null||filterType===key;
              return(
                <button key={key} onClick={()=>setFilterType(filterType===key?null:key)} className={`flex items-center gap-1.5 mb-0.5 w-full text-left rounded px-1 py-px transition-all ${isActive?'opacity-100':'opacity-30'} hover:bg-white/5`}>
                  <div className="w-5 h-[3px] rounded-full flex-shrink-0" style={{background:hex}}/>
                  <span className="text-[8px] font-mono text-gray-400 flex-1 truncate">{label}</span>
                  {count>0&&<span className="text-[8px] font-mono" style={{color:hex}}>{count}</span>}
                </button>
              );
            })}
            <div className="border-t border-white/[0.06] mt-1.5 pt-1.5">
              <p className="text-[7px] text-gray-700 font-mono uppercase tracking-widest mb-1">Severity = Brightness</p>
              {['critical','high','medium','low'].map(s=>(
                <div key={s} className="flex items-center gap-1 mb-px">
                  <div className="w-4 h-[2px] rounded-full" style={{background:`rgba(255,255,255,${SEV_MOD[s]?.opacity||0.5})`}}/>
                  <span className="text-[7px] font-mono text-gray-600 uppercase">{s}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* BOTTOM RIGHT: Controls */}
        <div className="absolute bottom-4 right-4 z-10" style={{right:showPanel?'316px':'16px',transition:'right 0.3s'}}>
          <div className="backdrop-blur-xl bg-black/50 border border-white/[0.08] rounded-xl p-1 flex flex-col gap-0.5">
            <button onClick={() => setMapMode(m => m === 'stylized' ? 'precision' : 'stylized')} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" title="Toggle Globe Mode">
              <Layers className="w-3.5 h-3.5 text-[#0ae0ff]"/>
            </button>
            <button onClick={handleReset} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" title="Reset"><RotateCcw className="w-3.5 h-3.5 text-gray-400"/></button>
            <button onClick={()=>globeR.current?.pointOfView({altitude:Math.max((globeR.current?.pointOfView()?.altitude||2.5)-.5,.8)},500)} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors" title="Zoom In"><Maximize2 className="w-3.5 h-3.5 text-gray-400"/></button>
          </div>
        </div>

        {/* BOTTOM CENTER: Ticker — uses attack-type color */}
        {arcCount>0&&arcsR.current.length>0&&(()=>{
          const last=arcsR.current[arcsR.current.length-1];
          const typeColor=ATTACK_COLORS[last?.attackType]?.hex||'#0ae0ff';
          return(
          <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-10">
            <div className="backdrop-blur-xl bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 flex items-center gap-2 max-w-md">
              <Activity className="w-3 h-3 flex-shrink-0" style={{color:typeColor}}/>
              <motion.div key={last?.id} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background:typeColor}}/>
                <span className="text-[9px] font-mono whitespace-nowrap" style={{color:typeColor}}>{ATTACK_COLORS[last?.attackType]?.label||last?.label?.replace(/_/g,' ')}</span>
                <span className="text-[8px] font-mono text-gray-600">{last?.severity?.toUpperCase()}</span>
              </motion.div>
            </div>
          </div>
          );
        })()}

        {/* INTEL PANEL TOGGLE */}
        <button onClick={()=>setShowPanel(!showPanel)} className="absolute top-1/2 -translate-y-1/2 z-20 backdrop-blur-xl bg-black/60 border border-white/[0.08] rounded-l-lg p-1.5 hover:bg-white/10 transition-all" style={{right:showPanel?'300px':'0',transition:'right 0.3s'}}>
          {showPanel?<ChevronRight className="w-3 h-3 text-gray-400"/>:<ChevronLeft className="w-3 h-3 text-gray-400"/>}
        </button>

        {/* ═══════════════════════════════════════════════════════════════
            RIGHT INTELLIGENCE PANEL — ELITE EXPANDABLE DRILL-DOWN
            ═══════════════════════════════════════════════════════════════ */}
        <div className="absolute top-0 bottom-0 z-10 overflow-y-auto transition-all duration-300 scrollbar-thin scrollbar-thumb-white/10" style={{right:showPanel?0:-300,width:300}}>
          <div className="h-full backdrop-blur-2xl bg-black/60 border-l border-white/[0.06] p-3 space-y-3">

            {/* ── 1. TOP ATTACK SOURCES (expandable per-country) ── */}
            <div>
              <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <span className="w-1 h-3 rounded-full bg-[#0ae0ff]/60"/>
                Top Attack Sources
                <span className="text-[8px] text-gray-700 normal-case ml-auto">{topSources.length} countries</span>
              </p>
              <div className="space-y-px">
                {topSources.map(([code,count],i)=>{
                  const isOpen=expandedSources.has(code);
                  const bd=sourceBreakdown[code];
                  return(
                    <div key={code}>
                      <button onClick={()=>toggleSet(expandedSources,code,setExpandedSources)} className="flex items-center gap-2 w-full text-left py-1 px-1 rounded hover:bg-white/[0.04] transition-colors group">
                        <span className="text-[9px] font-mono text-gray-600 w-3">{i+1}</span>
                        <span className="text-xs">{flag(code)}</span>
                        <span className="text-[10px] font-mono text-gray-300">{code}</span>
                        <div className="flex-1 h-[3px] rounded-full bg-white/[0.06] overflow-hidden">
                          <div className="h-full rounded-full bg-[#0ae0ff]/60 transition-all duration-500" style={{width:`${(count/maxSrc)*100}%`}}/>
                        </div>
                        <span className="text-[10px] font-mono text-[#0ae0ff] w-8 text-right">{count}</span>
                        <ChevronRight className={`w-2.5 h-2.5 text-gray-600 transition-transform duration-200 ${isOpen?'rotate-90':''} opacity-0 group-hover:opacity-100`}/>
                      </button>

                      {/* ── Expanded: per-country attack type + severity ── */}
                      {isOpen&&bd&&(
                        <motion.div initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} transition={{duration:0.2}}
                          className="ml-5 mr-1 mb-1 overflow-hidden">
                          <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg p-2 space-y-1.5">
                            {/* Attack types from this country */}
                            <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest">Attack Types</p>
                            {Object.entries(bd.types).sort((a,b)=>b[1]-a[1]).map(([type,cnt])=>{
                              const ac=ATTACK_COLORS[type]||ATTACK_COLORS.other;
                              return(
                                <div key={type} className="flex items-center gap-1.5">
                                  <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background:ac.hex}}/>
                                  <span className="text-[8px] font-mono text-gray-400 flex-1 truncate">{ac.label}</span>
                                  <div className="w-12 h-[2px] rounded-full bg-white/[0.06] overflow-hidden">
                                    <div className="h-full rounded-full" style={{width:`${(cnt/bd.total)*100}%`,background:ac.hex,opacity:0.7}}/>
                                  </div>
                                  <span className="text-[8px] font-mono" style={{color:ac.hex}}>{cnt}</span>
                                </div>
                              );
                            })}
                            {/* Severity mini-bar */}
                            <div className="pt-1 border-t border-white/[0.04]">
                              <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest mb-0.5">Severity</p>
                              <div className="flex h-[4px] rounded-full overflow-hidden gap-px">
                                {['critical','high','medium','low'].map(s=>{
                                  const cnt=bd.sevs[s]||0;
                                  if(!cnt)return null;
                                  return <div key={s} className="h-full rounded-sm" style={{width:`${(cnt/bd.total)*100}%`,background:SEV_COLORS[s]||'#666',minWidth:cnt>0?'3px':0}}/>;
                                })}
                              </div>
                              <div className="flex gap-2 mt-0.5">
                                {['critical','high','medium','low'].map(s=>{
                                  const cnt=bd.sevs[s]||0;
                                  if(!cnt)return null;
                                  return <span key={s} className="text-[7px] font-mono" style={{color:SEV_COLORS[s]}}>{s[0].toUpperCase()}:{cnt}</span>;
                                })}
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </div>
                  );
                })}
                {topSources.length===0&&<p className="text-[9px] text-gray-600 font-mono">Awaiting data...</p>}
              </div>
            </div>

            {/* ── 2. TOP ATTACK VECTORS (expandable per-type) ── */}
            <div>
              <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <span className="w-1 h-3 rounded-full bg-[#ff3bef]/60"/>
                Top Attack Vectors
                <span className="text-[8px] text-gray-700 normal-case ml-auto">{topVectors.length} types</span>
              </p>
              <div className="space-y-px">
                {topVectors.map(([cat,count])=>{
                  const aType=resolveAttackType(cat);
                  const ac=ATTACK_COLORS[aType]||ATTACK_COLORS.other;
                  const isOpen=expandedVectors.has(aType);
                  const bd=vectorBreakdown[aType];
                  return(
                    <div key={cat}>
                      <button onClick={()=>toggleSet(expandedVectors,aType,setExpandedVectors)}
                        className="w-full text-left py-1 px-1 rounded hover:bg-white/[0.04] transition-colors group">
                        <div className="flex items-center justify-between mb-0.5">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[8px] font-mono px-1 rounded" style={{color:ac.hex,background:`${ac.hex}15`}}>{ac.atlasId}</span>
                            <span className="text-[10px] font-mono text-gray-300">{ac.label}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] font-mono" style={{color:ac.hex}}>{count}</span>
                            <ChevronRight className={`w-2.5 h-2.5 text-gray-600 transition-transform duration-200 ${isOpen?'rotate-90':''} opacity-0 group-hover:opacity-100`}/>
                          </div>
                        </div>
                        <div className="h-[2px] rounded-full bg-white/[0.06] overflow-hidden">
                          <div className="h-full rounded-full transition-all duration-500" style={{width:`${(count/maxVec)*100}%`,background:ac.hex,opacity:0.6}}/>
                        </div>
                      </button>

                      {/* ── Expanded: raw categories + detectors + severity ── */}
                      {isOpen&&bd&&(
                        <motion.div initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} transition={{duration:0.2}}
                          className="ml-2 mr-1 mb-1 overflow-hidden">
                          <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg p-2 space-y-1.5">
                            {/* Raw categories */}
                            <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest">Raw Categories</p>
                            {Object.entries(bd.rawCats).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([raw,cnt])=>(
                              <div key={raw} className="flex items-center gap-1.5">
                                <span className="text-[7px] font-mono text-gray-500 flex-1 truncate" title={raw}>{raw.replace(/_/g,' ')}</span>
                                <div className="w-10 h-[2px] rounded-full bg-white/[0.06] overflow-hidden">
                                  <div className="h-full rounded-full" style={{width:`${(cnt/bd.total)*100}%`,background:ac.hex,opacity:0.5}}/>
                                </div>
                                <span className="text-[7px] font-mono" style={{color:`${ac.hex}99`}}>{cnt}</span>
                              </div>
                            ))}

                            {/* Detectors triggered */}
                            {Object.keys(bd.detectors).length>0&&(
                              <>
                                <div className="pt-1 border-t border-white/[0.04]">
                                  <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest mb-0.5">Detectors Triggered</p>
                                  {Object.entries(bd.detectors).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([det,cnt])=>(
                                    <div key={det} className="flex items-center gap-1.5">
                                      <span className="w-1 h-1 rounded-full flex-shrink-0" style={{background:ac.hex,opacity:0.5}}/>
                                      <span className="text-[7px] font-mono text-gray-500 flex-1 truncate">{det.replace(/_/g,' ')}</span>
                                      <span className="text-[7px] font-mono text-gray-600">{cnt}</span>
                                    </div>
                                  ))}
                                </div>
                              </>
                            )}

                            {/* Severity breakdown */}
                            <div className="pt-1 border-t border-white/[0.04]">
                              <div className="flex h-[4px] rounded-full overflow-hidden gap-px">
                                {['critical','high','medium','low'].map(s=>{
                                  const cnt=bd.sevs[s]||0;
                                  if(!cnt)return null;
                                  return <div key={s} className="h-full rounded-sm" style={{width:`${(cnt/bd.total)*100}%`,background:SEV_COLORS[s]||'#666',minWidth:'3px'}}/>;
                                })}
                              </div>
                              <div className="flex gap-2 mt-0.5">
                                {['critical','high','medium','low'].map(s=>{
                                  const cnt=bd.sevs[s]||0;
                                  if(!cnt)return null;
                                  return <span key={s} className="text-[7px] font-mono" style={{color:SEV_COLORS[s]}}>{s[0].toUpperCase()}:{cnt}</span>;
                                })}
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </div>
                  );
                })}
                {topVectors.length===0&&<p className="text-[9px] text-gray-600 font-mono">Awaiting data...</p>}
              </div>
            </div>

            {/* ── 3. SEVERITY BREAKDOWN (expandable per-level) ── */}
            <div>
              <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <span className="w-1 h-3 rounded-full bg-[#ff3b3b]/60"/>
                Severity Breakdown
              </p>
              <div className="space-y-px">
                {sevBreak.map(({sev,count,pct})=>{
                  const isOpen=expandedSevs.has(sev);
                  const typeMap=sevTypeBreakdown[sev]||{};
                  const sevColor=SEV_COLORS[sev]||'#666';
                  return(
                    <div key={sev}>
                      <button onClick={()=>toggleSet(expandedSevs,sev,setExpandedSevs)}
                        className="w-full text-left py-1 px-1 rounded hover:bg-white/[0.04] transition-colors group">
                        <div className="flex items-center justify-between mb-0.5">
                          <div className="flex items-center gap-1.5">
                            <div className="w-1.5 h-1.5 rounded-full" style={{background:sevColor}}/>
                            <span className="text-[10px] font-mono text-gray-400 uppercase">{sev}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] font-mono text-gray-500">{count} <span className="text-gray-600">({pct}%)</span></span>
                            <ChevronRight className={`w-2.5 h-2.5 text-gray-600 transition-transform duration-200 ${isOpen?'rotate-90':''} opacity-0 group-hover:opacity-100`}/>
                          </div>
                        </div>
                        <div className="h-[3px] rounded-full bg-white/[0.04] overflow-hidden">
                          <div className="h-full rounded-full transition-all duration-500" style={{width:`${pct}%`,background:sevColor}}/>
                        </div>
                      </button>

                      {/* ── Expanded: which attack types hit this severity ── */}
                      {isOpen&&Object.keys(typeMap).length>0&&(
                        <motion.div initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} transition={{duration:0.2}}
                          className="ml-4 mr-1 mb-1 overflow-hidden">
                          <div className="bg-white/[0.02] border border-white/[0.06] rounded-lg p-2 space-y-1">
                            <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest">Contributing Attack Types</p>
                            {Object.entries(typeMap).sort((a,b)=>b[1]-a[1]).map(([type,cnt])=>{
                              const ac=ATTACK_COLORS[type]||ATTACK_COLORS.other;
                              return(
                                <div key={type} className="flex items-center gap-1.5">
                                  <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background:ac.hex}}/>
                                  <span className="text-[8px] font-mono text-gray-400 flex-1 truncate">{ac.label}</span>
                                  <div className="w-12 h-[2px] rounded-full bg-white/[0.06] overflow-hidden">
                                    <div className="h-full rounded-full" style={{width:`${(cnt/count)*100}%`,background:ac.hex,opacity:0.6}}/>
                                  </div>
                                  <span className="text-[8px] font-mono" style={{color:ac.hex}}>{cnt}</span>
                                </div>
                              );
                            })}
                          </div>
                        </motion.div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* ── 4. ATTACK TYPE TREE (expandable per-type with full sub-detail) ── */}
            <div>
              <p className="text-[9px] font-mono text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <span className="w-1 h-3 rounded-full bg-[#facc15]/60"/>
                Attack Intelligence
                <span className="text-[8px] text-gray-700 normal-case ml-auto">{typeCounts.length} active</span>
              </p>
              <div className="space-y-px">
                {typeCounts.map(([key,count])=>{
                  const ac=ATTACK_COLORS[key]||ATTACK_COLORS.other;
                  const isOpen=expandedTypes.has(key);
                  const bd=vectorBreakdown[key];
                  const totalAll=typeCounts.reduce((a,b)=>a+b[1],0)||1;
                  return(
                    <div key={key}>
                      <button onClick={()=>toggleSet(expandedTypes,key,setExpandedTypes)}
                        className="w-full text-left py-1 px-1 rounded hover:bg-white/[0.04] transition-colors group">
                        <div className="flex items-center gap-1.5">
                          <div className="w-2 h-2 rounded-sm flex-shrink-0" style={{background:ac.hex}}/>
                          <span className="text-[9px] font-mono text-gray-300 flex-1">{ac.label}</span>
                          <span className="text-[8px] font-mono" style={{color:`${ac.hex}80`}}>{ac.atlasId}</span>
                          <span className="text-[9px] font-mono font-bold" style={{color:ac.hex}}>{count}</span>
                          <span className="text-[7px] font-mono text-gray-600">{Math.round(count/totalAll*100)}%</span>
                          <ChevronRight className={`w-2.5 h-2.5 text-gray-600 transition-transform duration-200 ${isOpen?'rotate-90':''} opacity-0 group-hover:opacity-100`}/>
                        </div>
                        {/* Proportional bar */}
                        <div className="h-[2px] rounded-full bg-white/[0.04] overflow-hidden mt-0.5">
                          <div className="h-full rounded-full" style={{width:`${(count/totalAll)*100}%`,background:ac.hex,opacity:0.5}}/>
                        </div>
                      </button>

                      {/* ── Expanded: full attack type intelligence ── */}
                      {isOpen&&bd&&(
                        <motion.div initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}} transition={{duration:0.2}}
                          className="ml-3 mr-1 mb-1 overflow-hidden">
                          <div className="bg-white/[0.02] border-l-2 border-white/[0.06] pl-2 pr-1 py-1.5 space-y-1.5" style={{borderLeftColor:`${ac.hex}40`}}>
                            
                            {/* Sub-categories */}
                            <div>
                              <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest mb-0.5">Sub-Categories</p>
                              {Object.entries(bd.rawCats).sort((a,b)=>b[1]-a[1]).map(([raw,cnt])=>(
                                <div key={raw} className="flex items-center gap-1 py-px">
                                  <span className="text-[7px] text-gray-700">├</span>
                                  <span className="text-[7px] font-mono text-gray-500 flex-1 truncate" title={raw}>{raw.replace(/_/g,' ').replace(/\./g,' › ')}</span>
                                  <span className="text-[7px] font-mono" style={{color:`${ac.hex}80`}}>{cnt}</span>
                                </div>
                              ))}
                            </div>

                            {/* Triggered detectors */}
                            {Object.keys(bd.detectors).length>0&&(
                              <div>
                                <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest mb-0.5">Detectors</p>
                                <div className="flex flex-wrap gap-1">
                                  {Object.entries(bd.detectors).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([det,cnt])=>(
                                    <span key={det} className="text-[7px] font-mono rounded px-1 py-px border" style={{color:`${ac.hex}99`,borderColor:`${ac.hex}20`,background:`${ac.hex}08`}}>
                                      {det.replace(/_/g,' ')} <span style={{color:ac.hex}}>{cnt}</span>
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Severity distribution */}
                            <div>
                              <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest mb-0.5">Severity Split</p>
                              <div className="flex gap-1 items-center">
                                <div className="flex-1 flex h-[5px] rounded-full overflow-hidden gap-px">
                                  {['critical','high','medium','low'].map(s=>{
                                    const cnt=bd.sevs[s]||0;
                                    if(!cnt)return null;
                                    return <div key={s} className="h-full rounded-sm transition-all" style={{width:`${(cnt/bd.total)*100}%`,background:SEV_COLORS[s],minWidth:'4px'}} title={`${s}: ${cnt}`}/>;
                                  })}
                                </div>
                              </div>
                              <div className="flex gap-1.5 mt-0.5 flex-wrap">
                                {['critical','high','medium','low'].map(s=>{
                                  const cnt=bd.sevs[s]||0;
                                  if(!cnt)return null;
                                  return(
                                    <div key={s} className="flex items-center gap-0.5">
                                      <div className="w-1 h-1 rounded-full" style={{background:SEV_COLORS[s]}}/>
                                      <span className="text-[6px] font-mono uppercase" style={{color:SEV_COLORS[s]}}>{s}</span>
                                      <span className="text-[7px] font-mono text-gray-600">{cnt}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>

                            {/* Source countries for this type */}
                            {(()=>{
                              const srcMap:Record<string,number>={};
                              recentScans.filter(s=>resolveAttackType(s.category||'')===key).forEach(s=>{
                                const c=s.country||nearCountry(s.lat||0,s.lng||0);
                                srcMap[c]=(srcMap[c]||0)+1;
                              });
                              const srcs=Object.entries(srcMap).sort((a,b)=>b[1]-a[1]).slice(0,5);
                              if(!srcs.length)return null;
                              return(
                                <div>
                                  <p className="text-[7px] font-mono text-gray-600 uppercase tracking-widest mb-0.5">Top Sources</p>
                                  <div className="flex gap-1.5 flex-wrap">
                                    {srcs.map(([c,cnt])=>(
                                      <span key={c} className="text-[7px] font-mono text-gray-500">
                                        {flag(c)} {c} <span style={{color:`${ac.hex}80`}}>{cnt}</span>
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                        </motion.div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

          </div>
        </div>

        {/* Loading */}
        {!ready && mapMode === 'stylized' && (
          <div className="absolute inset-0 z-20 flex items-center justify-center bg-[#030712]">
            <div className="text-center">
              <div className="w-16 h-16 rounded-full border-2 border-[#0ae0ff]/30 border-t-[#0ae0ff] animate-spin mx-auto mb-4"/>
              <p className="text-sm font-mono text-[#0ae0ff]/60 uppercase tracking-widest">Initializing Globe</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
