'use client';
import { useState, useEffect, useCallback } from 'react';
import { Link2, RefreshCw, Copy, Check, Code2 } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const CODE_SAMPLES: Record<string, { install: string; code: string }> = {
  langchain: { install: 'pip install ghostprompt', code: `from ghostprompt.integrations import GhostPromptLangChainLLM\n\nllm = GhostPromptLangChainLLM(\n    api_key="gp_vk_your_key",\n    base_url="https://api.ghostprompt.ai",\n    model="gpt-4o"\n)\n\n# Use exactly like ChatOpenAI\nresponse = llm._generate([\n    {"role": "user", "content": "Hello!"}\n])` },
  llamaindex: { install: 'pip install ghostprompt', code: `from ghostprompt.integrations import GhostPromptLlamaIndexLLM\n\nllm = GhostPromptLlamaIndexLLM(\n    api_key="gp_vk_your_key",\n    model="gpt-4o"\n)\n\nresponse = llm.complete("Explain quantum computing")` },
  crewai: { install: 'pip install ghostprompt', code: `from ghostprompt.integrations import GhostPromptCrewAILLM\n\nllm = GhostPromptCrewAILLM(\n    api_key="gp_vk_your_key",\n    model="claude-3-5-sonnet"\n)\n\n# Drop-in replacement\nresult = llm.call("Analyze this data...")` },
  autogen: { install: 'pip install ghostprompt', code: `from ghostprompt.integrations import GhostPromptAutoGenConfig\n\nconfig = GhostPromptAutoGenConfig(\n    api_key="gp_vk_your_key",\n    models=["gpt-4o", "claude-3-5-sonnet"]\n)\n\n# Use in AutoGen\nconfig_list = config.to_config_list()` },
  haystack: { install: 'pip install ghostprompt', code: `from ghostprompt.integrations import GhostPromptHaystackComponent\n\nllm = GhostPromptHaystackComponent(\n    api_key="gp_vk_your_key",\n    model="gpt-4o"\n)\n\nresult = llm.run("Summarize this document...")` },
  openai_agents: { install: 'pip install ghostprompt', code: `from ghostprompt.integrations import GhostPromptOpenAIAgentsClient\n\nclient = GhostPromptOpenAIAgentsClient(\n    api_key="gp_vk_your_key",\n    model="gpt-4o"\n)\n\n# Use client.chat.completions.create()\nresponse = client.chat.completions.create(\n    model="gpt-4o",\n    messages=[{"role": "user", "content": "Hello"}]\n)` },
};

export default function IntegrationsView({ token }: { token: string }) {
  const [integrations, setIntegrations] = useState<any>({});
  const [selected, setSelected] = useState<string>('langchain');
  const [copied, setCopied] = useState(false);
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  useEffect(() => {
    fetch(`${API}/api/v1/platform/integrations`, { headers }).then(r => r.json()).then(d => setIntegrations(d.integrations || {})).catch(() => {});
  }, [token]);

  const copyCode = () => { navigator.clipboard.writeText(CODE_SAMPLES[selected]?.code || ''); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-3"><Link2 className="w-6 h-6 text-cyan-400" /> Framework Integrations</h2>
        <p className="text-sm text-gray-400 mt-1">One-line drop-in replacements — all security, routing, and caching applies automatically</p>
      </div>

      <div className="grid grid-cols-6 gap-2">
        {Object.entries(integrations).map(([key, info]: [string, any]) => (
          <button key={key} onClick={() => setSelected(key)} className={`p-3 rounded-lg text-center transition-all ${selected === key ? 'bg-cyan-500/15 border border-cyan-500/40 shadow-[0_0_12px_rgba(0,212,255,0.1)]' : 'glass-card hover:border-white/20'}`}>
            <p className="text-xs font-bold text-white capitalize">{key.replace('_', ' ')}</p>
            <p className="text-[10px] text-gray-500 mt-1">{info.description}</p>
          </button>
        ))}
      </div>

      {CODE_SAMPLES[selected] && (
        <div className="glass-card p-5 border border-white/10">
          <div className="flex justify-between items-center mb-3">
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white capitalize">{selected.replace('_', ' ')} Integration</h3>
            </div>
            <button onClick={copyCode} className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition">
              {copied ? <><Check className="w-3 h-3 text-green-400" /> Copied!</> : <><Copy className="w-3 h-3" /> Copy</>}
            </button>
          </div>
          <div className="bg-black/40 rounded-lg p-4 border border-white/5">
            <p className="text-[10px] text-gray-500 mb-2">$ {CODE_SAMPLES[selected].install}</p>
            <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap overflow-x-auto">{CODE_SAMPLES[selected].code}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
