'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Copy, Check, Terminal } from 'lucide-react';

const CODE_TABS = [
  {
    label: 'cURL',
    lang: 'bash',
    code: `curl https://api.ghostprompt.ai/v1/chat/completions \\
  -H "Authorization: Bearer gp_sk_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello"}]
  }'`,
  },
  {
    label: 'Python',
    lang: 'python',
    code: `from openai import OpenAI

# Just change the base URL — everything else stays the same
client = OpenAI(
    api_key="gp_sk_...",
    base_url="https://api.ghostprompt.ai/v1"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}]
)
print(response.choices[0].message.content)`,
  },
  {
    label: 'Node.js',
    lang: 'javascript',
    code: `import OpenAI from 'openai';

// One line change: point to GhostPrompt
const client = new OpenAI({
  apiKey: 'gp_sk_...',
  baseURL: 'https://api.ghostprompt.ai/v1',
});

const completion = await client.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hello' }],
});
console.log(completion.choices[0].message.content);`,
  },
  {
    label: 'LangChain',
    lang: 'python',
    code: `from langchain_openai import ChatOpenAI

# Drop-in replacement — full OpenAI compatibility
llm = ChatOpenAI(
    model="gpt-4o",
    openai_api_key="gp_sk_...",
    openai_api_base="https://api.ghostprompt.ai/v1",
)

response = llm.invoke("Explain prompt injection.")
print(response.content)`,
  },
];

export default function CodeIntegration() {
  const [activeTab, setActiveTab] = useState(0);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(CODE_TABS[activeTab].code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 40, scale: 0.97 }}
      whileInView={{ opacity: 1, y: 0, scale: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
      className="max-w-3xl mx-auto"
    >
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-surface-1/80 border border-white/[0.06] border-b-0 rounded-t-xl">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
          </div>
          <span className="text-mono-xs text-gray-600 ml-2 uppercase tracking-wider flex items-center gap-1.5">
            <Terminal className="w-3 h-3" />
            ghostprompt://integrate
          </span>
        </div>
        <motion.button
          onClick={handleCopy}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="flex items-center gap-1.5 px-2 py-1 rounded text-mono-xs text-gray-500 hover:text-white hover:bg-white/[0.05] transition-all"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied' : 'Copy'}
        </motion.button>
      </div>

      {/* Language Tabs with animated underline */}
      <div className="flex border-x border-white/[0.06] bg-surface-05/80 relative">
        {CODE_TABS.map((tab, i) => (
          <button
            key={tab.label}
            onClick={() => setActiveTab(i)}
            className={`px-4 py-2 text-xs font-mono font-medium transition-all relative ${
              i === activeTab
                ? 'text-ghost-400 bg-ghost-600/5'
                : 'text-gray-600 hover:text-gray-400 hover:bg-white/[0.02]'
            }`}
          >
            {tab.label}
            {i === activeTab && (
              <motion.div
                layoutId="code-tab-underline"
                className="absolute bottom-0 left-0 right-0 h-0.5 bg-ghost-500"
                transition={{ type: 'spring', stiffness: 400, damping: 30 }}
              />
            )}
          </button>
        ))}
      </div>

      {/* Code Block with AnimatePresence */}
      <div className="relative bg-surface-0/90 border border-white/[0.06] border-t-0 rounded-b-xl overflow-hidden" style={{ boxShadow: '0 0 40px rgba(10,224,255,0.03)' }}>
        <div className="scanline-overlay opacity-[0.01]" />
        <AnimatePresence mode="wait">
          <motion.pre
            key={activeTab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
            className="p-5 overflow-x-auto text-[13px] leading-relaxed font-mono"
          >
            <code className="text-gray-300">
              {CODE_TABS[activeTab].code.split('\n').map((line, i) => (
                <motion.span
                  key={`${activeTab}-${i}`}
                  initial={{ opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03, duration: 0.3 }}
                  className="block"
                >
                  <span className="select-none text-gray-700 mr-4 text-[11px]">{String(i + 1).padStart(2, ' ')}</span>
                  {line.split(/(["'].*?["']|#.*$|\/\/.*$)/g).map((part, j) => {
                    if (/^["'].*["']$/.test(part)) return <span key={j} className="text-emerald-400">{part}</span>;
                    if (/^(#|\/\/)/.test(part)) return <span key={j} className="text-gray-600 italic">{part}</span>;
                    return <span key={j}>{part}</span>;
                  })}
                </motion.span>
              ))}
              <span className="inline-block w-[7px] h-[15px] bg-ghost-400 ml-0.5 animate-blink" />
            </code>
          </motion.pre>
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
