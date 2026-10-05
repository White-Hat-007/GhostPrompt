import Link from 'next/link';
import { Book, Code, Shield, Zap } from 'lucide-react';

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-6">Documentation</h1>
        <p className="text-gray-400 mb-12 text-lg">Learn how to integrate GhostPrompt's AI Firewall into your applications.</p>
        
        <div className="grid md:grid-cols-2 gap-6">
          <div className="p-6 bg-surface-1 border border-white/5 rounded-2xl">
            <Code className="w-8 h-8 text-ghost-400 mb-4" />
            <h3 className="text-xl font-bold mb-2">API Integration</h3>
            <p className="text-gray-400 mb-4">Directly scan inputs and outputs using our REST API before they reach your LLM.</p>
            <div className="bg-black/50 p-4 rounded-lg font-mono text-sm text-gray-300">
              POST /api/v1/scan<br/>
              Authorization: Bearer YOUR_TOKEN
            </div>
          </div>
          
          <div className="p-6 bg-surface-1 border border-white/5 rounded-2xl">
            <Zap className="w-8 h-8 text-cyber-400 mb-4" />
            <h3 className="text-xl font-bold mb-2">Proxy Setup</h3>
            <p className="text-gray-400 mb-4">Route your OpenAI or Anthropic calls through our secure proxy. Zero code changes required.</p>
            <div className="bg-black/50 p-4 rounded-lg font-mono text-sm text-gray-300">
              BASE_URL="https://api.ghostprompt.com/v1"
            </div>
          </div>

          <div className="p-6 bg-surface-1 border border-white/5 rounded-2xl">
            <Shield className="w-8 h-8 text-emerald-400 mb-4" />
            <h3 className="text-xl font-bold mb-2">Policy Configuration</h3>
            <p className="text-gray-400">Configure the 18 specific security policies across our 7 detection engines.</p>
          </div>
          
          <div className="p-6 bg-surface-1 border border-white/5 rounded-2xl">
            <Book className="w-8 h-8 text-blue-400 mb-4" />
            <h3 className="text-xl font-bold mb-2">SDKs & Libraries</h3>
            <p className="text-gray-400">Official SDKs available for Python, Node.js, and Go.</p>
          </div>
        </div>
        <div className="mt-12 text-center">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
