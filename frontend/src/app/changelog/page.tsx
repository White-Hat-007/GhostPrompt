import Link from 'next/link';

export default function ChangelogPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-6">Changelog</h1>
        <p className="text-gray-400 mb-12 text-lg">Latest updates and improvements to GhostPrompt.</p>
        
        <div className="space-y-12">
          <div className="relative pl-8 border-l border-white/10">
            <div className="absolute w-4 h-4 bg-ghost-500 rounded-full -left-2 top-1 shadow-[0_0_10px_rgba(100,255,218,0.5)]"></div>
            <h3 className="text-2xl font-bold mb-2">v1.2.0 - Advanced Attacker Profiling</h3>
            <p className="text-ghost-400 text-sm mb-4">May 2026</p>
            <ul className="list-disc list-inside text-gray-400 space-y-2">
              <li>Introduced Global Threat Map visualizations on the dashboard.</li>
              <li>Added real-time IP tracking and attacker fingerprinting.</li>
              <li>Expanded default policies from 12 to 18 specific detection engines.</li>
            </ul>
          </div>
          
          <div className="relative pl-8 border-l border-white/10">
            <div className="absolute w-4 h-4 bg-surface-3 border border-white/20 rounded-full -left-2 top-1"></div>
            <h3 className="text-2xl font-bold mb-2">v1.1.0 - Websocket Real-time Feeds</h3>
            <p className="text-gray-500 text-sm mb-4">April 2026</p>
            <ul className="list-disc list-inside text-gray-400 space-y-2">
              <li>Added live WebSocket streaming for instantaneous threat alerts.</li>
              <li>New filtering dashboard for prompt injection vs jailbreaks.</li>
              <li>Performance improvements reducing latency by 40%.</li>
            </ul>
          </div>

          <div className="relative pl-8 border-l border-white/10">
            <div className="absolute w-4 h-4 bg-surface-3 border border-white/20 rounded-full -left-2 top-1"></div>
            <h3 className="text-2xl font-bold mb-2">v1.0.0 - General Availability</h3>
            <p className="text-gray-500 text-sm mb-4">March 2026</p>
            <ul className="list-disc list-inside text-gray-400 space-y-2">
              <li>Initial release of GhostPrompt AI Runtime Security.</li>
              <li>Support for OpenAI, Anthropic, and Google Gemini integrations.</li>
            </ul>
          </div>
        </div>
        
        <div className="mt-16 border-t border-white/5 pt-8 text-center">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
