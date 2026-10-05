import Link from 'next/link';

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Privacy Policy</h1>
        <div className="prose prose-invert max-w-none text-gray-400">
          <p className="mb-6">Last updated: May 28, 2026</p>
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">1. Data Collection</h2>
          <p className="mb-4">GhostPrompt operates as a security gateway. To perform our threat detection services, we briefly process incoming prompts and outbound LLM responses. GhostPrompt does not use customer payload data to train our own foundational AI models.</p>
          
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">2. Data Retention</h2>
          <p className="mb-4">Logs and payloads are retained only according to your subscription tier (7 days, 30 days, or up to 1 year). Customers may opt-in to zero-retention mode where payloads are analyzed in memory and immediately discarded.</p>
          
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">3. Security Metrics</h2>
          <p className="mb-4">We collect aggregated, anonymized telemetry on threat vectors and attack signatures to improve our global threat intelligence networks.</p>

          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">4. Contact Information</h2>
          <p>For privacy inquiries, please contact me via <a href="https://www.linkedin.com/in/darshchatrani/" target="_blank" rel="noopener"><strong>LinkedIn</strong></a>.</p>
        </div>
        <div className="mt-12 pt-8 border-t border-white/5">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
