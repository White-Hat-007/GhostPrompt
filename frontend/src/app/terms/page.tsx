import Link from 'next/link';

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Terms of Service</h1>
        <div className="prose prose-invert max-w-none text-gray-400">
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">1. Acceptance of Terms</h2>
          <p className="mb-4">By accessing or using GhostPrompt's API and platform, you agree to be bound by these terms. If you do not agree, do not use the service.</p>
          
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">2. Service Usage</h2>
          <p className="mb-4">GhostPrompt is designed to detect and block malicious AI interactions. You agree not to use our API to intentionally bypass security controls, reverse-engineer our detection engines, or execute denial of service attacks.</p>
          
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">3. Service Level Agreement</h2>
          <p className="mb-4">Enterprise customers are guaranteed 99.99% uptime. Custom SLA compensation structures apply to specific tiers. We are not liable for outages of third-party LLM providers (e.g., OpenAI, Anthropic).</p>

          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">4. Billing and Pricing</h2>
          <p>Payments are processed securely via our partners. Refunds are evaluated on a case-by-case basis. Subscriptions automatically renew unless canceled prior to the billing cycle.</p>
        </div>
        <div className="mt-12 pt-8 border-t border-white/5">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
