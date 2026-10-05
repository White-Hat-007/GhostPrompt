import Link from 'next/link';
import { ShieldCheck, Lock, Server } from 'lucide-react';

export default function SecurityPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-6">Security & Compliance</h1>
        <p className="text-gray-400 mb-12 text-lg">We take the security of your data as seriously as we take the security of your AI.</p>
        
        <div className="grid md:grid-cols-3 gap-6 mb-12">
          <div className="bg-surface-1 p-6 rounded-2xl border border-white/5">
            <ShieldCheck className="w-8 h-8 text-ghost-400 mb-4" />
            <h3 className="font-bold text-lg mb-2">SOC 2 Type II</h3>
            <p className="text-sm text-gray-400">Our platform will undergoe rigorous annual audits to ensure compliance with enterprise security standards.</p>
          </div>
          <div className="bg-surface-1 p-6 rounded-2xl border border-white/5">
            <Lock className="w-8 h-8 text-cyber-400 mb-4" />
            <h3 className="font-bold text-lg mb-2">End-to-End Encryption</h3>
            <p className="text-sm text-gray-400">All data is encrypted in transit via TLS 1.3 and at rest using AES-256 encryption.</p>
          </div>
          <div className="bg-surface-1 p-6 rounded-2xl border border-white/5">
            <Server className="w-8 h-8 text-emerald-400 mb-4" />
            <h3 className="font-bold text-lg mb-2">Data Isolation</h3>
            <p className="text-sm text-gray-400">Enterprise plans include dedicated single-tenant infrastructure and strict network isolation.</p>
          </div>
        </div>
        
        <div className="text-center">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
