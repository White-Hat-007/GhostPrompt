import Link from 'next/link';
import { Mail, Phone, MapPin } from 'lucide-react';

export default function ContactPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-16">
          <h1 className="text-4xl font-bold mb-4">Contact Sales & Support</h1>
          <p className="text-gray-400 text-lg">We're here to help you secure your AI infrastructure.</p>
        </div>
        
        <div className="grid md:grid-cols-3 gap-6 mb-16">
          <div className="bg-surface-1 border border-white/5 p-8 rounded-2xl text-center">
            <Mail className="w-8 h-8 text-ghost-400 mx-auto mb-4" />
            <h3 className="font-bold mb-2">Open an Issue</h3>
            <p className="text-gray-400 text-sm mb-4">For bugs, features, and inquiries.</p>
            <a href="https://www.linkedin.com/in/darshchatrani/" target="_blank" rel="noopener" className="text-ghost-400 hover:text-white font-medium">LinkedIn Profile</a>
          </div>
          
          <div className="bg-surface-1 border border-white/5 p-8 rounded-2xl text-center">
            <Phone className="w-8 h-8 text-cyber-400 mx-auto mb-4" />
            <h3 className="font-bold mb-2">Discussions</h3>
            <p className="text-gray-400 text-sm mb-4">Community support & Q&A.</p>
            <a href="https://github.com/White-Hat-007/GhostPrompt/discussions" target="_blank" rel="noopener" className="text-cyber-400 hover:text-white font-medium">GitHub Discussions</a>
          </div>
          
          <div className="bg-surface-1 border border-white/5 p-8 rounded-2xl text-center">
            <MapPin className="w-8 h-8 text-emerald-400 mx-auto mb-4" />
            <h3 className="font-bold mb-2">Headquarters</h3>
            <p className="text-gray-400 text-sm">
              GhostPrompt Security<br/>
              Global Operations Center
            </p>
          </div>
        </div>
        
        <div className="text-center">
          <Link href="/" className="text-gray-500 hover:text-white">← Back Home</Link>
        </div>
      </div>
    </div>
  );
}
