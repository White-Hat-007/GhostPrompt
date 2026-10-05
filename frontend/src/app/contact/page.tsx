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
            <h3 className="font-bold mb-2">Email Us</h3>
            <p className="text-gray-400 text-sm mb-4">For general inquiries and sales.</p>
            <a href="mailto:admin@ghostprompt.dev" className="text-ghost-400 hover:text-white font-medium">admin@ghostprompt.dev</a>
          </div>
          
          <div className="bg-surface-1 border border-white/5 p-8 rounded-2xl text-center">
            <Phone className="w-8 h-8 text-cyber-400 mx-auto mb-4" />
            <h3 className="font-bold mb-2">Call Us</h3>
            <p className="text-gray-400 text-sm mb-4">Available Mon-Fri, 9am - 6pm.</p>
            <a href="tel:+18885550199" className="text-cyber-400 hover:text-white font-medium">+1 (888) 555-0199</a>
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
