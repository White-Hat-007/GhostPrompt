import Link from 'next/link';

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-3xl mx-auto text-center">
        <h1 className="text-4xl md:text-5xl font-bold mb-6">About GhostPrompt</h1>
        <p className="text-gray-400 mb-12 text-lg md:text-xl leading-relaxed">
          As Artificial Intelligence becomes deeply integrated into mission-critical business systems, 
          the attack surface has fundamentally changed. GhostPrompt was built to solve the hardest 
          problem in AI engineering: <strong>trusting the untrusted input</strong>.
        </p>
        
        <div className="bg-surface-1 border border-white/5 p-8 rounded-3xl text-left mb-12">
          <h2 className="text-2xl font-bold mb-4">Our Mission</h2>
          <p className="text-gray-400 mb-6">
            We exist to secure the next generation of software. By providing enterprise-grade 
            firewalls, prompt injection protection, and real-time observability, we allow teams 
            to deploy LLMs to production with absolute confidence.
          </p>
          <h2 className="text-2xl font-bold mb-4">The Platform</h2>
          <p className="text-gray-400">
            GhostPrompt utilizes 7 highly optimized detection engines to enforce 18 granular security 
            policies in under 50ms of latency. We act as the invisible shield between your users and your AI.
          </p>
        </div>

        <Link href="/" className="btn-primary px-8 py-3 rounded-full">
          Return to Dashboard
        </Link>
      </div>
    </div>
  );
}
