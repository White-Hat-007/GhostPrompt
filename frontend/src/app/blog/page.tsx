import Link from 'next/link';

export default function BlogPage() {
  const posts = [
    { title: "The Evolution of Prompt Injection in 2026", date: "May 24, 2026", category: "Research" },
    { title: "GhostPrompt 1.2: Global Threat Maps and Attacker Profiling", date: "May 10, 2026", category: "Product" },
    { title: "Why LLMs Can Never Be 100% Secure Out of the Box", date: "April 28, 2026", category: "Opinion" }
  ];

  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-4">GhostPrompt Blog</h1>
        <p className="text-gray-400 mb-12 text-lg">Insights on AI security, prompt injection, and product updates.</p>
        
        <div className="space-y-6">
          {posts.map((post, i) => (
            <div key={i} className="bg-surface-1 border border-white/5 p-6 rounded-2xl hover:border-ghost-500/50 transition-colors cursor-pointer group">
              <div className="flex items-center gap-3 mb-2">
                <span className="text-xs font-bold px-2 py-1 bg-white/5 rounded text-ghost-400">{post.category}</span>
                <span className="text-xs text-gray-500">{post.date}</span>
              </div>
              <h2 className="text-2xl font-bold group-hover:text-ghost-400 transition-colors">{post.title}</h2>
              <p className="text-gray-400 mt-2">Read the full breakdown and analysis by the GhostPrompt research team...</p>
            </div>
          ))}
        </div>
        
        <div className="mt-12 text-center">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
