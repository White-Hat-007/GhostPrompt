import Link from 'next/link';

export default function DPAPage() {
  return (
    <div className="min-h-screen bg-[#060610] text-white pt-24 pb-12 px-6">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Data Processing Agreement</h1>
        <div className="prose prose-invert max-w-none text-gray-400">
          <p className="mb-6">This Data Processing Agreement (DPA) outlines how GhostPrompt processes personal data on behalf of our customers under GDPR, CCPA, and global privacy frameworks.</p>
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">1. Roles of the Parties</h2>
          <p className="mb-4">The Customer acts as the Data Controller. GhostPrompt operates strictly as a Data Processor. We only process data in accordance with the documented instructions of the Customer.</p>
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">2. Subprocessors</h2>
          <p className="mb-4">We maintain a vetted list of subprocessors (such as AWS and GCP for infrastructure) required to deliver our services. Customers will be notified 30 days prior to any new subprocessor additions.</p>
          <h2 className="text-2xl font-semibold text-white mt-8 mb-4">3. Data Deletion</h2>
          <p>Upon termination of services, or upon explicit request, all customer data, logs, and traces are permanently purged from our systems within 30 days.</p>
        </div>
        <div className="mt-12 pt-8 border-t border-white/5">
          <Link href="/" className="text-ghost-400 hover:text-ghost-300">← Back to Home</Link>
        </div>
      </div>
    </div>
  );
}
