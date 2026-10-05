import type { Metadata } from 'next';
import './globals.css';
import AuthGuard from '@/components/auth/AuthGuard';
import CursorProvider from '@/components/cursor/CursorProvider';

export const metadata: Metadata = {
  title: 'GhostPrompt — AI Runtime Security Platform',
  description: 'Enterprise AI Firewall protecting against prompt injection, jailbreaks, and AI attacks. Real-time AI security for global enterprises.',
  keywords: ['AI security', 'prompt injection', 'jailbreak prevention', 'AI firewall', 'LLM security'],
  openGraph: {
    title: 'GhostPrompt — AI Runtime Security Platform',
    description: 'The Global AI Firewall. Protect your enterprise AI systems from prompt injection, jailbreaks, and adversarial attacks.',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="icon" href="/favicon.ico" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body className="min-h-screen bg-surface-0 text-white antialiased">
        <CursorProvider />
        <AuthGuard>
          {children}
        </AuthGuard>
      </body>
    </html>
  );
}

