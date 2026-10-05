import type { Metadata } from 'next';
import LandingPage from '@/components/landing/LandingPage';

export const metadata: Metadata = {
  title: 'GhostPrompt — The Global AI Firewall',
  description: 'Enterprise AI Runtime Security Platform. Protect your AI systems from prompt injection, jailbreaks, RAG poisoning, and adversarial attacks in real-time.',
  keywords: ['AI security', 'prompt injection', 'jailbreak prevention', 'AI firewall', 'LLM security', 'RAG poisoning', 'Threat Attribution'],
};

export default function Landing() {
  return <LandingPage />;
}
