"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import CyberGrid from "@/components/ui/CyberGrid";
import GhostLogo from "@/components/ui/GhostLogo";
import { Terminal, Shield, Lock, Cpu, Database, CheckCircle2 } from "lucide-react";

export default function BootSequencePage() {
  const router = useRouter();
  const [step, setStep] = useState(0);

  const sequence = [
    { text: "Establishing secure connection to GhostPrompt...", icon: Lock, color: "text-ghost-400" },
    { text: "Verifying cryptographic signatures...", icon: Shield, color: "text-cyber-400" },
    { text: "Loading Threat Intelligence databases...", icon: Database, color: "text-blue-400" },
    { text: "Initializing runtime protection engines...", icon: Cpu, color: "text-amber-400" },
    { text: "Access Granted. Welcome back.", icon: CheckCircle2, color: "text-emerald-400" },
  ];

  useEffect(() => {
    // Check if we actually have a token
    const token = localStorage.getItem("access_token");
    if (!token) {
      router.push("/auth/login");
      return;
    }

    // Sequence timing
    let currentStep = 0;
    const interval = setInterval(async () => {
      currentStep++;
      if (currentStep < sequence.length) {
        setStep(currentStep);
      } else {
        clearInterval(interval);
        try {
          const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
          const meRes = await fetch(`/api/v1/auth/me`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          const user = await meRes.json();
          const isSuperadmin = user.email === 'admin@ghostprompt.dev';

          const billRes = await fetch(`/api/v1/billing/status`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          const billing = billRes.ok ? await billRes.json() : null;

          setTimeout(() => {
            // Always go to dashboard for authenticated users
            // Pricing upsell is handled inside the dashboard UI
            router.push("/dashboard");
          }, 800);
        } catch (e) {
          setTimeout(() => router.push("/dashboard"), 800);
        }
      }
    }, 600);

    return () => clearInterval(interval);
  }, [router]);

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 z-0">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{ backgroundImage: "url('/bg/GhostPrompt_Boot_BG.jpeg')" }}
        />
        <div className="absolute inset-0 bg-surface-0/85" />
      </div>
      <CyberGrid opacity={0.15} />

      <div className="relative z-10 w-full max-w-2xl -mt-48">
        <div className="flex flex-col items-center mb-12">
          <GhostLogo className="text-4xl mb-6 flex-col gap-4" />
          <p className="text-sm text-gray-500 mt-2 font-mono uppercase tracking-[0.2em]">Boot Sequence Initiated</p>
        </div>

        {/* Terminal Window */}
        <div className="bg-surface-1 border border-white/10 rounded-xl overflow-hidden shadow-2xl backdrop-blur-sm">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-black/20">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-amber-500/80" />
              <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
            </div>
            <div className="ml-4 flex items-center gap-2 text-xs text-gray-500 font-mono">
              <Terminal className="w-3.5 h-3.5" />
              <span>system_boot.sh</span>
            </div>
          </div>

          <div className="p-6 font-mono text-sm space-y-4">
            {sequence.map((item, index) => {
              const Icon = item.icon;
              return (
                <div 
                  key={index} 
                  className={`flex items-start gap-4 transition-all duration-300 ${
                    index <= step ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
                  }`}
                >
                  <div className="mt-0.5">
                    {index < step ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    ) : index === step ? (
                      <div className="w-4 h-4 border-2 border-ghost-500 border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <div className="w-4 h-4" />
                    )}
                  </div>
                  <div className={index === step ? "text-white" : "text-gray-400"}>
                    <span className="text-gray-600 mr-3">[{new Date().toISOString().slice(11, 19)}]</span>
                    <span className={item.color}>{item.text}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
