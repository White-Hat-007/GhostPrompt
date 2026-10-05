"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Check, Loader2, Shield, Zap, Globe, Activity } from "lucide-react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

const PRICING_PLANS = [
  {
    id: "monthly",
    name: "Starter",
    price: "₹14,999",
    interval: "month",
    description: "Core AI firewall for evaluation and early-stage apps.",
    features: [
      "Up to 100K API Scans/mo",
      "12 Core Detection Engines",
      "Prompt Injection & Jailbreak Shield",
      "PII & Secret Detection (DLP)",
      "Encoded Payload Decoder",
      "Basic Semantic Caching (Exact Match)",
      "1 LLM Provider Connection",
      "7-Day Log Retention",
      "Community Support",
    ],
    icon: Shield,
    popular: false,
  },
  {
    id: "quarterly",
    name: "Pro",
    price: "₹39,999",
    interval: "month",
    description: "Advanced multi-layer defense for production workloads.",
    features: [
      "Up to 500K API Scans/mo",
      "24 Detection Engines (incl. Zero-Day, Cross-Lingual)",
      "Pack Hunt & Pliny Jailbreak Defense",
      "RAG Sandbox & Supply Chain Verification",
      "Multi-Agent Poisoning Guard",
      "Intelligent Routing (Cost/Latency/Semantic)",
      "Dual-Layer Semantic Cache (FAISS)",
      "Up to 5 LLM Provider Connections",
      "Virtual Key Vault (10 Keys, AES-256)",
      "Observability Dashboard (P50/P95 Latency & Cost)",
      "30-Day Log Retention",
      "Priority Email Support",
    ],
    popular: true,
    icon: Zap,
  },
  {
    id: "biannual",
    name: "Business",
    price: "₹79,999",
    interval: "month",
    description: "Full platform suite for scaling enterprise AI.",
    features: [
      "Up to 2M API Scans/mo",
      "All 34 Detection Engines",
      "Global Threat Map & Threat Attribution",
      "Hallucination Detection & Constitutional Auditor",
      "Hardware Side-Channel & Oracle Attack Defense",
      "Intelligent Routing (All Strategies + Failover)",
      "Unlimited Semantic Cache",
      "Up to 13 LLM Provider Connections (1600+ Models)",
      "Virtual Key Vault (Unlimited Keys)",
      "Prompt Studio (A/B Testing & Version Control)",
      "MCP Gateway",
      "Budget Controls (Per-Tenant/User/Key Spend Caps)",
      "Network Guardrails (IP/Geo-blocking, Tor/VPN)",
      "90-Day Log Retention",
      "Dedicated Account Manager",
    ],
    icon: Globe,
    popular: false,
  },
  {
    id: "yearly",
    name: "Enterprise",
    price: "₹1,49,999",
    interval: "month",
    description: "Full-scale enterprise security & operations gateway.",
    features: [
      "Unlimited API Scans",
      "All 34 Detection Engines + Custom ML Training",
      "Red Team Simulator (22 Payloads × 9 Categories)",
      "4-Tier Certification Engine (Bronze→Platinum)",
      "Automated Attack Cycle Testing",
      "Full Framework SDKs (LangChain, LlamaIndex, CrewAI, AutoGen, Haystack)",
      "SOC 2, GDPR, HIPAA Compliance Reports",
      "HMAC-Signed Tamper-Proof Audit Logs",
      "Data Residency & BYOK Encryption",
      "Rate Limiting (TPM/RPM) with Burst",
      "Spend Forecasting & Alert Thresholds",
      "1-Year Log Retention",
      "24/7 Priority Phone Support",
    ],
    icon: Activity,
    popular: false,
  },
  {
    id: "custom",
    name: "Custom",
    price: "Custom",
    interval: "",
    description: "For regulated industries & air-gapped deployments.",
    features: [
      "Everything in Enterprise",
      "On-Premise / Air-gapped Deployment",
      "Custom SIEM Integration (Splunk, Datadog, QRadar)",
      "Custom Detection Engine Training",
      "Dedicated Security Engineering Team",
      "Private LLM Routing (No Data Leaves Your Network)",
      "Custom Data Retention (Unlimited)",
      "SLA-backed 99.99% Uptime Guarantee",
    ],
    icon: Shield,
    popular: false,
  },
];

export default function PricingPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState<string | null>(null);

  const handleSubscribe = async (planId: string) => {
    setIsLoading(planId);
    try {
      if (planId === "custom") {
        alert("Please contact our sales team at admin@ghostprompt.dev or call us at +1 (888) 555-0199");
        setIsLoading(null);
        return;
      }

      const token = localStorage.getItem("access_token");
      if (!token) {
        router.push("/auth/login");
        return;
      }

      const res = await fetch(`/api/v1/billing/subscribe`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ interval: planId }),
      });

      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.detail || "Failed to subscribe");
      }

      // Success, redirect to dashboard
      router.push("/dashboard");
    } catch (err) {
      console.error(err);
      alert("Failed to process subscription. Please try again.");
    } finally {
      setIsLoading(null);
    }
  };

  return (
    <div className="min-h-screen bg-[#060610] flex flex-col justify-center py-12 px-4 relative overflow-hidden">
      {/* Background Effects */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-ghost-500/10 blur-[120px] rounded-full mix-blend-screen" />
        <div className="absolute top-[20%] right-[-10%] w-[50%] h-[50%] bg-cyber-500/10 blur-[120px] rounded-full mix-blend-screen" />
      </div>

      <div className="max-w-7xl mx-auto w-full relative z-10">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-ghost-500/10 border border-ghost-500/20 text-ghost-400 text-sm font-medium mb-6">
            <Activity className="w-4 h-4" />
            <span>Transparent Pricing</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 tracking-tight">
            Secure your AI at any scale
          </h1>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Choose the plan that best fits your organization's needs. Upgrade or downgrade at any time.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6 max-w-7xl mx-auto">
          {PRICING_PLANS.map((plan) => {
            const Icon = plan.icon;
            return (
              <div
                key={plan.id}
                className={`relative bg-surface-1 rounded-3xl border ${
                  plan.popular ? "border-ghost-500" : "border-white/10"
                } p-8 flex flex-col hover:border-ghost-500/50 transition-colors shadow-2xl`}
              >
                {plan.popular && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-ghost-500 text-surface-0 px-3 py-1 rounded-full text-sm font-bold shadow-[0_0_20px_rgba(100,255,218,0.4)]">
                    Most Popular
                  </div>
                )}
                <div className="mb-8">
                  <div className="w-12 h-12 bg-surface-2 rounded-xl border border-white/5 flex items-center justify-center mb-6">
                    <Icon className="w-6 h-6 text-ghost-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white mb-2">{plan.name}</h3>
                  <p className="text-sm text-gray-400 h-10">{plan.description}</p>
                </div>

                <div className="mb-8">
                  <div className="flex items-baseline gap-1">
                    <span className="text-4xl font-bold text-white">{plan.price}</span>
                    {plan.interval && <span className="text-gray-400">/{plan.interval}</span>}
                  </div>
                </div>

                <ul className="space-y-4 mb-8 flex-1">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <Check className="w-5 h-5 text-ghost-400 shrink-0 mt-0.5" />
                      <span className="text-sm text-gray-300">{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  onClick={() => handleSubscribe(plan.id)}
                  disabled={isLoading !== null}
                  className={`w-full py-3 rounded-xl font-bold transition-all flex items-center justify-center gap-2 ${
                    plan.popular
                      ? "bg-ghost-500 hover:bg-ghost-400 text-surface-0 shadow-[0_0_20px_rgba(100,255,218,0.2)]"
                      : "bg-surface-2 hover:bg-surface-3 text-white border border-white/5"
                  } disabled:opacity-70 disabled:cursor-not-allowed`}
                >
                  {isLoading === plan.id ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : plan.id === "custom" ? (
                    "Contact Sales"
                  ) : (
                    "Subscribe Now"
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
