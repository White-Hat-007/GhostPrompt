"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Key, Mail, ArrowRight, Loader2, AlertCircle, Building, User, Terminal } from "lucide-react";
import Link from "next/link";
import CyberGrid from "@/components/ui/CyberGrid";
import GhostLogo from "@/components/ui/GhostLogo";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export default function RegisterPage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    organization_name: "",
    full_name: "",
    username: "",
    email: "",
    password: "",
  });
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const res = await fetch(`/api/v1/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Registration failed. Please check your inputs.");
      }

      localStorage.setItem("access_token", data.access_token);
      localStorage.setItem("refresh_token", data.refresh_token);

      setIsSuccess(true);
      // We don't auto-redirect anymore since they must verify email first.
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  if (isSuccess) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center p-4 relative z-10">
        {/* Background image */}
        <div className="fixed inset-0 z-0">
          <div
            className="absolute inset-0 bg-cover bg-center bg-no-repeat"
            style={{ backgroundImage: "url('/bg/elliot.jpg')", opacity: 0.25 }}
          />
          <div className="absolute inset-0 bg-surface-0/80" />
        </div>
        <CyberGrid opacity={0.08} />
        
        <div className="w-full max-w-md bg-surface-1/80 backdrop-blur-xl rounded-2xl border border-white/5 p-8 shadow-2xl text-center relative z-10">
          <div className="w-16 h-16 bg-emerald-500/20 text-emerald-400 rounded-xl flex items-center justify-center mx-auto mb-6">
            <Mail className="w-8 h-8" />
          </div>
          <h2 className="text-2xl font-bold text-white mb-3">Check your email</h2>
          <p className="text-gray-400 mb-6 leading-relaxed">
            We've sent a verification link to <span className="text-white font-medium">{formData.email}</span>. Please verify your email to unlock all features.
          </p>
          <div className="flex flex-col items-center justify-center gap-4">
            <Link href="/auth/login" className="btn-primary w-full py-2.5 flex justify-center">
              Go to Login
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center p-4">
      {/* Background image */}
      <div className="fixed inset-0 z-0">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{ backgroundImage: "url('/bg/elliot.jpg')", opacity: 0.25 }}
        />
        <div className="absolute inset-0 bg-surface-0/75" />
      </div>
      {/* Interactive grid overlay */}
      <CyberGrid opacity={0.08} />

      <div className="w-full max-w-md relative z-10 py-8">
        <div className="flex flex-col items-center mb-8">
          <GhostLogo className="text-4xl flex-col gap-4 mb-4" />
          <h1 className="text-3xl font-hacker font-bold text-white mb-2 tracking-widest uppercase drop-shadow-[0_0_10px_rgba(255,255,255,0.3)] whitespace-nowrap">Create Organization</h1>
          <p className="text-gray-500 text-sm flex items-center gap-2 font-mono">
            <Terminal className="w-3.5 h-3.5 text-hacker" />
            <span className="font-mono text-hacker/80 text-xs">system.register()</span>
            <span className="text-gray-600">—</span>
            Deploy the AI Firewall
          </p>
        </div>

        <div className="bg-surface-1/80 backdrop-blur-xl rounded-2xl border border-white/5 p-8 shadow-2xl">
          {error && (
            <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-400 leading-relaxed">{error}</p>
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-gray-300">Organization Name</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Building className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="text"
                  name="organization_name"
                  value={formData.organization_name}
                  onChange={handleChange}
                  className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500"
                  placeholder="Acme Corp"
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-gray-300">Full Name</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-gray-500" />
                  </div>
                  <input
                    type="text"
                    name="full_name"
                    value={formData.full_name}
                    onChange={handleChange}
                    className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500"
                    placeholder="John Doe"
                    required
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-gray-300">Username</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-gray-500" />
                  </div>
                  <input
                    type="text"
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                    className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500"
                    placeholder="johndoe"
                    required
                  />
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-gray-300">Work Email</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500"
                  placeholder="john@acme.com"
                  required
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-gray-300">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Key className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-6 bg-transparent border border-hacker/50 hover:bg-hacker/10 text-hacker font-hacker uppercase tracking-widest font-bold py-3 px-4 rounded-none flex items-center justify-center gap-2 transition-all disabled:opacity-70 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(0,255,65,0.1)] hover:shadow-[0_0_25px_rgba(0,255,65,0.3)]"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <>
                  [ Initialize Account ]
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-500">
            Already have an account?{" "}
            <Link href="/auth/login" className="text-ghost-400 hover:text-ghost-300 font-medium transition-colors">
              Sign in
            </Link>
          </div>
        </div>

        <div className="mt-6 text-center">
          <p className="text-[11px] font-mono text-gray-600">
            <span className="text-hacker/40">●</span> End-to-end encrypted registration
          </p>
        </div>
      </div>
    </div>
  );
}
