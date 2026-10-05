"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Key, ArrowRight, Loader2, AlertCircle, Eye, EyeOff, User, Terminal } from "lucide-react";
import Link from "next/link";
import CyberGrid from "@/components/ui/CyberGrid";
import GhostLogo from "@/components/ui/GhostLogo";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const res = await fetch(`/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Invalid email or password");
      }

      localStorage.setItem("access_token", data.access_token);
      localStorage.setItem("refresh_token", data.refresh_token);
      
      try {
        const payload = JSON.parse(atob(data.access_token.split('.')[1]));
        router.push("/boot");
      } catch (err) {
        router.push("/");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center p-4">
      {/* Background image */}
      <div className="fixed inset-0 z-0">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{ backgroundImage: "url('/bg/hacker.jpg')", opacity: 1 }}
        />
        <div className="absolute inset-0 bg-surface-0/75" />
      </div>
      {/* Interactive grid overlay */}
      <CyberGrid opacity={0.08} />

      <div className="w-full max-w-md relative z-10">
        {/* Header */}
        <div className="flex flex-col items-center mb-8">
          <GhostLogo className="text-4xl flex-col gap-4 mb-4" />
          <h1 className="text-3xl font-hacker font-bold text-white mb-2 tracking-widest uppercase drop-shadow-[0_0_10px_rgba(255,255,255,0.3)]">Authenticate</h1>
          <p className="text-gray-500 text-sm font-mono flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-hacker" />
            <span className="text-hacker/80 text-xs">system.login()</span>
            <span className="text-gray-600">—</span>
            Awaiting credentials...
          </p>
        </div>

        {/* Card */}
        <div className="bg-surface-1/80 backdrop-blur-xl rounded-2xl border border-white/5 p-8 shadow-2xl">
          {error && (
            <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-400 leading-relaxed">{error}</p>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-5">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-gray-300">Email or Username</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="text"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500 transition-all"
                  placeholder="Email or Username (no spaces)"
                  required
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-300">Password</label>
                <Link href="/auth/forgot-password" className="text-xs text-ghost-400 hover:text-ghost-300 transition-colors">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Key className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-surface-0 border border-white/10 rounded-xl py-2.5 pl-10 pr-10 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-ghost-500/50 focus:border-ghost-500 transition-all"
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-gray-300 transition-colors focus:outline-none"
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
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
                  [ Initialize Session ]
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-500">
            Don't have an account?{" "}
            <Link href="/auth/register" className="text-ghost-400 hover:text-ghost-300 font-medium transition-colors">
              Create an organization
            </Link>
          </div>
        </div>

        {/* Subtle hacker accent at bottom */}
        <div className="mt-6 text-center">
          <p className="text-[11px] font-mono text-gray-600">
            <span className="text-hacker/40">●</span> Secure connection established
          </p>
        </div>
      </div>
    </div>
  );
}
