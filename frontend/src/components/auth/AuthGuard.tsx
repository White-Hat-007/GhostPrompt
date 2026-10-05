"use client";

import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { Loader2 } from "lucide-react";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    // Check if user has token
    const token = localStorage.getItem("access_token");
    
    // Public routes that don't need auth
    const publicRoutes = [
      "/",
      "/about",
      "/blog",
      "/changelog",
      "/contact",
      "/docs",
      "/dpa",
      "/pricing",
      "/privacy",
      "/security",
      "/terms",
      "/auth/login",
      "/auth/register",
      "/auth/forgot-password",
      "/auth/reset-password",
      "/auth/verify-email"
    ];
    
    if (!token && !publicRoutes.includes(pathname)) {
      router.push("/auth/login");
    } else {
      setIsAuthenticated(true);
    }
  }, [pathname, router]);

  if (isAuthenticated === null) {
    return (
      <div className="min-h-screen bg-[#060610] flex items-center justify-center">
        <Loader2 className="w-12 h-12 text-ghost-400 animate-spin" />
      </div>
    );
  }

  return <>{children}</>;
}
