"use client";

import { PackageX, ShieldAlert } from "lucide-react";
import { motion } from "framer-motion";

interface ScanEvent {
  category?: string;
  detections?: Array<{ category: string; description?: string }>;
  created_at: string;
}

interface SupplyChainPanelProps {
  scans?: ScanEvent[];
}

function timeAgo(date: string): string {
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

const SUPPLY_CHAIN_MATCH = ["external", "supply_chain", "hallucinated", "typosquat", "dependency", "package"];

function deriveIntercepts(scans: ScanEvent[]) {
  const results: Array<{ pkg: string; ecosystem: string; status: string; time: string }> = [];

  scans.forEach((s) => {
    const allCats: string[] = [];
    if (s.category) allCats.push(s.category.toLowerCase());
    (s.detections || []).forEach((d) => {
      if (d.category) allCats.push(d.category.toLowerCase());
    });

    const joined = allCats.join(" ");
    const isSupplyChain = SUPPLY_CHAIN_MATCH.some((m) => joined.includes(m));

    if (isSupplyChain) {
      // Extract a readable name from the detection description or category
      const det = (s.detections || [])[0];
      const desc = det?.description || det?.category || s.category || "unknown";
      const isHallucinated = joined.includes("hallucinated") || joined.includes("external");
      const isTyposquat = joined.includes("typosquat");

      results.push({
        pkg: desc.length > 40 ? desc.substring(0, 37) + "..." : desc,
        ecosystem: joined.includes("npm") ? "npm" : joined.includes("pypi") ? "pypi" : "package",
        status: isTyposquat ? "typosquatting" : isHallucinated ? "hallucinated" : "suspicious",
        time: timeAgo(s.created_at),
      });
    }
  });

  return results.slice(0, 5);
}

export default function SupplyChainPanel({ scans = [] }: SupplyChainPanelProps) {
  const intercepts = deriveIntercepts(scans);

  return (
    <div className="glass-card p-6 h-full relative overflow-hidden">
      <div className="absolute top-0 right-0 p-32 bg-orange-500/10 blur-[100px] pointer-events-none rounded-full" />

      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <PackageX className="w-4 h-4 text-orange-400" />
          Supply Chain Intercepts
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Hallucinated & malicious dependencies</p>
      </div>
      {intercepts.length > 0 ? (
        <div className="space-y-3">
          {intercepts.map((item, i) => (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.1 }}
              key={i}
              className="flex items-center justify-between p-3 rounded-lg border border-red-900/30 bg-red-950/20"
            >
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <div>
                  <p className="text-sm font-medium text-red-100 truncate max-w-[180px]">{item.pkg}</p>
                  <p className="text-xs text-red-400/70">{item.ecosystem} • {item.status}</p>
                </div>
              </div>
              <span className="text-xs text-gray-500">{item.time}</span>
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="h-[200px] flex items-center justify-center">
          <p className="text-xs text-gray-500">No supply chain intercepts yet</p>
        </div>
      )}
    </div>
  );
}
