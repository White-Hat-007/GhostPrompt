"use client";

import { ShieldAlert } from "lucide-react";

interface ScanEvent {
  category?: string;
  detections?: Array<{ category: string; description?: string }>;
}

interface Props {
  scans?: ScanEvent[];
}

export default function BusinessLogicChart({ scans = [] }: Props) {
  const counts = { urgency: 0, scope: 0, social: 0 };

  scans.forEach((s) => {
    const cats = [
      s.category?.toLowerCase() || "", 
      ...(s.detections || []).map(d => `${d.category || ""} ${d.description || ""}`.toLowerCase())
    ];
    const joined = cats.join(" ");
    if (joined.includes("intent")) {
      if (joined.includes("social")) counts.social++;
      else if (joined.includes("scope")) counts.scope++;
      else if (joined.includes("urgency")) counts.urgency++;
      else counts.urgency++;
    }
  });

  const total = counts.urgency + counts.scope + counts.social;

  const getPercentage = (val: number) => total > 0 ? Math.round((val / total) * 100) : 0;

  return (
    <div className="glass-card p-6 h-full xl:col-span-1">
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-orange-400" />
          Business Logic
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Valid Tool Misuse & Intent Exploits</p>
      </div>
      <div className="pt-2">
        {total > 0 ? (
          <div className="space-y-4 max-h-[200px] overflow-y-auto custom-scrollbar">
            {/* Urgency */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-gray-300">Urgency + Destructive</span>
                <span className="text-orange-400 font-medium">{getPercentage(counts.urgency)}%</span>
              </div>
              <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-orange-500 rounded-full transition-all duration-1000" style={{ width: `${getPercentage(counts.urgency)}%` }} />
              </div>
            </div>
            {/* Scope Escalation */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-gray-300">Scope Escalation</span>
                <span className="text-amber-400 font-medium">{getPercentage(counts.scope)}%</span>
              </div>
              <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-amber-500 rounded-full transition-all duration-1000" style={{ width: `${getPercentage(counts.scope)}%` }} />
              </div>
            </div>
            {/* Social Engineering */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-gray-300">Social Engineering</span>
                <span className="text-yellow-400 font-medium">{getPercentage(counts.social)}%</span>
              </div>
              <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-yellow-500 rounded-full transition-all duration-1000" style={{ width: `${getPercentage(counts.social)}%` }} />
              </div>
            </div>
          </div>
        ) : (
          <div className="h-[200px] flex items-center justify-center">
            <p className="text-xs text-gray-500">No intent exploits detected</p>
          </div>
        )}
      </div>
    </div>
  );
}
