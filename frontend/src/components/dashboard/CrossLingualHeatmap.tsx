"use client";

import { Globe2 } from "lucide-react";

interface ScanEvent {
  category?: string;
  detections?: Array<{ category: string; description?: string }>;
  prompt?: string;
}

interface CrossLingualHeatmapProps {
  scans?: ScanEvent[];
}

const LANGUAGE_KEYS = [
  { lang: "English", match: ["english", "en_", "latin", "ignore", "override", "delete", "repeat", "write", "list", "summarize", "explain", "complete", "read", "process"] },
  { lang: "Russian", match: ["russian", "cyrillic", "ru_", "\u0435", "\u0430", "\u043e"] },
  { lang: "Chinese", match: ["chinese", "mandarin", "cjk", "zh_", "\u4e2d\u6587"] },
  { lang: "Arabic", match: ["arabic", "rtl", "ar_", "\u0627\u0644"] },
  { lang: "Korean", match: ["korean", "ko_", "\ud55c\uad6d\uc5b4"] },
  { lang: "Japanese", match: ["japanese", "ja_", "\u65e5\u672c\u8a9e", "hiragana", "katakana"] },
  { lang: "Hindi", match: ["hindi", "hi_", "\u0939\u093f\u0928\u094d\u0926\u0940", "devanagari"] },
  { lang: "Persian", match: ["persian", "farsi", "fa_", "\u0641\u0627\u0631\u0633\u06cc"] },
  { lang: "Turkish", match: ["turkish", "tr_", "t\u00fcrk\u00e7e"] },
  { lang: "Vietnamese", match: ["vietnamese", "vi_", "ti\u1ebfng vi\u1ec7t"] },
  { lang: "Portuguese", match: ["portuguese", "pt_", "portugu\u00eas"] },
  { lang: "Swahili", match: ["swahili", "sw_", "african"] },
];

function deriveLangCounts(scans: ScanEvent[]) {
  const counts: Record<string, number> = {};
  LANGUAGE_KEYS.forEach((l) => (counts[l.lang] = 0));

  scans.forEach((s) => {
    const allText: string[] = [];
    if (s.category) allText.push(s.category.toLowerCase());
    if (s.prompt) allText.push(s.prompt.toLowerCase());
    (s.detections || []).forEach((d) => {
      if (d.category) allText.push(d.category.toLowerCase());
      if (d.description) allText.push(d.description.toLowerCase());
    });
    const joined = allText.join(" ");

    // Check for non-Latin scripts first (highest priority)
    let matched = false;
    for (const l of LANGUAGE_KEYS) {
      if (l.lang === "English") continue; // check English last
      if (l.match.some((m) => joined.includes(m))) {
        counts[l.lang]++;
        matched = true;
        break;
      }
    }
    if (!matched) {
      // Default to English
      counts["English"]++;
    }
  });

  return LANGUAGE_KEYS
    .map((l) => ({ lang: l.lang, count: counts[l.lang] }))
    .filter((d) => d.count > 0)
    .sort((a, b) => b.count - a.count);
}

export default function CrossLingualHeatmap({ scans = [] }: CrossLingualHeatmapProps) {
  const data = deriveLangCounts(scans);
  const maxCount = Math.max(...data.map((d) => d.count), 1);
  const total = data.reduce((s, d) => s + d.count, 0);

  // Color gradient from emerald to cyan based on position
  const colors = [
    "from-emerald-600 to-emerald-400",
    "from-teal-600 to-teal-400",
    "from-cyan-600 to-cyan-400",
    "from-sky-600 to-sky-400",
    "from-blue-600 to-blue-400",
    "from-indigo-600 to-indigo-400",
    "from-violet-600 to-violet-400",
    "from-purple-600 to-purple-400",
    "from-fuchsia-600 to-fuchsia-400",
    "from-pink-600 to-pink-400",
    "from-rose-600 to-rose-400",
    "from-orange-600 to-orange-400",
  ];

  return (
    <div className="glass-card p-6 h-full">
      <div className="mb-4 pb-2 border-b border-white/10">
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <Globe2 className="w-4 h-4 text-emerald-400" />
          Cross-Lingual Vectors
        </h3>
        <p className="text-xs text-gray-500 mt-0.5">Translated injection telemetry &bull; {data.length} languages detected</p>
      </div>
      {total > 0 ? (
        <div className="space-y-3 max-h-[280px] overflow-y-auto pr-1 custom-scrollbar">
          {data.map((l, idx) => (
            <div key={l.lang} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300 font-medium">{l.lang}</span>
                <span className="text-gray-500">{l.count} attempts</span>
              </div>
              <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div
                  className={`h-full bg-gradient-to-r ${colors[idx % colors.length]} rounded-full transition-all duration-500`}
                  style={{ width: `${(l.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="h-[200px] flex items-center justify-center">
          <p className="text-xs text-gray-500">No cross-lingual data yet</p>
        </div>
      )}
    </div>
  );
}
