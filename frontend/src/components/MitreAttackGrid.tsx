"use client";

import React, { useState } from "react";
import { ShieldCheck, ChevronDown, ChevronUp, AlertTriangle, HelpCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface MitreAttackGridProps {
  tactics: Record<
    string,
    Array<{
      permission: string;
      technique: string;
      description: string;
    }>
  >;
}

export default function MitreAttackGrid({ tactics }: MitreAttackGridProps) {
  const [expandedTactic, setExpandedTactic] = useState<string | null>(null);

  const tacticsKeys = Object.keys(tactics);

  const toggleTactic = (tactic: string) => {
    setExpandedTactic((prev) => (prev === tactic ? null : tactic));
  };

  if (tacticsKeys.length === 0) {
    return (
      <div className="p-8 rounded-2xl bg-emerald-950/20 border border-emerald-500/20 text-center flex flex-col items-center justify-center shadow-lg">
        <div className="p-3 bg-emerald-950/50 border border-emerald-500/30 rounded-full text-emerald-400 mb-3 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
          <ShieldCheck className="w-8 h-8" />
        </div>
        <h3 className="text-lg font-bold text-emerald-400 mb-1">
          MITRE ATT&CK Mapping Safe
        </h3>
        <p className="text-sm text-slate-400 max-w-sm">
          No structural permissions in the manifest are mapped to aggressive MITRE ATT&CK adversary tactics.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-2">
        <AlertTriangle className="w-5 h-5 text-amber-400" />
        <p className="text-sm text-slate-400">
          Adversary Tactics Groupings identified within app signatures:
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {tacticsKeys.map((tactic) => {
          const items = tactics[tactic];
          const isExpanded = expandedTactic === tactic;

          return (
            <div
              key={tactic}
              className={`rounded-xl border transition-all overflow-hidden ${
                isExpanded
                  ? "border-slate-700 bg-slate-900/60 shadow-lg"
                  : "border-slate-800 bg-slate-900/30 hover:border-slate-700 hover:bg-slate-900/40"
              }`}
            >
              {/* Card Header Accordion Trigger */}
              <button
                onClick={() => toggleTactic(tactic)}
                className="w-full flex items-center justify-between p-4 text-left font-bold text-slate-200 hover:text-slate-100 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
                  <span className="text-sm md:text-base font-bold text-slate-200">
                    {tactic}
                  </span>
                  <span className="text-xs bg-slate-800 border border-slate-700 text-slate-400 px-2 py-0.5 rounded-full font-mono">
                    {items.length} Techs
                  </span>
                </div>
                {isExpanded ? (
                  <ChevronUp className="w-4 h-4 text-slate-500" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-slate-500" />
                )}
              </button>

              {/* Accordion Content */}
              <AnimatePresence initial={false}>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0 }}
                    animate={{ height: "auto" }}
                    exit={{ height: 0 }}
                    transition={{ duration: 0.25, ease: "easeInOut" }}
                    className="overflow-hidden"
                  >
                    <div className="p-4 pt-0 border-t border-slate-800 bg-slate-950/20 space-y-4">
                      {items.map((item, idx) => (
                        <div
                          key={idx}
                          className="p-3.5 rounded-lg bg-slate-900/85 border border-slate-800 flex flex-col gap-1.5"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="text-xs md:text-sm font-extrabold text-slate-200">
                              🚩 {item.technique}
                            </span>
                            <span className="text-[10px] md:text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700 px-2.5 py-0.5 rounded-md">
                              API: {item.permission}
                            </span>
                          </div>
                          <p className="text-xs md:text-sm text-slate-400 leading-relaxed">
                            {item.description}
                          </p>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
}
