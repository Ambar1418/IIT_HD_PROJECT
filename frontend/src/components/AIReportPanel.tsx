"use client";

import React, { useState } from "react";
import { Brain, ListFilter, ShieldAlert, Award, FileSpreadsheet, Building2, HelpCircle } from "lucide-react";
import { motion } from "framer-motion";

interface AIReportPanelProps {
  explanation: {
    executive_summary: string;
    flagged_reasons: string[] | string;
    dangerous_permissions: string[] | string;
    threat_level_assessment: string;
    user_recommendation: string[] | string;
    business_impact: string[] | string;
    _info?: string;
  };
  verdict: string;
}

export default function AIReportPanel({ explanation, verdict }: AIReportPanelProps) {
  const [activeTab, setActiveTab] = useState<"summary" | "indicators" | "mitigations" | "enterprise">("summary");

  const normalizeList = (val: string[] | string): string[] => {
    if (typeof val === "string") {
      return [val];
    }
    return val || [];
  };

  const executiveSummary = explanation.executive_summary || "No summary generated.";
  const flaggedReasons = normalizeList(explanation.flagged_reasons);
  const dangerousPermissions = normalizeList(explanation.dangerous_permissions);
  const threatLevel = explanation.threat_level_assessment || "No threat details.";
  const userRecs = normalizeList(explanation.user_recommendation);
  const businessImpacts = normalizeList(explanation.business_impact);

  return (
    <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 shadow-xl flex flex-col gap-6 relative">
      {/* Decorative tech grid backdrop */}
      <div className="absolute top-4 right-4 text-blue-500/10 pointer-events-none">
        <Brain className="w-24 h-24 stroke-[1px]" />
      </div>

      <div className="flex items-center gap-3">
        <div className="p-3 bg-blue-950/50 border border-blue-500/30 rounded-xl text-blue-400 shadow-md">
          <Brain className="w-6 h-6" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-slate-100">AI Threat Intelligence Brief</h2>
          <p className="text-xs text-slate-500">Llama 3.3 Versatile Cognitive Layer</p>
        </div>
      </div>

      {/* Tabs list */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
        {[
          { id: "summary", label: "Executive Summary", icon: Award },
          { id: "indicators", label: "Risk Indicators", icon: ShieldAlert },
          { id: "mitigations", label: "Mitigations", icon: ListFilter },
          { id: "enterprise", label: "Enterprise Impact", icon: Building2 },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-lg border transition-all ${
                isActive
                  ? "bg-blue-600 border-blue-500 text-white shadow-md shadow-blue-500/15"
                  : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div className="min-h-[220px]">
        {activeTab === "summary" && (
          <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
          >
            <div className={`p-4 rounded-xl border ${
              verdict === "MALWARE"
                ? "bg-red-950/20 border-red-500/20 text-red-300"
                : verdict === "SUSPICIOUS APK"
                ? "bg-amber-950/20 border-amber-500/20 text-amber-300"
                : "bg-emerald-950/20 border-emerald-500/20 text-emerald-300"
            }`}>
              <p className="text-xs md:text-sm font-semibold leading-relaxed">
                {executiveSummary}
              </p>
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1.5">
                Threat Level Assessment
              </h4>
              <p className="text-xs md:text-sm text-slate-300 leading-relaxed">
                {threatLevel}
              </p>
            </div>
          </motion.div>
        )}

        {activeTab === "indicators" && (
          <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="grid grid-cols-1 md:grid-cols-2 gap-4"
          >
            <div>
              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2.5">
                Risk Indicators Identified
              </h4>
              <ul className="space-y-2 text-xs md:text-sm text-slate-300">
                {flaggedReasons.map((reason, i) => (
                  <li key={i} className="flex gap-2.5 items-start">
                    <span className="text-blue-500 font-bold mt-0.5">•</span>
                    <span className="leading-relaxed">{reason}</span>
                  </li>
                ))}
                {flaggedReasons.length === 0 && (
                  <li className="text-slate-500 italic">No heuristics flagged.</li>
                )}
              </ul>
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2.5">
                Dangerous Privilege Access
              </h4>
              <ul className="space-y-2 text-xs md:text-sm text-slate-300">
                {dangerousPermissions.map((perm, i) => (
                  <li key={i} className="flex gap-2.5 items-start">
                    <span className="text-red-500 font-bold mt-0.5">•</span>
                    <span className="leading-relaxed">{perm}</span>
                  </li>
                ))}
                {dangerousPermissions.length === 0 && (
                  <li className="text-slate-500 italic">No dangerous permissions identified.</li>
                )}
              </ul>
            </div>
          </motion.div>
        )}

        {activeTab === "mitigations" && (
          <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-3"
          >
            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">
              Actionable Defense Recommendations
            </h4>
            <div className="grid grid-cols-1 gap-2">
              {userRecs.map((rec, i) => (
                <div
                  key={i}
                  className="flex gap-3 items-center p-3 rounded-lg bg-slate-950/40 border border-slate-800 text-xs md:text-sm text-slate-200"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                  <span className="leading-relaxed">{rec}</span>
                </div>
              ))}
              {userRecs.length === 0 && (
                <p className="text-slate-500 italic text-sm">No mitigations specified.</p>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === "enterprise" && (
          <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-3"
          >
            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">
              Corporate Risk & Compliance Impact
            </h4>
            <div className="grid grid-cols-1 gap-2.5">
              {businessImpacts.map((impact, i) => (
                <div
                  key={i}
                  className="flex gap-3 items-start p-3.5 rounded-xl bg-slate-950/30 border border-slate-800/80 text-xs md:text-sm text-slate-300 leading-relaxed"
                >
                  <Building2 className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                  <span>{impact}</span>
                </div>
              ))}
              {businessImpacts.length === 0 && (
                <p className="text-slate-500 italic text-sm">No corporate impact data generated.</p>
              )}
            </div>
          </motion.div>
        )}
      </div>

      {explanation._info && (
        <div className="border-t border-slate-800 pt-3 text-[10px] text-slate-500 italic font-mono flex items-center gap-1.5">
          <HelpCircle className="w-3.5 h-3.5" />
          <span>System Details: {explanation._info}</span>
        </div>
      )}
    </div>
  );
}
