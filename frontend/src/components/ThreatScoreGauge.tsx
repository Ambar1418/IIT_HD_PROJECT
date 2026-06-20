"use client";

import React from "react";
import { Shield, ShieldAlert, ShieldX } from "lucide-react";
import { motion } from "framer-motion";

interface ThreatScoreGaugeProps {
  score: number;
  severity: string;
  verdict: string;
  confidence: number;
  mlPrediction: string;
  benignProb: number;
  malwareProb: number;
}

export default function ThreatScoreGauge({
  score,
  severity,
  verdict,
  confidence,
  mlPrediction,
  benignProb,
  malwareProb,
}: ThreatScoreGaugeProps) {
  // SVG Circle specs
  const radius = 55;
  const circumference = 2 * Math.PI * radius; // ~345.57
  const strokeDashoffset = circumference - (circumference * confidence) / 100;

  // Determine colors based on verdict
  const getVerdictTheme = () => {
    switch (verdict.toUpperCase()) {
      case "MALWARE":
        return {
          color: "stroke-red-500",
          glow: "shadow-[0_0_15px_rgba(239,68,68,0.4)]",
          border: "border-red-500/30",
          bg: "bg-red-500/10",
          text: "text-red-400",
          icon: ShieldX,
        };
      case "SUSPICIOUS APK":
      case "SUSPICIOUS":
        return {
          color: "stroke-amber-500",
          glow: "shadow-[0_0_15px_rgba(245,158,11,0.4)]",
          border: "border-amber-500/30",
          bg: "bg-amber-500/10",
          text: "text-amber-400",
          icon: ShieldAlert,
        };
      default:
        return {
          color: "stroke-emerald-500",
          glow: "shadow-[0_0_15px_rgba(16,185,129,0.4)]",
          border: "border-emerald-500/30",
          bg: "bg-emerald-500/10",
          text: "text-emerald-400",
          icon: Shield,
        };
    }
  };

  const theme = getVerdictTheme();
  const Icon = theme.icon;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full">
      {/* Integrated Verdict & Heuristics Card */}
      <div className={`p-6 rounded-2xl bg-slate-900/60 border ${theme.border} flex flex-col justify-between relative overflow-hidden shadow-lg`}>
        {/* Glow backdrop */}
        <div className={`absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-20 pointer-events-none -mr-10 -mt-10 ${theme.bg}`} />

        <div>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">
            Security Verdict Engine
          </h3>
          <div className="flex items-center gap-3 mb-6">
            <div className={`p-3.5 rounded-xl border ${theme.border} ${theme.bg} ${theme.text} shadow-md`}>
              <Icon className="w-7 h-7" />
            </div>
            <div>
              <p className="text-xs text-slate-400 font-medium">Integrated Status</p>
              <h2 className={`text-2xl font-black ${theme.text} tracking-tight`}>
                {verdict}
              </h2>
            </div>
          </div>

          <div className="mb-4">
            <div className="flex justify-between items-center text-xs font-semibold text-slate-300 mb-1.5">
              <span>Heuristic Risk Index</span>
              <span>{score}/100</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden border border-slate-700">
              <motion.div
                className={`h-full rounded-full ${
                  score >= 70 ? "bg-red-500" : score >= 40 ? "bg-amber-500" : "bg-emerald-500"
                }`}
                initial={{ width: "0%" }}
                animate={{ width: `${score}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-bold font-mono text-slate-400 mt-2">
          <span>RISK SEVERITY ASSIGNED:</span>
          <span className={`px-2.5 py-0.5 rounded-full border text-[10px] ${theme.border} ${theme.bg} ${theme.text}`}>
            {severity}
          </span>
        </div>
      </div>

      {/* Machine Learning Gauges Card */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col items-center justify-center shadow-lg relative">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 w-full text-left">
          XGBoost Classifier
        </h3>

        <div className="relative flex items-center justify-center w-[150px] h-[150px]">
          {/* Radial Track Background */}
          <svg className="w-full h-full transform -rotate-90">
            <circle
              cx="75"
              cy="75"
              r={radius}
              stroke="#1e293b"
              strokeWidth="10"
              fill="transparent"
            />
            {/* Target Dial Progress */}
            <motion.circle
              cx="75"
              cy="75"
              r={radius}
              className={`${theme.color}`}
              strokeWidth="10"
              fill="transparent"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              strokeLinecap="round"
            />
          </svg>

          {/* Central Percentage */}
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className="text-2xl font-black text-slate-100 tracking-tight">
              {confidence.toFixed(1)}%
            </span>
            <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider mt-0.5">
              {mlPrediction}
            </span>
          </div>
        </div>

        <div className="w-full flex justify-between gap-4 mt-4 pt-4 border-t border-slate-800 text-xs font-mono text-slate-400">
          <div className="flex flex-col items-center flex-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Benign Prob</span>
            <span className="text-emerald-400 font-extrabold mt-1">{benignProb.toFixed(1)}%</span>
          </div>
          <div className="w-[1px] bg-slate-800 self-stretch" />
          <div className="flex flex-col items-center flex-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Malware Prob</span>
            <span className="text-red-400 font-extrabold mt-1">{malwareProb.toFixed(1)}%</span>
          </div>
        </div>
      </div>
    </div>
  );
}
