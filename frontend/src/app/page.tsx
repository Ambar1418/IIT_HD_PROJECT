"use client";

import React from "react";
import { Shield, ShieldAlert, Cpu, FileText, CheckSquare, Zap, Terminal } from "lucide-react";
import { motion, Variants } from "framer-motion";

export default function LandingPage() {
  const containerVariants: Variants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15,
      },
    },
  };

  const itemVariants: Variants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: "easeOut" as any } },
  };

  return (
    <div className="relative w-full flex-1 flex flex-col justify-between cyber-grid overflow-hidden">
      {/* Decorative backdrop bubbles */}
      <div className="absolute top-1/4 left-1/4 w-[400px] h-[400px] rounded-full bg-blue-600/5 ambient-glow -translate-x-1/2 -translate-y-1/2" />
      <div className="absolute bottom-1/4 right-1/4 w-[450px] h-[450px] rounded-full bg-indigo-600/5 ambient-glow translate-x-1/2 translate-y-1/2" />

      {/* Hero Section */}
      <section className="max-w-7xl mx-auto px-4 md:px-6 pt-16 md:pt-24 pb-12 flex flex-col items-center text-center relative z-10">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6 }}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-900/80 border border-slate-800 rounded-full text-xs font-bold text-slate-400 mb-6 shadow-md"
        >
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          <span>CYBERSECURITY INTELLIGENCE ENGINE v2.0</span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight text-white max-w-4xl leading-tight"
        >
          Android APK{" "}
          <span className="bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent">
            Malware Analyzer
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-base sm:text-lg md:text-xl text-slate-400 font-medium max-w-2xl mt-6 leading-relaxed"
        >
          An AI-powered multi-layer threat classification platform combining static analysis, XGBoost machine learning, MITRE ATT&CK mappings, and Llama 3.3 security explanations.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="flex flex-col sm:flex-row gap-4 mt-10 w-full sm:w-auto"
        >
          <a
            href="/analyze"
            className="px-8 py-3.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold rounded-xl text-sm transition-all shadow-[0_4px_20px_rgba(59,130,246,0.35)] hover:shadow-[0_4px_25px_rgba(59,130,246,0.5)] flex items-center justify-center gap-2 group"
          >
            Start Diagnostics
            <span className="group-hover:translate-x-1 transition-transform">→</span>
          </a>
          <a
            href="#architecture"
            className="px-8 py-3.5 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 font-bold rounded-xl text-sm transition-all flex items-center justify-center"
          >
            View Engine Pipeline
          </a>
        </motion.div>
      </section>

      {/* Feature Cards Grid */}
      <section className="max-w-7xl mx-auto px-4 md:px-6 py-16 relative z-10 w-full">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-100px" }}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {[
            {
              title: "Static Manifest Decompiler",
              desc: "Dynamic in-memory parsing of APK resources, activities, and permissions utilizing Androguard.",
              icon: Terminal,
              color: "text-blue-400 border-blue-500/20 bg-blue-500/5",
            },
            {
              title: "Heuristic Risk Scoring",
              desc: "Multi-tier priority weights combined with dangerous permission combination triggers.",
              icon: ShieldAlert,
              color: "text-amber-400 border-amber-500/20 bg-amber-500/5",
            },
            {
              title: "MITRE ATT&CK Matrix Map",
              desc: "Aligns app capabilities directly to standard corporate adversary tactics and techniques.",
              icon: CheckSquare,
              color: "text-purple-400 border-purple-500/20 bg-purple-500/5",
            },
            {
              title: "XGBoost Machine Learning",
              desc: "Supervised classification engine trained on 15,036 Drebin samples yielding 98.6% accuracy.",
              icon: Cpu,
              color: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
            },
            {
              title: "Groq Llama 3.3 Security Explainer",
              desc: "Cognitive AI explanation layer mapping threat vectors, corporate business impact, and recommendations.",
              icon: Zap,
              color: "text-indigo-400 border-indigo-500/20 bg-indigo-500/5",
            },
            {
              title: "Certified PDF Exporter",
              desc: "Generates in-memory corporate-ready PDF diagnostic reports secure for compliance audit logging.",
              icon: FileText,
              color: "text-slate-400 border-slate-700/40 bg-slate-900/20",
            },
          ].map((feat, idx) => {
            const Icon = feat.icon;
            return (
              <motion.div
                key={idx}
                variants={itemVariants}
                className={`glass-container p-6 rounded-2xl border flex flex-col justify-between hover:scale-[1.02] transition-all duration-300 shadow-md ${feat.color}`}
              >
                <div>
                  <div className="p-3 bg-slate-950/60 rounded-xl w-fit border border-slate-800/80 mb-4 shadow-sm">
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="text-base font-bold text-slate-100 mb-2">{feat.title}</h3>
                  <p className="text-xs md:text-sm text-slate-400 leading-relaxed">{feat.desc}</p>
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      </section>

      {/* Visual Pipeline Section */}
      <section id="architecture" className="max-w-7xl mx-auto px-4 md:px-6 py-20 border-t border-slate-900/60 relative z-10 w-full text-center">
        <h2 className="text-2xl font-black text-slate-200 mb-4 tracking-tight">
          System Execution Pipeline
        </h2>
        <p className="text-sm text-slate-400 max-w-lg mx-auto mb-12 leading-relaxed">
          How our analyzer decompiles, classifies, maps, and explains threats:
        </p>

        {/* Visual Pipeline flow */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 max-w-6xl mx-auto text-center items-center justify-center font-bold font-mono text-[10px] md:text-xs">
          {[
            "Android APK",
            "Manifest Decompile",
            "Static Audit",
            "Heuristic scoring",
            "MITRE Map",
            "XGBoost Prediction",
            "Groq AI explanation",
            "Integrated Verdict",
          ].map((step, idx) => (
            <React.Fragment key={idx}>
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 shadow-md hover:border-slate-700 transition-colors flex flex-col items-center justify-center min-h-[70px]">
                <span className="text-slate-500 mb-1">0{idx + 1}</span>
                <span className="text-center leading-snug">{step}</span>
              </div>
              {idx < 7 && (
                <div className="hidden lg:flex justify-center text-slate-600 font-bold text-base select-none">
                  →
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </section>
    </div>
  );
}
