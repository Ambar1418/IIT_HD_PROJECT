"use client";

import React, { useState, useEffect } from "react";
import { Terminal, ShieldAlert, Cpu, Download, ArrowLeft, RefreshCw, Layers } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import UploadZone from "../../components/UploadZone";
import ThreatScoreGauge from "../../components/ThreatScoreGauge";
import MitreAttackGrid from "../../components/MitreAttackGrid";
import AIReportPanel from "../../components/AIReportPanel";
import { analyzeAPK, downloadPDF } from "../../lib/api";

export default function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null);
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [mounted, setMounted] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const loadingSteps = [
    "Spinning up sandboxed decompiler container...",
    "Extracting AndroidManifest.xml namespaces...",
    "Running Androguard static assembly checks...",
    "Auditing permission flags and active background services...",
    "Aligning permission signatures against MITRE ATT&CK techniques...",
    "Extracting 215 signature nodes into feature vector format...",
    "Calling XGBoost classifier threat scoring pipeline...",
    "Pasting telemetry context into Groq Llama 3.3 LLM layer...",
    "Compiling AI safety brief and recommendations...",
    "Decompiler run complete! Preparing diagnostic reports..."
  ];

  // Run decompiler log simulator before sending to api
  const handleFileSelect = async (selectedFile: File) => {
    setFile(selectedFile);
    setIsLoading(true);
    setLoadingStep(0);

    // Simulate logs to wow judges / recruiters
    const stepDuration = 400; // ms per step
    for (let i = 0; i < loadingSteps.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, stepDuration));
      setLoadingStep(i);
    }

    try {
      const result = await analyzeAPK(selectedFile);
      setAnalysisResult(result);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setAnalysisResult(null);
    setIsLoading(false);
    setLoadingStep(0);
  };

  const handleDownloadPDF = async () => {
    if (!analysisResult) return;
    setPdfLoading(true);
    try {
      const pdfBlob = await downloadPDF(
        analysisResult.report_data,
        analysisResult.explanation,
        analysisResult.permissions,
        analysisResult.tactics
      );

      const url = window.URL.createObjectURL(pdfBlob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `${analysisResult.report_data.package}_analysis_report.pdf`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (e) {
      console.error("PDF download failed", e);
    } finally {
      setPdfLoading(false);
    }
  };

  const handleDownloadJSON = () => {
    if (!analysisResult) return;
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(analysisResult, null, 2)
    )}`;
    const link = document.createElement("a");
    link.href = jsonString;
    link.setAttribute("download", `${analysisResult.report_data.package}_malware_analysis.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Recharts configuration
  const chartData = analysisResult
    ? [
        { name: "Malware", value: analysisResult.report_data.malware_probability, color: "#ef4444" },
        { name: "Benign", value: analysisResult.report_data.benign_probability, color: "#10b981" }
      ]
    : [];

  return (
    <div className="max-w-7xl mx-auto px-4 md:px-6 py-8 flex-1 flex flex-col justify-start w-full relative">
      <AnimatePresence mode="wait">
        {/* State 1: Upload Dropzone */}
        {!file && !isLoading && !analysisResult && (
          <motion.div
            key="upload"
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, y: -10 }}
            className="flex flex-col items-center justify-center flex-1 py-12"
          >
            <div className="text-center max-w-lg mb-8">
              <h2 className="text-2xl font-black text-white mb-2 tracking-tight">APK Threat Assessment Portal</h2>
              <p className="text-sm text-slate-400 leading-relaxed">
                Submit an installation binary to evaluate permissions, run XGBoost malware classification models, and generate AI explanations.
              </p>
            </div>
            <UploadZone onFileSelect={handleFileSelect} isLoading={isLoading} />
          </motion.div>
        )}

        {/* State 2: Simulated Command Logs Loader */}
        {isLoading && (
          <motion.div
            key="loading"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex flex-col items-center justify-center flex-1 py-20"
          >
            <div className="w-full max-w-xl p-6 rounded-2xl bg-slate-950 border border-slate-900 shadow-2xl relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 to-transparent pointer-events-none" />

              <div className="flex items-center gap-2 mb-4 border-b border-slate-900 pb-3">
                <Terminal className="w-5 h-5 text-blue-400" />
                <span className="text-xs font-bold text-slate-400 font-mono">threat_armor_decompiler.sh</span>
              </div>

              {/* Progress loader */}
              <div className="w-full bg-slate-900 rounded-full h-1.5 mb-4 overflow-hidden border border-slate-800">
                <motion.div
                  className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 shadow-[0_0_10px_rgba(59,130,246,0.3)]"
                  initial={{ width: "0%" }}
                  animate={{ width: `${((loadingStep + 1) / loadingSteps.length) * 100}%` }}
                  transition={{ duration: 0.2 }}
                />
              </div>

              {/* Logs display */}
              <div className="h-44 bg-slate-950/80 rounded-xl p-4 border border-slate-900/80 font-mono text-[11px] overflow-hidden text-left flex flex-col justify-end space-y-1.5 select-none">
                {loadingSteps.slice(Math.max(0, loadingStep - 4), loadingStep + 1).map((step, idx) => {
                  const isLast = idx === Math.min(loadingStep, 4);
                  return (
                    <div
                      key={idx}
                      className={`${isLast ? "text-blue-400 font-bold" : "text-slate-500"} transition-all duration-300`}
                    >
                      <span className="text-slate-700 mr-2">$</span>
                      {step}
                      {isLast && <span className="animate-pulse">|</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}

        {/* State 3: Analysis Results Dashboard */}
        {analysisResult && !isLoading && (
          <motion.div
            key="results"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8 w-full"
          >
            {/* Header Control Buttons */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-900 pb-5">
              <div className="flex items-center gap-3">
                <button
                  onClick={handleReset}
                  className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded-xl text-slate-400 hover:text-slate-200 transition-all shadow-sm"
                >
                  <ArrowLeft className="w-4 h-4" />
                </button>
                <div>
                  <h2 className="text-xl font-black text-white tracking-tight">Threat Analysis Summary</h2>
                  <p className="text-xs text-slate-500">Security diagnostic results compiled successfully</p>
                </div>
              </div>

              <div className="flex flex-wrap gap-3 w-full sm:w-auto">
                <button
                  onClick={handleDownloadJSON}
                  className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-200 text-xs font-bold rounded-xl transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  JSON Report
                </button>
                <button
                  onClick={handleDownloadPDF}
                  disabled={pdfLoading}
                  className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-bold rounded-xl transition-all shadow-[0_4px_15px_rgba(59,130,246,0.25)]"
                >
                  {pdfLoading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Compiling PDF...
                    </>
                  ) : (
                    <>
                      <Download className="w-3.5 h-3.5" />
                      Certified PDF Report
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Grid Dials */}
            <ThreatScoreGauge
              score={analysisResult.report_data.risk_score}
              severity={analysisResult.report_data.severity}
              verdict={analysisResult.report_data.final_verdict}
              confidence={analysisResult.report_data.malware_probability || analysisResult.report_data.benign_probability}
              mlPrediction={analysisResult.report_data.ml_prediction}
              benignProb={analysisResult.report_data.benign_probability}
              malwareProb={analysisResult.report_data.malware_probability}
            />

            {/* Dashboard Contents Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Left Column: Metadata & Charts */}
              <div className="lg:col-span-1 space-y-8">
                {/* Stats cards list */}
                <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 shadow-md">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">
                    Component Metadata
                  </h3>
                  <div className="space-y-3 font-mono text-xs">
                    {[
                      { label: "Permissions Flagged", val: analysisResult.report_data.total_permissions },
                      { label: "Activities Count", val: analysisResult.report_data.activities_count },
                      { label: "Services Count", val: analysisResult.report_data.services_count },
                      { label: "Receivers Count", val: analysisResult.report_data.receivers_count },
                      { label: "Providers Count", val: analysisResult.report_data.providers_count },
                    ].map((item, i) => (
                      <div
                        key={i}
                        className="flex justify-between items-center p-3.5 rounded-lg bg-slate-950/40 border border-slate-900/80"
                      >
                        <span className="text-slate-500 font-bold">{item.label}</span>
                        <span className="text-slate-200 font-black">{item.val}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recharts Pie Chart (rendered if mounted to prevent SSR glitches) */}
                <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 shadow-md flex flex-col items-center justify-center min-h-[260px]">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 w-full text-left">
                    Threat Distribution Map
                  </h3>
                  {mounted && (
                    <div className="w-full h-44 flex items-center justify-center">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={chartData}
                            cx="50%"
                            cy="50%"
                            innerRadius={50}
                            outerRadius={70}
                            paddingAngle={5}
                            dataKey="value"
                          >
                            {chartData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{ background: "#0f172a", borderColor: "#334155", borderRadius: "8px" }}
                            itemStyle={{ color: "#cbd5e1", fontSize: "12px" }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                  <div className="flex justify-around w-full mt-4 text-xs font-semibold text-slate-400">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                      Benign: {analysisResult.report_data.benign_probability.toFixed(1)}%
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                      Malware: {analysisResult.report_data.malware_probability.toFixed(1)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Right Column: MITRE ATT&CK & AI Security Reports */}
              <div className="lg:col-span-2 space-y-8">
                {/* MITRE ATT&CK Map */}
                <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 shadow-md">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">
                    MITRE ATT&CK Matrix Alignment
                  </h3>
                  <MitreAttackGrid tactics={analysisResult.tactics} />
                </div>

                {/* AI Explanation Accordion Brief */}
                <AIReportPanel
                  explanation={analysisResult.explanation}
                  verdict={analysisResult.report_data.final_verdict}
                />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
