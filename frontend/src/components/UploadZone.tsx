"use client";

import React, { useState, useRef } from "react";
import { Upload, FileText, AlertCircle, CheckCircle2, ShieldAlert } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface UploadZoneProps {
  onFileSelect: (file: File) => void;
  isLoading: boolean;
}

export default function UploadZone({ onFileSelect, isLoading }: UploadZoneProps) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): boolean => {
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "apk" && ext !== "json") {
      setError("Unsupported file type. Please upload a .apk or .json manifest file.");
      setSelectedFile(null);
      return false;
    }
    setError(null);
    return true;
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const simulateProgress = (file: File) => {
    setSelectedFile(file);
    setUploadProgress(0);
    const interval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          onFileSelect(file);
          return 100;
        }
        return prev + 10;
      });
    }, 150);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (validateFile(file)) {
        simulateProgress(file);
      }
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (validateFile(file)) {
        simulateProgress(file);
      }
    }
  };

  const onButtonClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        onClick={onButtonClick}
        className={`relative border-2 border-dashed rounded-2xl p-10 flex flex-col items-center justify-center cursor-pointer transition-all duration-300 min-h-[300px] overflow-hidden ${
          dragActive
            ? "border-blue-500 bg-blue-500/10 shadow-[0_0_20px_rgba(59,130,246,0.3)]"
            : "border-slate-700 bg-slate-900/40 hover:border-slate-500 hover:bg-slate-900/60"
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept=".apk,.json"
          onChange={handleChange}
        />

        {/* Ambient decorative grid behind dropzone */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:24px_24px] opacity-10 pointer-events-none" />

        <AnimatePresence mode="wait">
          {!selectedFile && !error && (
            <motion.div
              key="prompt"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex flex-col items-center text-center z-10"
            >
              <div className="p-4 bg-slate-800/80 rounded-full border border-slate-700 mb-4 shadow-lg group-hover:scale-110 transition-transform">
                <Upload className="w-8 h-8 text-blue-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-100 mb-2">
                Upload Android Package
              </h3>
              <p className="text-sm text-slate-400 max-w-sm mb-4">
                Drag and drop your <span className="text-blue-400 font-semibold">.apk</span> binary or <span className="text-blue-400 font-semibold">.json</span> manifest file here to trigger analysis.
              </p>
              <span className="text-xs bg-slate-800 border border-slate-700 text-slate-400 px-3 py-1.5 rounded-full font-mono">
                MAX FILE SIZE: 50MB
              </span>
            </motion.div>
          )}

          {error && (
            <motion.div
              key="error"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center text-center z-10"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="p-4 bg-red-950/40 rounded-full border border-red-500/30 mb-4 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)] animate-pulse">
                <AlertCircle className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-bold text-red-400 mb-2">File Rejected</h3>
              <p className="text-sm text-slate-400 max-w-xs mb-4">{error}</p>
              <button
                onClick={() => setError(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-all"
              >
                Clear Error
              </button>
            </motion.div>
          )}

          {selectedFile && !error && (
            <motion.div
              key="uploading"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="w-full max-w-md z-10 flex flex-col items-center"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center gap-3 w-full bg-slate-800/80 border border-slate-700 rounded-xl p-4 mb-4 shadow-lg">
                <div className="p-3 bg-blue-950/50 border border-blue-500/30 rounded-lg text-blue-400">
                  <FileText className="w-6 h-6" />
                </div>
                <div className="flex-1 text-left min-w-0">
                  <p className="text-sm font-bold text-slate-200 truncate">
                    {selectedFile.name}
                  </p>
                  <p className="text-xs text-slate-400">
                    {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                  </p>
                </div>
                {uploadProgress === 100 ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <span className="text-xs font-mono text-blue-400 font-bold">
                    {uploadProgress}%
                  </span>
                )}
              </div>

              {/* Progress Slider */}
              <div className="w-full bg-slate-800 rounded-full h-2 mb-4 overflow-hidden border border-slate-700">
                <motion.div
                  className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 shadow-[0_0_10px_rgba(59,130,246,0.5)]"
                  initial={{ width: "0%" }}
                  animate={{ width: `${uploadProgress}%` }}
                  transition={{ duration: 0.1 }}
                />
              </div>

              {isLoading && uploadProgress === 100 && (
                <div className="flex items-center gap-2 text-blue-400 text-xs font-mono font-bold animate-pulse">
                  <ShieldAlert className="w-4 h-4" />
                  RUNNING STATIC & ML CLASSIFIERS...
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
