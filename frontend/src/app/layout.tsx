import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Android APK Malware Analyzer",
  description: "AI-Powered Multi-Layer Threat Classification and Heuristic Detection Platform",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased min-h-screen flex flex-col">
        {/* Navigation Header */}
        <header className="sticky top-0 z-50 w-full border-b border-slate-900 bg-slate-950/70 backdrop-blur-md">
          <div className="max-w-7xl mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
            <a href="/" className="flex items-center gap-2 font-black tracking-tight text-white hover:opacity-90 transition-opacity">
              <span className="text-xl">🛡️</span>
              <span className="text-sm md:text-base bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
                APK Threat Armor
              </span>
            </a>
            <div className="flex items-center gap-4 text-xs font-bold text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                SYSTEM RUNNING
              </span>
              <a
                href="https://github.com/Ambar1418/IIT_HD_PROJECT"
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 hover:text-slate-200 transition-all"
              >
                GitHub Source
              </a>
            </div>
          </div>
        </header>

        {/* Dynamic Page content */}
        <main className="flex-1 flex flex-col">{children}</main>

        {/* Footer */}
        <footer className="border-t border-slate-900 bg-slate-950/60 py-6 text-center text-xs text-slate-600 font-medium">
          <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
            <p>© 2026 Android APK Malware Analyzer. All Rights Reserved.</p>
            <p>Trained on Drebin Dataset (98.6% Accuracy) • Llama 3.3 Security Intelligence</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
