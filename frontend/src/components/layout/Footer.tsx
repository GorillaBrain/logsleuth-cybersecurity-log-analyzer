import React from 'react';
import { Shield, Lock } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="mt-16 border-t border-navy-800/80 bg-navy-950/60 py-8 text-xs text-gray-500 font-mono print:hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-gray-300 font-semibold font-sans">LogSleuth — Cybersecurity Log Analyzer</span>
          <span>•</span>
          <span className="text-gray-400">Defensive Portfolio Project</span>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <span className="flex items-center gap-1 text-teal-400">
            <Lock className="w-3 h-3" /> 100% Client-Side Privacy
          </span>
          <span className="text-gray-600">|</span>
          <span>FastAPI • React 19 • TypeScript • Tailwind CSS</span>
          <span className="text-gray-600">|</span>
          <a
            href="https://github.com/GorillaBrain/logsleuth-cybersecurity-log-analyzer"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 text-gray-400 hover:text-cyan-400 transition-colors"
          >
            <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            <span>GitHub</span>
          </a>
        </div>
      </div>
    </footer>
  );
};
