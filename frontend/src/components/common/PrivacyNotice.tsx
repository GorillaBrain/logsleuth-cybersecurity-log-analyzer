import React from 'react';
import { Lock, ShieldCheck, CheckCircle2 } from 'lucide-react';

export const PrivacyNotice: React.FC = () => {
  return (
    <div className="p-4 rounded-xl border border-teal-500/20 bg-teal-950/20 text-xs text-teal-300 flex items-start gap-3">
      <ShieldCheck className="w-5 h-5 text-teal-400 shrink-0 mt-0.5" />
      <div>
        <div className="font-semibold text-teal-200 mb-1 flex items-center gap-1.5">
          <Lock className="w-3.5 h-3.5" />
          Zero-Trust Client-Side Privacy Guarantee
        </div>
        <p className="text-teal-300/80 leading-relaxed mb-2">
          Your security logs, IP addresses, credentials, and internal hostnames are parsed and analyzed entirely within your browser memory.
          No log data, file contents, or indicators are sent to third-party clouds or external AI models.
        </p>
        <div className="flex flex-wrap gap-4 text-[11px] text-teal-400/90 font-mono">
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-teal-400" /> No cloud log storage
          </span>
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-teal-400" /> Offline functional
          </span>
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-teal-400" /> Export sanitization options
          </span>
        </div>
      </div>
    </div>
  );
};
