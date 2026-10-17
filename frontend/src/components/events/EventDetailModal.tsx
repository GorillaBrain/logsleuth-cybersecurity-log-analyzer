import React, { useEffect } from 'react';
import { X, Copy, Check, ShieldAlert, Terminal, Globe, User, Server } from 'lucide-react';
import type { ParsedEvent } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';

interface EventDetailModalProps {
  event: ParsedEvent | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!event) return null;

  const handleCopyRaw = () => {
    void navigator.clipboard.writeText(event.raw_message);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-navy-900 border border-navy-700/80 rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-navy-800 flex items-center justify-between bg-navy-950/40">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={event.severity} />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-gray-200">
                  Line {event.line_number ?? 'N/A'} • Event Inspector
                </span>
                {event.is_suspicious && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/30 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" /> Flagged Suspicious
                  </span>
                )}
              </div>
              <span className="font-mono text-[11px] text-gray-500">ID: {event.id}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-200 hover:bg-navy-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1 text-xs">
          {/* Matched Detections Banner */}
          {event.detection_ids.length > 0 && (
            <div className="p-3.5 bg-red-950/20 border border-red-500/30 rounded-xl space-y-1">
              <span className="font-mono font-semibold text-red-400 text-xs flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" /> Triggered Detection Rules:
              </span>
              <div className="flex flex-wrap gap-2 pt-1">
                {event.detection_ids.map(rid => (
                  <span
                    key={rid}
                    className="px-2 py-1 bg-red-500/20 text-red-300 font-mono text-[11px] rounded border border-red-500/30 font-semibold"
                  >
                    {rid}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Primary Attributes Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
              <span className="text-[10px] font-mono text-gray-500 uppercase">Timestamp</span>
              <p className="font-mono text-gray-200 truncate">{event.timestamp || 'Not extracted'}</p>
            </div>

            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
              <span className="text-[10px] font-mono text-gray-500 uppercase flex items-center gap-1">
                <Globe className="w-3 h-3 text-cyan-400" /> Source IP
              </span>
              <p className="font-mono text-cyan-400 font-semibold truncate">{event.source_ip || 'None'}</p>
            </div>

            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
              <span className="text-[10px] font-mono text-gray-500 uppercase flex items-center gap-1">
                <User className="w-3 h-3 text-teal-400" /> Username
              </span>
              <p className="font-mono text-gray-200 truncate">{event.username || 'None'}</p>
            </div>

            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
              <span className="text-[10px] font-mono text-gray-500 uppercase">Category</span>
              <p className="font-mono text-gray-200 capitalize">{event.event_category}</p>
            </div>

            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
              <span className="text-[10px] font-mono text-gray-500 uppercase">Action</span>
              <p className="font-mono text-gray-200">{event.event_action || 'None'}</p>
            </div>

            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
              <span className="text-[10px] font-mono text-gray-500 uppercase flex items-center gap-1">
                <Server className="w-3 h-3 text-purple-400" /> Hostname / System
              </span>
              <p className="font-mono text-gray-200 truncate">{event.hostname || 'None'}</p>
            </div>
          </div>

          {/* Web Details if available */}
          {(event.http_method || event.http_path || event.http_status) && (
            <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-2">
              <span className="text-[10px] font-mono text-cyan-400 uppercase font-semibold">
                HTTP Request Telemetry
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
                <div>
                  <span className="text-gray-500 text-[10px] block">Method</span>
                  <span className="font-bold text-gray-200">{event.http_method || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-gray-500 text-[10px] block">Path</span>
                  <span className="text-gray-200 break-all">{event.http_path || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-gray-500 text-[10px] block">Response Code</span>
                  <span className={`font-bold ${event.http_status && event.http_status >= 400 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {event.http_status || 'N/A'}
                  </span>
                </div>
              </div>
              {event.http_user_agent && (
                <div className="pt-1 text-[11px] font-mono text-gray-400 border-t border-navy-900 break-all">
                  <span className="text-gray-500">User-Agent: </span>
                  {event.http_user_agent}
                </div>
              )}
            </div>
          )}

          {/* Raw Log Line */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-gray-500" /> Raw Log Message
              </span>
              <button
                onClick={handleCopyRaw}
                className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <pre className="p-3 bg-navy-950 border border-navy-800 rounded-xl font-mono text-xs text-gray-300 whitespace-pre-wrap break-all select-all leading-relaxed max-h-40 overflow-y-auto">
              {event.raw_message}
            </pre>
          </div>

          {/* Extra metadata if present */}
          {event.extra && Object.keys(event.extra).length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider text-gray-400">
                Additional Extracted Fields
              </span>
              <pre className="p-3 bg-navy-950 border border-navy-800 rounded-xl font-mono text-[11px] text-gray-400 max-h-32 overflow-y-auto">
                {JSON.stringify(event.extra, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
