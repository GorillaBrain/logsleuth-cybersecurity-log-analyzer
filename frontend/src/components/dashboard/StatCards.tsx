import { Activity, CheckCircle2, Layers, ShieldAlert } from 'lucide-react';
import type { AnalysisResult } from '../../types';

interface StatCardsProps {
  analysis: AnalysisResult;
  onNavigateFindings: () => void;
  onNavigateEvents: () => void;
}

export const StatCards: React.FC<StatCardsProps> = ({
  analysis,
  onNavigateFindings,
  onNavigateEvents,
}) => {
  const { summary, parse_result } = analysis;
  const criticalCount = summary.severity_counts['critical'] || 0;
  const highCount = summary.severity_counts['high'] || 0;
  const mediumCount = summary.severity_counts['medium'] || 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* 1. Total Events */}
      <div
        onClick={onNavigateEvents}
        className="cursor-pointer group p-5 bg-navy-900/80 border border-navy-700/80 hover:border-cyan-500/50 rounded-xl transition-all shadow-md relative overflow-hidden"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-mono uppercase tracking-wider text-gray-400">Total Events</span>
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 group-hover:scale-110 transition-transform">
            <Activity className="w-4 h-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-gray-100">{summary.total_events}</span>
          <span className="text-xs text-gray-400">parsed lines</span>
        </div>
        <div className="mt-3 flex items-center justify-between text-[11px] text-gray-400 border-t border-navy-800 pt-2 font-mono">
          <span>Format: {parse_result.format_detected || 'generic'}</span>
          <span>{summary.suspicious_events} flagged</span>
        </div>
      </div>

      {/* 2. Suspicious Findings */}
      <div
        onClick={onNavigateFindings}
        className="cursor-pointer group p-5 bg-navy-900/80 border border-navy-700/80 hover:border-red-500/50 rounded-xl transition-all shadow-md relative overflow-hidden"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-mono uppercase tracking-wider text-gray-400">Threat Findings</span>
          <div className="p-2 rounded-lg bg-red-500/10 text-red-400 group-hover:scale-110 transition-transform">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-gray-100">{summary.total_findings}</span>
          <span className="text-xs text-gray-400">rules triggered</span>
        </div>
        <div className="mt-3 flex items-center gap-2 text-[11px] font-mono border-t border-navy-800 pt-2">
          {criticalCount > 0 && (
            <span className="text-red-400 font-semibold">{criticalCount} Critical</span>
          )}
          {highCount > 0 && (
            <span className="text-orange-400 font-semibold">{highCount} High</span>
          )}
          {mediumCount > 0 && (
            <span className="text-amber-400">{mediumCount} Med</span>
          )}
          {criticalCount === 0 && highCount === 0 && mediumCount === 0 && (
            <span className="text-emerald-400">Clean baseline</span>
          )}
        </div>
      </div>

      {/* 3. Authentication Posture */}
      <div className="p-5 bg-navy-900/80 border border-navy-700/80 rounded-xl shadow-md">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-mono uppercase tracking-wider text-gray-400">Authentication</span>
          <div className="p-2 rounded-lg bg-teal-500/10 text-teal-400">
            <CheckCircle2 className="w-4 h-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-3">
          <div className="flex items-center gap-1.5">
            <span className="text-xl font-bold font-mono text-emerald-400">{summary.auth_success}</span>
            <span className="text-[11px] text-gray-400">OK</span>
          </div>
          <span className="text-gray-600">/</span>
          <div className="flex items-center gap-1.5">
            <span className="text-xl font-bold font-mono text-red-400">{summary.auth_failed}</span>
            <span className="text-[11px] text-gray-400">Failed</span>
          </div>
        </div>
        <div className="mt-3 text-[11px] text-gray-400 border-t border-navy-800 pt-2 flex justify-between font-mono">
          <span>Targeted Accts:</span>
          <span className="text-gray-200">{summary.top_usernames.length}</span>
        </div>
      </div>

      {/* 4. Parsing Quality */}
      <div className="p-5 bg-navy-900/80 border border-navy-700/80 rounded-xl shadow-md">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-mono uppercase tracking-wider text-gray-400">Parsing Health</span>
          <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
            <Layers className="w-4 h-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-gray-100">
            {summary.parse_stats.total_lines > 0
              ? `${Math.round((summary.parse_stats.parsed / summary.parse_stats.total_lines) * 100)}%`
              : '100%'}
          </span>
          <span className="text-xs text-emerald-400">normalized</span>
        </div>
        <div className="mt-3 flex items-center justify-between text-[11px] text-gray-400 border-t border-navy-800 pt-2 font-mono">
          <span>Errors: {summary.parse_stats.errors}</span>
          <span>Skipped: {summary.parse_stats.skipped}</span>
        </div>
      </div>
    </div>
  );
};
