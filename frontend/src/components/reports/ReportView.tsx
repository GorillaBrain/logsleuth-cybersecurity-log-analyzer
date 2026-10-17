import React, { useState } from 'react';
import {
  FileText,
  Printer,
  Download,
  AlertTriangle,
  Lock,
} from 'lucide-react';
import type { AnalysisResult } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import {
  exportFullAnalysisJSON,
  exportFindingsToJSON,
  exportIOCsToCSV,
  exportEventsToCSV,
} from '../../services/exportUtils';

interface ReportViewProps {
  analysis: AnalysisResult;
}

export const ReportView: React.FC<ReportViewProps> = ({ analysis }) => {
  const [redactSecrets, setRedactSecrets] = useState(true);

  const handlePrint = () => {
    window.print();
  };

  const { summary, parse_result, findings, iocs } = analysis;

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Action Bar (hidden during print) */}
      <div className="p-4 bg-navy-900/90 border border-navy-700/80 rounded-xl shadow-md flex flex-wrap items-center justify-between gap-4 print:hidden">
        <div>
          <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Investigation Report & Export Center</span>
          </h2>
          <p className="text-xs text-gray-400">
            Generate audit-ready SOC summaries and export sanitized threat telemetry
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Redaction toggle */}
          <label className="flex items-center gap-2 px-3 py-1.5 bg-navy-950 border border-navy-800 rounded-lg text-xs font-mono text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={redactSecrets}
              onChange={(e) => setRedactSecrets(e.target.checked)}
              className="accent-cyan-500"
            />
            <span className="flex items-center gap-1 text-cyan-400">
              <Lock className="w-3 h-3" /> Auto-Redact Secrets
            </span>
          </label>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-navy-950 rounded-lg text-xs font-bold transition-colors"
          >
            <Printer className="w-4 h-4" />
            <span>Print / Save PDF</span>
          </button>

          <button
            onClick={() => exportFullAnalysisJSON(analysis, redactSecrets)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Analysis JSON</span>
          </button>

          <button
            onClick={() => exportFindingsToJSON(findings)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Findings</span>
          </button>

          <button
            onClick={() => exportIOCsToCSV(iocs)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>IOCs CSV</span>
          </button>

          <button
            onClick={() => exportEventsToCSV(analysis.events, redactSecrets)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Events CSV</span>
          </button>
        </div>
      </div>

      {/* Printable Report Document */}
      <div className="bg-navy-900 border border-navy-700/80 rounded-2xl p-8 shadow-2xl space-y-6 text-gray-200 print:bg-white print:text-black print:border-none print:shadow-none print:p-0">
        {/* Document Header */}
        <div className="border-b border-navy-800 print:border-gray-300 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 print:text-blue-600 font-bold">
                LOGSLEUTH SECURITY INCIDENT REPORT
              </span>
            </div>
            <h1 className="text-2xl font-black text-gray-100 print:text-gray-900 tracking-tight">
              {analysis.dataset_name || 'Security Event Log Analysis'}
            </h1>
            <p className="text-xs text-gray-400 print:text-gray-600 font-mono mt-1">
              Analysis ID: {analysis.analysis_id}
            </p>
          </div>

          <div className="text-right font-mono text-xs text-gray-400 print:text-gray-600">
            <div>Generated: {new Date(analysis.analysis_timestamp).toUTCString()}</div>
            <div>Format: {parse_result.format_detected}</div>
            <div>Status: Completed</div>
          </div>
        </div>

        {/* Executive Summary Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3.5 bg-navy-950/60 print:bg-gray-100 rounded-xl border border-navy-800 print:border-gray-300">
            <span className="text-[10px] font-mono uppercase text-gray-500 block mb-1">Total Events</span>
            <span className="text-xl font-bold font-mono text-gray-100 print:text-black">{summary.total_events}</span>
          </div>

          <div className="p-3.5 bg-navy-950/60 print:bg-gray-100 rounded-xl border border-navy-800 print:border-gray-300">
            <span className="text-[10px] font-mono uppercase text-gray-500 block mb-1">Threat Findings</span>
            <span className="text-xl font-bold font-mono text-red-400 print:text-red-600">{summary.total_findings}</span>
          </div>

          <div className="p-3.5 bg-navy-950/60 print:bg-gray-100 rounded-xl border border-navy-800 print:border-gray-300">
            <span className="text-[10px] font-mono uppercase text-gray-500 block mb-1">Extracted IOCs</span>
            <span className="text-xl font-bold font-mono text-cyan-400 print:text-blue-600">{iocs.length}</span>
          </div>

          <div className="p-3.5 bg-navy-950/60 print:bg-gray-100 rounded-xl border border-navy-800 print:border-gray-300">
            <span className="text-[10px] font-mono uppercase text-gray-500 block mb-1">Failed Logins</span>
            <span className="text-xl font-bold font-mono text-orange-400 print:text-orange-600">{summary.auth_failed}</span>
          </div>
        </div>

        {/* Section: Threat Findings Detail */}
        <div className="space-y-4">
          <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-cyan-400 print:text-blue-600 border-b border-navy-800 print:border-gray-300 pb-2">
            Identified Security Findings ({findings.length})
          </h2>

          {findings.length === 0 ? (
            <div className="p-4 bg-navy-950/40 rounded-lg text-xs text-gray-400 font-mono">
              No threat detections triggered. Analyzed log entries appear consistent with normal operations.
            </div>
          ) : (
            <div className="space-y-4">
              {findings.map((finding, idx) => (
                <div
                  key={finding.id}
                  className="p-4 rounded-xl border border-navy-800 print:border-gray-300 bg-navy-950/40 print:bg-gray-50 space-y-2 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-gray-400 font-bold">#{idx + 1}</span>
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <span className="font-bold text-gray-200 print:text-black">{finding.title}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-gray-500">
                        Rule: {finding.rule_id}
                      </span>
                      <StatusBadge status={finding.investigation_status} size="sm" />
                    </div>
                  </div>

                  <p className="text-gray-300 print:text-gray-700 leading-relaxed">{finding.explanation}</p>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono text-gray-400 pt-1">
                    <div>
                      <span className="text-gray-500">Source IPs: </span>
                      <span className="text-gray-300 print:text-black">{finding.source_ips.join(', ') || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Target Accounts: </span>
                      <span className="text-gray-300 print:text-black">{finding.usernames.join(', ') || 'None'}</span>
                    </div>
                  </div>

                  {/* Analyst Notes if present */}
                  {finding.analyst_notes.length > 0 && (
                    <div className="mt-2 p-2 bg-navy-900 print:bg-white rounded border border-navy-800 print:border-gray-200 text-[11px] font-mono space-y-1">
                      <span className="font-semibold text-cyan-400 print:text-blue-600 block">Analyst Case Notes:</span>
                      {finding.analyst_notes.map((n, i) => (
                        <div key={i} className="text-gray-300 print:text-gray-800">{n}</div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section: Key Indicators of Compromise */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-cyan-400 print:text-blue-600 border-b border-navy-800 print:border-gray-300 pb-2">
            Top Observable Indicators ({Math.min(iocs.length, 10)})
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-gray-500 border-b border-navy-800 print:border-gray-300 text-[10px]">
                  <th className="py-2">Type</th>
                  <th className="py-2">Indicator</th>
                  <th className="py-2">Occurrences</th>
                  <th className="py-2">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-800/60 print:divide-gray-200">
                {iocs.slice(0, 10).map((ioc, i) => (
                  <tr key={i}>
                    <td className="py-2 uppercase text-[10px] text-gray-400">{ioc.ioc_type}</td>
                    <td className="py-2 text-gray-200 print:text-black">{ioc.value}</td>
                    <td className="py-2 text-gray-400">{ioc.count}</td>
                    <td className="py-2 text-gray-400">{ioc.is_private ? 'Internal/Private' : 'External'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section: Defensive Limitations & Disclaimers */}
        <div className="p-4 bg-navy-950/60 print:bg-gray-100 rounded-xl border border-navy-800 print:border-gray-300 text-xs space-y-2">
          <span className="font-bold font-mono text-gray-300 print:text-black uppercase text-[11px] flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Investigation Scope & Limitations
          </span>
          <p className="text-gray-400 print:text-gray-600 leading-relaxed text-[11px]">
            LogSleuth performs deterministic, rule-based log correlation. Detection rules indicate suspicious patterns rather than confirmed breaches.
            Findings must be corroborated with endpoint telemetry, active network captures, and identity provider logs before initiating destructive containment actions.
          </p>
        </div>
      </div>
    </div>
  );
};
