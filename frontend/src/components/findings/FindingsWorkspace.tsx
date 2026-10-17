import React, { useState } from 'react';
import {
  ShieldAlert,
  ArrowRight,
  Download,
  CheckCircle,
  MessageSquare,
  Plus,
  Clock,
  Globe,
  User,
  ShieldCheck,
} from 'lucide-react';
import type { Finding, InvestigationStatus, Severity } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { useAnalysis } from '../../context/AnalysisContext';
import { exportFindingsToJSON } from '../../services/exportUtils';

interface FindingsWorkspaceProps {
  findings: Finding[];
  onFilterEventsByFinding: (eventIds: string[]) => void;
}

export const FindingsWorkspace: React.FC<FindingsWorkspaceProps> = ({
  findings,
  onFilterEventsByFinding,
}) => {
  const { updateFindingStatus, addAnalystNote } = useAnalysis();
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'all'>('all');
  const [noteInputs, setNoteInputs] = useState<Record<string, string>>({});
  const [expandedNotes, setExpandedNotes] = useState<Record<string, boolean>>({});

  const filteredFindings = findings.filter(f => {
    if (selectedSeverity !== 'all' && f.severity !== selectedSeverity) return false;
    return true;
  });

  const handleAddNote = (findingId: string) => {
    const text = noteInputs[findingId] || '';
    if (!text.trim()) return;
    addAnalystNote(findingId, text);
    setNoteInputs(prev => ({ ...prev, [findingId]: '' }));
    setExpandedNotes(prev => ({ ...prev, [findingId]: true }));
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Workspace Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-navy-900/90 border border-navy-700/80 rounded-xl shadow-md">
        <div>
          <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <span>Security Findings & Investigation Workspace</span>
          </h2>
          <p className="text-xs text-gray-400">
            Explainable rule-based security anomalies with analyst notes and triage workflows
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Severity filter chips */}
          <div className="flex items-center bg-navy-950 p-1 rounded-lg border border-navy-800 text-xs font-mono">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-md capitalize transition-all ${
                  selectedSeverity === sev
                    ? 'bg-cyan-600 text-navy-950 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <button
            onClick={() => exportFindingsToJSON(filteredFindings)}
            className="flex items-center gap-1.5 px-3 py-2 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="p-12 text-center bg-navy-900/60 border border-navy-800 rounded-xl">
          <ShieldCheck className="w-12 h-12 text-emerald-400/60 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-gray-200 mb-1">No Threat Findings</h3>
          <p className="text-xs text-gray-500">
            No events matched the detection rules for the selected severity level.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredFindings.map(finding => {
            const hasNotes = finding.analyst_notes.length > 0;
            const isNotesExpanded = expandedNotes[finding.id] ?? false;

            return (
              <div
                key={finding.id}
                className="bg-navy-900/90 border border-navy-700/80 rounded-xl p-5 shadow-lg space-y-4 transition-all"
              >
                {/* Header Row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-navy-800 pb-3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <SeverityBadge severity={finding.severity} />
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-navy-950 text-cyan-400 border border-navy-800">
                      {finding.rule_id}
                    </span>
                    {finding.mitre_technique && (
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                        MITRE {finding.mitre_technique}
                      </span>
                    )}
                    <span
                      className={`font-mono text-[11px] px-2 py-0.5 rounded border ${
                        finding.evidence_strength === 'Strong'
                          ? 'bg-red-500/10 text-red-400 border-red-500/20'
                          : finding.evidence_strength === 'Moderate'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                      }`}
                    >
                      {finding.evidence_strength} Evidence
                    </span>
                  </div>

                  {/* Status Dropdown */}
                  <div className="flex items-center gap-2">
                    <StatusBadge status={finding.investigation_status} size="sm" />
                    <select
                      value={finding.investigation_status}
                      onChange={(e) => updateFindingStatus(finding.id, e.target.value as InvestigationStatus)}
                      className="bg-navy-950 border border-navy-700 text-xs text-gray-200 rounded-lg px-2.5 py-1 focus:outline-none focus:border-cyan-500 font-mono"
                    >
                      <option value="new">New</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>
                </div>

                {/* Title & Description */}
                <div>
                  <h3 className="text-base font-bold text-gray-100 mb-1">{finding.title}</h3>
                  <p className="text-xs text-gray-300 font-mono mb-2">{finding.description}</p>
                  <p className="text-xs text-gray-400 leading-relaxed bg-navy-950/60 p-3 rounded-lg border border-navy-800/80">
                    {finding.explanation}
                  </p>
                </div>

                {/* Evidence Metadata Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  {finding.source_ips.length > 0 && (
                    <div className="p-2.5 bg-navy-950/60 border border-navy-800 rounded-lg">
                      <span className="text-[10px] text-gray-500 uppercase flex items-center gap-1 mb-1">
                        <Globe className="w-3 h-3 text-cyan-400" /> Source IPs
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {finding.source_ips.map(ip => (
                          <span key={ip} className="text-cyan-400 font-semibold">{ip}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {finding.usernames.length > 0 && (
                    <div className="p-2.5 bg-navy-950/60 border border-navy-800 rounded-lg">
                      <span className="text-[10px] text-gray-500 uppercase flex items-center gap-1 mb-1">
                        <User className="w-3 h-3 text-teal-400" /> Targeted Accounts
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {finding.usernames.map(u => (
                          <span key={u} className="text-gray-300 bg-navy-900 px-1.5 py-0.2 rounded border border-navy-700">{u}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="p-2.5 bg-navy-950/60 border border-navy-800 rounded-lg">
                    <span className="text-[10px] text-gray-500 uppercase flex items-center gap-1 mb-1">
                      <Clock className="w-3 h-3 text-purple-400" /> Activity Range
                    </span>
                    <span className="text-gray-300 text-[11px] block truncate">
                      {finding.first_seen ? `${new Date(finding.first_seen).toLocaleTimeString()} - ${new Date(finding.last_seen || finding.first_seen).toLocaleTimeString()}` : 'No timestamp'}
                    </span>
                  </div>
                </div>

                {/* Recommended Investigation Steps */}
                <div className="space-y-1.5">
                  <span className="text-xs font-mono font-semibold text-gray-300 flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-cyan-400" /> Recommended SOC Investigation Steps:
                  </span>
                  <ul className="space-y-1 bg-navy-950/40 p-3 rounded-lg border border-navy-800/80">
                    {finding.recommended_actions.map((action, i) => (
                      <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                        <span className="text-cyan-400 font-mono text-[11px] mt-0.5">•</span>
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Action Row & Analyst Notes Accordion */}
                <div className="border-t border-navy-800 pt-3 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                  <button
                    onClick={() => onFilterEventsByFinding(finding.event_ids)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600/10 hover:bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-mono transition-colors"
                  >
                    <span>View {finding.event_count} Supporting Events</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => setExpandedNotes(prev => ({ ...prev, [finding.id]: !isNotesExpanded }))}
                    className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors font-mono"
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    <span>
                      Analyst Notes ({finding.analyst_notes.length})
                    </span>
                  </button>
                </div>

                {/* Notes Expansion Box */}
                {isNotesExpanded && (
                  <div className="p-3 bg-navy-950 rounded-xl border border-navy-800 space-y-3">
                    {hasNotes && (
                      <div className="space-y-1.5">
                        {finding.analyst_notes.map((note, idx) => (
                          <div
                            key={idx}
                            className="text-xs font-mono text-gray-300 p-2 bg-navy-900 rounded border border-navy-800 flex items-start justify-between"
                          >
                            <span>{note}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="Add analyst observation or containment action..."
                        value={noteInputs[finding.id] || ''}
                        onChange={(e) => setNoteInputs(prev => ({ ...prev, [finding.id]: e.target.value }))}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleAddNote(finding.id);
                        }}
                        className="flex-1 bg-navy-900 border border-navy-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-500 font-mono"
                      />
                      <button
                        onClick={() => handleAddNote(finding.id)}
                        className="flex items-center gap-1 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-navy-950 font-bold rounded-lg text-xs transition-colors"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>Add</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
