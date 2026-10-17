import React, { useState, useRef } from 'react';
import { X, Upload, FileText, Play, AlertCircle, Database, Check } from 'lucide-react';
import { SAMPLE_DATASETS } from '../../services/sampleData';
import { useAnalysis } from '../../context/AnalysisContext';
import { CSVColumnMapper } from './CSVColumnMapper';

interface LogIngestionModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LogIngestionModal: React.FC<LogIngestionModalProps> = ({ isOpen, onClose }) => {
  const { analyze, loadSample, isLoading } = useAnalysis();
  const [activeTab, setActiveTab] = useState<'upload' | 'paste' | 'samples'>('upload');
  const [rawText, setRawText] = useState('');
  const [datasetName, setDatasetName] = useState('');
  const [formatHint, setFormatHint] = useState<string>('auto');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // CSV mapping state
  const [csvHeaders, setCsvHeaders] = useState<string[] | null>(null);
  const [csvContent, setCsvContent] = useState<string | null>(null);
  const [customMapping, setCustomMapping] = useState<Record<string, string>>({});

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileProcess = (file: File) => {
    setErrorMsg(null);
    if (file.size > 15 * 1024 * 1024) {
      setErrorMsg('File exceeds 15MB limit. Please provide a smaller log slice for browser performance.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content || !content.trim()) {
        setErrorMsg('The selected file is empty.');
        return;
      }

      setDatasetName(file.name);

      // Check if it's CSV
      const isCsv = file.name.endsWith('.csv') || formatHint === 'csv';
      if (isCsv) {
        const firstLine = content.split('\n')[0];
        const headers = firstLine.split(',').map(h => h.replace(/^["']|["']$/g, '').trim());
        if (headers.length >= 2) {
          setCsvHeaders(headers);
          setCsvContent(content);
          return;
        }
      }

      void analyze(content, file.name, formatHint === 'auto' ? undefined : formatHint);
      onClose();
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read the selected file.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handlePasteSubmit = () => {
    if (!rawText.trim()) {
      setErrorMsg('Please paste some log lines to analyze.');
      return;
    }
    setErrorMsg(null);
    const name = datasetName.trim() || 'Pasted Log Extract';
    void analyze(rawText, name, formatHint === 'auto' ? undefined : formatHint);
    onClose();
  };

  const handleApplyCsvMapping = (mapping: Record<string, string>) => {
    if (csvContent) {
      setCustomMapping(mapping);
      void analyze(csvContent, datasetName || 'CSV Log Export', 'csv', mapping);
      setCsvHeaders(null);
      setCsvContent(null);
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-navy-900 border border-navy-700/80 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-navy-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-lg">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-gray-100">Ingest Security Logs</h2>
              <p className="text-xs text-gray-400">All analysis runs locally in your browser with zero data leakage</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 p-1.5 rounded-lg hover:bg-navy-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-navy-800 bg-navy-950/60 px-6">
          <button
            onClick={() => { setActiveTab('upload'); setCsvHeaders(null); }}
            className={`py-3 px-4 text-xs font-medium border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'upload'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            <Upload className="w-4 h-4" />
            File Upload
          </button>
          <button
            onClick={() => { setActiveTab('paste'); setCsvHeaders(null); }}
            className={`py-3 px-4 text-xs font-medium border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'paste'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            <FileText className="w-4 h-4" />
            Paste Logs
          </button>
          <button
            onClick={() => { setActiveTab('samples'); setCsvHeaders(null); }}
            className={`py-3 px-4 text-xs font-medium border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'samples'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            <Database className="w-4 h-4" />
            Synthetic Datasets
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {errorMsg && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Format Selector */}
          {activeTab !== 'samples' && !csvHeaders && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pb-2">
              <div>
                <label className="block text-[11px] font-mono text-gray-400 mb-1">Dataset Name (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g., Incident-2026-auth.log"
                  value={datasetName}
                  onChange={(e) => setDatasetName(e.target.value)}
                  className="w-full bg-navy-950 border border-navy-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-mono text-gray-400 mb-1">Log Format</label>
                <select
                  value={formatHint}
                  onChange={(e) => setFormatHint(e.target.value)}
                  className="w-full bg-navy-950 border border-navy-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="auto">Auto-Detect Format</option>
                  <option value="auth_log">Linux Auth / SSH Log</option>
                  <option value="apache_access">Apache Combined Access Log</option>
                  <option value="nginx_access">Nginx Access Log</option>
                  <option value="jsonl">JSON Lines (JSONL)</option>
                  <option value="csv">CSV (Comma-Separated)</option>
                  <option value="syslog">Syslog (RFC 3164/5424)</option>
                  <option value="generic">Generic Text Log</option>
                </select>
              </div>
            </div>
          )}

          {/* CSV Mapper if CSV triggered */}
          {csvHeaders ? (
            <CSVColumnMapper
              headers={csvHeaders}
              initialMapping={customMapping}
              onApply={handleApplyCsvMapping}
              onCancel={() => { setCsvHeaders(null); setCsvContent(null); }}
            />
          ) : (
            <>
              {/* Tab 1: Upload */}
              {activeTab === 'upload' && (
                <div
                  onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                    isDragging
                      ? 'border-cyan-400 bg-cyan-500/5'
                      : 'border-navy-700 hover:border-cyan-500/50 bg-navy-950/40'
                  }`}
                >
                  <input
                    type="file"
                    ref={fileInputRef}
                    className="hidden"
                    accept=".log,.txt,.csv,.json,.jsonl"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        handleFileProcess(e.target.files[0]);
                      }
                    }}
                  />
                  <div className="w-12 h-12 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center mx-auto mb-3">
                    <Upload className="w-6 h-6" />
                  </div>
                  <p className="text-sm font-semibold text-gray-200 mb-1">
                    Drag and drop log file here, or browse
                  </p>
                  <p className="text-xs text-gray-400 mb-3">
                    Supports .log, .txt, .csv, .jsonl, .json (max 15MB)
                  </p>
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-md">
                    <Check className="w-3 h-3" /> Zero server uploads — 100% in-browser processing
                  </span>
                </div>
              )}

              {/* Tab 2: Paste */}
              {activeTab === 'paste' && (
                <div className="space-y-3">
                  <textarea
                    rows={10}
                    value={rawText}
                    onChange={(e) => setRawText(e.target.value)}
                    placeholder="Paste raw log lines here...&#10;Oct 15 09:00:02 webserver01 sshd[1234]: Failed password for root from 198.51.100.23 port 41234 ssh2&#10;Oct 15 09:00:15 webserver01 sshd[1235]: Failed password for admin from 198.51.100.23 port 41236 ssh2..."
                    className="w-full bg-navy-950 border border-navy-700 rounded-xl p-3 text-xs font-mono text-gray-200 focus:outline-none focus:border-cyan-500 resize-none"
                  />
                  <div className="flex justify-between items-center text-xs text-gray-400">
                    <span>{rawText.split('\n').filter(l => l.trim()).length} lines detected</span>
                    <button
                      onClick={handlePasteSubmit}
                      disabled={isLoading || !rawText.trim()}
                      className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-navy-950 font-semibold rounded-lg text-xs transition-colors"
                    >
                      {isLoading ? 'Analyzing...' : 'Analyze Log Lines'}
                    </button>
                  </div>
                </div>
              )}

              {/* Tab 3: Samples */}
              {activeTab === 'samples' && (
                <div className="grid grid-cols-1 gap-2.5">
                  {SAMPLE_DATASETS.map((sample) => (
                    <div
                      key={sample.id}
                      className="p-3.5 rounded-xl border border-navy-700 bg-navy-950/60 hover:border-cyan-500/40 transition-all flex items-start justify-between gap-4"
                    >
                      <div>
                        <div className="font-semibold text-gray-200 text-xs flex items-center gap-2 mb-1">
                          <span>{sample.name}</span>
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-navy-800 text-cyan-400">
                            {sample.format}
                          </span>
                        </div>
                        <p className="text-gray-400 text-xs leading-relaxed">{sample.description}</p>
                      </div>
                      <button
                        onClick={() => {
                          void loadSample(sample.id);
                          onClose();
                        }}
                        disabled={isLoading}
                        className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-cyan-500 hover:text-navy-950 text-cyan-400 rounded-lg text-xs font-medium transition-all"
                      >
                        <Play className="w-3.5 h-3.5" />
                        <span>Load</span>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
