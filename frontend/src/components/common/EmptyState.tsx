import React from 'react';
import { ShieldAlert, Play, Upload } from 'lucide-react';
import { SAMPLE_DATASETS } from '../../services/sampleData';
import { useAnalysis } from '../../context/AnalysisContext';

interface EmptyStateProps {
  onOpenIngest: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ onOpenIngest }) => {
  const { loadSample, isLoading } = useAnalysis();

  return (
    <div className="flex flex-col items-center justify-center p-12 text-center max-w-2xl mx-auto my-12 border border-navy-700/60 bg-navy-900/60 rounded-xl backdrop-blur-sm shadow-xl">
      <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mb-6 text-cyan-400">
        <ShieldAlert className="w-8 h-8" />
      </div>

      <h2 className="text-2xl font-bold text-gray-100 mb-2">No Active Log Analysis</h2>
      <p className="text-gray-400 mb-8 text-sm leading-relaxed max-w-lg">
        LogSleuth processes security logs entirely inside your browser by default with zero data leaks.
        Upload a supported log file, paste raw events, or launch an interactive synthetic scenario below.
      </p>

      <div className="flex flex-wrap items-center justify-center gap-3 mb-8">
        <button
          onClick={onOpenIngest}
          className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-navy-950 font-semibold rounded-lg text-sm transition-all shadow-lg shadow-cyan-900/20"
        >
          <Upload className="w-4 h-4" />
          Ingest Logs / Upload File
        </button>
      </div>

      <div className="w-full border-t border-navy-800 pt-6">
        <span className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-4 block">
          Or Quick-Load Synthetic SOC Datasets
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
          {SAMPLE_DATASETS.map((sample) => (
            <button
              key={sample.id}
              disabled={isLoading}
              onClick={() => void loadSample(sample.id)}
              className="group p-3 rounded-lg border border-navy-800 hover:border-cyan-500/40 bg-navy-950/50 hover:bg-navy-800/50 transition-all text-xs flex flex-col justify-between"
            >
              <div>
                <div className="font-semibold text-gray-200 group-hover:text-cyan-400 flex items-center justify-between mb-1">
                  <span>{sample.name}</span>
                  <Play className="w-3.5 h-3.5 text-gray-500 group-hover:text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <p className="text-gray-400 line-clamp-2 text-[11px]">{sample.description}</p>
              </div>
              <div className="mt-2 text-[10px] font-mono text-cyan-500/80">
                {sample.format} • {sample.eventCount} lines
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
