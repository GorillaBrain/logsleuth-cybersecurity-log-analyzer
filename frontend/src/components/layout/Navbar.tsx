import React from 'react';
import {
  Shield,
  Layers,
  AlertTriangle,
  FileText,
  BookOpen,
  Upload,
  RotateCcw,
  Cpu,
  Lock,
  Activity,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

export type NavTab = 'dashboard' | 'events' | 'findings' | 'iocs' | 'rules' | 'reports';

interface NavbarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenIngest: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab, onOpenIngest }) => {
  const { analysis, engineMode, setEngineMode, backendAvailable, clearAnalysis } = useAnalysis();

  const navItems: Array<{ id: NavTab; label: string; icon: React.ReactNode; badge?: number }> = [
    { id: 'dashboard', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
    {
      id: 'events',
      label: 'Event Explorer',
      icon: <Layers className="w-4 h-4" />,
      badge: analysis?.summary.total_events,
    },
    {
      id: 'findings',
      label: 'Findings',
      icon: <AlertTriangle className="w-4 h-4" />,
      badge: analysis?.summary.total_findings,
    },
    {
      id: 'iocs',
      label: 'IOC Explorer',
      icon: <Shield className="w-4 h-4" />,
      badge: analysis?.iocs.length,
    },
    { id: 'rules', label: 'Detection Rules', icon: <BookOpen className="w-4 h-4" /> },
    { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
  ];

  return (
    <header className="sticky top-0 z-40 bg-navy-950/90 backdrop-blur-md border-b border-navy-800 shadow-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-teal-500 flex items-center justify-center text-navy-950 shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 fill-navy-950" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-gray-100 text-base tracking-tight">LogSleuth</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold">
                  v1.0.0
                </span>
              </div>
              <p className="text-[10px] font-mono text-gray-400 hidden sm:block">
                Defensive Log Analyzer & Investigation
              </p>
            </div>
          </div>

          {/* Center Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-navy-800 text-cyan-400 font-semibold shadow-inner'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-navy-900'
                  }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                        item.id === 'findings'
                          ? 'bg-red-500/20 text-red-400'
                          : 'bg-navy-950 text-cyan-400 border border-navy-700'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Action Tools */}
          <div className="flex items-center gap-2.5">
            {/* Dual Engine Badge / Selector */}
            <div
              title={
                backendAvailable
                  ? 'Click to toggle between Python FastAPI backend and Client-Side zero-leak engine'
                  : 'Running client-side in browser memory with zero cloud network leakage'
              }
              onClick={() => {
                if (backendAvailable) {
                  setEngineMode(engineMode === 'python' ? 'client' : 'python');
                }
              }}
              className={`hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-mono border transition-all ${
                backendAvailable
                  ? 'cursor-pointer bg-navy-900 border-navy-700 hover:border-cyan-500/50'
                  : 'bg-teal-950/40 border-teal-500/30 text-teal-300'
              }`}
            >
              {engineMode === 'python' && backendAvailable ? (
                <>
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-gray-300 font-semibold">Engine: Python FastAPI</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5 text-teal-400" />
                  <span className="text-teal-200">Local Browser Engine</span>
                  <span className="text-[10px] text-teal-400 font-bold px-1 rounded bg-teal-500/10">Zero-Leak</span>
                </>
              )}
            </div>

            {/* Ingest Button */}
            <button
              onClick={onOpenIngest}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-navy-950 font-bold rounded-lg text-xs transition-all shadow-md shadow-cyan-900/30"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Ingest Logs</span>
            </button>

            {/* Clear Button */}
            {analysis && (
              <button
                onClick={clearAnalysis}
                className="p-1.5 text-gray-400 hover:text-gray-200 rounded-lg hover:bg-navy-900 transition-colors border border-navy-800"
                title="Clear current analysis"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Mobile Subnavigation Tabs */}
        <div className="flex md:hidden overflow-x-auto py-2 border-t border-navy-800 gap-1 text-xs">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] whitespace-nowrap ${
                currentTab === item.id
                  ? 'bg-navy-800 text-cyan-400 font-bold'
                  : 'text-gray-400'
              }`}
            >
              {item.label}
              {item.badge !== undefined && item.badge > 0 && (
                <span className="text-[9px] font-mono px-1 rounded bg-navy-950 text-cyan-400">
                  {item.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
};
