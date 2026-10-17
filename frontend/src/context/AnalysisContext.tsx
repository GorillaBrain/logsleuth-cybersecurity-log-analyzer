import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type {
  AnalysisResult,
  Finding,
  InvestigationStatus,
  EventFilterState,
} from '../types';
import { SAMPLE_DATASETS } from '../services/sampleData';
import { analyzeLogsAPI, checkBackendHealth } from '../services/apiClient';
import { analyzeLogsClient } from '../services/clientEngine/analyzer';

const LOCAL_STORAGE_KEY_NOTES = 'logsleuth_analyst_notes_v1';
const LOCAL_STORAGE_KEY_STATUS = 'logsleuth_finding_statuses_v1';

interface AnalysisContextType {
  analysis: AnalysisResult | null;
  isLoading: boolean;
  error: string | null;
  engineMode: 'client' | 'python';
  setEngineMode: (mode: 'client' | 'python') => void;
  backendAvailable: boolean;
  findings: Finding[];
  filterState: EventFilterState;
  setFilterState: React.Dispatch<React.SetStateAction<EventFilterState>>;
  analyze: (content: string, datasetName?: string, formatHint?: string, mapping?: Record<string, string>) => Promise<void>;
  loadSample: (sampleId: string) => Promise<void>;
  updateFindingStatus: (findingId: string, status: InvestigationStatus) => void;
  addAnalystNote: (findingId: string, note: string) => void;
  clearAnalysis: () => void;
  refreshBackendStatus: () => Promise<void>;
}

const defaultFilterState: EventFilterState = {
  search: '',
  severity: 'all',
  category: 'all',
  sourceIp: '',
  username: '',
  httpStatus: '',
  suspiciousOnly: false,
};

const AnalysisContext = createContext<AnalysisContextType | undefined>(undefined);

export const AnalysisProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [engineMode, setEngineMode] = useState<'client' | 'python'>('client');
  const [backendAvailable, setBackendAvailable] = useState<boolean>(false);
  const [filterState, setFilterState] = useState<EventFilterState>(defaultFilterState);

  const refreshBackendStatus = useCallback(async () => {
    const isUp = await checkBackendHealth();
    setBackendAvailable(isUp);
  }, []);

  useEffect(() => {
    void refreshBackendStatus();
    const interval = setInterval(() => {
      void refreshBackendStatus();
    }, 15000);
    return () => clearInterval(interval);
  }, [refreshBackendStatus]);

  // Load saved notes & statuses from local storage
  const applyStoredAnnotations = useCallback((loadedFindings: Finding[]): Finding[] => {
    try {
      const storedNotes = JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY_NOTES) || '{}') as Record<string, string[]>;
      const storedStatus = JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY_STATUS) || '{}') as Record<string, InvestigationStatus>;

      return loadedFindings.map(f => ({
        ...f,
        investigation_status: storedStatus[f.id] || f.investigation_status,
        analyst_notes: storedNotes[f.id] || f.analyst_notes,
      }));
    } catch {
      return loadedFindings;
    }
  }, []);

  const analyze = useCallback(async (
    content: string,
    datasetName = 'Custom Analysis',
    formatHint?: string,
    mapping?: Record<string, string>
  ) => {
    setIsLoading(true);
    setError(null);
    try {
      const preferBackend = engineMode === 'python' && backendAvailable;
      const { result, engineUsed } = await analyzeLogsAPI(
        content,
        datasetName,
        formatHint,
        mapping,
        preferBackend
      );

      const annotatedFindings = applyStoredAnnotations(result.findings);
      setAnalysis({ ...result, findings: annotatedFindings });
      setFindings(annotatedFindings);
      if (engineUsed !== engineMode) {
        setEngineMode(engineUsed);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsLoading(false);
    }
  }, [engineMode, backendAvailable, applyStoredAnnotations]);

  const loadSample = useCallback(async (sampleId: string) => {
    const sample = SAMPLE_DATASETS.find(s => s.id === sampleId);
    if (!sample) return;
    await analyze(sample.content, sample.name, sample.format);
  }, [analyze]);

  // Initialize with SSH Brute-Force sample on first load
  useEffect(() => {
    if (!analysis && !isLoading) {
      const initial = SAMPLE_DATASETS.find(s => s.id === 'auth_bruteforce');
      if (initial) {
        const res = analyzeLogsClient(initial.content, initial.name, initial.format);
        const annotated = applyStoredAnnotations(res.findings);
        setAnalysis({ ...res, findings: annotated });
        setFindings(annotated);
      }
    }
  }, [analysis, isLoading, applyStoredAnnotations]);

  const updateFindingStatus = useCallback((findingId: string, status: InvestigationStatus) => {
    setFindings(prev => {
      const updated = prev.map(f => f.id === findingId ? { ...f, investigation_status: status } : f);
      try {
        const stored = JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY_STATUS) || '{}') as Record<string, InvestigationStatus>;
        stored[findingId] = status;
        localStorage.setItem(LOCAL_STORAGE_KEY_STATUS, JSON.stringify(stored));
      } catch {
        // ignore storage errors
      }
      return updated;
    });

    setAnalysis(prev => prev ? {
      ...prev,
      findings: prev.findings.map(f => f.id === findingId ? { ...f, investigation_status: status } : f)
    } : null);
  }, []);

  const addAnalystNote = useCallback((findingId: string, note: string) => {
    if (!note.trim()) return;
    const formattedNote = `[${new Date().toLocaleTimeString()}] ${note.trim()}`;

    setFindings(prev => {
      const updated = prev.map(f => {
        if (f.id === findingId) {
          const notes = [...f.analyst_notes, formattedNote];
          try {
            const stored = JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY_NOTES) || '{}') as Record<string, string[]>;
            stored[findingId] = notes;
            localStorage.setItem(LOCAL_STORAGE_KEY_NOTES, JSON.stringify(stored));
          } catch {
            // ignore
          }
          return { ...f, analyst_notes: notes };
        }
        return f;
      });
      return updated;
    });

    setAnalysis(prev => prev ? {
      ...prev,
      findings: prev.findings.map(f => f.id === findingId ? {
        ...f,
        analyst_notes: [...f.analyst_notes, formattedNote]
      } : f)
    } : null);
  }, []);

  const clearAnalysis = useCallback(() => {
    setAnalysis(null);
    setFindings([]);
    setError(null);
    setFilterState(defaultFilterState);
  }, []);

  return (
    <AnalysisContext.Provider
      value={{
        analysis,
        isLoading,
        error,
        engineMode,
        setEngineMode,
        backendAvailable,
        findings,
        filterState,
        setFilterState,
        analyze,
        loadSample,
        updateFindingStatus,
        addAnalystNote,
        clearAnalysis,
        refreshBackendStatus,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
};

export function useAnalysis(): AnalysisContextType {
  const context = useContext(AnalysisContext);
  if (!context) {
    throw new Error('useAnalysis must be used within an AnalysisProvider');
  }
  return context;
}
