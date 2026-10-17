import type { AnalysisResult } from '../types';
import { analyzeLogsClient } from './clientEngine/analyzer';

const API_BASE = '/api';

export interface BackendHealth {
  status: string;
  version: string;
}

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(2000), // 2s quick ping
    });
    if (!res.ok) return false;
    const data = await res.json() as BackendHealth;
    return data.status === 'ok';
  } catch {
    return false;
  }
}

export async function analyzeLogsAPI(
  content: string,
  datasetName?: string | null,
  formatHint?: string | null,
  columnMapping?: Record<string, string>,
  preferBackend = false
): Promise<{ result: AnalysisResult; engineUsed: 'python' | 'client' }> {
  if (preferBackend) {
    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content,
          dataset_name: datasetName,
          format_hint: formatHint,
          column_mapping: columnMapping,
        }),
      });

      if (res.ok) {
        const result = await res.json() as AnalysisResult;
        return { result, engineUsed: 'python' };
      }
    } catch {
      console.warn('Backend unavailable, falling back to client-side engine.');
    }
  }

  // Fallback or explicit client-side execution (Zero-leak local privacy)
  const result = analyzeLogsClient(content, datasetName, formatHint, columnMapping);
  return { result, engineUsed: 'client' };
}
