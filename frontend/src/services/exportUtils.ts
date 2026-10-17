import type { ParsedEvent, Finding, IOC, AnalysisResult } from '../types';

export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Redact common secret patterns (passwords, tokens, keys)
export function redactSecrets(text: string): string {
  return text
    .replace(/(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*([^\s,;&"']+)/gi, '$1=[REDACTED]')
    .replace(/(bearer\s+)[a-zA-Z0-9_\-.]{16,}/gi, '$1[REDACTED]')
    .replace(/(basic\s+)[a-zA-Z0-9+/=]{16,}/gi, '$1[REDACTED]');
}

export function exportEventsToCSV(events: ParsedEvent[], redact = true): void {
  const headers = [
    'Line',
    'Timestamp',
    'Severity',
    'Category',
    'Action',
    'SourceIP',
    'Username',
    'HTTPMethod',
    'HTTPPath',
    'HTTPStatus',
    'Suspicious',
    'Detections',
    'Message',
  ];

  const escapeCSV = (val: unknown): string => {
    if (val === null || val === undefined) return '""';
    const str = redact ? redactSecrets(String(val)) : String(val);
    return `"${str.replace(/"/g, '""')}"`;
  };

  const rows = events.map(e => [
    e.line_number ?? '',
    e.timestamp ?? '',
    e.severity,
    e.event_category,
    e.event_action ?? '',
    e.source_ip ?? '',
    e.username ?? '',
    e.http_method ?? '',
    e.http_path ?? '',
    e.http_status ?? '',
    e.is_suspicious ? 'TRUE' : 'FALSE',
    e.detection_ids.join(';'),
    e.raw_message,
  ].map(escapeCSV).join(','));

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const filename = `logsleuth_events_${new Date().toISOString().slice(0, 10)}.csv`;
  downloadFile(csvContent, filename, 'text/csv;charset=utf-8;');
}

export function exportFindingsToJSON(findings: Finding[]): void {
  const jsonContent = JSON.stringify(findings, null, 2);
  const filename = `logsleuth_findings_${new Date().toISOString().slice(0, 10)}.json`;
  downloadFile(jsonContent, filename, 'application/json;charset=utf-8;');
}

export function exportIOCsToCSV(iocs: IOC[]): void {
  const headers = ['Type', 'Indicator', 'Count', 'PrivateIP', 'FirstSeen', 'LastSeen', 'Context'];
  const escapeCSV = (val: unknown) => `"${String(val ?? '').replace(/"/g, '""')}"`;

  const rows = iocs.map(i => [
    i.ioc_type,
    i.value,
    i.count,
    i.is_private ? 'YES' : 'NO',
    i.first_seen ?? '',
    i.last_seen ?? '',
    i.context,
  ].map(escapeCSV).join(','));

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const filename = `logsleuth_iocs_${new Date().toISOString().slice(0, 10)}.csv`;
  downloadFile(csvContent, filename, 'text/csv;charset=utf-8;');
}

export function exportIOCsToJSON(iocs: IOC[]): void {
  const jsonContent = JSON.stringify(iocs, null, 2);
  const filename = `logsleuth_iocs_${new Date().toISOString().slice(0, 10)}.json`;
  downloadFile(jsonContent, filename, 'application/json;charset=utf-8;');
}

export function exportFullAnalysisJSON(analysis: AnalysisResult, redact = true): void {
  const payload = redact
    ? {
        ...analysis,
        events: analysis.events.map(e => ({
          ...e,
          raw_message: redactSecrets(e.raw_message),
        })),
      }
    : analysis;

  const jsonContent = JSON.stringify(payload, null, 2);
  const filename = `logsleuth_full_analysis_${new Date().toISOString().slice(0, 10)}.json`;
  downloadFile(jsonContent, filename, 'application/json;charset=utf-8;');
}
