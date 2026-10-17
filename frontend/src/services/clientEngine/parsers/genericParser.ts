import type { ParsedEvent, Severity } from '../../../types';
import { parseTimestamp } from '../timestampUtils';
import { extractIPv4 } from '../ipUtils';

export function parseGenericLine(line: string, lineNumber: number): ParsedEvent {
  const timestamp = parseTimestamp(line);
  const ips = extractIPv4(line);

  let severity: Severity = 'informational';
  const lower = line.toLowerCase();
  if (['critical', 'fatal', 'emergency', 'emerg'].some(k => lower.includes(k))) {
    severity = 'critical';
  } else if (['error', 'err', 'alert'].some(k => lower.includes(k))) {
    severity = 'medium';
  } else if (['warning', 'warn'].some(k => lower.includes(k))) {
    severity = 'low';
  }

  let eventAction: string | null = null;
  if (lower.includes('fail') || lower.includes('denied')) {
    eventAction = 'failure';
  } else if (lower.includes('success') || lower.includes('accepted')) {
    eventAction = 'success';
  }

  return {
    id: `generic-${lineNumber}-${Math.random().toString(36).substring(2, 9)}`,
    timestamp,
    raw_message: line,
    source_ip: ips[0] || null,
    event_category: 'unknown',
    event_action: eventAction,
    severity,
    is_suspicious: false,
    detection_ids: [],
    line_number: lineNumber,
  };
}
