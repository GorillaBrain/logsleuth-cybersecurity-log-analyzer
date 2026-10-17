import type { ParsedEvent, Severity } from '../../../types';
import { parseTimestamp } from '../timestampUtils';
import { extractIPv4 } from '../ipUtils';

const SYSLOG_PREFIX = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/;

export function parseSyslogLine(line: string, lineNumber: number): ParsedEvent {
  const timestamp = parseTimestamp(line);
  const m = line.match(SYSLOG_PREFIX);

  const id = `syslog-${lineNumber}-${Math.random().toString(36).substring(2, 9)}`;

  if (!m) {
    const ips = extractIPv4(line);
    return {
      id,
      timestamp,
      raw_message: line,
      event_category: 'system',
      source_ip: ips[0] || null,
      severity: 'informational',
      is_suspicious: false,
      detection_ids: [],
      line_number: lineNumber,
    };
  }

  const hostname = m[2];
  const processName = m[3];
  const pid = m[4] ? parseInt(m[4], 10) : null;
  const message = m[5];

  const ips = extractIPv4(message);
  let severity: Severity = 'informational';
  let eventAction: string | null = null;
  const lower = message.toLowerCase();

  if (lower.includes('crit') || lower.includes('alert') || lower.includes('emerg')) {
    severity = 'high';
    eventAction = 'critical';
  } else if (lower.includes('error') || lower.includes('fail')) {
    severity = 'medium';
    eventAction = 'error';
  } else if (lower.includes('warn')) {
    severity = 'low';
    eventAction = 'warning';
  }

  return {
    id,
    timestamp,
    raw_message: line,
    hostname,
    process_name: processName,
    pid,
    event_category: 'system',
    event_action: eventAction,
    source_ip: ips[0] || null,
    severity,
    is_suspicious: false,
    detection_ids: [],
    line_number: lineNumber,
  };
}

export function canParseSyslog(sample: string): number {
  const lines = sample.split('\n').filter(l => l.trim()).slice(0, 20);
  if (!lines.length) return 0;
  const matches = lines.filter(l => SYSLOG_PREFIX.test(l)).length;
  return Math.min(matches / lines.length, 0.9);
}
