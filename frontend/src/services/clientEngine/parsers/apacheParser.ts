import type { ParsedEvent, Severity } from '../../../types';
import { parseTimestamp } from '../timestampUtils';

// Combined log format:
// 192.168.1.1 - user [10/Oct/2026:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326 "referer" "user-agent"
const APACHE_COMBINED = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s*(\S*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

export function parseApacheLogLine(line: string, lineNumber: number, formatName = 'apache_access'): ParsedEvent | null {
  const m = line.match(APACHE_COMBINED);
  if (!m) return null;

  const ip = m[1];
  const user = m[3] !== '-' ? m[3] : null;
  const tsStr = m[4];
  const method = m[5];
  const path = m[6];
  const status = parseInt(m[8], 10);
  const size = m[9];
  const referer = m[10] && m[10] !== '-' ? m[10] : null;
  const userAgent = m[11] || null;

  const timestamp = parseTimestamp(tsStr);

  let severity: Severity = 'informational';
  if (status === 401 || status === 403) {
    severity = 'low';
  } else if (status >= 500) {
    severity = 'medium';
  }

  let eventAction = `http_${method.toLowerCase()}`;
  if (status === 401) eventAction = 'http_unauthorized';
  else if (status === 403) eventAction = 'http_forbidden';
  else if (status === 404) eventAction = 'http_not_found';

  return {
    id: `${formatName}-${lineNumber}-${Math.random().toString(36).substring(2, 9)}`,
    timestamp,
    raw_message: line,
    source_ip: ip,
    username: user,
    event_category: 'web_access',
    event_action: eventAction,
    http_method: method,
    http_path: path,
    http_status: status,
    http_user_agent: userAgent,
    severity,
    is_suspicious: false,
    detection_ids: [],
    extra: {
      referer,
      response_size: size !== '-' ? parseInt(size, 10) : undefined
    },
    line_number: lineNumber,
  };
}

export function canParseApacheLog(sample: string): number {
  const lines = sample.split('\n').filter(l => l.trim()).slice(0, 20);
  if (!lines.length) return 0;
  const matches = lines.filter(l => APACHE_COMBINED.test(l)).length;
  return Math.min(matches / lines.length, 1.0);
}
