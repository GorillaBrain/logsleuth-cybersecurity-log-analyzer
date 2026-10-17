import type { ParsedEvent, Severity, ParseResult } from '../../../types';
import { parseTimestamp } from '../timestampUtils';

// Simple CSV parser respecting quoted commas
function parseCSVLine(line: string): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      values.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  values.push(current.trim());
  return values;
}

const TIMESTAMP_HEADERS = ['timestamp', 'time', 'datetime', 'date', '@timestamp', 'eventtime', 'ts', 'created'];
const SOURCE_IP_HEADERS = ['source_ip', 'src_ip', 'sourceip', 'remote_addr', 'clientip', 'client_ip', 'ip', 'ipaddress', 'src'];
const USERNAME_HEADERS = ['username', 'user', 'account', 'login', 'uid', 'targetusername', 'subjectusername'];
const MESSAGE_HEADERS = ['message', 'msg', 'log', 'description', 'text', 'event_message'];
const SEVERITY_HEADERS = ['severity', 'level', 'priority', 'log_level'];
const STATUS_HEADERS = ['status', 'status_code', 'statuscode', 'http_status', 'response_code'];
const HOSTNAME_HEADERS = ['hostname', 'host', 'computer', 'source'];

export function parseCSVLogs(content: string, customMapping: Record<string, string> = {}): ParseResult {
  const lines = content.split('\n').filter(l => l.trim());
  if (lines.length < 2) {
    return {
      events: [],
      total_lines: lines.length,
      parsed_count: 0,
      skipped_count: lines.length,
      error_count: 0,
      errors: [],
      format_detected: 'csv',
    };
  }

  const headers = parseCSVLine(lines[0]).map(h => h.replace(/^["']|["']$/g, '').trim());
  const headerMap = new Map<string, number>();
  headers.forEach((h, i) => headerMap.set(h.toLowerCase(), i));

  // Resolve mapping
  const mapping: Record<string, number> = {};

  const findCol = (field: string, candidates: string[]) => {
    if (customMapping[field] && headerMap.has(customMapping[field].toLowerCase())) {
      mapping[field] = headerMap.get(customMapping[field].toLowerCase())!;
      return;
    }
    for (const c of candidates) {
      if (headerMap.has(c)) {
        mapping[field] = headerMap.get(c)!;
        return;
      }
    }
  };

  findCol('timestamp', TIMESTAMP_HEADERS);
  findCol('source_ip', SOURCE_IP_HEADERS);
  findCol('username', USERNAME_HEADERS);
  findCol('message', MESSAGE_HEADERS);
  findCol('severity', SEVERITY_HEADERS);
  findCol('status', STATUS_HEADERS);
  findCol('hostname', HOSTNAME_HEADERS);

  const events: ParsedEvent[] = [];
  const errors: { line: number; content: string; error: string }[] = [];
  let skipped = 0;

  for (let i = 1; i < lines.length; i++) {
    const rawLine = lines[i];
    try {
      const values = parseCSVLine(rawLine);
      if (values.length < 2) {
        skipped++;
        continue;
      }

      const getVal = (field: string): string | null => {
        const idx = mapping[field];
        return idx !== undefined && values[idx] ? values[idx].replace(/^["']|["']$/g, '').trim() : null;
      };

      const tsVal = getVal('timestamp');
      const timestamp = tsVal ? parseTimestamp(tsVal) : null;
      const sourceIp = getVal('source_ip');
      const username = getVal('username');
      const msgVal = getVal('message') || rawLine;
      const hostVal = getVal('hostname');
      const statusStr = getVal('status');
      const status = statusStr ? parseInt(statusStr, 10) : null;

      const sevStr = getVal('severity')?.toLowerCase();
      let severity: Severity = 'informational';
      if (sevStr) {
        if (['crit', 'critical', 'fatal', 'emerg'].some(k => sevStr.includes(k))) severity = 'critical';
        else if (['high', 'alert', 'err', 'error'].some(k => sevStr.includes(k))) severity = 'medium';
        else if (['warn', 'warning', 'low'].some(k => sevStr.includes(k))) severity = 'low';
      }

      events.push({
        id: `csv-${i}-${Math.random().toString(36).substring(2, 9)}`,
        timestamp,
        raw_message: msgVal,
        source_ip: sourceIp,
        username,
        hostname: hostVal,
        event_category: 'unknown',
        http_status: isNaN(status ?? NaN) ? null : status,
        severity,
        is_suspicious: false,
        detection_ids: [],
        line_number: i + 1,
      });
    } catch (err) {
      errors.push({
        line: i + 1,
        content: rawLine.slice(0, 200),
        error: String(err),
      });
    }
  }

  return {
    events,
    total_lines: lines.length - 1,
    parsed_count: events.length,
    skipped_count: skipped,
    error_count: errors.length,
    errors,
    format_detected: 'csv',
  };
}

export function canParseCSV(sample: string): number {
  const lines = sample.split('\n').filter(l => l.trim()).slice(0, 5);
  if (lines.length < 2) return 0;
  if (lines[0].includes(',') && lines.slice(1).every(l => l.includes(','))) {
    return 0.6;
  }
  return 0;
}
