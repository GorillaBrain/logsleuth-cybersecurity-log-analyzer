import type { ParseResult, ParsedEvent } from '../../../types';
import { parseAuthLogLine, canParseAuthLog } from './authLogParser';
import { parseApacheLogLine, canParseApacheLog } from './apacheParser';
import { parseSyslogLine, canParseSyslog } from './syslogParser';
import { parseJSONLLine, canParseJSONL } from './jsonlParser';
import { parseCSVLogs, canParseCSV } from './csvParser';
import { parseGenericLine } from './genericParser';

export function detectFormat(content: string): string {
  const sample = content.split('\n').slice(0, 30).join('\n');
  const scores: Record<string, number> = {
    auth_log: canParseAuthLog(sample),
    apache_access: canParseApacheLog(sample),
    jsonl: canParseJSONL(sample),
    csv: canParseCSV(sample),
    syslog: canParseSyslog(sample),
    generic: 0.1,
  };

  let bestFormat = 'generic';
  let bestScore = 0;
  for (const [fmt, score] of Object.entries(scores)) {
    if (score > bestScore) {
      bestScore = score;
      bestFormat = fmt;
    }
  }
  return bestFormat;
}

export function parseLogsClient(
  content: string,
  formatHint?: string | null,
  columnMapping?: Record<string, string>
): ParseResult {
  const format = formatHint || detectFormat(content);

  if (format === 'csv') {
    return parseCSVLogs(content, columnMapping);
  }

  const lines = content.split('\n');
  const events: ParsedEvent[] = [];
  const errors: { line: number; content: string; error: string }[] = [];
  let skipped = 0;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (!trimmed) {
      skipped++;
      continue;
    }

    try {
      let event: ParsedEvent | null = null;
      if (format === 'auth_log') {
        event = parseAuthLogLine(trimmed, i + 1);
      } else if (format === 'apache_access' || format === 'nginx_access') {
        event = parseApacheLogLine(trimmed, i + 1, format);
      } else if (format === 'jsonl') {
        event = parseJSONLLine(trimmed, i + 1);
      } else if (format === 'syslog') {
        event = parseSyslogLine(trimmed, i + 1);
      } else {
        event = parseGenericLine(trimmed, i + 1);
      }

      if (event) {
        events.push(event);
      } else {
        skipped++;
      }
    } catch (err) {
      errors.push({
        line: i + 1,
        content: trimmed.slice(0, 200),
        error: String(err),
      });
    }
  }

  return {
    events,
    total_lines: lines.length,
    parsed_count: events.length,
    skipped_count: skipped,
    error_count: errors.length,
    errors,
    format_detected: format,
  };
}
