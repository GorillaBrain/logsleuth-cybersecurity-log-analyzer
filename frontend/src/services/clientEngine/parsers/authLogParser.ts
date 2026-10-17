import type { ParsedEvent, Severity } from '../../../types';
import { parseTimestamp } from '../timestampUtils';
import { extractIPv4 } from '../ipUtils';

const SSH_FAILED = /Failed\s+(password|publickey)\s+for\s+(invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/i;
const SSH_ACCEPTED = /Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/i;
const SSH_INVALID_USER = /Invalid\s+user\s+(\S+)\s+from\s+(\S+)/i;
const SUDO_PATTERN = /(\S+)\s*:.*COMMAND=(.*)/i;
const SESSION_PATTERN = /session\s+(opened|closed)\s+for\s+user\s+(\S+)/i;
const SYSLOG_PREFIX = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/;

export function parseAuthLogLine(line: string, lineNumber: number): ParsedEvent | null {
  const timestamp = parseTimestamp(line);
  const prefixMatch = line.match(SYSLOG_PREFIX);

  let hostname: string | null = null;
  let processName: string | null = null;
  let pid: number | null = null;
  let message = line;

  if (prefixMatch) {
    hostname = prefixMatch[2];
    processName = prefixMatch[3];
    pid = prefixMatch[4] ? parseInt(prefixMatch[4], 10) : null;
    message = prefixMatch[5];
  }

  const id = `auth-${lineNumber}-${Math.random().toString(36).substring(2, 9)}`;

  // Failed login
  const failMatch = line.match(SSH_FAILED);
  if (failMatch) {
    const isInvalid = Boolean(failMatch[2]);
    return {
      id,
      timestamp,
      raw_message: line,
      hostname,
      process_name: processName,
      pid,
      event_category: 'authentication',
      event_action: isInvalid ? 'login_failed_invalid_user' : 'login_failed',
      username: failMatch[3],
      source_ip: failMatch[4],
      severity: (isInvalid ? 'medium' : 'low') as Severity,
      is_suspicious: false,
      detection_ids: [],
      line_number: lineNumber,
    };
  }

  // Accepted login
  const acceptMatch = line.match(SSH_ACCEPTED);
  if (acceptMatch) {
    return {
      id,
      timestamp,
      raw_message: line,
      hostname,
      process_name: processName,
      pid,
      event_category: 'authentication',
      event_action: 'login_success',
      username: acceptMatch[2],
      source_ip: acceptMatch[3],
      severity: 'informational',
      is_suspicious: false,
      detection_ids: [],
      line_number: lineNumber,
    };
  }

  // Invalid user
  const invalidMatch = line.match(SSH_INVALID_USER);
  if (invalidMatch) {
    return {
      id,
      timestamp,
      raw_message: line,
      hostname,
      process_name: processName,
      pid,
      event_category: 'authentication',
      event_action: 'invalid_user',
      username: invalidMatch[1],
      source_ip: invalidMatch[2],
      severity: 'low',
      is_suspicious: false,
      detection_ids: [],
      line_number: lineNumber,
    };
  }

  // Sudo
  const sudoMatch = message.match(SUDO_PATTERN);
  if (sudoMatch) {
    const ips = extractIPv4(line);
    return {
      id,
      timestamp,
      raw_message: line,
      hostname,
      process_name: processName,
      pid,
      event_category: 'authorization',
      event_action: 'sudo_command',
      username: sudoMatch[1],
      source_ip: ips[0] || null,
      severity: 'informational',
      is_suspicious: false,
      detection_ids: [],
      extra: { command: sudoMatch[2].trim() },
      line_number: lineNumber,
    };
  }

  // Session
  const sessionMatch = line.match(SESSION_PATTERN);
  if (sessionMatch) {
    const ips = extractIPv4(line);
    return {
      id,
      timestamp,
      raw_message: line,
      hostname,
      process_name: processName,
      pid,
      event_category: 'authentication',
      event_action: `session_${sessionMatch[1].toLowerCase()}`,
      username: sessionMatch[2],
      source_ip: ips[0] || null,
      severity: 'informational',
      is_suspicious: false,
      detection_ids: [],
      line_number: lineNumber,
    };
  }

  // Generic fallback within auth
  const ips = extractIPv4(line);
  let severity: Severity = 'informational';
  let eventAction: string | null = null;
  const lower = message.toLowerCase();

  if (lower.includes('fail') || lower.includes('denied') || lower.includes('error')) {
    severity = 'low';
    eventAction = 'auth_failure';
  } else if (lower.includes('accept') || lower.includes('success')) {
    eventAction = 'auth_success';
  }

  return {
    id,
    timestamp,
    raw_message: line,
    hostname,
    process_name: processName,
    pid,
    event_category: 'authentication',
    event_action: eventAction,
    source_ip: ips[0] || null,
    severity,
    is_suspicious: false,
    detection_ids: [],
    line_number: lineNumber,
  };
}

export function canParseAuthLog(sample: string): number {
  const lines = sample.split('\n').filter(l => l.trim()).slice(0, 20);
  if (!lines.length) return 0;
  let matches = 0;
  for (const line of lines) {
    if (SYSLOG_PREFIX.test(line)) {
      const lower = line.toLowerCase();
      if (['sshd', 'pam', 'sudo', 'auth', 'login', 'session'].some(k => lower.includes(k))) {
        matches++;
      }
    }
  }
  return Math.min((matches / lines.length) * 1.5, 1.0);
}
