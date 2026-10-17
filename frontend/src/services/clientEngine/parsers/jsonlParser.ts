import type { ParsedEvent, Severity, EventCategory } from '../../../types';
import { parseTimestamp } from '../timestampUtils';

const TIMESTAMP_FIELDS = ['timestamp', 'time', 'datetime', 'date', '@timestamp', 'eventTime', 'ts', 'created'];
const SOURCE_IP_FIELDS = ['source_ip', 'src_ip', 'sourceIp', 'remote_addr', 'clientIp', 'client_ip', 'ip', 'IpAddress', 'src'];
const USERNAME_FIELDS = ['username', 'user', 'userName', 'account', 'login', 'uid', 'TargetUserName', 'SubjectUserName'];
const MESSAGE_FIELDS = ['message', 'msg', 'log', 'description', 'text', 'event_message', 'Message'];
const SEVERITY_FIELDS = ['severity', 'level', 'priority', 'log_level', 'Level'];
const CATEGORY_FIELDS = ['category', 'event_type', 'type', 'eventType', 'EventID', 'Channel'];
const HOSTNAME_FIELDS = ['hostname', 'host', 'computer', 'Computer', 'source'];
const STATUS_FIELDS = ['status', 'status_code', 'http_status', 'response_code'];
const METHOD_FIELDS = ['method', 'http_method', 'request_method'];
const PATH_FIELDS = ['path', 'url', 'uri', 'request_uri', 'request'];

const SEVERITY_MAP: Record<string, Severity> = {
  debug: 'informational',
  info: 'informational',
  information: 'informational',
  notice: 'informational',
  warn: 'low',
  warning: 'low',
  error: 'medium',
  err: 'medium',
  critical: 'high',
  crit: 'high',
  alert: 'high',
  fatal: 'critical',
  emergency: 'critical',
  emerg: 'critical',
};

function findField(obj: Record<string, unknown>, candidates: string[]): string | null {
  const lowerKeys = Object.keys(obj).reduce<Record<string, string>>((acc, k) => {
    acc[k.toLowerCase()] = k;
    return acc;
  }, {});
  for (const c of candidates) {
    if (lowerKeys[c.toLowerCase()]) {
      return lowerKeys[c.toLowerCase()];
    }
  }
  return null;
}

export function parseJSONLLine(line: string, lineNumber: number): ParsedEvent | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(trimmed);
  } catch {
    return null;
  }

  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return null;

  const tsKey = findField(obj, TIMESTAMP_FIELDS);
  const timestamp = tsKey ? parseTimestamp(String(obj[tsKey])) : null;

  const ipKey = findField(obj, SOURCE_IP_FIELDS);
  const sourceIp = ipKey ? String(obj[ipKey]) : null;

  const userKey = findField(obj, USERNAME_FIELDS);
  const username = userKey && obj[userKey] ? String(obj[userKey]) : null;

  const msgKey = findField(obj, MESSAGE_FIELDS);
  const message = msgKey ? String(obj[msgKey]) : trimmed;

  const sevKey = findField(obj, SEVERITY_FIELDS);
  let severity: Severity = 'informational';
  if (sevKey) {
    const sevStr = String(obj[sevKey]).toLowerCase().trim();
    if (SEVERITY_MAP[sevStr]) {
      severity = SEVERITY_MAP[sevStr];
    }
  }

  const catKey = findField(obj, CATEGORY_FIELDS);
  let category: EventCategory = 'unknown';
  if (catKey) {
    const catStr = String(obj[catKey]).toLowerCase();
    const categories: EventCategory[] = ['authentication', 'authorization', 'network', 'web_access', 'system', 'application', 'security'];
    for (const c of categories) {
      if (catStr.includes(c)) {
        category = c;
        break;
      }
    }
  }

  const hostKey = findField(obj, HOSTNAME_FIELDS);
  const hostname = hostKey ? String(obj[hostKey]) : null;

  const statusKey = findField(obj, STATUS_FIELDS);
  let httpStatus: number | null = null;
  if (statusKey) {
    const num = parseInt(String(obj[statusKey]), 10);
    if (!isNaN(num)) httpStatus = num;
  }

  const methodKey = findField(obj, METHOD_FIELDS);
  const httpMethod = methodKey ? String(obj[methodKey]).toUpperCase() : null;

  const pathKey = findField(obj, PATH_FIELDS);
  const httpPath = pathKey ? String(obj[pathKey]) : null;

  const actKey = findField(obj, ['action', 'event_action', 'Action']);
  const eventAction = actKey ? String(obj[actKey]) : null;

  const used = new Set([tsKey, ipKey, userKey, msgKey, sevKey, catKey, hostKey, statusKey, methodKey, pathKey, actKey].filter(Boolean));
  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (!used.has(k)) extra[k] = v;
  }

  return {
    id: `jsonl-${lineNumber}-${Math.random().toString(36).substring(2, 9)}`,
    timestamp,
    raw_message: message,
    source_ip: sourceIp,
    username,
    hostname,
    event_category: category,
    event_action: eventAction,
    http_method: httpMethod,
    http_path: httpPath,
    http_status: httpStatus,
    severity,
    is_suspicious: false,
    detection_ids: [],
    extra,
    line_number: lineNumber,
  };
}

export function canParseJSONL(sample: string): number {
  const lines = sample.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 20);
  if (!lines.length) return 0;
  let validCount = 0;
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        validCount++;
      }
    } catch {
      // ignore
    }
  }
  return Math.min(validCount / lines.length, 1.0);
}
