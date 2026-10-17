import { describe, it, expect } from 'vitest';
import { parseAuthLogLine } from '../parsers/authLogParser';
import { parseApacheLogLine } from '../parsers/apacheParser';
import { parseJSONLLine } from '../parsers/jsonlParser';
import { parseCSVLogs } from '../parsers/csvParser';
import { detectFormat, parseLogsClient } from '../parsers/parserRouter';
import { parseTimestamp } from '../timestampUtils';

describe('Timestamp Parsing & Normalization', () => {
  it('parses ISO 8601 timestamps', () => {
    const ts = parseTimestamp('2026-10-15T09:00:02Z');
    expect(ts).toBe('2026-10-15T09:00:02.000Z');
  });

  it('parses Syslog timestamps (adds current year)', () => {
    const ts = parseTimestamp('Oct 15 09:00:02 webserver01 sshd[123]: message');
    expect(ts).not.toBeNull();
    expect(ts).toContain('-10-15T09:00:02');
  });

  it('parses Apache CLF timestamps', () => {
    const ts = parseTimestamp('192.0.2.1 - - [15/Oct/2026:09:00:02 +0000] "GET / HTTP/1.1" 200 123');
    expect(ts).toBe('2026-10-15T09:00:02.000Z');
  });

  it('handles invalid timestamps gracefully by returning null', () => {
    expect(parseTimestamp('invalid timestamp string')).toBeNull();
  });
});

describe('Auth Log Parser', () => {
  it('correctly parses SSH failed password attempts', () => {
    const line = 'Oct 15 09:01:00 webserver01 sshd[1234]: Failed password for root from 198.51.100.23 port 41234 ssh2';
    const event = parseAuthLogLine(line, 1);
    expect(event).not.toBeNull();
    expect(event?.username).toBe('root');
    expect(event?.source_ip).toBe('198.51.100.23');
    expect(event?.event_action).toBe('login_failed');
    expect(event?.severity).toBe('low');
  });

  it('correctly parses SSH invalid user failed attempts', () => {
    const line = 'Oct 15 09:01:05 webserver01 sshd[1235]: Failed password for invalid user hacker from 198.51.100.23 port 41235 ssh2';
    const event = parseAuthLogLine(line, 2);
    expect(event).not.toBeNull();
    expect(event?.username).toBe('hacker');
    expect(event?.event_action).toBe('login_failed_invalid_user');
    expect(event?.severity).toBe('medium');
  });

  it('correctly parses accepted SSH logins', () => {
    const line = 'Oct 15 09:08:45 webserver01 sshd[1250]: Accepted password for admin from 198.51.100.23 port 41250 ssh2';
    const event = parseAuthLogLine(line, 3);
    expect(event).not.toBeNull();
    expect(event?.username).toBe('admin');
    expect(event?.source_ip).toBe('198.51.100.23');
    expect(event?.event_action).toBe('login_success');
    expect(event?.severity).toBe('informational');
  });

  it('correctly parses sudo commands', () => {
    const line = 'Oct 15 08:14:10 webserver01 sudo[12160]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/systemctl status nginx';
    const event = parseAuthLogLine(line, 4);
    expect(event).not.toBeNull();
    expect(event?.username).toBe('alice');
    expect(event?.event_category).toBe('authorization');
    expect(event?.extra?.command).toBe('/bin/systemctl status nginx');
  });
});

describe('Apache Access Log Parser', () => {
  it('extracts IP, status, method, path, and user-agent', () => {
    const line = '198.51.100.42 - - [15/Oct/2026:10:00:10 +0000] "GET /admin HTTP/1.1" 403 402 "-" "Nikto/2.1.6"';
    const event = parseApacheLogLine(line, 1);
    expect(event).not.toBeNull();
    expect(event?.source_ip).toBe('198.51.100.42');
    expect(event?.http_method).toBe('GET');
    expect(event?.http_path).toBe('/admin');
    expect(event?.http_status).toBe(403);
    expect(event?.http_user_agent).toBe('Nikto/2.1.6');
    expect(event?.event_action).toBe('http_forbidden');
    expect(event?.severity).toBe('low');
  });
});

describe('JSONL Parser', () => {
  it('parses structured JSON lines with flexible keys', () => {
    const line = JSON.stringify({
      timestamp: '2026-10-15T12:00:00Z',
      level: 'error',
      source_ip: '203.0.113.5',
      user: 'jdoe',
      message: 'Database query timeout after 30s',
      service: 'payment-svc',
    });
    const event = parseJSONLLine(line, 1);
    expect(event).not.toBeNull();
    expect(event?.timestamp).toBe('2026-10-15T12:00:00.000Z');
    expect(event?.severity).toBe('medium');
    expect(event?.source_ip).toBe('203.0.113.5');
    expect(event?.username).toBe('jdoe');
    expect(event?.raw_message).toBe('Database query timeout after 30s');
    expect(event?.extra?.service).toBe('payment-svc');
  });
});

describe('CSV Parser', () => {
  it('parses CSV logs with automatic column header detection', () => {
    const csvContent = `Timestamp,ClientIP,Account,EventDescription,StatusCode,Severity
2026-10-15T09:00:00Z,192.168.1.50,admin,User logged in,200,Info
2026-10-15T09:05:00Z,198.51.100.4,root,Unauthorized access attempt,403,Warning`;

    const res = parseCSVLogs(csvContent);
    expect(res.total_lines).toBe(2);
    expect(res.parsed_count).toBe(2);
    expect(res.error_count).toBe(0);
    expect(res.events[0].source_ip).toBe('192.168.1.50');
    expect(res.events[0].username).toBe('admin');
    expect(res.events[1].http_status).toBe(403);
  });
});

describe('Format Auto-Detection & Resilient Parsing', () => {
  it('correctly auto-detects auth_log format', () => {
    const sample = `Oct 15 08:00:01 webserver01 CRON[12100]: pam_unix(cron:session): session opened
Oct 15 08:12:32 webserver01 sshd[12150]: Accepted publickey for alice from 192.0.2.10 port 49200`;
    expect(detectFormat(sample)).toBe('auth_log');
  });

  it('correctly auto-detects apache_access format', () => {
    const sample = `192.0.2.50 - - [15/Oct/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
192.0.2.50 - - [15/Oct/2026:10:00:05 +0000] "GET /about HTTP/1.1" 200 4567`;
    expect(detectFormat(sample)).toBe('apache_access');
  });

  it('handles malformed and empty lines without crashing', () => {
    const messyLog = `
Oct 15 08:00:01 webserver01 sshd[1]: Accepted password for user1 from 192.0.2.1 port 22

SOME UNFORMATTED CORRUPTED BYTES &*#^@
Oct 15 08:00:05 webserver01 sshd[2]: Accepted password for user2 from 192.0.2.2 port 22
`;
    const res = parseLogsClient(messyLog);
    expect(res.total_lines).toBe(6);
    expect(res.parsed_count).toBeGreaterThanOrEqual(2);
    expect(res.skipped_count).toBeGreaterThanOrEqual(1);
  });
});
