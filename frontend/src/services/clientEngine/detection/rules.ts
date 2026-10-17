import type { ParsedEvent, Finding, Severity } from '../../../types';

export interface DetectionConfig {
  brute_force_threshold: number;
  brute_force_window_minutes: number;
  password_spray_min_users: number;
  success_after_failure_min: number;
  http_404_threshold: number;
  http_auth_failure_threshold: number;
  high_volume_threshold: number;
  error_burst_threshold: number;
  error_burst_window_minutes: number;
}

export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  brute_force_threshold: 5,
  brute_force_window_minutes: 10,
  password_spray_min_users: 3,
  success_after_failure_min: 3,
  http_404_threshold: 10,
  http_auth_failure_threshold: 5,
  high_volume_threshold: 100,
  error_burst_threshold: 10,
  error_burst_window_minutes: 5,
};

function generateFindingId(ruleId: string): string {
  return `${ruleId.toLowerCase()}-${Math.random().toString(36).substring(2, 9)}`;
}

// 1. AUTH-001: Brute Force
export function checkBruteForce(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const threshold = config.brute_force_threshold;
  const windowMs = config.brute_force_window_minutes * 60 * 1000;

  const failedByIp = new Map<string, ParsedEvent[]>();
  for (const e of events) {
    if (e.event_action && e.event_action.toLowerCase().includes('fail') && e.source_ip) {
      if (!failedByIp.has(e.source_ip)) failedByIp.set(e.source_ip, []);
      failedByIp.get(e.source_ip)!.push(e);
    }
  }

  const findings: Finding[] = [];
  for (const [ip, failedEvents] of failedByIp.entries()) {
    if (failedEvents.length < threshold) continue;

    // Check sliding window if timestamps exist
    const hasTimestamps = failedEvents.every(e => e.timestamp);
    if (hasTimestamps) {
      const sorted = [...failedEvents].sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
      for (let i = 0; i < sorted.length; i++) {
        const windowStart = new Date(sorted[i].timestamp!).getTime();
        const windowEvents = sorted.slice(i).filter(e => new Date(e.timestamp!).getTime() - windowStart <= windowMs);
        if (windowEvents.length >= threshold) {
          const usernames = Array.from(new Set(windowEvents.map(e => e.username).filter(Boolean))) as string[];
          const timestamps = windowEvents.map(e => e.timestamp!).filter(Boolean);
          const severity: Severity = windowEvents.length >= threshold * 2 ? 'high' : 'medium';

          findings.push({
            id: generateFindingId('AUTH-001'),
            title: `Potential brute-force attack from ${ip}`,
            severity,
            rule_id: 'AUTH-001',
            rule_name: 'Brute Force / Repeated Failed Logins',
            description: `${windowEvents.length} failed login attempts from ${ip} within ${config.brute_force_window_minutes} minutes.`,
            explanation: `The source IP ${ip} generated ${windowEvents.length} failed authentication attempts within a ${config.brute_force_window_minutes}-minute window, targeting ${usernames.length} account(s). This pattern is consistent with brute-force activity, but could also be caused by misconfigured services or forgotten credentials.`,
            evidence_strength: windowEvents.length >= threshold * 3 ? 'Strong' : 'Moderate',
            first_seen: timestamps[0] || null,
            last_seen: timestamps[timestamps.length - 1] || null,
            source_ips: [ip],
            usernames,
            event_count: windowEvents.length,
            event_ids: windowEvents.map(e => e.id),
            recommended_actions: [
              `Verify whether ${ip} is an expected corporate or user source.`,
              'Check if any of the targeted accounts were subsequently compromised.',
              'Review firewall and perimeter logs for coordinated activity.',
              'Consider rate-limiting or blocking the source IP if activity persists.',
            ],
            mitre_technique: 'T1110.001',
            investigation_status: 'new',
            analyst_notes: [],
          });
          break; // One finding per IP
        }
      }
    } else {
      const usernames = Array.from(new Set(failedEvents.map(e => e.username).filter(Boolean))) as string[];
      findings.push({
        id: generateFindingId('AUTH-001'),
        title: `Repeated failed logins from ${ip}`,
        severity: 'medium',
        rule_id: 'AUTH-001',
        rule_name: 'Brute Force / Repeated Failed Logins',
        description: `${failedEvents.length} failed login attempts from ${ip}.`,
        explanation: `The source IP ${ip} generated ${failedEvents.length} failed authentication attempts. Without complete timestamps, burst analysis cannot be confirmed.`,
        evidence_strength: 'Weak',
        first_seen: null,
        last_seen: null,
        source_ips: [ip],
        usernames,
        event_count: failedEvents.length,
        event_ids: failedEvents.map(e => e.id),
        recommended_actions: [
          `Verify whether ${ip} is a known host.`,
          'Check authentication logs for successful compromises.',
        ],
        mitre_technique: 'T1110.001',
        investigation_status: 'new',
        analyst_notes: [],
      });
    }
  }

  return findings;
}

// 2. AUTH-002: Password Spraying
export function checkPasswordSpray(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const minUsers = config.password_spray_min_users;
  const failedByIp = new Map<string, ParsedEvent[]>();

  for (const e of events) {
    if (e.event_action && e.event_action.toLowerCase().includes('fail') && e.source_ip && e.username) {
      if (!failedByIp.has(e.source_ip)) failedByIp.set(e.source_ip, []);
      failedByIp.get(e.source_ip)!.push(e);
    }
  }

  const findings: Finding[] = [];
  for (const [ip, failedEvents] of failedByIp.entries()) {
    const users = Array.from(new Set(failedEvents.map(e => e.username!)));
    if (users.length >= minUsers) {
      const timestamps = failedEvents.map(e => e.timestamp!).filter(Boolean);
      findings.push({
        id: generateFindingId('AUTH-002'),
        title: `Potential password spraying from ${ip}`,
        severity: 'high',
        rule_id: 'AUTH-002',
        rule_name: 'Password Spraying',
        description: `Source IP ${ip} attempted authentication against ${users.length} distinct usernames with ${failedEvents.length} total failures.`,
        explanation: `The IP ${ip} tested ${users.length} distinct usernames (${users.slice(0, 5).join(', ')}${users.length > 5 ? '...' : ''}). Password spraying tries common passwords across multiple accounts to bypass single-account lockout thresholds. Could also represent a shared proxy or corporate VPN gateway.`,
        evidence_strength: 'Moderate',
        first_seen: timestamps[0] || null,
        last_seen: timestamps[timestamps.length - 1] || null,
        source_ips: [ip],
        usernames: users,
        event_count: failedEvents.length,
        event_ids: failedEvents.map(e => e.id),
        recommended_actions: [
          'Verify if the IP address belongs to an external adversary or corporate NAT.',
          'Identify whether any targeted accounts subsequently authenticated successfully.',
          'Review password hygiene and enforce multi-factor authentication (MFA).',
        ],
        mitre_technique: 'T1110.003',
        investigation_status: 'new',
        analyst_notes: [],
      });
    }
  }

  return findings;
}

// 3. AUTH-003: Success After Repeated Failures
export function checkSuccessAfterFailure(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const minFailures = config.success_after_failure_min;
  const eventsByUserIp = new Map<string, ParsedEvent[]>();

  for (const e of events) {
    if (e.username && e.source_ip && e.event_action) {
      const key = `${e.username}@@${e.source_ip}`;
      if (!eventsByUserIp.has(key)) eventsByUserIp.set(key, []);
      eventsByUserIp.get(key)!.push(e);
    }
  }

  const findings: Finding[] = [];
  for (const [key, userEvents] of eventsByUserIp.entries()) {
    const [username, ip] = key.split('@@');
    const sorted = [...userEvents].sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return ta - tb;
    });

    let failures: ParsedEvent[] = [];
    for (const e of sorted) {
      const action = (e.event_action || '').toLowerCase();
      if (action.includes('fail')) {
        failures.push(e);
      } else if (action.includes('success') && failures.length >= minFailures) {
        const relevant = [...failures, e];
        const timestamps = relevant.map(ev => ev.timestamp!).filter(Boolean);
        findings.push({
          id: generateFindingId('AUTH-003'),
          title: `Successful login after ${failures.length} failures for '${username}'`,
          severity: 'high',
          rule_id: 'AUTH-003',
          rule_name: 'Successful Login After Repeated Failures',
          description: `User '${username}' authenticated from ${ip} after ${failures.length} consecutive failed attempts.`,
          explanation: `A successful login from ${ip} for user '${username}' followed ${failures.length} failed attempts. This sequence is a key indicator of a successful brute-force attack or credential stuffing, though it can also occur if a legitimate user mistyped their password repeatedly.`,
          evidence_strength: 'Strong',
          first_seen: timestamps[0] || null,
          last_seen: timestamps[timestamps.length - 1] || null,
          source_ips: [ip],
          usernames: [username],
          event_count: relevant.length,
          event_ids: relevant.map(ev => ev.id),
          recommended_actions: [
            `Contact the owner of account '${username}' to confirm if they initiated the login.`,
            'Inspect post-login activity for anomalous data access, privilege escalation, or lateral movement.',
            'Trigger an immediate password reset and session invalidation if unauthorized.',
          ],
          mitre_technique: 'T1110',
          investigation_status: 'new',
          analyst_notes: [],
        });
        failures = [];
      } else if (action.includes('success')) {
        failures = [];
      }
    }
  }

  return findings;
}

// 4. WEB-001: Web Recon / Directory Scanning
export function checkHTTPRecon(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const threshold = config.http_404_threshold;
  const errorsByIp = new Map<string, ParsedEvent[]>();

  for (const e of events) {
    if (e.http_status === 404 && e.source_ip) {
      if (!errorsByIp.has(e.source_ip)) errorsByIp.set(e.source_ip, []);
      errorsByIp.get(e.source_ip)!.push(e);
    }
  }

  const findings: Finding[] = [];
  for (const [ip, errorEvents] of errorsByIp.entries()) {
    if (errorEvents.length >= threshold) {
      const paths = Array.from(new Set(errorEvents.map(e => e.http_path).filter(Boolean))) as string[];
      const timestamps = errorEvents.map(e => e.timestamp!).filter(Boolean);
      findings.push({
        id: generateFindingId('WEB-001'),
        title: `Potential directory scanning from ${ip}`,
        severity: 'medium',
        rule_id: 'WEB-001',
        rule_name: 'Web Reconnaissance / Directory Scanning',
        description: `${errorEvents.length} HTTP 404 responses for requests from ${ip}, probing ${paths.length} distinct paths.`,
        explanation: `Source IP ${ip} received ${errorEvents.length} HTTP 404 Not Found responses. A rapid burst of 404s targeting multiple paths is characteristic of automated web vulnerability scanners (e.g., Nikto, Gobuster, DirBuster). Sample paths: ${paths.slice(0, 5).join(', ')}.`,
        evidence_strength: errorEvents.length >= threshold * 2 ? 'Moderate' : 'Weak',
        first_seen: timestamps[0] || null,
        last_seen: timestamps[timestamps.length - 1] || null,
        source_ips: [ip],
        usernames: [],
        event_count: errorEvents.length,
        event_ids: errorEvents.map(e => e.id),
        recommended_actions: [
          'Analyze requested paths for signs of known exploit payloads or web shell lookups.',
          'Check if source IP is a known legitimate search crawler (Googlebot, Bingbot).',
          'Review WAF metrics and consider blocklisting if unauthorized.',
        ],
        mitre_technique: 'T1595.002',
        investigation_status: 'new',
        analyst_notes: [],
      });
    }
  }

  return findings;
}

// 5. WEB-002: Sensitive Path Access & Directory Traversal
const SENSITIVE_PATHS = [
  '/admin', '/administrator', '/wp-admin', '/wp-login', '/phpmyadmin',
  '/manager', '/console', '/.env', '/.git', '/.htaccess', '/.htpasswd',
  '/config', '/backup', '/shell', '/cmd', '/eval', '/exec',
  '/etc/passwd', '/etc/shadow', '/proc/self', '/api/admin',
  '/actuator', '/debug', '/trace', '/server-status', '/xmlrpc.php',
];

const TRAVERSAL_PATTERNS = ['../', '..\\', '%2e%2e', '%252e%252e', '..../'];

export function checkSensitivePaths(events: ParsedEvent[]): Finding[] {
  const sensitiveEvents: ParsedEvent[] = [];
  const traversalEvents: ParsedEvent[] = [];

  for (const e of events) {
    if (!e.http_path) continue;
    const pathLower = e.http_path.toLowerCase();

    if (TRAVERSAL_PATTERNS.some(p => pathLower.includes(p))) {
      traversalEvents.push(e);
      continue;
    }

    if (SENSITIVE_PATHS.some(sp => pathLower.startsWith(sp) || pathLower === sp)) {
      sensitiveEvents.push(e);
    }
  }

  const findings: Finding[] = [];

  if (traversalEvents.length > 0) {
    const ips = Array.from(new Set(traversalEvents.map(e => e.source_ip).filter(Boolean))) as string[];
    const timestamps = traversalEvents.map(e => e.timestamp!).filter(Boolean);
    findings.push({
      id: generateFindingId('WEB-002-TRAVERSAL'),
      title: 'Path traversal attempts detected',
      severity: 'high',
      rule_id: 'WEB-002',
      rule_name: 'Requests to Sensitive Paths / Path Traversal',
      description: `${traversalEvents.length} request(s) contain path traversal sequences (../).`,
      explanation: `Requests containing directory traversal patterns were observed from IPs: ${ips.join(', ')}. Traversal sequences are used to break out of web document roots and access arbitrary files (e.g., /etc/passwd or system configurations).`,
      evidence_strength: 'Strong',
      first_seen: timestamps[0] || null,
      last_seen: timestamps[timestamps.length - 1] || null,
      source_ips: ips,
      usernames: [],
      event_count: traversalEvents.length,
      event_ids: traversalEvents.map(e => e.id),
      recommended_actions: [
        'Inspect server responses: verify that no 200 OK responses returned sensitive file contents.',
        'Ensure web server file permissions and input sanitization enforce strict root boundaries.',
        'Block source IPs exhibiting explicit exploit patterns.',
      ],
      mitre_technique: 'T1190',
      investigation_status: 'new',
      analyst_notes: [],
    });
  }

  if (sensitiveEvents.length > 0) {
    const ips = Array.from(new Set(sensitiveEvents.map(e => e.source_ip).filter(Boolean))) as string[];
    const paths = Array.from(new Set(sensitiveEvents.map(e => e.http_path).filter(Boolean))) as string[];
    const timestamps = sensitiveEvents.map(e => e.timestamp!).filter(Boolean);
    findings.push({
      id: generateFindingId('WEB-002-SENSITIVE'),
      title: 'Requests to sensitive or administrative paths',
      severity: 'medium',
      rule_id: 'WEB-002',
      rule_name: 'Requests to Sensitive Paths',
      description: `${sensitiveEvents.length} request(s) targeted administrative, debug, or configuration endpoints.`,
      explanation: `Web requests probed sensitive paths: ${paths.slice(0, 6).join(', ')}. These endpoints frequently expose administrative portals, credential stores, or environment secrets (.env, .git).`,
      evidence_strength: 'Moderate',
      first_seen: timestamps[0] || null,
      last_seen: timestamps[timestamps.length - 1] || null,
      source_ips: ips,
      usernames: [],
      event_count: sensitiveEvents.length,
      event_ids: sensitiveEvents.map(e => e.id),
      recommended_actions: [
        'Confirm whether any administrative endpoints responded with HTTP 200 (Success).',
        'Ensure configuration files (.git, .env) are blocked at the web server layer.',
        'Implement IP restriction or VPN requirements for administrative consoles.',
      ],
      mitre_technique: 'T1190',
      investigation_status: 'new',
      analyst_notes: [],
    });
  }

  return findings;
}

// 6. WEB-003: HTTP 401/403 Failures
export function checkHTTPAuthFailures(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const threshold = config.http_auth_failure_threshold;
  const byIp = new Map<string, ParsedEvent[]>();

  for (const e of events) {
    if ((e.http_status === 401 || e.http_status === 403) && e.source_ip) {
      if (!byIp.has(e.source_ip)) byIp.set(e.source_ip, []);
      byIp.get(e.source_ip)!.push(e);
    }
  }

  const findings: Finding[] = [];
  for (const [ip, authEvents] of byIp.entries()) {
    if (authEvents.length >= threshold) {
      const count401 = authEvents.filter(e => e.http_status === 401).length;
      const count403 = authEvents.filter(e => e.http_status === 403).length;
      const timestamps = authEvents.map(e => e.timestamp!).filter(Boolean);
      findings.push({
        id: generateFindingId('WEB-003'),
        title: `Repeated HTTP authorization failures from ${ip}`,
        severity: 'medium',
        rule_id: 'WEB-003',
        rule_name: 'HTTP Authentication Failures (401/403)',
        description: `${authEvents.length} HTTP 401/403 responses to ${ip} (401: ${count401}, 403: ${count403}).`,
        explanation: `The source IP ${ip} repeatedly triggered HTTP 401 Unauthorized or 403 Forbidden responses. This suggests repeated attempts to bypass authentication or access restricted administrative resources.`,
        evidence_strength: 'Moderate',
        first_seen: timestamps[0] || null,
        last_seen: timestamps[timestamps.length - 1] || null,
        source_ips: [ip],
        usernames: [],
        event_count: authEvents.length,
        event_ids: authEvents.map(e => e.id),
        recommended_actions: [
          'Review the targeted resources to verify access control effectiveness.',
          'Verify if valid credentials were eventually supplied by this client.',
        ],
        mitre_technique: 'T1190',
        investigation_status: 'new',
        analyst_notes: [],
      });
    }
  }

  return findings;
}

// 7. NET-001: High Request Volume
export function checkHighVolume(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const threshold = config.high_volume_threshold;
  const countByIp = new Map<string, ParsedEvent[]>();

  for (const e of events) {
    if (e.source_ip) {
      if (!countByIp.has(e.source_ip)) countByIp.set(e.source_ip, []);
      countByIp.get(e.source_ip)!.push(e);
    }
  }

  const findings: Finding[] = [];
  for (const [ip, ipEvents] of countByIp.entries()) {
    if (ipEvents.length >= threshold) {
      const timestamps = ipEvents.map(e => e.timestamp!).filter(Boolean);
      findings.push({
        id: generateFindingId('NET-001'),
        title: `High request volume from ${ip}`,
        severity: ipEvents.length >= threshold * 5 ? 'high' : 'medium',
        rule_id: 'NET-001',
        rule_name: 'High Request Volume from Single Source',
        description: `${ipEvents.length} events from ${ip}, significantly exceeding baseline volume.`,
        explanation: `Source IP ${ip} generated ${ipEvents.length} events (threshold: ${threshold}). High request volume may indicate automated scraping, denial-of-service attempts, or automated fuzzing.`,
        evidence_strength: 'Moderate',
        first_seen: timestamps[0] || null,
        last_seen: timestamps[timestamps.length - 1] || null,
        source_ips: [ip],
        usernames: [],
        event_count: ipEvents.length,
        event_ids: ipEvents.slice(0, 50).map(e => e.id),
        recommended_actions: [
          'Examine request patterns and user agents associated with this IP.',
          'Implement rate-limiting controls at the load balancer or ingress controller.',
        ],
        mitre_technique: 'T1498',
        investigation_status: 'new',
        analyst_notes: [],
      });
    }
  }

  return findings;
}

// 8. SYS-001: System Error Burst
export function checkSystemErrorBurst(events: ParsedEvent[], config: DetectionConfig): Finding[] {
  const threshold = config.error_burst_threshold;
  const windowMs = config.error_burst_window_minutes * 60 * 1000;

  const errorEvents = events.filter(e => 
    ['medium', 'high', 'critical'].includes(e.severity) ||
    (e.event_action && e.event_action.toLowerCase().includes('error'))
  );

  if (errorEvents.length < threshold) return [];

  const timestamped = [...errorEvents]
    .filter(e => e.timestamp)
    .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());

  if (!timestamped.length) {
    return [{
      id: generateFindingId('SYS-001'),
      title: 'High volume of system error events',
      severity: 'medium',
      rule_id: 'SYS-001',
      rule_name: 'System Error Burst',
      description: `${errorEvents.length} error-level events detected across the dataset.`,
      explanation: `A total of ${errorEvents.length} error events were observed. Timestamps were insufficient for burst clustering, but overall error frequency warrants investigation.`,
      evidence_strength: 'Weak',
      first_seen: null,
      last_seen: null,
      source_ips: [],
      usernames: [],
      event_count: errorEvents.length,
      event_ids: errorEvents.slice(0, 30).map(e => e.id),
      recommended_actions: [
        'Review application and service health dashboards for correlated faults.',
        'Inspect error stack traces for underlying exceptions.',
      ],
      investigation_status: 'new',
      analyst_notes: [],
    }];
  }

  const findings: Finding[] = [];
  let i = 0;
  while (i < timestamped.length) {
    const startMs = new Date(timestamped[i].timestamp!).getTime();
    const burst = timestamped.slice(i).filter(e => new Date(e.timestamp!).getTime() - startMs <= windowMs);
    if (burst.length >= threshold) {
      const timestamps = burst.map(e => e.timestamp!).filter(Boolean);
      findings.push({
        id: generateFindingId('SYS-001'),
        title: `Error burst: ${burst.length} errors in ${config.error_burst_window_minutes} minutes`,
        severity: burst.length >= threshold * 2 ? 'high' : 'medium',
        rule_id: 'SYS-001',
        rule_name: 'System Error Burst',
        description: `${burst.length} error events occurred within ${config.error_burst_window_minutes} minutes starting at ${timestamps[0]}.`,
        explanation: `A dense burst of ${burst.length} error events was detected within ${config.error_burst_window_minutes} minutes. This frequently corresponds to denial of service, service crashes, database outages, or cascading component failure.`,
        evidence_strength: 'Moderate',
        first_seen: timestamps[0] || null,
        last_seen: timestamps[timestamps.length - 1] || null,
        source_ips: [],
        usernames: [],
        event_count: burst.length,
        event_ids: burst.map(e => e.id),
        recommended_actions: [
          'Investigate root-cause exceptions during this specific time window.',
          'Correlate with concurrent network and authentication activity.',
        ],
        investigation_status: 'new',
        analyst_notes: [],
      });
      i += burst.length;
    } else {
      i++;
    }
  }

  return findings.slice(0, 5);
}
