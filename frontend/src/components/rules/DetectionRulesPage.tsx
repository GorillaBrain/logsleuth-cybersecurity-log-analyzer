import React from 'react';
import { BookOpen, AlertTriangle, ExternalLink } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import type { DetectionRuleMeta } from '../../types';

export const DETECTION_RULES_CATALOG: DetectionRuleMeta[] = [
  {
    rule_id: 'AUTH-001',
    rule_name: 'Brute Force / Repeated Failed Logins',
    description: 'Detects a high frequency of authentication failures from a single source IP address within a configurable time window.',
    mitre_technique: 'T1110.001',
    severity: 'high',
    category: 'Authentication',
    logic: 'Triggers when a single source IP generates 5 or more failed login events within a sliding 10-minute time window. Escalates to HIGH severity if count exceeds 10.',
    limitations: 'Without timestamps or on shared proxies/NAT gateways, legitimate users may pool failures under one IP.',
    false_positives: 'Users who recently changed passwords but have cached credentials in email/SSH clients; automated health-check scripts with expired tokens.',
  },
  {
    rule_id: 'AUTH-002',
    rule_name: 'Password Spraying',
    description: 'Detects a single source IP attempting authentication across multiple distinct usernames.',
    mitre_technique: 'T1110.003',
    severity: 'high',
    category: 'Authentication',
    logic: 'Triggers when failed authentication attempts from one IP target 3 or more distinct user accounts.',
    limitations: 'Attackers utilizing distributed botnets (low and slow across rotating IPs) will not be detected by single-IP aggregation alone.',
    false_positives: 'Single-sign-on (SSO) gateways or internal load balancers masking internal client addresses; penetration test exercises.',
  },
  {
    rule_id: 'AUTH-003',
    rule_name: 'Successful Login After Repeated Failures',
    description: 'Detects a successful authentication event preceded by multiple failed attempts for the same username from the same IP.',
    mitre_technique: 'T1110',
    severity: 'high',
    category: 'Authentication',
    logic: 'Identifies sequences where 3 or more failed login attempts are immediately followed by an accepted/successful authentication for that user.',
    limitations: 'Requires sequential event logs with consistent user and source IP fields.',
    false_positives: 'A legitimate user who mistyped their password three times before entering the correct one.',
  },
  {
    rule_id: 'WEB-001',
    rule_name: 'Web Reconnaissance / Directory Scanning',
    description: 'Detects excessive HTTP 404 (Not Found) responses originating from a single client IP address.',
    mitre_technique: 'T1595.002',
    severity: 'medium',
    category: 'Web Access',
    logic: 'Triggers when an IP receives 10 or more HTTP 404 errors, indicating automated URL enumeration (DirBuster, Nikto, ffuf).',
    limitations: 'Heavily broken website links or missing assets (images, CSS) can trigger 404 cascades from normal visitors.',
    false_positives: 'Legitimate search engine crawlers (Googlebot, Bingbot); broken web applications with missing assets.',
  },
  {
    rule_id: 'WEB-002',
    rule_name: 'Requests to Sensitive Paths & Directory Traversal',
    description: 'Detects HTTP requests targeting administrative endpoints, sensitive configuration files (.env, .git), or path traversal patterns (../).',
    mitre_technique: 'T1190',
    severity: 'high',
    category: 'Web Access',
    logic: 'Inspects HTTP path attributes against known sensitive endpoints (/wp-admin, /phpmyadmin, /.env, /.git, /etc/passwd) and path traversal encodings (../, ..\\, %2e%2e).',
    limitations: 'Does not inspect request bodies (POST data) in combined access logs.',
    false_positives: 'Security scanners, legitimate administrative usage from authorized personnel, or misconfigured reverse proxies.',
  },
  {
    rule_id: 'WEB-003',
    rule_name: 'HTTP Authentication & Access Failures (401/403)',
    description: 'Detects repeated HTTP 401 Unauthorized or 403 Forbidden responses to a single source client.',
    mitre_technique: 'T1190',
    severity: 'medium',
    category: 'Web Access',
    logic: 'Triggers when a source IP accumulates 5 or more HTTP 401/403 status codes.',
    limitations: 'Expired web session cookies on single-page apps can produce bursts of 401s.',
    false_positives: 'Clients with expired JWTs or authentication sessions hitting periodic background polling endpoints.',
  },
  {
    rule_id: 'NET-001',
    rule_name: 'High Request Volume from Single Source',
    description: 'Detects unusually elevated request volumes from a single IP, indicating automated fuzzing or scraping.',
    mitre_technique: 'T1498',
    severity: 'medium',
    category: 'Network',
    logic: 'Triggers when a single IP generates 100 or more log events in the analyzed dataset.',
    limitations: 'Static thresholds do not account for natural volume variations during peak traffic hours.',
    false_positives: 'Corporate forward proxies, NAT gateways, internal API microservices, or partner webhooks.',
  },
  {
    rule_id: 'SYS-001',
    rule_name: 'System Error Burst',
    description: 'Detects sudden bursts of error-level messages across services indicating potential denial-of-service or cascade failure.',
    mitre_technique: 'T1499',
    severity: 'medium',
    category: 'System',
    logic: 'Triggers when 10 or more error or critical events occur within a 5-minute sliding window.',
    limitations: 'Requires normalized severity levels from application logs.',
    false_positives: 'Database maintenance windows, scheduled batch job failures, or upstream network blips.',
  },
];

export const DetectionRulesPage: React.FC = () => {
  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Header */}
      <div className="p-5 bg-navy-900/90 border border-navy-700/80 rounded-xl shadow-md">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-lg">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-gray-100">Detection Rules & Threshold Catalog</h2>
            <p className="text-xs text-gray-400">
              Explainable defensive detection logic, MITRE ATT&CK mappings, and SOC false-positive considerations
            </p>
          </div>
        </div>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 gap-4">
        {DETECTION_RULES_CATALOG.map(rule => (
          <div
            key={rule.rule_id}
            className="p-5 bg-navy-900/80 border border-navy-700/80 rounded-xl shadow-md space-y-3"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-navy-800 pb-3">
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-xs px-2.5 py-1 rounded bg-navy-950 text-cyan-400 border border-navy-700 font-bold">
                  {rule.rule_id}
                </span>
                <h3 className="text-sm font-bold text-gray-100">{rule.rule_name}</h3>
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={rule.severity} />
                {rule.mitre_technique && (
                  <a
                    href={`https://attack.mitre.org/techniques/${rule.mitre_technique.replace('.', '/')}`}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:border-purple-400 flex items-center gap-1 transition-colors"
                  >
                    <span>MITRE {rule.mitre_technique}</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>

            <p className="text-xs text-gray-300 leading-relaxed">{rule.description}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
              <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
                <span className="text-[10px] font-mono text-cyan-400 uppercase font-semibold">
                  Rule Evaluation Logic
                </span>
                <p className="text-gray-300 text-xs leading-relaxed">{rule.logic}</p>
              </div>

              <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1">
                <span className="text-[10px] font-mono text-amber-400 uppercase font-semibold flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> False Positive Considerations
                </span>
                <p className="text-gray-400 text-xs leading-relaxed">{rule.false_positives}</p>
              </div>
            </div>

            <div className="text-[11px] font-mono text-gray-500 border-t border-navy-800 pt-2 flex items-center justify-between">
              <span>Category: {rule.category}</span>
              <span>Scope: Single-dataset correlation</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
