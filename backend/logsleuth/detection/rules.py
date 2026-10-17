"""Detection rule definitions — modular, independently testable rules."""
from __future__ import annotations
import uuid
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional
from ..models import ParsedEvent, Finding, Severity, EventCategory


class DetectionRule(ABC):
    """Base class for detection rules."""
    RULE_ID: str = ""
    RULE_NAME: str = ""
    DESCRIPTION: str = ""
    MITRE_TECHNIQUE: Optional[str] = None
    
    @abstractmethod
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        """Evaluate the rule against a list of events. Return findings."""
        ...
    
    def _make_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        explanation: str,
        evidence_strength: str,
        matched_events: list[ParsedEvent],
        recommended_actions: list[str],
        source_ips: list[str] | None = None,
        usernames: list[str] | None = None,
    ) -> Finding:
        timestamps = [e.timestamp for e in matched_events if e.timestamp]
        return Finding(
            id=str(uuid.uuid4()),
            title=title,
            severity=severity,
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            description=description,
            explanation=explanation,
            evidence_strength=evidence_strength,
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
            source_ips=source_ips or [],
            usernames=usernames or [],
            event_count=len(matched_events),
            event_ids=[e.id for e in matched_events],
            recommended_actions=recommended_actions,
            mitre_technique=self.MITRE_TECHNIQUE,
        )


class BruteForceRule(DetectionRule):
    RULE_ID = "AUTH-001"
    RULE_NAME = "Brute Force / Repeated Failed Logins"
    DESCRIPTION = "Detects repeated authentication failures from a single source IP, which may indicate a brute-force attack attempt."
    MITRE_TECHNIQUE = "T1110.001"
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        threshold = config.get("brute_force_threshold", 5)
        window_minutes = config.get("brute_force_window_minutes", 10)
        
        # Group failed logins by source IP
        failed_by_ip: defaultdict[str, list[ParsedEvent]] = defaultdict(list)
        for e in events:
            if e.event_action and 'fail' in e.event_action.lower() and e.source_ip:
                failed_by_ip[e.source_ip].append(e)
        
        findings = []
        for ip, failed_events in failed_by_ip.items():
            if len(failed_events) < threshold:
                continue
            
            # Check time window if timestamps are available
            if all(e.timestamp for e in failed_events):
                sorted_events = sorted(failed_events, key=lambda e: e.timestamp)
                # Sliding window
                for i in range(len(sorted_events)):
                    window_events = []
                    for j in range(i, len(sorted_events)):
                        if sorted_events[j].timestamp - sorted_events[i].timestamp <= timedelta(minutes=window_minutes):
                            window_events.append(sorted_events[j])
                    if len(window_events) >= threshold:
                        usernames = list(set(e.username for e in window_events if e.username))
                        severity = Severity.HIGH if len(window_events) >= threshold * 2 else Severity.MEDIUM
                        findings.append(self._make_finding(
                            title=f"Potential brute-force attack from {ip}",
                            severity=severity,
                            description=f"{len(window_events)} failed login attempts from {ip} within {window_minutes} minutes.",
                            explanation=(
                                f"The source IP {ip} generated {len(window_events)} failed authentication attempts "
                                f"within a {window_minutes}-minute window, targeting {len(usernames)} account(s). "
                                f"This pattern is consistent with brute-force activity, but could also be caused by "
                                f"misconfigured services, automated scripts, or legitimate users with forgotten credentials."
                            ),
                            evidence_strength="Moderate" if len(window_events) < threshold * 3 else "Strong",
                            matched_events=window_events,
                            recommended_actions=[
                                f"Verify whether {ip} is a known or expected source.",
                                "Check if any of the targeted accounts were subsequently compromised.",
                                "Review firewall and IDS logs for additional context.",
                                "Consider temporarily blocking the source IP if the activity is ongoing.",
                            ],
                            source_ips=[ip],
                            usernames=usernames,
                        ))
                        break  # One finding per IP
            else:
                # No timestamps, just count
                usernames = list(set(e.username for e in failed_events if e.username))
                findings.append(self._make_finding(
                    title=f"Repeated failed logins from {ip}",
                    severity=Severity.MEDIUM,
                    description=f"{len(failed_events)} failed login attempts from {ip}.",
                    explanation=(
                        f"The source IP {ip} generated {len(failed_events)} failed authentication attempts "
                        f"targeting {len(usernames)} account(s). Without timestamps, the time distribution "
                        f"cannot be assessed. This may indicate brute-force activity or a misconfigured service."
                    ),
                    evidence_strength="Weak",
                    matched_events=failed_events,
                    recommended_actions=[
                        f"Verify whether {ip} is a known or expected source.",
                        "Check if any targeted accounts were compromised.",
                    ],
                    source_ips=[ip],
                    usernames=usernames,
                ))
        
        return findings


class PasswordSprayRule(DetectionRule):
    RULE_ID = "AUTH-002"
    RULE_NAME = "Password Spraying"
    DESCRIPTION = "Detects a single source IP attempting to authenticate against multiple distinct usernames, which may indicate password spraying."
    MITRE_TECHNIQUE = "T1110.003"
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        min_users = config.get("password_spray_min_users", 3)
        
        failed_by_ip: defaultdict[str, list[ParsedEvent]] = defaultdict(list)
        for e in events:
            if e.event_action and 'fail' in e.event_action.lower() and e.source_ip and e.username:
                failed_by_ip[e.source_ip].append(e)
        
        findings = []
        for ip, failed_events in failed_by_ip.items():
            unique_users = set(e.username for e in failed_events)
            if len(unique_users) >= min_users:
                findings.append(self._make_finding(
                    title=f"Potential password spraying from {ip}",
                    severity=Severity.HIGH,
                    description=(
                        f"Source IP {ip} attempted to authenticate as {len(unique_users)} "
                        f"different usernames with {len(failed_events)} total failed attempts."
                    ),
                    explanation=(
                        f"The IP {ip} tried {len(unique_users)} distinct usernames: "
                        f"{', '.join(sorted(unique_users)[:10])}{'...' if len(unique_users) > 10 else ''}. "
                        f"Password spraying attacks try common passwords against many accounts to avoid "
                        f"account lockout thresholds. However, this could also be a shared NAT gateway "
                        f"or a misconfigured application."
                    ),
                    evidence_strength="Moderate",
                    matched_events=failed_events,
                    recommended_actions=[
                        "Determine if the IP belongs to a NAT gateway, VPN exit node, or shared infrastructure.",
                        "Check if any of the targeted accounts were subsequently compromised.",
                        "Review password policies and account lockout settings.",
                        "Correlate with other log sources for additional indicators.",
                    ],
                    source_ips=[ip],
                    usernames=list(unique_users),
                ))
        
        return findings


class SuccessAfterFailureRule(DetectionRule):
    RULE_ID = "AUTH-003"
    RULE_NAME = "Successful Login After Repeated Failures"
    DESCRIPTION = "Detects a successful authentication following multiple failures for the same username, which may indicate a successful brute-force compromise."
    MITRE_TECHNIQUE = "T1110"
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        min_failures = config.get("success_after_failure_min", 3)
        
        # Group by (username, source_ip)
        events_by_user_ip: defaultdict[tuple, list[ParsedEvent]] = defaultdict(list)
        for e in events:
            if e.username and e.source_ip and e.event_action:
                events_by_user_ip[(e.username, e.source_ip)].append(e)
        
        findings = []
        for (username, ip), user_events in events_by_user_ip.items():
            sorted_events = sorted(user_events, key=lambda e: e.timestamp or datetime.min)
            
            failures = []
            for e in sorted_events:
                if 'fail' in (e.event_action or '').lower():
                    failures.append(e)
                elif 'success' in (e.event_action or '').lower() and len(failures) >= min_failures:
                    all_relevant = failures + [e]
                    findings.append(self._make_finding(
                        title=f"Successful login after {len(failures)} failures for '{username}'",
                        severity=Severity.HIGH,
                        description=(
                            f"User '{username}' successfully authenticated from {ip} "
                            f"after {len(failures)} consecutive failed attempts."
                        ),
                        explanation=(
                            f"A successful login from {ip} for user '{username}' was preceded by "
                            f"{len(failures)} failed attempts. This pattern is consistent with a "
                            f"successful brute-force attack, but could also indicate a legitimate user "
                            f"who remembered their password after several incorrect attempts."
                        ),
                        evidence_strength="Strong",
                        matched_events=all_relevant,
                        recommended_actions=[
                            f"Verify the login for '{username}' was legitimate by contacting the account owner.",
                            "Check for post-login suspicious activity (data access, privilege escalation).",
                            "Review whether the password should be reset.",
                            "Check if multi-factor authentication is enabled for this account.",
                        ],
                        source_ips=[ip],
                        usernames=[username],
                    ))
                    failures = []
                elif 'success' in (e.event_action or '').lower():
                    failures = []  # Reset on success without enough failures
        
        return findings


class HTTPReconRule(DetectionRule):
    RULE_ID = "WEB-001"
    RULE_NAME = "Web Reconnaissance / Directory Scanning"
    DESCRIPTION = "Detects excessive HTTP 404 responses from a single IP, which may indicate directory enumeration or vulnerability scanning."
    MITRE_TECHNIQUE = "T1595.002"
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        threshold = config.get("http_404_threshold", 10)
        
        errors_by_ip: defaultdict[str, list[ParsedEvent]] = defaultdict(list)
        for e in events:
            if e.http_status == 404 and e.source_ip:
                errors_by_ip[e.source_ip].append(e)
        
        findings = []
        for ip, error_events in errors_by_ip.items():
            if len(error_events) >= threshold:
                paths = list(set(e.http_path for e in error_events if e.http_path))[:20]
                findings.append(self._make_finding(
                    title=f"Potential directory scanning from {ip}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(error_events)} HTTP 404 responses to requests from {ip}, "
                        f"targeting {len(paths)} distinct paths."
                    ),
                    explanation=(
                        f"The source IP {ip} received {len(error_events)} HTTP 404 (Not Found) responses. "
                        f"A high volume of 404s may indicate automated directory enumeration or vulnerability "
                        f"scanning. Sample targeted paths: {', '.join(paths[:5])}. "
                        f"However, this could also be caused by broken links, web crawlers, or misconfigured clients."
                    ),
                    evidence_strength="Moderate" if len(error_events) >= threshold * 2 else "Weak",
                    matched_events=error_events,
                    recommended_actions=[
                        f"Examine the requested paths for sensitive directories or known exploit paths.",
                        f"Check if {ip} is a known search engine crawler or monitoring service.",
                        "Review web application firewall logs for related blocked requests.",
                        "Consider rate-limiting or blocking the source if scanning continues.",
                    ],
                    source_ips=[ip],
                ))
        
        return findings


class SensitivePathRule(DetectionRule):
    RULE_ID = "WEB-002"
    RULE_NAME = "Requests to Sensitive Paths"
    DESCRIPTION = "Detects HTTP requests targeting paths commonly associated with administration, configuration, or exploitation attempts."
    MITRE_TECHNIQUE = "T1190"
    
    SENSITIVE_PATHS = [
        '/admin', '/administrator', '/wp-admin', '/wp-login', '/phpmyadmin',
        '/manager', '/console', '/.env', '/.git', '/.htaccess', '/.htpasswd',
        '/config', '/backup', '/shell', '/cmd', '/eval', '/exec',
        '/etc/passwd', '/etc/shadow', '/proc/self', '/api/admin',
        '/actuator', '/debug', '/trace', '/server-status', '/server-info',
        '/xmlrpc.php', '/wp-config', '/web.config', '/robots.txt',
    ]
    
    TRAVERSAL_PATTERNS = ['../', '..\\', '%2e%2e', '%252e%252e', '..../']
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        findings = []
        sensitive_events: list[ParsedEvent] = []
        traversal_events: list[ParsedEvent] = []
        
        for e in events:
            if not e.http_path:
                continue
            path_lower = e.http_path.lower()
            
            # Check traversal
            if any(t in path_lower for t in self.TRAVERSAL_PATTERNS):
                traversal_events.append(e)
                continue
            
            # Check sensitive paths
            if any(path_lower.startswith(sp) or path_lower == sp for sp in self.SENSITIVE_PATHS):
                sensitive_events.append(e)
        
        if traversal_events:
            ips = list(set(e.source_ip for e in traversal_events if e.source_ip))
            findings.append(self._make_finding(
                title="Path traversal attempts detected",
                severity=Severity.HIGH,
                description=f"{len(traversal_events)} requests contain directory traversal sequences.",
                explanation=(
                    f"Requests containing directory traversal patterns (../) were detected. "
                    f"These are commonly used to access files outside the web root. "
                    f"Source IPs: {', '.join(ips[:5])}."
                ),
                evidence_strength="Strong",
                matched_events=traversal_events,
                recommended_actions=[
                    "Verify the web application properly validates and sanitizes file paths.",
                    "Check if any traversal attempts succeeded (2xx responses).",
                    "Block source IPs if the activity is clearly malicious.",
                ],
                source_ips=ips,
            ))
        
        if sensitive_events:
            ips = list(set(e.source_ip for e in sensitive_events if e.source_ip))
            paths_hit = list(set(e.http_path for e in sensitive_events if e.http_path))[:15]
            findings.append(self._make_finding(
                title="Requests to sensitive or administrative paths",
                severity=Severity.MEDIUM,
                description=f"{len(sensitive_events)} requests targeted known sensitive paths.",
                explanation=(
                    f"HTTP requests were observed targeting sensitive paths: {', '.join(paths_hit[:5])}. "
                    f"These paths are commonly associated with administrative interfaces, configuration files, "
                    f"or known vulnerability endpoints. The requests may be part of automated scanning."
                ),
                evidence_strength="Moderate",
                matched_events=sensitive_events,
                recommended_actions=[
                    "Check the HTTP response codes — 200 responses to sensitive paths require immediate investigation.",
                    "Ensure administrative paths are protected by authentication and IP restrictions.",
                    "Review web server configuration to prevent exposure of sensitive files.",
                ],
                source_ips=ips,
            ))
        
        return findings


class HTTPAuthFailureRule(DetectionRule):
    RULE_ID = "WEB-003"
    RULE_NAME = "HTTP Authentication Failures (401/403)"
    DESCRIPTION = "Detects repeated HTTP 401 and 403 responses that may indicate unauthorized access attempts."
    MITRE_TECHNIQUE = "T1190"
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        threshold = config.get("http_auth_failure_threshold", 5)
        
        by_ip: defaultdict[str, list[ParsedEvent]] = defaultdict(list)
        for e in events:
            if e.http_status in (401, 403) and e.source_ip:
                by_ip[e.source_ip].append(e)
        
        findings = []
        for ip, auth_events in by_ip.items():
            if len(auth_events) >= threshold:
                status_counts = Counter(e.http_status for e in auth_events)
                findings.append(self._make_finding(
                    title=f"Repeated HTTP authentication failures from {ip}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(auth_events)} HTTP 401/403 responses to {ip}. "
                        f"401s: {status_counts.get(401, 0)}, 403s: {status_counts.get(403, 0)}."
                    ),
                    explanation=(
                        f"The source IP {ip} triggered {len(auth_events)} authentication/authorization "
                        f"failures. Repeated 401 responses may indicate credential guessing against "
                        f"web authentication. Repeated 403 responses may indicate attempts to access "
                        f"restricted resources."
                    ),
                    evidence_strength="Moderate",
                    matched_events=auth_events,
                    recommended_actions=[
                        "Review which paths were being accessed.",
                        "Check if valid credentials were eventually used.",
                        "Verify web application authentication mechanisms.",
                    ],
                    source_ips=[ip],
                ))
        
        return findings


class HighVolumeRule(DetectionRule):
    RULE_ID = "NET-001"
    RULE_NAME = "High Request Volume from Single Source"
    DESCRIPTION = "Detects unusually high request volumes from a single IP address, which may indicate automated scanning, DoS attempts, or scraping."
    MITRE_TECHNIQUE = "T1498"
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        threshold = config.get("high_volume_threshold", 100)
        
        by_ip: Counter = Counter()
        events_by_ip: defaultdict[str, list[ParsedEvent]] = defaultdict(list)
        for e in events:
            if e.source_ip:
                by_ip[e.source_ip] += 1
                events_by_ip[e.source_ip].append(e)
        
        findings = []
        for ip, count in by_ip.most_common():
            if count >= threshold:
                ip_events = events_by_ip[ip]
                findings.append(self._make_finding(
                    title=f"High request volume from {ip}",
                    severity=Severity.MEDIUM if count < threshold * 5 else Severity.HIGH,
                    description=f"{count} events from {ip}, significantly above normal levels.",
                    explanation=(
                        f"The source IP {ip} generated {count} events, which is above the threshold "
                        f"of {threshold}. This may indicate automated tools, DoS activity, or legitimate "
                        f"high-usage clients. Review the nature of requests to determine intent."
                    ),
                    evidence_strength="Moderate",
                    matched_events=ip_events[:50],  # Limit for performance
                    recommended_actions=[
                        "Determine if the IP belongs to a known service, bot, or legitimate user.",
                        "Review the types of requests being made.",
                        "Consider rate limiting if the behavior is disruptive.",
                    ],
                    source_ips=[ip],
                ))
        
        return findings


class SystemErrorBurstRule(DetectionRule):
    RULE_ID = "SYS-001"
    RULE_NAME = "System Error Burst"
    DESCRIPTION = "Detects bursts of error-level events that may indicate system instability, attacks, or service disruption."
    
    def evaluate(self, events: list[ParsedEvent], config: dict) -> list[Finding]:
        threshold = config.get("error_burst_threshold", 10)
        window_minutes = config.get("error_burst_window_minutes", 5)
        
        error_events = [
            e for e in events 
            if e.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
            or (e.event_action and 'error' in e.event_action.lower())
        ]
        
        if len(error_events) < threshold:
            return []
        
        # Check for burst within time window
        timestamped = sorted([e for e in error_events if e.timestamp], key=lambda e: e.timestamp)
        
        if not timestamped:
            if len(error_events) >= threshold:
                return [self._make_finding(
                    title="High volume of error events",
                    severity=Severity.MEDIUM,
                    description=f"{len(error_events)} error-level events detected.",
                    explanation=(
                        f"A total of {len(error_events)} error events were found. Without timestamps, "
                        f"burst analysis is limited. The volume of errors may indicate system issues."
                    ),
                    evidence_strength="Weak",
                    matched_events=error_events[:30],
                    recommended_actions=[
                        "Review the error messages for common root causes.",
                        "Check system and application health.",
                    ],
                )]
            return []
        
        # Sliding window burst detection
        findings = []
        i = 0
        while i < len(timestamped):
            window_end = timestamped[i].timestamp + timedelta(minutes=window_minutes)
            burst = [e for e in timestamped[i:] if e.timestamp <= window_end]
            if len(burst) >= threshold:
                findings.append(self._make_finding(
                    title=f"Error burst: {len(burst)} errors in {window_minutes} minutes",
                    severity=Severity.HIGH if len(burst) >= threshold * 2 else Severity.MEDIUM,
                    description=(
                        f"{len(burst)} error events within a {window_minutes}-minute window "
                        f"starting at {timestamped[i].timestamp.isoformat()}."
                    ),
                    explanation=(
                        f"A burst of {len(burst)} errors occurred within {window_minutes} minutes. "
                        f"This may indicate a service outage, attack, or cascading failure."
                    ),
                    evidence_strength="Moderate",
                    matched_events=burst,
                    recommended_actions=[
                        "Investigate the root cause of the error burst.",
                        "Check for correlated network or authentication events.",
                        "Review service health during the affected time period.",
                    ],
                ))
                i += len(burst)
            else:
                i += 1
        
        return findings[:5]  # Limit findings


# Registry of all rules
DETECTION_RULES: list[type[DetectionRule]] = [
    BruteForceRule,
    PasswordSprayRule,
    SuccessAfterFailureRule,
    HTTPReconRule,
    SensitivePathRule,
    HTTPAuthFailureRule,
    HighVolumeRule,
    SystemErrorBurstRule,
]
