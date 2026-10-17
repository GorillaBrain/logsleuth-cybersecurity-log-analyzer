# LogSleuth — Detection Rules Specification

LogSleuth implements **8 deterministic, rule-based detection modules** designed to identify suspicious adversary behavior across authentication, web services, network traffic, and system operations.

Every rule is transparent, explainable, and maps to the **MITRE ATT&CK® Framework**.

---

## Detection Rules Summary

| Rule ID | Rule Name | Category | Default Severity | MITRE ATT&CK | Threshold Defaults |
|---|---|---|---|---|---|
| `AUTH-001` | Brute Force / Repeated Failed Logins | Authentication | High / Medium | T1110.001 | 5 failures / 10 mins |
| `AUTH-002` | Password Spraying | Authentication | High | T1110.003 | 3 distinct accounts / 1 IP |
| `AUTH-003` | Success After Repeated Failures | Authentication | High | T1110 | 3+ failures then success |
| `WEB-001` | Web Reconnaissance & Directory Scanning | Web Access | Medium | T1595.002 | 10 HTTP 404s / 1 IP |
| `WEB-002` | Sensitive Path Access & Directory Traversal | Web Access | High / Medium | T1190 | Traversal sequences / sensitive roots |
| `WEB-003` | HTTP Authentication & Access Failures | Web Access | Medium | T1190 | 5 HTTP 401/403s |
| `NET-001` | High Request Volume from Single Source | Network | Medium / High | T1498 | 100 requests / 1 IP |
| `SYS-001` | System Error Burst | System | Medium / High | T1499 | 10 errors / 5 mins |

---

## Detailed Rule Specifications

### 1. AUTH-001: Brute Force / Repeated Failed Logins
- **Objective**: Identify password guessing against a single host or account.
- **MITRE Technique**: [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- **Trigger**: $\ge 5$ failed authentication attempts from a single source IP within a 10-minute sliding window. Escalates to `HIGH` if $\ge 10$ attempts.
- **Evidence Strength**: Moderate ($\ge 5$), Strong ($\ge 15$).
- **False Positive Considerations**: Users with expired stored passwords in desktop email/chat clients; automated credential verification tools.

---

### 2. AUTH-002: Password Spraying
- **Objective**: Detect adversaries testing common passwords across many accounts to evade single-account lockout policies.
- **MITRE Technique**: [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- **Trigger**: A single source IP generates failed authentications targeting $\ge 3$ distinct usernames.
- **Evidence Strength**: Moderate.
- **False Positive Considerations**: Shared corporate NAT gateways or outbound proxy servers where multiple employees mistype credentials simultaneously.

---

### 3. AUTH-003: Successful Login After Repeated Failures
- **Objective**: Flag compromised accounts where an adversary succeeded after repeated incorrect attempts.
- **MITRE Technique**: [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Trigger**: An accepted authentication event is immediately preceded by $\ge 3$ consecutive failed attempts for that user and source IP.
- **Evidence Strength**: Strong.
- **Analyst Action**: Verify with account owner; check for unauthorized lateral movement or privilege escalation immediately post-login.

---

### 4. WEB-001: Web Reconnaissance & Directory Scanning
- **Objective**: Detect automated web scanners attempting to enumerate unlinked directories, backups, and administrative endpoints.
- **MITRE Technique**: [T1595.002 — Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
- **Trigger**: $\ge 10$ HTTP 404 (Not Found) responses returned to a single client IP.
- **Evidence Strength**: Moderate.
- **False Positive Considerations**: Search engine crawlers (Googlebot); broken site layouts with missing static CSS/image assets.

---

### 5. WEB-002: Sensitive Path Access & Directory Traversal
- **Objective**: Detect exploitation attempts targeting environment files, git repositories, server configuration, or directory traversal (`../`).
- **MITRE Technique**: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **Trigger**:
  - `traversal`: Requests containing `../`, `..\`, `%2e%2e`, or `..../` (Severity: `HIGH`).
  - `sensitive`: Requests targeting endpoints such as `/admin`, `/.env`, `/.git`, `/phpmyadmin`, `/etc/passwd`, `/actuator` (Severity: `MEDIUM`).
- **Evidence Strength**: Strong for traversal sequences, Moderate for sensitive paths.

---

### 6. WEB-003: HTTP Authentication & Access Failures
- **Objective**: Detect unauthorized attempts to access protected web resources.
- **MITRE Technique**: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **Trigger**: $\ge 5$ HTTP 401 Unauthorized or 403 Forbidden responses to a single client IP.

---

### 7. NET-001: High Request Volume from Single Source
- **Objective**: Detect high-rate fuzzing, scraping, or denial-of-service attempts.
- **MITRE Technique**: [T1498 — Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- **Trigger**: $\ge 100$ total events from a single IP in the dataset. Escalates to `HIGH` if $\ge 500$.

---

### 8. SYS-001: System Error Burst
- **Objective**: Identify cascading service errors, crashes, or unhandled exceptions.
- **MITRE Technique**: [T1499 — Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- **Trigger**: $\ge 10$ error- or critical-level log events within a 5-minute sliding window.
