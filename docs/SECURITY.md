# LogSleuth — Security & Privacy Architecture

Log files often contain sensitive personal data, internal IP addresses, server names, credentials, and business logic. Treating privacy as a core engineering feature is paramount.

---

## 1. Zero-Trust Client-Side Processing

- **No Remote Log Storage**: LogSleuth parses and correlates events within client browser memory.
- **No Third-Party AI / Analytics Transmissions**: Log entries are never dispatched to external LLMs, analytics trackers, or commercial telemetry providers.
- **Offline Capable**: Once the application assets are loaded in the browser, all parsing, rule evaluation, and IOC extraction remain fully operational without an active Internet connection.
- **Ephemeral Session Storage**: Uploaded files and pasted entries remain in temporary browser memory. When the page or tab is closed, raw logs are discarded.
- **Analyst Annotations**: Case notes and investigation status changes are stored solely in the user's browser `localStorage` and are never synced to remote servers without explicit user export.

---

## 2. Defensive Safeguards Against Malicious Log Input

Adversaries often inject malicious payloads into log files (e.g., Log4Shell, XSS payloads in User-Agents). LogSleuth implements strict defensive measures:

1. **Safe Text Rendering**: All log content and message extracts are rendered strictly as raw text inside React DOM elements. No `dangerouslySetInnerHTML` is used anywhere in the codebase.
2. **No Command / Script Execution**: Embedded bash commands, escape sequences, or JSON script blocks within log entries are treated purely as inert text strings and are never evaluated or spawned as subcommands.
3. **Payload Sanitization & Redaction**: The export pipeline provides an automatic secret-redaction filter that strips passwords, tokens, API keys, and Authorization headers (`Bearer`, `Basic`) before CSV or JSON downloads.
4. **Input Size Limits**: Browser uploads are capped at 15MB to prevent browser memory exhaustion (OOM), and FastAPI endpoints enforce strict 10MB request limits with 413 Payload Too Large responses.

---

## 3. Responsible Vulnerability Reporting

If you identify a security vulnerability in LogSleuth, please submit a responsible disclosure report via GitHub Security Advisories on the repository rather than filing a public issue.
