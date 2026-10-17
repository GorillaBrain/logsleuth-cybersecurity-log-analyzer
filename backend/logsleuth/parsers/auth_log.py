"""Parser for Linux auth.log / secure log (SSH, PAM, sudo)."""
from __future__ import annotations
import re
from typing import Optional
from ..models import ParsedEvent, EventCategory, Severity
from .base import BaseParser
from .timestamp_utils import parse_timestamp
from .ip_utils import extract_ipv4

# Patterns for auth log events
SSH_FAILED = re.compile(
    r'Failed\s+(password|publickey)\s+for\s+(invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)',
    re.IGNORECASE
)
SSH_ACCEPTED = re.compile(
    r'Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)',
    re.IGNORECASE
)
SSH_INVALID_USER = re.compile(
    r'Invalid\s+user\s+(\S+)\s+from\s+(\S+)',
    re.IGNORECASE
)
SUDO_PATTERN = re.compile(
    r'(\S+)\s*:.*COMMAND=(.*)',
    re.IGNORECASE
)
SESSION_PATTERN = re.compile(
    r'session\s+(opened|closed)\s+for\s+user\s+(\S+)',
    re.IGNORECASE
)
SYSLOG_PREFIX = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
)


class AuthLogParser(BaseParser):
    FORMAT_NAME = "auth_log"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        timestamp = parse_timestamp(line)
        
        # Try syslog prefix
        prefix_match = SYSLOG_PREFIX.match(line)
        hostname = None
        process = None
        pid = None
        message = line
        
        if prefix_match:
            hostname = prefix_match.group(2)
            process = prefix_match.group(3)
            pid = int(prefix_match.group(4)) if prefix_match.group(4) else None
            message = prefix_match.group(5)
        
        event = ParsedEvent(
            id=self.generate_id(),
            timestamp=timestamp,
            raw_message=line,
            hostname=hostname,
            process_name=process,
            pid=pid,
            event_category=EventCategory.AUTHENTICATION,
            line_number=line_number,
        )
        
        # SSH failed login
        m = SSH_FAILED.search(line)
        if m:
            event.event_action = "login_failed"
            event.username = m.group(3)
            event.source_ip = m.group(4)
            event.severity = Severity.LOW
            if m.group(2):  # invalid user
                event.event_action = "login_failed_invalid_user"
                event.severity = Severity.MEDIUM
            return event
        
        # SSH accepted login
        m = SSH_ACCEPTED.search(line)
        if m:
            event.event_action = "login_success"
            event.username = m.group(2)
            event.source_ip = m.group(3)
            event.severity = Severity.INFORMATIONAL
            return event
        
        # Invalid user
        m = SSH_INVALID_USER.search(line)
        if m:
            event.event_action = "invalid_user"
            event.username = m.group(1)
            event.source_ip = m.group(2)
            event.severity = Severity.LOW
            return event
        
        # Sudo command
        m = SUDO_PATTERN.search(message)
        if m:
            event.event_action = "sudo_command"
            event.event_category = EventCategory.AUTHORIZATION
            event.username = m.group(1)
            event.extra["command"] = m.group(2).strip()
            event.severity = Severity.INFORMATIONAL
            # Extract IPs from message
            ips = extract_ipv4(line)
            if ips:
                event.source_ip = ips[0]
            return event
        
        # Session open/close
        m = SESSION_PATTERN.search(line)
        if m:
            action = m.group(1).lower()
            event.event_action = f"session_{action}"
            event.username = m.group(2)
            event.severity = Severity.INFORMATIONAL
            ips = extract_ipv4(line)
            if ips:
                event.source_ip = ips[0]
            return event
        
        # Generic auth event
        ips = extract_ipv4(line)
        if ips:
            event.source_ip = ips[0]
        
        # Detect common auth keywords
        lower_msg = message.lower()
        if 'fail' in lower_msg or 'denied' in lower_msg or 'error' in lower_msg:
            event.event_action = "auth_failure"
            event.severity = Severity.LOW
        elif 'accept' in lower_msg or 'success' in lower_msg:
            event.event_action = "auth_success"
        elif 'disconnect' in lower_msg:
            event.event_action = "disconnect"
        
        return event
    
    @classmethod
    def can_parse(cls, sample: str) -> float:
        lines = sample.strip().splitlines()[:20]
        matches = 0
        for line in lines:
            if SYSLOG_PREFIX.match(line):
                if any(kw in line.lower() for kw in ['sshd', 'pam', 'sudo', 'auth', 'login', 'session']):
                    matches += 1
        return min(matches / max(len(lines), 1) * 1.5, 1.0)
