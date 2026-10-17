"""Parser for generic syslog messages."""
from __future__ import annotations
import re
from typing import Optional
from ..models import ParsedEvent, EventCategory, Severity
from .base import BaseParser
from .timestamp_utils import parse_timestamp
from .ip_utils import extract_ipv4

SYSLOG_PREFIX = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
)


class SyslogParser(BaseParser):
    FORMAT_NAME = "syslog"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        timestamp = parse_timestamp(line)
        m = SYSLOG_PREFIX.match(line)
        
        if not m:
            # Fallback: try to extract what we can
            return ParsedEvent(
                id=self.generate_id(),
                timestamp=timestamp,
                raw_message=line,
                event_category=EventCategory.SYSTEM,
                source_ip=extract_ipv4(line)[0] if extract_ipv4(line) else None,
                line_number=line_number,
            )
        
        hostname = m.group(2)
        process = m.group(3)
        pid = int(m.group(4)) if m.group(4) else None
        message = m.group(5)
        
        event = ParsedEvent(
            id=self.generate_id(),
            timestamp=timestamp,
            raw_message=line,
            hostname=hostname,
            process_name=process,
            pid=pid,
            event_category=EventCategory.SYSTEM,
            line_number=line_number,
        )
        
        ips = extract_ipv4(message)
        if ips:
            event.source_ip = ips[0]
        
        lower = message.lower()
        if 'error' in lower or 'fail' in lower:
            event.severity = Severity.LOW
            event.event_action = "error"
        elif 'warn' in lower:
            event.severity = Severity.LOW
            event.event_action = "warning"
        elif 'crit' in lower or 'alert' in lower or 'emerg' in lower:
            event.severity = Severity.HIGH
            event.event_action = "critical"
        
        return event
    
    @classmethod
    def can_parse(cls, sample: str) -> float:
        lines = sample.strip().splitlines()[:20]
        matches = sum(1 for l in lines if SYSLOG_PREFIX.match(l))
        return min(matches / max(len(lines), 1), 0.9)
