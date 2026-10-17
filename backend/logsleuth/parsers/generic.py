"""Generic fallback parser for unrecognized log formats."""
from __future__ import annotations
from typing import Optional
from ..models import ParsedEvent, EventCategory, Severity
from .base import BaseParser
from .timestamp_utils import parse_timestamp
from .ip_utils import extract_ipv4


class GenericParser(BaseParser):
    FORMAT_NAME = "generic"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        timestamp = parse_timestamp(line)
        ips = extract_ipv4(line)
        
        severity = Severity.INFORMATIONAL
        lower = line.lower()
        if any(kw in lower for kw in ['critical', 'fatal', 'emergency', 'emerg']):
            severity = Severity.CRITICAL
        elif any(kw in lower for kw in ['error', 'err', 'alert']):
            severity = Severity.MEDIUM
        elif any(kw in lower for kw in ['warning', 'warn']):
            severity = Severity.LOW
        
        event_action = None
        if 'fail' in lower or 'denied' in lower:
            event_action = "failure"
        elif 'success' in lower or 'accepted' in lower:
            event_action = "success"
        
        return ParsedEvent(
            id=self.generate_id(),
            timestamp=timestamp,
            raw_message=line,
            source_ip=ips[0] if ips else None,
            event_category=EventCategory.UNKNOWN,
            event_action=event_action,
            severity=severity,
            line_number=line_number,
        )
    
    @classmethod  
    def can_parse(cls, sample: str) -> float:
        return 0.1  # Always available as fallback
