"""Parser for Apache/Combined access logs."""
from __future__ import annotations
import re
from typing import Optional
from ..models import ParsedEvent, EventCategory, Severity
from .base import BaseParser
from .timestamp_utils import parse_timestamp

# Combined log format:
# 192.168.1.1 - user [10/Oct/2023:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326 "referer" "user-agent"
APACHE_COMBINED = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s*(\S*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)


class ApacheAccessParser(BaseParser):
    FORMAT_NAME = "apache_access"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        m = APACHE_COMBINED.match(line)
        if not m:
            return None
        
        ip = m.group(1)
        user = m.group(3) if m.group(3) != '-' else None
        ts_str = m.group(4)
        method = m.group(5)
        path = m.group(6)
        protocol = m.group(7)
        status = int(m.group(8))
        size = m.group(9)
        referer = m.group(10) if m.group(10) and m.group(10) != '-' else None
        user_agent = m.group(11) if m.group(11) else None
        
        timestamp = parse_timestamp(ts_str)
        
        # Determine severity based on status code
        severity = Severity.INFORMATIONAL
        if status == 401 or status == 403:
            severity = Severity.LOW
        elif status == 404:
            severity = Severity.INFORMATIONAL
        elif status >= 500:
            severity = Severity.MEDIUM
        
        event_action = f"http_{method.lower()}"
        if status == 401:
            event_action = "http_unauthorized"
        elif status == 403:
            event_action = "http_forbidden"
        elif status == 404:
            event_action = "http_not_found"
        
        event = ParsedEvent(
            id=self.generate_id(),
            timestamp=timestamp,
            raw_message=line,
            source_ip=ip,
            username=user,
            event_category=EventCategory.WEB_ACCESS,
            event_action=event_action,
            http_method=method,
            http_path=path,
            http_status=status,
            http_user_agent=user_agent,
            severity=severity,
            line_number=line_number,
        )
        
        if referer:
            event.extra["referer"] = referer
        if size and size != '-':
            try:
                event.extra["response_size"] = int(size)
            except ValueError:
                pass
        
        return event
    
    @classmethod
    def can_parse(cls, sample: str) -> float:
        lines = sample.strip().splitlines()[:20]
        matches = sum(1 for l in lines if APACHE_COMBINED.match(l))
        return min(matches / max(len(lines), 1), 1.0)
