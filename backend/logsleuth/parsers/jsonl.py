"""Parser for JSON Lines (JSONL) and newline-separated JSON."""
from __future__ import annotations
import json
from typing import Optional
from ..models import ParsedEvent, EventCategory, Severity
from .base import BaseParser
from .timestamp_utils import parse_timestamp
from .ip_utils import extract_ipv4

# Common field name mappings
TIMESTAMP_FIELDS = ['timestamp', 'time', 'datetime', 'date', '@timestamp', 'eventTime', 'ts', 'created', 'logged']
SOURCE_IP_FIELDS = ['source_ip', 'src_ip', 'sourceIp', 'remote_addr', 'clientIp', 'client_ip', 'ip', 'IpAddress', 'src']
USERNAME_FIELDS = ['username', 'user', 'userName', 'account', 'login', 'uid', 'TargetUserName', 'SubjectUserName']
MESSAGE_FIELDS = ['message', 'msg', 'log', 'description', 'text', 'event_message', 'Message']
SEVERITY_FIELDS = ['severity', 'level', 'priority', 'log_level', 'Level']
CATEGORY_FIELDS = ['category', 'event_type', 'type', 'eventType', 'EventID', 'Channel']
HOSTNAME_FIELDS = ['hostname', 'host', 'computer', 'Computer', 'source']
STATUS_FIELDS = ['status', 'status_code', 'http_status', 'response_code']
METHOD_FIELDS = ['method', 'http_method', 'request_method']
PATH_FIELDS = ['path', 'url', 'uri', 'request_uri', 'request']

SEVERITY_MAP = {
    'debug': Severity.INFORMATIONAL,
    'info': Severity.INFORMATIONAL,
    'information': Severity.INFORMATIONAL,
    'notice': Severity.INFORMATIONAL,
    'warn': Severity.LOW,
    'warning': Severity.LOW,
    'error': Severity.MEDIUM,
    'err': Severity.MEDIUM,
    'critical': Severity.HIGH,
    'crit': Severity.HIGH,
    'alert': Severity.HIGH,
    'fatal': Severity.CRITICAL,
    'emergency': Severity.CRITICAL,
    'emerg': Severity.CRITICAL,
}


def _find_field(obj: dict, candidates: list[str]) -> Optional[str]:
    """Find the first matching field name (case-insensitive)."""
    lower_keys = {k.lower(): k for k in obj}
    for c in candidates:
        if c.lower() in lower_keys:
            return lower_keys[c.lower()]
    return None


class JSONLParser(BaseParser):
    FORMAT_NAME = "jsonl"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        stripped = line.strip()
        if not stripped:
            return None
        
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        
        if not isinstance(obj, dict):
            return None
        
        # Extract fields
        ts_key = _find_field(obj, TIMESTAMP_FIELDS)
        timestamp = parse_timestamp(str(obj[ts_key])) if ts_key else None
        
        ip_key = _find_field(obj, SOURCE_IP_FIELDS)
        source_ip = str(obj[ip_key]) if ip_key else None
        
        user_key = _find_field(obj, USERNAME_FIELDS)
        username = str(obj[user_key]) if user_key and obj[user_key] else None
        
        msg_key = _find_field(obj, MESSAGE_FIELDS)
        message = str(obj[msg_key]) if msg_key else json.dumps(obj)
        
        sev_key = _find_field(obj, SEVERITY_FIELDS)
        severity = Severity.INFORMATIONAL
        if sev_key:
            sev_str = str(obj[sev_key]).lower().strip()
            severity = SEVERITY_MAP.get(sev_str, Severity.INFORMATIONAL)
        
        cat_key = _find_field(obj, CATEGORY_FIELDS)
        category = EventCategory.UNKNOWN
        if cat_key:
            cat_str = str(obj[cat_key]).lower()
            for ec in EventCategory:
                if ec.value in cat_str:
                    category = ec
                    break
        
        host_key = _find_field(obj, HOSTNAME_FIELDS)
        hostname = str(obj[host_key]) if host_key else None
        
        status_key = _find_field(obj, STATUS_FIELDS)
        http_status = None
        if status_key:
            try:
                http_status = int(obj[status_key])
            except (ValueError, TypeError):
                pass
        
        method_key = _find_field(obj, METHOD_FIELDS)
        http_method = str(obj[method_key]).upper() if method_key else None
        
        path_key = _find_field(obj, PATH_FIELDS)
        http_path = str(obj[path_key]) if path_key else None
        
        # Determine event action
        event_action = None
        if 'action' in {k.lower() for k in obj}:
            act_key = _find_field(obj, ['action', 'event_action', 'Action'])
            if act_key:
                event_action = str(obj[act_key])
        
        # Build extra fields (everything not already extracted)
        used_keys = {ts_key, ip_key, user_key, msg_key, sev_key, cat_key, host_key, status_key, method_key, path_key}
        extra = {k: v for k, v in obj.items() if k not in used_keys and k is not None}
        
        return ParsedEvent(
            id=self.generate_id(),
            timestamp=timestamp,
            raw_message=line.strip(),
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            event_category=category,
            event_action=event_action,
            http_method=http_method,
            http_path=http_path,
            http_status=http_status,
            severity=severity,
            extra=extra,
            line_number=line_number,
        )
    
    @classmethod
    def can_parse(cls, sample: str) -> float:
        lines = [l.strip() for l in sample.strip().splitlines()[:20] if l.strip()]
        if not lines:
            return 0.0
        json_count = 0
        for l in lines:
            try:
                obj = json.loads(l)
                if isinstance(obj, dict):
                    json_count += 1
            except json.JSONDecodeError:
                pass
        return min(json_count / max(len(lines), 1), 1.0)
