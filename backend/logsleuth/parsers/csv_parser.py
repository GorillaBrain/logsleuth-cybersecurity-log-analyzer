"""Parser for CSV log files with auto-detection and manual column mapping."""
from __future__ import annotations
import csv
import io
from typing import Optional
from ..models import ParsedEvent, EventCategory, Severity, ParseResult
from .base import BaseParser
from .timestamp_utils import parse_timestamp
from .ip_utils import extract_ipv4

# Auto-detect column mappings
TIMESTAMP_HEADERS = {'timestamp', 'time', 'datetime', 'date', '@timestamp', 'eventtime', 'ts', 'created'}
SOURCE_IP_HEADERS = {'source_ip', 'src_ip', 'sourceip', 'remote_addr', 'clientip', 'client_ip', 'ip', 'ipaddress', 'src'}
USERNAME_HEADERS = {'username', 'user', 'account', 'login', 'uid', 'targetusername', 'subjectusername'}
MESSAGE_HEADERS = {'message', 'msg', 'log', 'description', 'text', 'event_message'}
SEVERITY_HEADERS = {'severity', 'level', 'priority', 'log_level'}
CATEGORY_HEADERS = {'category', 'event_type', 'type', 'eventtype', 'eventid', 'channel'}
STATUS_HEADERS = {'status', 'status_code', 'http_status', 'response_code'}
HOSTNAME_HEADERS = {'hostname', 'host', 'computer', 'source'}


class CSVLogParser(BaseParser):
    FORMAT_NAME = "csv"
    
    def __init__(self, column_mapping: Optional[dict[str, str]] = None):
        """Initialize with optional explicit column mapping.
        
        column_mapping: dict mapping our field names to CSV column names.
        e.g. {"timestamp": "EventTime", "source_ip": "ClientIP"}
        """
        self.column_mapping = column_mapping or {}
    
    def parse(self, content: str) -> ParseResult:
        """Override to handle CSV header detection."""
        reader = csv.DictReader(io.StringIO(content))
        
        if not reader.fieldnames:
            return ParseResult(total_lines=0, format_detected=self.FORMAT_NAME)
        
        # Auto-detect columns if no mapping provided
        mapping = self._resolve_mapping(reader.fieldnames)
        
        result = ParseResult(format_detected=self.FORMAT_NAME)
        line_num = 1  # header is line 1
        
        for row in reader:
            line_num += 1
            result.total_lines += 1
            try:
                event = self._parse_row(row, mapping, line_num)
                if event:
                    result.events.append(event)
                    result.parsed_count += 1
                else:
                    result.skipped_count += 1
            except Exception as e:
                result.error_count += 1
                result.errors.append({
                    "line": line_num,
                    "content": str(dict(row))[:200],
                    "error": str(e)
                })
        
        return result
    
    def _resolve_mapping(self, fieldnames: list[str]) -> dict[str, str]:
        """Resolve column names to our field names."""
        mapping = dict(self.column_mapping)  # Start with user-provided
        lower_fields = {f.lower().strip(): f for f in fieldnames}
        
        def auto_map(our_field: str, candidates: set[str]):
            if our_field not in mapping:
                for c in candidates:
                    if c in lower_fields:
                        mapping[our_field] = lower_fields[c]
                        return
        
        auto_map('timestamp', TIMESTAMP_HEADERS)
        auto_map('source_ip', SOURCE_IP_HEADERS)
        auto_map('username', USERNAME_HEADERS)
        auto_map('message', MESSAGE_HEADERS)
        auto_map('severity', SEVERITY_HEADERS)
        auto_map('category', CATEGORY_HEADERS)
        auto_map('status', STATUS_HEADERS)
        auto_map('hostname', HOSTNAME_HEADERS)
        
        return mapping
    
    def _parse_row(self, row: dict, mapping: dict[str, str], line_number: int) -> Optional[ParsedEvent]:
        """Parse a single CSV row into a ParsedEvent."""
        # Build raw message from all fields
        raw_parts = [f"{k}={v}" for k, v in row.items() if v]
        raw_message = ", ".join(raw_parts)
        
        ts_col = mapping.get('timestamp')
        timestamp = parse_timestamp(row.get(ts_col, '')) if ts_col else None
        
        ip_col = mapping.get('source_ip')
        source_ip = row.get(ip_col, '').strip() or None if ip_col else None
        
        user_col = mapping.get('username')
        username = row.get(user_col, '').strip() or None if user_col else None
        
        msg_col = mapping.get('message')
        message = row.get(msg_col, '').strip() if msg_col else raw_message
        
        sev_col = mapping.get('severity')
        severity = Severity.INFORMATIONAL
        if sev_col and row.get(sev_col):
            sev_map = {
                'info': Severity.INFORMATIONAL, 'information': Severity.INFORMATIONAL,
                'low': Severity.LOW, 'warning': Severity.LOW, 'warn': Severity.LOW,
                'medium': Severity.MEDIUM, 'error': Severity.MEDIUM,
                'high': Severity.HIGH, 'critical': Severity.CRITICAL,
            }
            severity = sev_map.get(row[sev_col].lower().strip(), Severity.INFORMATIONAL)
        
        status_col = mapping.get('status')
        http_status = None
        if status_col and row.get(status_col):
            try:
                http_status = int(row[status_col])
            except ValueError:
                pass
        
        host_col = mapping.get('hostname')
        hostname = row.get(host_col, '').strip() or None if host_col else None
        
        # Collect extra fields
        mapped_cols = set(mapping.values())
        extra = {k: v for k, v in row.items() if k not in mapped_cols and v}
        
        return ParsedEvent(
            id=self.generate_id(),
            timestamp=timestamp,
            raw_message=raw_message,
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            event_category=EventCategory.UNKNOWN,
            http_status=http_status,
            severity=severity,
            extra=extra,
            line_number=line_number,
        )
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        # CSV parser uses the bulk parse() method instead
        return None
    
    @classmethod
    def can_parse(cls, sample: str) -> float:
        lines = sample.strip().splitlines()[:5]
        if len(lines) < 2:
            return 0.0
        try:
            dialect = csv.Sniffer().sniff(sample[:2000])
            reader = csv.reader(io.StringIO(sample[:2000]), dialect)
            header = next(reader, None)
            row = next(reader, None)
            if header and row and len(header) >= 2 and len(header) == len(row):
                return 0.7
        except csv.Error:
            pass
        # Fallback: check comma-separated
        if ',' in lines[0] and all(',' in l for l in lines[:3]):
            return 0.4
        return 0.0
