"""Timestamp parsing utilities supporting multiple formats."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
import re

# Common timestamp patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601
    (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?', [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]),
    # Syslog: Mon DD HH:MM:SS (no year)
    (r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', [
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ]),
    # Common log format: DD/Mon/YYYY:HH:MM:SS +ZZZZ
    (r'\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}', [
        "%d/%b/%Y:%H:%M:%S %z",
    ]),
    # YYYY-MM-DD HH:MM:SS
    (r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?', [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]),
    # MM/DD/YYYY HH:MM:SS
    (r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', [
        "%m/%d/%Y %H:%M:%S",
    ]),
    # Unix epoch (10 or 13 digits)
    (r'(?<![\d.])1[3-9]\d{8}(?:\d{3})?(?![\d.])', []),
]


def parse_timestamp(text: str) -> Optional[datetime]:
    """Try to extract and parse a timestamp from text."""
    for pattern, formats in TIMESTAMP_PATTERNS:
        match = re.search(pattern, text)
        if match:
            ts_str = match.group(0)
            
            # Handle Unix epoch
            if not formats:
                try:
                    epoch = int(ts_str)
                    if epoch > 1e12:  # milliseconds
                        epoch = epoch / 1000
                    return datetime.fromtimestamp(epoch, tz=timezone.utc)
                except (ValueError, OSError):
                    continue
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(ts_str, fmt)
                    # Syslog has no year - use current year
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return dt
                except ValueError:
                    continue
    return None


def extract_timestamp_string(text: str) -> Optional[str]:
    """Extract the timestamp string from text without parsing."""
    for pattern, _ in TIMESTAMP_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return None
