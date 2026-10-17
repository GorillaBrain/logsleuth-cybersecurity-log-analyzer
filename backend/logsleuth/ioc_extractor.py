"""Indicator of Compromise (IOC) extraction from parsed events."""
from __future__ import annotations
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional
from .models import ParsedEvent, IOC, IOCType
from .parsers.ip_utils import is_private_ip

# Patterns
IPV4_RE = re.compile(r'(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)')
DOMAIN_RE = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|co|info|biz|dev|xyz|me|tv|cc|ru|cn|de|uk|fr|au|ca|jp|br|in|nl|se|no|fi|dk|ch|at|be|es|it|pt|pl|cz|sk|hu|ro|bg|hr|si|lt|lv|ee|ie|lu|mt|cy|gr|tr|ua|by|md|ge|am|az|kz|uz|tm|kg|tj|mn|la|kh|mm|vn|th|my|sg|id|ph|bd|lk|np|pk|af|iq|ir|sa|ae|qa|kw|bh|om|ye|jo|lb|sy|il|ps|eg|ly|tn|dz|ma|sn|ng|gh|ke|ug|tz|za|zw|mz|ao|cm|ci|ml|bf|ne|td|mg|mu|rw|bw|na|sz|ls|mw|zm|et|dj|er|so|sd|ss|cd|cg|ga|gq|st|cv|gw|km|sc|yt|re|pm|wf|pf|nc|vu|fj|to|ws|ki|tv|nr|pw|fm|mh|as|gu|mp|vi|pr|gp|mq|bl|mf|sx|cw|aw|bq|tc|vg|ai|ms|kn|lc|vc|gd|dm|ag|bb|tt|jm|ht|bs|ky|bm|gl|fo|is|ax|gg|je|im|gi|mc|sm|va|ad|li|me|rs|mk|al|ba|xk|me|eus|cat|gal|scot|wales|cymru|london|nyc|paris|berlin|tokyo|moscow|tel|mobi|asia|aero|coop|museum|int|arpa|nato|mil|gov|edu|ac|travel|post|jobs|name|pro|museum|xxx|onion)\b')
URL_RE = re.compile(r'https?://[^\s<>"\']+')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Common false positive domains to exclude
FALSE_POSITIVE_DOMAINS = {
    'localhost', 'example.com', 'example.org', 'example.net',
    'localhost.localdomain', 'invalid', 'test', 'local',
}


def extract_iocs(events: list[ParsedEvent]) -> list[IOC]:
    """Extract and deduplicate IOCs from parsed events."""
    ioc_map: dict[tuple[str, IOCType], IOC] = {}
    
    for event in events:
        text = event.raw_message
        
        # Extract IPv4 addresses
        for ip in IPV4_RE.findall(text):
            _add_ioc(ioc_map, ip, IOCType.IPV4, event, is_private=is_private_ip(ip))
        
        # Extract domains
        for domain in DOMAIN_RE.findall(text):
            domain_lower = domain.lower().rstrip('.')
            if domain_lower not in FALSE_POSITIVE_DOMAINS and len(domain_lower) > 4:
                _add_ioc(ioc_map, domain_lower, IOCType.DOMAIN, event)
        
        # Extract URLs
        for url in URL_RE.findall(text):
            _add_ioc(ioc_map, url, IOCType.URL, event)
        
        # Extract emails
        for email in EMAIL_RE.findall(text):
            _add_ioc(ioc_map, email.lower(), IOCType.EMAIL, event)
        
        # Extract hashes (check longest first to avoid partial matches)
        for sha256 in SHA256_RE.findall(text):
            _add_ioc(ioc_map, sha256.lower(), IOCType.SHA256, event)
        
        # Only check SHA1 if not already a substring of a SHA256
        sha256_set = set(SHA256_RE.findall(text))
        for sha1 in SHA1_RE.findall(text):
            if not any(sha1.lower() in s.lower() for s in sha256_set):
                _add_ioc(ioc_map, sha1.lower(), IOCType.SHA1, event)
        
        # Only check MD5 if not part of longer hashes
        sha1_set = set(SHA1_RE.findall(text))
        all_longer = sha256_set | sha1_set
        for md5 in MD5_RE.findall(text):
            if not any(md5.lower() in s.lower() for s in all_longer):
                _add_ioc(ioc_map, md5.lower(), IOCType.MD5, event)
    
    return sorted(ioc_map.values(), key=lambda i: (-i.count, i.value))


def _add_ioc(
    ioc_map: dict[tuple[str, IOCType], IOC],
    value: str,
    ioc_type: IOCType,
    event: ParsedEvent,
    is_private: bool = False,
) -> None:
    """Add or update an IOC in the map."""
    key = (value, ioc_type)
    if key in ioc_map:
        ioc = ioc_map[key]
        ioc.count += 1
        if event.id not in ioc.event_ids:
            ioc.event_ids.append(event.id)
        if event.timestamp:
            if ioc.first_seen is None or event.timestamp < ioc.first_seen:
                ioc.first_seen = event.timestamp
            if ioc.last_seen is None or event.timestamp > ioc.last_seen:
                ioc.last_seen = event.timestamp
    else:
        ioc_map[key] = IOC(
            value=value,
            ioc_type=ioc_type,
            count=1,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_ids=[event.id],
            context=f"Extracted from log entry at line {event.line_number or 'unknown'}",
            is_private=is_private,
        )
