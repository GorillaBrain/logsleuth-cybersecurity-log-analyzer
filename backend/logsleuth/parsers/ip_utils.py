"""IP address extraction and validation utilities."""
from __future__ import annotations
import ipaddress
import re
from typing import Optional

IPV4_PATTERN = re.compile(
    r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])'
)


def extract_ipv4(text: str) -> list[str]:
    """Extract all valid IPv4 addresses from text."""
    return IPV4_PATTERN.findall(text)


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_valid_public_ip(ip: str) -> bool:
    """Check if an IP is a valid public (non-private, non-reserved) IPv4."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_reserved or addr.is_loopback 
                    or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False
