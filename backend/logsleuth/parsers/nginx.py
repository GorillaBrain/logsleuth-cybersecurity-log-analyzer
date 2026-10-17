"""Parser for Nginx access logs (same combined format as Apache)."""
from __future__ import annotations
from typing import Optional
from ..models import ParsedEvent
from .apache import ApacheAccessParser


class NginxAccessParser(ApacheAccessParser):
    FORMAT_NAME = "nginx_access"
    # Nginx default combined log format is identical to Apache's
    # This is here for format labeling; the parsing logic is inherited.
