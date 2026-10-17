"""Format detection and parser routing."""
from __future__ import annotations
from ..models import ParseResult
from .auth_log import AuthLogParser
from .syslog import SyslogParser
from .apache import ApacheAccessParser
from .nginx import NginxAccessParser
from .jsonl import JSONLParser
from .csv_parser import CSVLogParser
from .generic import GenericParser

PARSERS = [
    AuthLogParser,
    ApacheAccessParser,
    JSONLParser,
    CSVLogParser,
    SyslogParser,
    GenericParser,
]


def detect_format(content: str) -> str:
    """Detect the most likely log format."""
    sample = "\n".join(content.splitlines()[:50])
    best_parser = GenericParser
    best_score = 0.0
    
    for parser_cls in PARSERS:
        score = parser_cls.can_parse(sample)
        if score > best_score:
            best_score = score
            best_parser = parser_cls
    
    return best_parser.FORMAT_NAME


def parse_logs(content: str, format_hint: str | None = None, column_mapping: dict | None = None) -> ParseResult:
    """Parse log content, auto-detecting format if not specified."""
    if format_hint:
        parser_map = {p.FORMAT_NAME: p for p in PARSERS}
        parser_cls = parser_map.get(format_hint, GenericParser)
    else:
        sample = "\n".join(content.splitlines()[:50])
        best_parser = GenericParser
        best_score = 0.0
        for parser_cls in PARSERS:
            score = parser_cls.can_parse(sample)
            if score > best_score:
                best_score = score
                best_parser = parser_cls
        parser_cls = best_parser
    
    if parser_cls == CSVLogParser:
        parser = CSVLogParser(column_mapping=column_mapping)
    else:
        parser = parser_cls()
    
    return parser.parse(content)
