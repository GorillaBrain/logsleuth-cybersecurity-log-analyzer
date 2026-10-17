"""Base parser interface."""
from __future__ import annotations
import uuid
from abc import ABC, abstractmethod
from typing import Optional
from ..models import ParsedEvent, ParseResult


class BaseParser(ABC):
    """Abstract base class for log parsers."""
    
    FORMAT_NAME: str = "unknown"
    
    def parse(self, content: str) -> ParseResult:
        """Parse log content and return structured result."""
        lines = content.splitlines()
        result = ParseResult(
            total_lines=len(lines),
            format_detected=self.FORMAT_NAME,
        )
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                result.skipped_count += 1
                continue
            try:
                event = self.parse_line(stripped, line_number=i)
                if event:
                    result.events.append(event)
                    result.parsed_count += 1
                else:
                    result.skipped_count += 1
            except Exception as e:
                result.error_count += 1
                result.errors.append({"line": i, "content": stripped[:200], "error": str(e)})
        
        return result
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        """Parse a single log line into a ParsedEvent."""
        ...
    
    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())
    
    @classmethod
    def can_parse(cls, sample: str) -> float:
        """Return confidence 0.0-1.0 that this parser handles the given sample."""
        return 0.0
