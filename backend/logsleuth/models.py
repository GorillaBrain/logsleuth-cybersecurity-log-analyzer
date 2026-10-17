"""Core data models for LogSleuth."""
from __future__ import annotations
import enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvestigationStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class EventCategory(str, enum.Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    WEB_ACCESS = "web_access"
    SYSTEM = "system"
    APPLICATION = "application"
    SECURITY = "security"
    UNKNOWN = "unknown"


class ParsedEvent(BaseModel):
    """A normalized log event."""
    id: str = Field(description="Unique event identifier")
    timestamp: Optional[datetime] = None
    raw_message: str = Field(description="Original log line")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    event_category: EventCategory = EventCategory.UNKNOWN
    event_action: Optional[str] = None  # e.g., "login_failed", "login_success"
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    severity: Severity = Severity.INFORMATIONAL
    is_suspicious: bool = False
    detection_ids: list[str] = Field(default_factory=list)
    extra: dict = Field(default_factory=dict, description="Additional extracted fields")
    line_number: Optional[int] = None


class ParseResult(BaseModel):
    """Result of parsing a log source."""
    events: list[ParsedEvent] = Field(default_factory=list)
    total_lines: int = 0
    parsed_count: int = 0
    skipped_count: int = 0
    error_count: int = 0
    errors: list[dict] = Field(default_factory=list, description="Line number and error message for failed lines")
    format_detected: Optional[str] = None


class IOCType(str, enum.Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IOC(BaseModel):
    """An extracted Indicator of Compromise."""
    value: str
    ioc_type: IOCType
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_ids: list[str] = Field(default_factory=list)
    context: str = ""
    is_private: bool = False  # For private/reserved IPs


class Finding(BaseModel):
    """A security detection finding."""
    id: str
    title: str
    severity: Severity
    rule_id: str
    rule_name: str
    description: str
    explanation: str
    evidence_strength: str = Field(description="One of: Weak, Moderate, Strong")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_ips: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    event_count: int = 0
    event_ids: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    investigation_status: InvestigationStatus = InvestigationStatus.NEW
    analyst_notes: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Complete analysis output."""
    analysis_id: str
    analysis_timestamp: datetime
    dataset_name: Optional[str] = None
    parse_result: ParseResult
    events: list[ParsedEvent]
    findings: list[Finding] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
