"""Tests for detection rules and detection engine."""
import pytest
from datetime import datetime, timezone
from logsleuth.models import ParsedEvent, Severity, EventCategory
from logsleuth.detection.engine import DetectionEngine
from logsleuth.detection.rules import (
    BruteForceRule,
    PasswordSprayRule,
    SuccessAfterFailureRule,
    HTTPReconRule,
    SensitivePathRule,
    HTTPAuthFailureRule,
    HighVolumeRule,
    SystemErrorBurstRule,
)
from logsleuth.samples import get_sample
from logsleuth.parsers.router import parse_logs


def test_brute_force_rule():
    rule = BruteForceRule()
    events = [
        ParsedEvent(
            id=f"e-{i}",
            timestamp=datetime(2024, 10, 15, 10, i, 0, tzinfo=timezone.utc),
            raw_message=f"Failed password for user test from 198.51.100.1",
            source_ip="198.51.100.1",
            username="test",
            event_action="login_failed",
        )
        for i in range(6)
    ]
    findings = rule.evaluate(events, {"brute_force_threshold": 5, "brute_force_window_minutes": 10})
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-001"
    assert "198.51.100.1" in findings[0].source_ips


def test_password_spray_rule():
    rule = PasswordSprayRule()
    events = [
        ParsedEvent(
            id=f"e-{i}",
            timestamp=datetime(2024, 10, 15, 10, i, 0, tzinfo=timezone.utc),
            raw_message=f"Failed password for user_{i} from 198.51.100.2",
            source_ip="198.51.100.2",
            username=f"user_{i}",
            event_action="login_failed",
        )
        for i in range(4)
    ]
    findings = rule.evaluate(events, {"password_spray_min_users": 3})
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-002"
    assert len(findings[0].usernames) == 4


def test_success_after_failure_rule():
    rule = SuccessAfterFailureRule()
    events = [
        ParsedEvent(
            id=f"e-{i}",
            timestamp=datetime(2024, 10, 15, 10, i, 0, tzinfo=timezone.utc),
            raw_message=f"Failed login attempt",
            source_ip="198.51.100.3",
            username="admin",
            event_action="login_failed",
        )
        for i in range(3)
    ]
    events.append(
        ParsedEvent(
            id="e-success",
            timestamp=datetime(2024, 10, 15, 10, 4, 0, tzinfo=timezone.utc),
            raw_message="Accepted password for admin",
            source_ip="198.51.100.3",
            username="admin",
            event_action="login_success",
        )
    )
    findings = rule.evaluate(events, {"success_after_failure_min": 3})
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-003"
    assert findings[0].severity == Severity.HIGH


def test_http_recon_rule():
    rule = HTTPReconRule()
    events = [
        ParsedEvent(
            id=f"e-{i}",
            timestamp=datetime(2024, 10, 15, 10, 0, i, tzinfo=timezone.utc),
            raw_message="GET /missing",
            source_ip="198.51.100.4",
            http_status=404,
            http_path=f"/path_{i}",
        )
        for i in range(12)
    ]
    findings = rule.evaluate(events, {"http_404_threshold": 10})
    assert len(findings) == 1
    assert findings[0].rule_id == "WEB-001"


def test_sensitive_path_and_traversal_rule():
    rule = SensitivePathRule()
    events = [
        ParsedEvent(
            id="e-trav",
            raw_message="GET /../../etc/passwd",
            http_path="/../../etc/passwd",
            source_ip="198.51.100.5",
        ),
        ParsedEvent(
            id="e-env",
            raw_message="GET /.env",
            http_path="/.env",
            source_ip="198.51.100.5",
        ),
    ]
    findings = rule.evaluate(events, {})
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert all(r == "WEB-002" for r in rule_ids)
    titles = [f.title for f in findings]
    assert any("traversal" in t.lower() for t in titles)
    assert any("sensitive" in t.lower() for t in titles)


def test_detection_engine_sample_bruteforce():
    content = get_sample("auth_bruteforce")
    parsed = parse_logs(content)
    engine = DetectionEngine()
    findings = engine.analyze(parsed.events)
    assert len(findings) >= 3
    rule_ids = {f.rule_id for f in findings}
    assert "AUTH-001" in rule_ids
    assert "AUTH-002" in rule_ids
    assert "AUTH-003" in rule_ids
    assert any(e.is_suspicious for e in parsed.events)
