"""Main analysis orchestrator."""
from __future__ import annotations
import uuid
from collections import Counter
from datetime import datetime, timezone
from .models import AnalysisResult, ParseResult, ParsedEvent, Finding, Severity, EventCategory
from .parsers.router import parse_logs
from .detection.engine import DetectionEngine, DEFAULT_CONFIG
from .ioc_extractor import extract_iocs


def analyze_logs(
    content: str,
    dataset_name: str | None = None,
    format_hint: str | None = None,
    column_mapping: dict | None = None,
    detection_config: dict | None = None,
) -> AnalysisResult:
    """Full pipeline: parse -> detect -> extract IOCs -> summarize."""
    # Parse
    parse_result = parse_logs(content, format_hint=format_hint, column_mapping=column_mapping)
    events = parse_result.events
    
    # Detect
    engine = DetectionEngine(config=detection_config)
    findings = engine.analyze(events)
    
    # Extract IOCs
    iocs = extract_iocs(events)
    
    # Build summary
    summary = _build_summary(events, findings, parse_result)
    
    return AnalysisResult(
        analysis_id=str(uuid.uuid4()),
        analysis_timestamp=datetime.now(timezone.utc),
        dataset_name=dataset_name,
        parse_result=parse_result,
        events=events,
        findings=findings,
        iocs=iocs,
        summary=summary,
    )


def _build_summary(events: list[ParsedEvent], findings: list[Finding], parse_result: ParseResult) -> dict:
    """Build an analysis summary dict."""
    severity_counts = Counter(f.severity.value for f in findings)
    category_counts = Counter(e.event_category.value for e in events)
    
    # Top IPs
    ip_counts = Counter(e.source_ip for e in events if e.source_ip)
    top_ips = [{'ip': ip, 'count': count} for ip, count in ip_counts.most_common(10)]
    
    # Top usernames
    user_counts = Counter(e.username for e in events if e.username)
    top_users = [{'username': u, 'count': c} for u, c in user_counts.most_common(10)]
    
    # Auth stats
    auth_events = [e for e in events if e.event_category == EventCategory.AUTHENTICATION]
    auth_success = sum(1 for e in auth_events if e.event_action and 'success' in e.event_action.lower())
    auth_failed = sum(1 for e in auth_events if e.event_action and 'fail' in e.event_action.lower())
    
    # Timeline (events per hour)
    timeline = {}
    for e in events:
        if e.timestamp:
            hour_key = e.timestamp.strftime('%Y-%m-%d %H:00')
            timeline[hour_key] = timeline.get(hour_key, 0) + 1
    
    sorted_timeline = [{'time': k, 'count': v} for k, v in sorted(timeline.items())]
    
    return {
        'total_events': len(events),
        'total_findings': len(findings),
        'severity_counts': dict(severity_counts),
        'category_counts': dict(category_counts),
        'top_source_ips': top_ips,
        'top_usernames': top_users,
        'auth_success': auth_success,
        'auth_failed': auth_failed,
        'timeline': sorted_timeline,
        'parse_stats': {
            'total_lines': parse_result.total_lines,
            'parsed': parse_result.parsed_count,
            'skipped': parse_result.skipped_count,
            'errors': parse_result.error_count,
            'format': parse_result.format_detected,
        },
        'suspicious_events': sum(1 for e in events if e.is_suspicious),
    }
