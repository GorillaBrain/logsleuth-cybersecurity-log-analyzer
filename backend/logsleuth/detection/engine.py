"""Detection engine that runs all rules against parsed events."""
from __future__ import annotations
from ..models import ParsedEvent, Finding
from .rules import DETECTION_RULES, DetectionRule

# Default detection configuration
DEFAULT_CONFIG = {
    "brute_force_threshold": 5,
    "brute_force_window_minutes": 10,
    "password_spray_min_users": 3,
    "success_after_failure_min": 3,
    "http_404_threshold": 10,
    "http_auth_failure_threshold": 5,
    "high_volume_threshold": 100,
    "error_burst_threshold": 10,
    "error_burst_window_minutes": 5,
}


class DetectionEngine:
    """Runs detection rules against parsed events."""
    
    def __init__(self, config: dict | None = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rules: list[DetectionRule] = [rule_cls() for rule_cls in DETECTION_RULES]
    
    def analyze(self, events: list[ParsedEvent]) -> list[Finding]:
        """Run all detection rules and return findings."""
        all_findings: list[Finding] = []
        
        for rule in self.rules:
            try:
                findings = rule.evaluate(events, self.config)
                all_findings.extend(findings)
            except Exception:
                # Don't let a single rule failure break analysis
                pass
        
        # Mark events as suspicious based on findings
        suspicious_event_ids = set()
        for f in all_findings:
            suspicious_event_ids.update(f.event_ids)
        
        for event in events:
            if event.id in suspicious_event_ids:
                event.is_suspicious = True
                # Collect detection IDs
                for f in all_findings:
                    if event.id in f.event_ids:
                        event.detection_ids.append(f.rule_id)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))
        
        return all_findings
    
    def get_rules_info(self) -> list[dict]:
        """Return information about all detection rules."""
        return [
            {
                "rule_id": rule.RULE_ID,
                "rule_name": rule.RULE_NAME,
                "description": rule.DESCRIPTION,
                "mitre_technique": rule.MITRE_TECHNIQUE,
                "configurable_thresholds": {
                    k: v for k, v in self.config.items()
                    if rule.RULE_ID.split('-')[0].lower() in k or k.startswith(rule.RULE_ID.lower().replace('-', '_'))
                },
            }
            for rule in self.rules
        ]
