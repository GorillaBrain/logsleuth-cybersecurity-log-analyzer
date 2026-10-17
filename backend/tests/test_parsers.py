"""Tests for log parsers."""
import pytest
from logsleuth.parsers import (
    detect_format,
    parse_logs,
    AuthLogParser,
    SyslogParser,
    ApacheAccessParser,
    NginxAccessParser,
    JSONLParser,
    CSVLogParser,
    GenericParser,
)
from logsleuth.models import EventCategory, Severity
from logsleuth.samples import get_sample


def test_auth_log_parser_normal():
    content = get_sample("auth_normal")
    parser = AuthLogParser()
    result = parser.parse(content)
    assert result.total_lines > 0
    assert result.parsed_count == result.total_lines
    assert result.error_count == 0
    assert result.format_detected == "auth_log"
    assert any(e.username == "alice" for e in result.events)
    assert any(e.event_action == "sudo_command" for e in result.events)


def test_auth_log_parser_failed_and_accepted():
    log = """Oct 15 09:01:02 webserver01 sshd[123]: Failed password for invalid user hacker from 198.51.100.23 port 54101 ssh2
Oct 15 09:05:00 webserver01 sshd[124]: Accepted password for admin from 198.51.100.23 port 54102 ssh2"""
    parser = AuthLogParser()
    res = parser.parse(log)
    assert res.parsed_count == 2
    assert res.events[0].event_action == "login_failed_invalid_user"
    assert res.events[0].username == "hacker"
    assert res.events[0].source_ip == "198.51.100.23"
    assert res.events[1].event_action == "login_success"
    assert res.events[1].username == "admin"


def test_apache_access_parser():
    content = get_sample("web_recon")
    parser = ApacheAccessParser()
    result = parser.parse(content)
    assert result.parsed_count > 50
    assert result.format_detected == "apache_access"
    assert any(e.http_status == 404 for e in result.events)
    assert any(e.http_method == "GET" for e in result.events)


def test_jsonl_parser():
    content = get_sample("mixed_application")
    parser = JSONLParser()
    result = parser.parse(content)
    assert result.parsed_count > 40
    assert result.format_detected == "jsonl"
    assert any(e.severity == Severity.MEDIUM for e in result.events)


def test_csv_parser():
    csv_content = """timestamp,source_ip,username,message,severity
2024-10-15 10:00:00,192.0.2.1,alice,Successful login,info
2024-10-15 10:01:00,198.51.100.5,admin,Failed password attempt,warning"""
    parser = CSVLogParser()
    result = parser.parse(csv_content)
    assert result.parsed_count == 2
    assert result.events[0].source_ip == "192.0.2.1"
    assert result.events[0].username == "alice"
    assert result.events[1].source_ip == "198.51.100.5"
    assert result.events[1].severity == Severity.LOW


def test_syslog_parser():
    syslog_content = """Oct 15 10:00:00 server01 kernel[0]: [    0.000000] Linux version 5.15.0
Oct 15 10:01:00 server01 app[101]: Critical condition on database connecting to 192.0.2.99"""
    parser = SyslogParser()
    result = parser.parse(syslog_content)
    assert result.parsed_count == 2
    assert result.events[1].severity == Severity.HIGH
    assert result.events[1].source_ip == "192.0.2.99"


def test_generic_fallback_parser():
    log = "Random unformatted log line with an IP 203.0.113.195 and ERROR keyword"
    parser = GenericParser()
    result = parser.parse(log)
    assert result.parsed_count == 1
    assert result.events[0].source_ip == "203.0.113.195"
    assert result.events[0].severity == Severity.MEDIUM


def test_router_auto_detection():
    auth_content = get_sample("auth_normal")
    assert detect_format(auth_content) == "auth_log"
    
    web_content = get_sample("web_recon")
    assert detect_format(web_content) in ["apache_access", "nginx_access"]
    
    json_content = get_sample("mixed_application")
    assert detect_format(json_content) == "jsonl"
