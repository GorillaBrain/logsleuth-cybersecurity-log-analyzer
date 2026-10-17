"""Tests for IOC extraction."""
from logsleuth.models import ParsedEvent, IOCType
from logsleuth.ioc_extractor import extract_iocs


def test_ioc_extraction():
    events = [
        ParsedEvent(
            id="e-1",
            raw_message="Suspicious connection to 93.184.216.34 downloading malware from http://malicious.evil.com/payload.exe",
        ),
        ParsedEvent(
            id="e-2",
            raw_message="Internal log from 192.168.1.10 contacted admin@corp.internal, sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ]
    iocs = extract_iocs(events)
    ioc_values = {i.value: i for i in iocs}

    assert "93.184.216.34" in ioc_values
    assert not ioc_values["93.184.216.34"].is_private

    assert "192.168.1.10" in ioc_values
    assert ioc_values["192.168.1.10"].is_private

    assert "malicious.evil.com" in ioc_values
    assert "http://malicious.evil.com/payload.exe" in ioc_values

    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in ioc_values
    assert ioc_values["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].ioc_type == IOCType.SHA256
