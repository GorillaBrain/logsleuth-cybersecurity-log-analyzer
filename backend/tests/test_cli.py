"""Tests for the LogSleuth CLI."""
import json
import pytest
from logsleuth.cli import main
from pathlib import Path


def test_cli_basic(monkeypatch, capsys, tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_text("Oct 15 10:00:00 server01 sshd[10]: Accepted password for alice from 192.0.2.10 port 22 ssh2\n")

    monkeypatch.setattr("sys.argv", ["logsleuth", str(log_file)])
    main()

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["dataset_name"] == "sample.log"
    assert output["parse_result"]["parsed_count"] == 1


def test_cli_findings_only(monkeypatch, capsys, tmp_path):
    log_file = tmp_path / "auth_failed.log"
    lines = [f"Oct 15 10:0{i}:00 server01 sshd[10{i}]: Failed password for root from 198.51.100.23 port {5000+i} ssh2" for i in range(7)]
    log_file.write_text("\n".join(lines) + "\n")

    monkeypatch.setattr("sys.argv", ["logsleuth", str(log_file), "--findings-only"])
    main()

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert isinstance(output, list)
    assert len(output) >= 1
    assert any(f["rule_id"] == "AUTH-001" for f in output)


def test_cli_output_file(monkeypatch, capsys, tmp_path):
    log_file = tmp_path / "sample.log"
    out_file = tmp_path / "result.json"
    log_file.write_text("Oct 15 10:00:00 server01 sshd[10]: Accepted password for alice from 192.0.2.10 port 22 ssh2\n")

    monkeypatch.setattr("sys.argv", ["logsleuth", str(log_file), "-o", str(out_file)])
    main()

    captured = capsys.readouterr()
    assert "Results written to" in captured.err
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["parse_result"]["parsed_count"] == 1
