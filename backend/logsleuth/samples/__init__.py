"""Bundled synthetic sample datasets for demonstration."""
from pathlib import Path

SAMPLES_DIR = Path(__file__).parent


def get_sample(name: str) -> str:
    """Load a sample dataset by name."""
    path = SAMPLES_DIR / f"{name}.log"
    if not path.exists():
        raise FileNotFoundError(f"Sample dataset '{name}' not found")
    return path.read_text(encoding="utf-8")


def list_samples() -> list[dict]:
    """List available sample datasets."""
    return [
        {
            "id": "auth_normal",
            "name": "Normal Linux Authentication Activity",
            "description": "Routine SSH logins, sudo usage, and session activity. Demonstrates normal baseline behavior.",
            "format": "auth_log",
        },
        {
            "id": "auth_bruteforce",
            "name": "SSH Brute-Force Attack",
            "description": "Repeated SSH failures followed by a suspicious successful login. Demonstrates brute-force detection.",
            "format": "auth_log",
        },
        {
            "id": "web_recon",
            "name": "Web Server Reconnaissance",
            "description": "Apache access logs with directory scanning, sensitive path probes, and normal traffic.",
            "format": "apache_access",
        },
        {
            "id": "mixed_application",
            "name": "Mixed Application Logs",
            "description": "JSON-formatted application logs with errors, auth events, and unusual patterns.",
            "format": "jsonl",
        },
    ]
