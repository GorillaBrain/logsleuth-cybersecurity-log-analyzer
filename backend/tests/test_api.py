"""Tests for FastAPI endpoints."""
import pytest
from httpx import AsyncClient, ASGITransport
from logsleuth.api import app
from logsleuth.samples import get_sample


@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_supported_formats():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/supported-formats")
        assert response.status_code == 200
        data = response.json()
        format_ids = [f["id"] for f in data["formats"]]
        assert "auth_log" in format_ids
        assert "apache_access" in format_ids
        assert "jsonl" in format_ids


@pytest.mark.asyncio
async def test_detection_rules():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/detection-rules")
        assert response.status_code == 200
        data = response.json()
        assert len(data["rules"]) >= 8
        assert "brute_force_threshold" in data["default_config"]


@pytest.mark.asyncio
async def test_analyze_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        content = get_sample("auth_bruteforce")
        payload = {
            "content": content,
            "dataset_name": "test_bruteforce",
            "format_hint": "auth_log",
        }
        response = await client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["dataset_name"] == "test_bruteforce"
        assert len(data["findings"]) >= 3
        assert len(data["events"]) == 53
        assert data["summary"]["total_events"] == 53


@pytest.mark.asyncio
async def test_analyze_empty_content():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze", json={"content": "   "})
        assert response.status_code == 400
