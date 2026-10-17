"""FastAPI REST API for LogSleuth."""
from __future__ import annotations
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from .analyzer import analyze_logs
from .detection.engine import DetectionEngine, DEFAULT_CONFIG
from .models import AnalysisResult

app = FastAPI(
    title="LogSleuth API",
    description="Cybersecurity Log Analyzer — REST API",
    version="1.0.0",
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configurable in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Maximum content size (10MB)
MAX_CONTENT_SIZE = 10 * 1024 * 1024


class AnalyzeRequest(BaseModel):
    content: str = Field(description="Raw log content to analyze")
    dataset_name: Optional[str] = Field(default=None, description="Optional dataset name")
    format_hint: Optional[str] = Field(default=None, description="Hint for log format")
    column_mapping: Optional[dict[str, str]] = Field(default=None, description="CSV column mapping")
    detection_config: Optional[dict] = Field(default=None, description="Detection threshold overrides")


class HealthResponse(BaseModel):
    status: str
    version: str


@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", version="1.0.0")


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze(request: AnalyzeRequest):
    """Analyze log content and return findings."""
    if len(request.content) > MAX_CONTENT_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Content too large. Maximum size is {MAX_CONTENT_SIZE // (1024*1024)}MB."
        )
    
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    
    try:
        result = analyze_logs(
            content=request.content,
            dataset_name=request.dataset_name,
            format_hint=request.format_hint,
            column_mapping=request.column_mapping,
            detection_config=request.detection_config,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


@app.get("/api/detection-rules")
async def get_detection_rules():
    """Return information about detection rules."""
    engine = DetectionEngine()
    return {
        "rules": engine.get_rules_info(),
        "default_config": DEFAULT_CONFIG,
    }


@app.get("/api/supported-formats")
async def supported_formats():
    """Return supported log formats."""
    return {
        "formats": [
            {"id": "auth_log", "name": "Linux Auth Log", "description": "SSH/PAM/sudo authentication logs"},
            {"id": "syslog", "name": "Syslog", "description": "Generic syslog messages"},
            {"id": "apache_access", "name": "Apache Access Log", "description": "Apache combined access logs"},
            {"id": "nginx_access", "name": "Nginx Access Log", "description": "Nginx combined access logs"},
            {"id": "jsonl", "name": "JSON Lines", "description": "Newline-separated JSON objects"},
            {"id": "csv", "name": "CSV", "description": "Comma-separated values with headers"},
            {"id": "generic", "name": "Generic", "description": "Fallback parser for any text log"},
        ]
    }
