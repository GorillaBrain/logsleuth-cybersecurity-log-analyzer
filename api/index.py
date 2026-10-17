"""Vercel Serverless Function entry point for LogSleuth FastAPI backend."""
import sys
from pathlib import Path

# Add backend package directory to python path
root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from logsleuth.api import app

# Export app for Vercel ASGI runner
__all__ = ["app"]
