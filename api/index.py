"""Vercel serverless entrypoint.

Vercel looks for an ASGI app named `app` in a module under `api/`. The real
application lives in `backend/`, so this adds it to the path and re-exports it.
"""
from __future__ import annotations

import pathlib
import sys

BACKEND = pathlib.Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from app import app  # noqa: E402,F401  (re-exported for Vercel)
