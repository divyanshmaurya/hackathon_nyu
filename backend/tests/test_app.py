"""Hardening of the public HTTP surface: rate limits, upload caps, input
bounds, security headers, sanitized errors, and the legal pages.

These are about keeping a single unauthenticated request's cost fixed
regardless of what a caller sends — the same "absence of evidence is never
evidence" discipline the detectors follow, applied to the API boundary that
carries them.
"""
from __future__ import annotations

import io
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import app as app_module  # noqa: E402
from groundtruth.ratelimit import FixedWindowLimiter  # noqa: E402

OFFERS = pathlib.Path(__file__).resolve().parents[2] / "samples" / "offers"
CLEAN_PDF = OFFERS / "05_control_hand_filled.pdf"

client = TestClient(app_module.app)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Every test gets a fresh limiter window, whichever object is current."""
    app_module._verify_limiter.reset()
    yield
    app_module._verify_limiter.reset()


def _form(**overrides) -> dict:
    data = {"sender": "recruiter@datadoghq.com", "company": "Datadog",
            "message": "Hi, following up on your application."}
    data.update(overrides)
    return data


# --------------------------------------------------------------- headers ---

def test_security_headers_present_on_every_response():
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" in r.headers
    assert "x-request-id" in r.headers


def test_health_reports_operational_limits():
    body = client.get("/api/health").json()
    assert body["rate_limit_per_minute"] > 0
    assert body["max_upload_mb"] > 0


# ------------------------------------------------------------- legal pages -

def test_privacy_and_terms_are_served():
    assert client.get("/privacy").status_code == 200
    assert client.get("/terms").status_code == 200


def test_landing_page_links_to_privacy_and_terms():
    html = client.get("/").text
    assert "/privacy" in html
    assert "/terms" in html


def test_privacy_page_does_not_overclaim_storage():
    # The page must accurately describe the finally-block deletion behaviour
    # in app.py, not aspirational language a real audit would contradict.
    text = client.get("/privacy").text.lower()
    assert "not stored" in text or "no database" in text


# --------------------------------------------------------------- input caps

def test_oversized_message_is_rejected():
    r = client.post("/api/verify", data=_form(message="x" * 25_000))
    assert r.status_code == 422


def test_missing_sender_is_rejected():
    r = client.post("/api/verify", data={"company": "Datadog"})
    assert r.status_code == 422


def test_oversized_document_is_rejected(monkeypatch):
    monkeypatch.setattr(app_module, "_MAX_UPLOAD_BYTES", 1024)
    big = io.BytesIO(b"%PDF-1.4\n" + b"0" * 4096)
    r = client.post("/api/verify", data=_form(),
                    files={"document": ("offer.pdf", big, "application/pdf")})
    assert r.status_code == 413


def test_document_within_cap_is_processed(monkeypatch):
    monkeypatch.setattr(app_module, "_MAX_UPLOAD_BYTES", 10 * 1024 * 1024)
    with open(CLEAN_PDF, "rb") as fh:
        r = client.post("/api/verify", data=_form(),
                        files={"document": ("offer.pdf", fh, "application/pdf")})
    assert r.status_code == 200
    assert r.json()["document"]["verdict"] == "clean"


# --------------------------------------------------------- rate limiting ---

def test_rate_limit_returns_429_with_retry_after(monkeypatch):
    monkeypatch.setattr(app_module, "_verify_limiter",
                        FixedWindowLimiter(limit=2, window_seconds=60.0))
    for _ in range(2):
        assert client.post("/api/verify", data=_form()).status_code == 200
    r = client.post("/api/verify", data=_form())
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers.keys()}


def test_stream_endpoint_is_also_rate_limited(monkeypatch):
    monkeypatch.setattr(app_module, "_verify_limiter",
                        FixedWindowLimiter(limit=1, window_seconds=60.0))
    ok = client.post("/api/verify/stream", data=_form(),
                     headers={"x-forwarded-for": "198.51.100.1"})
    assert ok.status_code == 200
    blocked = client.post("/api/verify/stream", data=_form(),
                          headers={"x-forwarded-for": "198.51.100.1"})
    assert blocked.status_code == 429


def test_stream_endpoint_rejects_oversized_upload(monkeypatch):
    monkeypatch.setattr(app_module, "_MAX_UPLOAD_BYTES", 1024)
    big = io.BytesIO(b"%PDF-1.4\n" + b"0" * 4096)
    r = client.post("/api/verify/stream", data=_form(),
                    files={"document": ("offer.pdf", big, "application/pdf")})
    assert r.status_code == 413


def test_rate_limit_is_keyed_per_client():
    """Two different forwarded-for identities each get their own budget."""
    app_module._verify_limiter.reset()
    limit = app_module._verify_limiter.limit
    for _ in range(limit):
        r = client.post("/api/verify", data=_form(),
                        headers={"x-forwarded-for": "203.0.113.5"})
        assert r.status_code == 200
    blocked = client.post("/api/verify", data=_form(),
                          headers={"x-forwarded-for": "203.0.113.5"})
    assert blocked.status_code == 429

    still_ok = client.post("/api/verify", data=_form(),
                           headers={"x-forwarded-for": "203.0.113.9"})
    assert still_ok.status_code == 200


# --------------------------------------------------------- error handling --

def test_unhandled_error_returns_sanitized_500(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("boom: internal stack detail that must not leak")
    monkeypatch.setattr(app_module, "verify", boom)
    # Starlette's ServerErrorMiddleware always re-raises after building the
    # response, specifically so servers/tests see the real exception in
    # logs -- raise_server_exceptions=False is the documented way to still
    # get the response object back in a test, which is what we're asserting.
    quiet_client = TestClient(app_module.app, raise_server_exceptions=False)
    r = quiet_client.post("/api/verify", data=_form())
    assert r.status_code == 500
    assert "boom" not in r.text
    assert "internal stack detail" not in r.text
    # The response must still say plainly that nothing was verified, per the
    # house rule that a failure is never dressed up as a clean result.
    assert "not" in r.json()["detail"].lower()
