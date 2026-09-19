"""PRISM setup verification.

The distinction these tests protect: a host we could not reach is not a
credential that was rejected. Conflating them sends someone to rotate a
perfectly good key.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.observability import check  # noqa: E402
from groundtruth.observability.prism import PrismRecorder, Trace  # noqa: E402


def test_unreachable_host_raises_rather_than_reporting_a_bad_key(monkeypatch):
    def boom(*a, **k):
        raise OSError("403 Forbidden")
    monkeypatch.setattr("httpx.post", boom)
    with pytest.raises(check.Unreachable):
        check.handshake("pt-sk-x", "proj", "https://example.invalid")


def test_rejected_credential_is_reported_as_a_failure(monkeypatch):
    class R:
        status_code = 401
        text = '{"detail":"was revoked"}'
        def json(self): return {"detail": "was revoked"}
    monkeypatch.setattr("httpx.post", lambda *a, **k: R())
    ok, detail = check.handshake("pt-sk-x", "proj", "https://example.invalid")
    assert ok is False and "was revoked" in detail


def test_handshake_sends_the_key_header_not_bearer(monkeypatch):
    seen = {}
    class R:
        status_code = 200
        def json(self): return {}
    def capture(url, headers=None, json=None, timeout=None):
        seen.update(headers or {})
        return R()
    monkeypatch.setattr("httpx.post", capture)
    check.handshake("pt-sk-abc", "proj", "https://example.invalid")
    # Bearer is a dashboard session and 401s this key class.
    assert seen.get("X-PRISMtrace-Key") == "pt-sk-abc"
    assert "Authorization" not in seen


def test_missing_credentials_exit_before_any_network_call(monkeypatch):
    monkeypatch.delenv("PRISMTRACE_API_KEY", raising=False)
    monkeypatch.delenv("PRISMTRACE_PROJECT_ID", raising=False)
    monkeypatch.setattr("httpx.post", lambda *a, **k: pytest.fail("called network"))
    assert check.run(verbose=False) == 1


def test_step_traces_are_not_emitted_without_a_client():
    """Telemetry must never be the thing that breaks a verification."""
    r = PrismRecorder()
    assert r.enabled is False
    t = r.submit(Trace().step("reasoning", "x"))
    assert t.submitted is False and "not set" in t.note


def test_step_trace_model_is_not_disguised_as_an_llm():
    """Groundtruth is deterministic; labelling traces as a real model would
    misrepresent the system."""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "groundtruth" / "observability" / "prism.py").read_text()
    assert 'model="groundtruth/rules-engine"' in src
    for fake in ("gpt-4", "gpt-3.5", "claude-3", "gemini"):
        assert f'model="{fake}' not in src


def test_standing_prism_rule_is_present_for_the_next_agent():
    root = pathlib.Path(__file__).resolve().parents[2]
    text = (root / "CLAUDE.md").read_text()
    assert "## PRISM tracing (do not remove)" in text
    assert "Standing rule." in text
    assert "PRISMTRACE_API_KEY" in text
