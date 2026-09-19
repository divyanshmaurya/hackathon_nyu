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


def test_only_substantive_steps_are_traced(monkeypatch):
    """Bookkeeping steps tripled the request count for no added signal and
    pushed the tail of the flush past its window."""
    sent = []

    class FakeClient:
        def trace_llm(self, **kw): sent.append(kw)
        def flush(self, timeout=0): pass

    r = PrismRecorder.__new__(PrismRecorder)
    r.agent_name = "test"
    r._client = FakeClient()

    t = Trace()
    t.step("reasoning", "bookkeeping only")            # 0ms, not a tool call
    t.tool("tavily.search", "real work", ms=120)
    t.step("final_answer", "summary", duration_ms=5)
    r._emit_step_traces(t)

    labels = [s["metadata"]["label"] for s in sent]
    assert "real work" in labels
    assert "summary" in labels
    assert "bookkeeping only" not in labels


def test_every_emitted_trace_shares_the_run_as_session_id():
    """Without a shared session_id the doctor reports trace_normalized and the
    steps never group into one trajectory."""
    sent = []

    class FakeClient:
        def trace_llm(self, **kw): sent.append(kw)
        def flush(self, timeout=0): pass

    r = PrismRecorder.__new__(PrismRecorder)
    r.agent_name = "test"
    r._client = FakeClient()
    t = Trace()
    t.tool("a", "one", ms=1)
    t.tool("b", "two", ms=2)
    r._emit_step_traces(t)
    assert {s["session_id"] for s in sent} == {t.run_id}


def test_flush_budget_shrinks_on_serverless(monkeypatch):
    """A 15s flush would exceed Vercel Hobby's 10s invocation cap and take the
    response down with it, losing both the trace and the answer."""
    from groundtruth.observability import prism
    monkeypatch.delenv("VERCEL", raising=False)
    assert prism._flush_timeout() == 15.0
    monkeypatch.setenv("VERCEL", "1")
    assert prism._flush_timeout() < 5.0
