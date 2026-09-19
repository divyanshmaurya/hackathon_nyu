"""PRISM tracing for verification runs.

Every verification Groundtruth performs is an ordered sequence of checks, which
is exactly the shape PRISM calls a trajectory. Submitting it gives us three
things we would otherwise have to build:

  - an audit trail: "why did this message get flagged, on that date?" stays
    answerable after the fact, which matters because the decisions people make
    from this tool (sign, pay, send documents) are ones they may need to
    reconstruct later;
  - evaluation: PRISM scores the trajectory, so we can tell whether our
    verdicts are stable rather than assuming it;
  - a regression signal when a detector starts behaving differently.

Degrades to a local-only recorder when no API key is configured, so the rest of
the system never has to care whether tracing is on.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Step:
    step_type: str
    label: str
    output_summary: str = ""
    tool_name: str | None = None
    input_summary: str = ""
    duration_ms: int = 0
    status: str = "success"

    def to_prism(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "step_type": self.step_type,
            "label": self.label,
            "output_summary": self.output_summary[:1000],
            "input_summary": self.input_summary[:1000],
            "duration_ms": self.duration_ms,
            "status": self.status,
        }
        if self.tool_name:
            d["tool_name"] = self.tool_name
        return d


@dataclass
class Trace:
    """Accumulates steps for one verification, then ships them to PRISM."""

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    steps: list[Step] = field(default_factory=list)
    submitted: bool = False
    trajectory_id: str | None = None
    note: str = ""
    _t0: float = field(default_factory=time.perf_counter)

    def step(self, step_type: str, label: str, **kw: Any) -> "Trace":
        self.steps.append(Step(step_type=step_type, label=label, **kw))
        return self

    def tool(self, tool_name: str, label: str, out: str = "", inp: str = "",
             ms: int = 0, status: str = "success") -> "Trace":
        return self.step("tool_call", label, tool_name=tool_name,
                         output_summary=out, input_summary=inp,
                         duration_ms=ms, status=status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "trajectory_id": self.trajectory_id,
            "submitted": self.submitted,
            "note": self.note,
            "total_ms": int((time.perf_counter() - self._t0) * 1000),
            "steps": [s.to_prism() for s in self.steps],
        }


class PrismRecorder:
    """Submits traces to PRISM when configured; records locally when not."""

    def __init__(self, api_key: str | None = None, project_id: str | None = None,
                 host: str | None = None, agent_name: str = "groundtruth-verifier"):
        self.agent_name = agent_name
        self.api_key = api_key or os.environ.get("PRISMTRACE_API_KEY")
        self.project_id = project_id or os.environ.get("PRISMTRACE_PROJECT_ID")
        self.host = host or os.environ.get("PRISMTRACE_HOST")
        self._client = None

        if self.api_key and self.project_id:
            try:
                from prismtrace import PRISMtrace
                from prismtrace._config import resolve_host

                self._client = PRISMtrace(
                    api_key=self.api_key,
                    host=resolve_host(self.host),
                    project_id=self.project_id,
                    # The default 10s is per-request; a run emits a trajectory
                    # plus one trace per step, and the tail of those was timing
                    # out on a cold connection.
                    timeout=30,
                )
            except Exception as exc:  # pragma: no cover - depends on env
                self._client = None
                self._init_error = str(exc)

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def why_disabled(self) -> str:
        if self.enabled:
            return ""
        if not self.api_key:
            return ("PRISMTRACE_API_KEY not set — traces recorded locally only. "
                    "Get a key at https://prism.blockconvey.com (Settings → API Keys).")
        if not self.project_id:
            return "PRISMTRACE_PROJECT_ID not set — traces recorded locally only."
        return f"PRISM client failed to initialise: {getattr(self, '_init_error', '?')}"

    def _emit_step_traces(self, trace: Trace) -> None:
        """Also emit per-step traces sharing one session_id.

        The trajectory endpoint records the run; the traces endpoint is what
        the setup doctor watches for `live_connected`, and it reports
        `trace_normalized` when traces arrive without a shared session_id. So
        the run id is used as the session id, which is also what makes the
        steps group into one conversation in the dashboard.

        The model string is deliberately not a model name. Groundtruth's
        verification path is fully deterministic -- there is no LLM in it --
        and labelling these as GPT-anything to make a dashboard look
        conventional would misrepresent what the system does.
        """
        # Only steps that did real work. Emitting a trace for bookkeeping
        # steps triples the request count for no added signal, which is what
        # was pushing the tail past the flush window.
        worth_tracing = [s for s in trace.steps
                         if s.step_type == "tool_call" or s.duration_ms > 0]
        for step in worth_tracing:
            try:
                self._client.trace_llm(  # type: ignore[union-attr]
                    model="groundtruth/rules-engine",
                    input_messages=[{"role": "user",
                                     "content": step.input_summary or step.label}],
                    output=step.output_summary or "",
                    latency_ms=step.duration_ms,
                    session_id=trace.run_id,
                    agent_id=self.agent_name,
                    agent_name=self.agent_name,
                    metadata={"step_type": step.step_type, "label": step.label,
                              "tool": step.tool_name or "", "status": step.status,
                              "deterministic": True},
                )
            except Exception:
                # Step traces are supplementary; never fail a verification over
                # telemetry.
                return

    def submit(self, trace: Trace, final_status: str = "success") -> Trace:
        if not self.enabled:
            trace.note = self.why_disabled()
            return trace
        try:
            resp = self._client.submit_trajectory(  # type: ignore[union-attr]
                [s.to_prism() for s in trace.steps],
                agent_name=self.agent_name,
                agent_id=self.agent_name,
                request_id=trace.run_id,
                final_status=final_status,
            )
            if resp:
                trace.submitted = True
                trace.trajectory_id = resp.get("trajectory_id") or resp.get("id")
                trace.note = "Submitted to PRISM."
                self._emit_step_traces(trace)
                try:
                    # Generous: the process may exit right after this, and an
                    # unflushed trace is simply lost.
                    self._client.flush(timeout=15.0)  # type: ignore[union-attr]
                except Exception:
                    # A telemetry flush must never fail a verification. The
                    # trajectory is already accepted at this point.
                    pass
            else:
                trace.note = "PRISM returned no response; trace kept locally."
        except Exception as exc:
            trace.note = f"PRISM submission failed ({exc}); trace kept locally."
        return trace

    def evaluation(self, trajectory_id: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            return self._client.get_trajectory_evaluation(trajectory_id)  # type: ignore[union-attr]
        except Exception:
            return None
