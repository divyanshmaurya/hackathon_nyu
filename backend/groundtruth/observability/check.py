"""One command that proves the PRISM setup end to end.

Runs the sequence the PRISM setup brief asks for:

  1. handshake  — does the credential authenticate?
  2. live run   — a real verification, traced, not a synthetic
  3. doctor     — did a non-demo trace actually arrive?

It exists because editing files is not evidence that traces arrive, and
because the environment this repository was built in cannot reach PRISM at all
(the egress policy returns 403 on CONNECT). Everything here therefore has to be
runnable by a human in one step, on a machine with network access.
"""

from __future__ import annotations

import json
import sys

DOCTOR_PATH = "/api/setup-doctor"
HANDSHAKE_PATH = "/api/setup-doctor/handshake"


class Unreachable(RuntimeError):
    """The host could not be contacted, as distinct from rejecting us."""


def _host() -> str:
    import os
    from prismtrace._config import resolve_host
    return resolve_host(os.environ.get("PRISMTRACE_HOST")).rstrip("/")


def handshake(api_key: str, project_id: str, host: str) -> tuple[bool, str]:
    import httpx

    try:
        r = httpx.post(
            f"{host}{HANDSHAKE_PATH}",
            headers={"Content-Type": "application/json",
                     # Not a Bearer token: that is a dashboard session and 401s.
                     "X-PRISMtrace-Key": api_key},
            json={"project_id": project_id, "send_test_trace": True,
                  "client": "claude_code"},
            timeout=25.0,
        )
    except Exception as exc:
        # Unreachable is not invalid. Reporting a network failure as a bad
        # credential sends the reader to rotate a key that was fine, which is
        # the same "absence of evidence is not evidence" rule the findings
        # model enforces.
        raise Unreachable(f"could not reach {host}: {exc}") from exc

    if r.status_code == 200:
        return True, "credential valid, synthetic trace stored"
    try:
        detail = r.json().get("detail", r.text)
    except Exception:
        detail = r.text
    return False, f"HTTP {r.status_code}: {detail}"


def doctor(api_key: str, project_id: str, host: str) -> tuple[dict, str]:
    import httpx

    try:
        r = httpx.get(f"{host}{DOCTOR_PATH}", params={"project_id": project_id},
                      headers={"X-PRISMtrace-Key": api_key}, timeout=25.0)
    except Exception as exc:
        return {}, f"could not reach doctor: {exc}"
    if r.status_code != 200:
        return {}, f"HTTP {r.status_code}: {r.text[:300]}"
    try:
        return r.json(), ""
    except Exception as exc:
        return {}, f"doctor returned non-JSON: {exc}"


def run(verbose: bool = True) -> int:
    import os

    from .prism import PrismRecorder
    from ..config import load_env

    load_env()
    api_key = os.environ.get("PRISMTRACE_API_KEY", "")
    project_id = os.environ.get("PRISMTRACE_PROJECT_ID", "")

    def say(*a):
        if verbose:
            print(*a)

    if not api_key or not project_id:
        say("\n  CREDENTIAL FAIL: PRISMTRACE_API_KEY and PRISMTRACE_PROJECT_ID "
            "must both be set (see .env.example).\n")
        return 1

    host = _host()
    say(f"\n  host        {host}")
    say(f"  project     {project_id}")
    say(f"  key         {api_key[:8]}…{api_key[-4:]}\n")

    say("  1/3  handshake …")
    try:
        ok, detail = handshake(api_key, project_id, host)
    except Unreachable as exc:
        say(f"\n  CREDENTIAL UNVERIFIED: {exc}")
        say("       The credential was not rejected — it was never checked. A "
            "403 on CONNECT\n       means an egress policy blocked the request "
            "before it left this machine.\n       Run this from a network that "
            "can reach the host.\n")
        return 3
    if not ok:
        say(f"\n  CREDENTIAL FAIL: {detail}\n")
        return 1
    say(f"       CREDENTIAL OK — {detail}\n")

    # A real traced run. The brief is explicit that a handshake synthetic does
    # not count as live, so this drives the actual verification pipeline.
    say("  2/3  emitting a live trace from a real verification …")
    from ..corroborate.transport import CassetteTransport, default_transport
    from ..verify import verify
    import pathlib

    cassettes = pathlib.Path(__file__).resolve().parents[2] / "tests" / "cassettes"
    transport = (default_transport(cassettes) if not os.environ.get("TAVILY_API_KEY")
                 else default_transport())
    recorder = PrismRecorder()
    if not recorder.enabled:
        say(f"       could not initialise the PRISM client: {recorder.why_disabled()}")
        return 1

    v = verify("careers@dataddoghq.com",
               "Hi, we'd like to move forward with your application.",
               "Datadog", transport=transport, recorder=recorder)
    t = v.trace
    say(f"       run {t.run_id[:8]} · {len(t.steps)} steps · "
        f"verdict {v.max_severity.value} · {t.note}")
    if not t.submitted:
        say(f"\n  WAITING FOR LIVE: trajectory was not accepted — {t.note}\n")
        return 1
    say(f"       trajectory {t.trajectory_id}\n")

    say("  3/3  re-checking the doctor …")
    data, err = doctor(api_key, project_id, host)
    if err:
        say(f"\n  WAITING FOR LIVE: doctor unreachable — {err}\n")
        return 1

    live = bool(data.get("live_connected"))
    blocked = data.get("blocked_step") or "-"
    overall = data.get("overall") or "-"
    say(f"       live_connected={live}  blocked_step={blocked}  overall={overall}\n")

    if live:
        say("  LIVE CONNECTED: PRISM is receiving live traces from the "
            "Groundtruth verification pipeline.\n")
        return 0

    say(f"  WAITING FOR LIVE: blocked at '{blocked}'. Analysis lag is not a "
        f"setup failure — re-run this in a minute if the step is "
        f"'analysis_ready'.\n")
    if verbose:
        print("  doctor response:")
        print("   " + json.dumps(data, indent=2)[:900].replace("\n", "\n   "))
    return 2


if __name__ == "__main__":
    sys.exit(run())
