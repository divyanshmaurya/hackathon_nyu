"""Command-line entry point.

    python3 -m groundtruth.cli verify --from hr@x.top --company "Acme" --message-file m.txt
    python3 -m groundtruth.cli demo
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .corroborate.transport import CassetteTransport, default_transport
from .integrity.findings import Severity
from .verify import verify

C = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
     "low": "\033[36m", "info": "\033[32m", "dim": "\033[2m", "b": "\033[1m", "0": "\033[0m"}


def _c(s: str, k: str) -> str:
    return f"{C.get(k, '')}{s}{C['0']}" if sys.stdout.isatty() else s


def render(v) -> str:
    out: list[str] = []
    sev = v.max_severity.value
    out.append("")
    out.append(_c(f"  {sev.upper()}  ", sev))
    out.append(_c(v.headline, "b"))
    out.append("")
    out.append(f"  From:    {v.sender}")
    if v.claimed_company:
        out.append(f"  Claims:  {v.claimed_company}")
    if v.employer and v.employer.likely_domain:
        out.append(f"  Real domain: {_c(v.employer.likely_domain, 'b')} "
                   f"({v.employer.confidence:.0%} confidence)")
    out.append("")

    tiers = {"illegal": "NOT LAWFUL TO ASK", "harmful": "PUTS YOU AT RISK",
             "context": "WORTH KNOWING"}
    shown: set[str] = set()
    for tier, heading in tiers.items():
        group = [f for f in v.findings if f.meta.get("tier") == tier]
        if not group:
            continue
        out.append(_c(f"  ── {heading} ──", "b"))
        for f in group:
            shown.add(f.code)
            out.append(f"   {_c('●', f.severity.value)} {_c(f.title, 'b')}")
            out.append(f"     {f.detail[:220]}")
            if f.remediation:
                out.append(_c(f"     → {f.remediation[:200]}", "dim"))
        out.append("")

    rest = [f for f in v.findings if f.code not in shown]
    if rest:
        out.append(_c("  ── ABOUT THE SENDER ──", "b"))
        for f in rest:
            out.append(f"   {_c('●', f.severity.value)} {_c(f.title, 'b')}")
            out.append(f"     {f.detail[:220]}")
            if f.remediation:
                out.append(_c(f"     → {f.remediation[:200]}", "dim"))
        out.append("")

    out.append(_c("  WHAT TO DO", "b"))
    for line in _wrap(v.recommendation, 74):
        out.append(f"  {line}")
    out.append("")
    if v.trace:
        t = v.trace.to_dict()
        out.append(_c(f"  trace {t['run_id'][:8]} · {len(t['steps'])} steps · "
                      f"{t['total_ms']}ms · {t['note'] or 'submitted to PRISM'}", "dim"))
    return "\n".join(out)


def _wrap(text: str, width: int) -> list[str]:
    words, line, lines = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line); line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


DEMOS = [
    ("OPT consultancy scam", "hr@apex-global-consultancy.top",
     "Apex Global Consultancy Inc",
     """Congratulations! You have been selected for a Software Developer position with
a leading Fortune 500 client. No interview is required. We charge a one-time
registration fee of $1,500 which covers training and documentation. Don't worry if you
lack experience - we will create work experience letters for you so your OPT
requirements are met. You will be on bench until we find a client project; salary
starts once billing begins. Please share your SSN, passport copy and I-20 today.
Payment can be made via Zelle. This offer expires in 24 hours. Contact us on WhatsApp."""),
    ("Look-alike of a real employer", "careers@dataddoghq.com", "Datadog",
     "Hi, we'd like to move forward with your application. Please confirm your details."),
    ("Legitimate recruiter", "recruiter@datadoghq.com", "Datadog",
     """Hi Alex, I'm a recruiter at Datadog. I came across your GitHub and wondered if
you'd be open to chatting about our Platform Engineering team. Happy to set up a
30-minute call next week — no pressure if the timing isn't right."""),
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="groundtruth", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    vp = sub.add_parser("verify", help="check one piece of recruiter outreach")
    vp.add_argument("--from", dest="sender", required=True)
    vp.add_argument("--company", default=None)
    vp.add_argument("--message", default="")
    vp.add_argument("--message-file", default=None)
    vp.add_argument("--document", default=None, help="attached offer letter (PDF)")
    vp.add_argument("--cassettes", default=None)
    vp.add_argument("--json", action="store_true")

    dp = sub.add_parser("demo", help="run the built-in demo cases")
    dp.add_argument("--cassettes", default="tests/cassettes")

    a = ap.parse_args(argv)

    if a.cmd == "demo":
        tp = (CassetteTransport(a.cassettes)
              if pathlib.Path(a.cassettes).is_dir() else default_transport())
        for title, sender, company, msg in DEMOS:
            print("\n" + "═" * 78)
            print(_c(f"  {title}", "b"))
            print("═" * 78)
            print(render(verify(sender, msg, company, transport=tp)))
        return 0

    msg = a.message
    if a.message_file:
        msg = pathlib.Path(a.message_file).read_text()
    tp = (CassetteTransport(a.cassettes)
          if a.cassettes and pathlib.Path(a.cassettes).is_dir() else default_transport())
    v = verify(a.sender, msg, a.company, document_path=a.document, transport=tp)
    print(json.dumps(v.to_dict(), indent=2) if a.json else render(v))
    return 2 if v.max_severity >= Severity.HIGH else 0


if __name__ == "__main__":
    raise SystemExit(main())
