"""Command-line entry point.

    python3 -m groundtruth.cli verify --from hr@x.top --company "Acme" --message-file m.txt
    python3 -m groundtruth.cli demo
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from .attest.keys import EmployerKey, WELL_KNOWN_PATH
from .attest.resolver import LocalRegistry, default_resolver
from .attest.token import issue as issue_token
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


def _default_cassettes() -> pathlib.Path:
    """Cassettes live next to the package, not next to the user's shell.

    Resolving this relative to the CWD meant `demo` only worked from backend/,
    which is exactly the kind of thing that wastes someone's time at 2am.
    """
    return pathlib.Path(__file__).resolve().parents[1] / "tests" / "cassettes"


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
    vp.add_argument("--attestation", default=None,
                    help="signed attestation token (gt1.…) from the sender")
    vp.add_argument("--me", default=None,
                    help="your own email, to check the attestation was issued for you")
    vp.add_argument("--registry", default=None,
                    help="local directory of well-known key documents (demo/testing)")
    vp.add_argument("--json", action="store_true")

    kp = sub.add_parser("keygen",
                        help="employer: create a signing key and the file to publish")
    kp.add_argument("--domain", required=True)
    kp.add_argument("--contact", default=None, help="abuse-reporting address")
    kp.add_argument("--out", default=".", help="directory to write into")

    ip = sub.add_parser("issue", help="employer: sign an attestation for one message")
    ip.add_argument("--domain", required=True)
    ip.add_argument("--key", required=True, help="path to the private key PEM")
    ip.add_argument("--role", required=True)
    ip.add_argument("--recruiter", required=True)
    ip.add_argument("--to", default=None, help="candidate email (hashed, never stored)")
    ip.add_argument("--days", type=int, default=30)

    dp = sub.add_parser("demo", help="run the built-in demo cases")
    dp.add_argument("--cassettes", default=None)

    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        key = EmployerKey.generate(a.domain)
        out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
        priv = out / f"{a.domain}.private.pem"
        pub = out / "groundtruth.json"
        priv.write_text(key.private_pem()); priv.chmod(0o600)
        pub.write_text(key.well_known_json(a.contact))
        print(f"\n  Signing key   {priv}   (keep secret, never commit)")
        print(f"  Publish       {pub}")
        print(f"                → https://{a.domain}{WELL_KNOWN_PATH}")
        print(f"  Key id        {key.kid}\n")
        print("  Candidates verify signatures against that published file, so the")
        print("  trust anchor is your domain. Groundtruth is never consulted.\n")
        return 0

    if a.cmd == "issue":
        key = EmployerKey.load_private_pem(a.domain, pathlib.Path(a.key).read_text())
        tok = issue_token(key, a.role, a.recruiter, a.to, ttl_days=a.days)
        print(tok)
        return 0

    if a.cmd == "demo":
        cass = pathlib.Path(a.cassettes) if a.cassettes else _default_cassettes()
        tp = CassetteTransport(cass) if cass.is_dir() else default_transport()
        for title, sender, company, msg in DEMOS:
            print("\n" + "═" * 78)
            print(_c(f"  {title}", "b"))
            print("═" * 78)
            print(render(verify(sender, msg, company, transport=tp)))
        return 0

    msg = a.message
    if a.message_file:
        msg = pathlib.Path(a.message_file).read_text()
    cass = pathlib.Path(a.cassettes) if a.cassettes else _default_cassettes()
    tp = (default_transport() if os.environ.get("TAVILY_API_KEY")
          else (CassetteTransport(cass) if cass.is_dir() else default_transport()))
    rs = LocalRegistry(a.registry) if a.registry else default_resolver()
    v = verify(a.sender, msg, a.company, document_path=a.document,
               attestation=a.attestation, recipient_email=a.me,
               transport=tp, resolver=rs)
    print(json.dumps(v.to_dict(), indent=2) if a.json else render(v))
    return 2 if v.max_severity >= Severity.HIGH else 0


if __name__ == "__main__":
    raise SystemExit(main())
