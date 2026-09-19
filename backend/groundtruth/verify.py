"""One verification run over a piece of recruiter outreach.

Ties the four checks together in the order that is most useful to a job seeker,
and records the whole thing as a PRISM trajectory so the result stays
explainable after the fact.

Order is deliberate. Employer corroboration runs *before* the final domain
judgement, because knowing the company's real domain turns the sender check
from "this resembles Google" into "this is not Google's domain."
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterator

from .attest.resolver import KeyResolver, KeysUnavailable, default_resolver
from .attest.token import TokenCheck, parse as parse_token, verify as verify_token
from .corroborate.browser import Browser, default_browser
from .corroborate.employer import EmployerEvidence, verify_employer
from .corroborate.posting import PostingEvidence, check_posting
from .corroborate.transport import Transport, default_transport
from .integrity.findings import Finding, Severity
from .integrity.scanner import IntegrityReport, scan_pdf
from .observability.prism import PrismRecorder, Trace
from .outreach.domains import DomainVerdict, analyse as analyse_domain, domain_of
from .outreach.practices import PracticeReport, scan as scan_practices


@dataclass
class Verification:
    sender: str
    claimed_company: str | None
    domain: DomainVerdict | None = None
    practices: PracticeReport | None = None
    employer: EmployerEvidence | None = None
    document: IntegrityReport | None = None
    posting: PostingEvidence | None = None
    attestation: TokenCheck | None = None
    attestation_findings: list[Finding] = field(default_factory=list)
    trace: Trace | None = None
    headline: str = ""
    recommendation: str = ""

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = list(self.attestation_findings)
        for part in (self.domain, self.practices, self.employer, self.document,
                     self.posting):
            if part is not None:
                out.extend(part.findings)
        return sorted(out, key=lambda f: -f.severity.rank)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sender": self.sender,
            "claimed_company": self.claimed_company,
            "headline": self.headline,
            "recommendation": self.recommendation,
            "max_severity": self.max_severity.value,
            "finding_count": len(self.findings),
            "domain": self.domain.to_dict() if self.domain else None,
            "practices": self.practices.to_dict() if self.practices else None,
            "employer": self.employer.to_dict() if self.employer else None,
            "document": self.document.to_dict() if self.document else None,
            "posting": self.posting.to_dict() if self.posting else None,
            "attestation": self.attestation.to_dict() if self.attestation else None,
            # Exposed separately: attestation findings are not nested under any
            # of the four check objects, so a consumer iterating those alone
            # would silently drop them -- including the critical replay case.
            "attestation_findings": [f.to_dict() for f in self.attestation_findings],
            "trace": self.trace.to_dict() if self.trace else None,
        }


@dataclass
class Progress:
    """One completed stage, emitted while a verification is still running.

    Real events from the real pipeline. The UI shows checks completing as they
    complete; it does not replay a finished result on a timer, which would be
    theatre dressed as instrumentation.
    """

    stage: str
    label: str
    status: str            # done | skipped | error
    summary: str = ""
    ms: int = 0
    severity: str = "info"
    #: True only when the check found *positive* evidence. A check that
    #: completed without confirming anything is not a pass, and showing it as
    #: a green tick would tell the reader the opposite of the truth — the same
    #: absence-of-evidence conflation the findings model forbids.
    positive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"event": "progress", "stage": self.stage, "label": self.label,
                "status": self.status, "summary": self.summary, "ms": self.ms,
                "severity": self.severity, "positive": self.positive}


#: Declared up front so the UI can render the checklist before anything runs.
STAGES: list[tuple[str, str]] = [
    ("practices", "What they're asking you to do"),
    ("employer", "Whether the company exists"),
    ("domain", "Who actually sent it"),
    ("attestation", "Signed verification code"),
    ("posting", "Whether the role is listed"),
    ("document", "The attached document"),
]


def _attestation_findings(check: TokenCheck | None,
                          unavailable: str | None,
                          sender_domain: str | None = None) -> list[Finding]:
    """Express an attestation result in the same evidence model as everything else."""
    from .integrity.findings import Layer

    def mk(code, title, sev, detail, evidence="", remediation="", conf=1.0):
        return Finding(code=code, title=title, severity=sev, layer=Layer.VISIBLE,
                       detail=detail, evidence=evidence, remediation=remediation,
                       confidence=conf)

    if unavailable:
        return [mk(
            "ATTEST_NOT_CHECKED", "The attestation could not be checked",
            Severity.INFO,
            "This message carried a signed attestation, but we could not "
            "retrieve the issuer's keys to check it. Nothing was verified — "
            "that is not the same as the signature failing.",
            evidence=unavailable,
            remediation="Try again with a connection, or check the issuer's "
                        "site yourself.")]
    if check is None:
        return []

    if check.valid:
        att = check.attestation

        # A signature proves who *issued* the attestation, not who sent the
        # message carrying it. Tokens travel in email and can be leaked,
        # forwarded or scraped, so a valid one replayed from another domain
        # would otherwise be laundered into "signed by datadoghq.com" — the
        # trust signal vouching for a scam. Binding the two is what makes the
        # signature mean anything.
        if sender_domain and att:
            iss = att.issuer.lower()
            if not (sender_domain == iss or sender_domain.endswith("." + iss)):
                return [mk(
                    "ATTEST_ISSUER_MISMATCH",
                    "The signature is real, but it did not come from this sender",
                    Severity.CRITICAL,
                    f"This attestation was genuinely issued by '{iss}', and the "
                    f"signature checks out — but the message was sent from "
                    f"'{sender_domain}'. A valid attestation proves who created "
                    f"it, not who forwarded it. Attaching someone else's real "
                    f"attestation to your own message is the most likely way "
                    f"this pattern occurs.",
                    evidence=f"issued by: {iss}   |   sent from: {sender_domain}",
                    remediation=f"Treat this as impersonation of {iss}. If you "
                                f"want to reach them, go to their website "
                                f"directly.")]

        return [mk(
            "ATTEST_VALID", f"Cryptographically signed by {check.issuer}",
            Severity.INFO,
            f"This message carries a valid signature from '{check.issuer}', "
            f"verified against the public key published on that domain. "
            f"Groundtruth is not trusted in this check — the signature is "
            f"checked directly against the company's own site. "
            f"{check.reason}",
            evidence=(f"role={att.role!r} recruiter={att.recruiter} "
                      f"expires={att.expires_at[:10]}" if att else ""),
            remediation="Origin confirmed. Terms, pay and the role itself are "
                        "still yours to evaluate.")]

    sev = Severity.HIGH if check.expired or check.recipient_matches is False \
        else Severity.CRITICAL
    return [mk(
        "ATTEST_INVALID", "The attestation on this message does not check out",
        sev,
        check.reason,
        evidence=f"claimed issuer: {check.issuer or 'unknown'}",
        remediation=("Do not rely on this message's claimed origin. Contact the "
                     "company through their published website."))]


def _summarise(v: Verification) -> tuple[str, str]:
    """Plain-language headline and next step. Never an accusation."""
    illegal = [f for f in v.findings if f.meta.get("tier") == "illegal"]
    critical = [f for f in v.findings if f.severity is Severity.CRITICAL]
    high = [f for f in v.findings if f.severity is Severity.HIGH]

    if illegal:
        return (
            f"This message asks you to do {len(illegal)} thing(s) that are not "
            "lawful for an employer to ask.",
            "Do not pay, sign, or send documents. Save this message. If you are "
            "on a student or work visa, speak to your school's international "
            "student office or an immigration attorney before replying — the "
            "consequences of these arrangements fall on you, not on them.",
        )
    mismatch = next((f for f in v.findings
                     if f.code == "ATTEST_ISSUER_MISMATCH"), None)
    if mismatch:
        issuer = (v.attestation.issuer if v.attestation else "another company")
        return (
            f"This message carries a real signature from {issuer} — but it was "
            f"not sent by them.",
            "A signature proves who created it, not who forwarded it. Someone "
            "has attached another company's verification code to their own "
            "message. Treat this as impersonation and contact the company "
            "through their own website.",
        )
    if critical:
        return (
            f"{len(critical)} serious problem(s) found with who this is from or "
            "what it asks for.",
            "Do not reply or click links. If you think the company is real, "
            "contact them through a phone number or address you found yourself.",
        )
    if high:
        return (
            f"{len(high)} thing(s) here could not be verified or do not match "
            "normal hiring practice.",
            "Slow down and confirm independently before sending anything. A "
            "legitimate employer will wait.",
        )
    if (any(f.code == "POSTING_FOUND" for f in v.findings)
            and not high and not critical):
        signed = any(f.code == "ATTEST_VALID" for f in v.findings)
        return (
            "This role is listed on the company's own careers page"
            + (" and the message is cryptographically signed." if signed else "."),
            "That is the strongest check available here: nobody can publish a "
            "job on a company's own site but the company. Apply through that "
            "page directly rather than through a link you were sent.",
        )
    if any(f.code == "ATTEST_VALID" for f in v.findings) and not high and not critical:
        return (
            f"This message is cryptographically signed by "
            f"{v.attestation.issuer if v.attestation else 'the employer'}.",
            "The signature confirms the message genuinely came from that "
            "domain. It does not confirm the role, the pay, or that the "
            "recruiter has the authority they claim — evaluate those normally.",
        )
    medium = [f for f in v.findings if f.severity is Severity.MEDIUM]
    if medium:
        return (
            f"{len(medium)} thing(s) here are worth a second look before you "
            "reply.",
            "None of these is alarming on its own, and each has ordinary "
            "explanations. Read them, then decide whether to confirm anything "
            "independently before sending documents or money.",
        )
    if any(f.code == "EMPLOYER_NOT_CHECKED" for f in v.findings):
        return (
            "Nothing alarming found — but the employer check did not run.",
            "Verify the company's website yourself and compare it to the "
            "sender's address.",
        )
    return (
        "Nothing alarming found in what we could check.",
        "This is not a guarantee. We checked the sender's domain, the employer's "
        "public presence, and what the message asks for — not whether the job or "
        "the person is real.",
    )


def verify_iter(
    sender: str,
    message: str = "",
    claimed_company: str | None = None,
    document_path: str | None = None,
    attestation: str | None = None,
    recipient_email: str | None = None,
    role: str | None = None,
    check_posting_page: bool = False,
    transport: Transport | None = None,
    recorder: PrismRecorder | None = None,
    resolver: KeyResolver | None = None,
    browser: Browser | None = None,
) -> Iterator[Progress | Verification]:
    """Run every check, yielding a Progress event as each one finishes.

    The final item is the Verification itself. `verify()` drains this and
    returns that, so callers that do not care about progress are unaffected.
    """
    transport = transport or default_transport()
    recorder = recorder or PrismRecorder()
    trace = Trace()
    v = Verification(sender=sender, claimed_company=claimed_company, trace=trace)

    trace.step("reasoning", "Parse outreach",
               input_summary=f"sender={sender!r} company={claimed_company!r}",
               output_summary=f"{len(message)} chars of message text")

    # 1. What is the message asking for? Independent of who sent it.
    if message.strip():
        t0 = time.perf_counter()
        v.practices = scan_practices(message)
        trace.tool("groundtruth.practices", "Scan requested actions",
                   inp=f"{len(message)} chars",
                   out=f"{len(v.practices.findings)} finding(s), tiers={v.practices.tiers}",
                   ms=int((time.perf_counter() - t0) * 1000))
        yield Progress("practices", "What they're asking you to do", "done",
                       f"{len(v.practices.findings)} finding(s)",
                       int((time.perf_counter() - t0) * 1000),
                       v.practices.max_severity.value)
    else:
        yield Progress("practices", "What they're asking you to do", "skipped",
                       "no message supplied")

    # 2. Who does the company say it is, and does it exist?
    known_domain = None
    if claimed_company:
        t0 = time.perf_counter()
        v.employer = verify_employer(claimed_company, transport)
        known_domain = v.employer.likely_domain
        trace.tool("tavily.search", "Corroborate employer",
                   inp=claimed_company,
                   out=f"domain={known_domain} confidence={v.employer.confidence:.2f} "
                       f"checked={v.employer.checked}",
                   ms=int((time.perf_counter() - t0) * 1000),
                   status="success" if v.employer.checked else "error")
        yield Progress("employer", "Whether the company exists",
                       "done" if v.employer.checked else "error",
                       (f"real domain: {known_domain}" if known_domain
                        else "no first-party site found"),
                       int((time.perf_counter() - t0) * 1000),
                       v.employer.max_severity.value,
                       positive=bool(known_domain))
    else:
        yield Progress("employer", "Whether the company exists", "skipped",
                       "no company name supplied")

    # 3. Sender check, now upgraded by whatever step 2 established.
    t0 = time.perf_counter()
    v.domain = analyse_domain(sender, claimed_company, known_domain=known_domain)
    trace.tool("groundtruth.domains", "Assess sender domain",
               inp=f"{sender} vs {known_domain or claimed_company}",
               out=f"verdict={v.domain.verdict} severity={v.domain.max_severity.value}",
               ms=int((time.perf_counter() - t0) * 1000))
    yield Progress("domain", "Who actually sent it", "done",
                   v.domain.verdict.replace("_", " "),
                   int((time.perf_counter() - t0) * 1000),
                   v.domain.max_severity.value,
                   positive=(v.domain.verdict == "matches_claim"))

    # 4. A signed attestation, if the sender supplied one. Checked against the
    #    issuer's own domain, never against anything the token points at.
    if attestation:
        t0 = time.perf_counter()
        resolver = resolver or default_resolver()
        try:
            issuer = parse_token(attestation).issuer
            well_known = resolver.fetch(issuer)
            v.attestation = verify_token(attestation, well_known,
                                         recipient_email=recipient_email)
            v.attestation_findings = _attestation_findings(
                v.attestation, None, sender_domain=domain_of(sender))
            status = "success" if v.attestation.valid else "error"
            out = f"issuer={issuer} valid={v.attestation.valid}"
        except (KeysUnavailable, ValueError) as exc:
            v.attestation_findings = _attestation_findings(
                None, str(exc), sender_domain=domain_of(sender))
            status, out = "error", f"unavailable: {exc}"
        trace.tool("groundtruth.attest", "Verify signed attestation",
                   inp=attestation[:40] + "…", out=out,
                   ms=int((time.perf_counter() - t0) * 1000), status=status)
        _sev = max((f.severity for f in v.attestation_findings),
                   default=Severity.INFO).value
        yield Progress("attestation", "Signed verification code",
                       "done" if status == "success" else "error", out,
                       int((time.perf_counter() - t0) * 1000), _sev,
                       positive=bool(v.attestation and v.attestation.valid
                                     and _sev == "info"))
    else:
        yield Progress("attestation", "Signed verification code", "skipped",
                       "none supplied")

    # 5. Is the role actually listed where this employer lists roles? Opt-in:
    #    it drives a real browser and costs seconds, not milliseconds.
    if role is None and v.attestation and v.attestation.valid and v.attestation.attestation:
        role = v.attestation.attestation.role  # a valid attestation names it
    if check_posting_page and known_domain and role:
        t0 = time.perf_counter()
        br = browser or default_browser()
        v.posting = check_posting(known_domain, role, br)
        trace.tool(f"browser.{v.posting.engine}", "Check careers page listing",
                   inp=f"{known_domain} / {role!r}",
                   out=f"found={v.posting.found} url={v.posting.careers_url}",
                   ms=int((time.perf_counter() - t0) * 1000),
                   status="success" if v.posting.checked else "error")
        yield Progress("posting", "Whether the role is listed",
                       "done" if v.posting.checked else "error",
                       ("listed on the careers page" if v.posting.found
                        else "not found on the careers page"),
                       int((time.perf_counter() - t0) * 1000),
                       v.posting.max_severity.value,
                       positive=bool(v.posting.found))
    else:
        yield Progress("posting", "Whether the role is listed", "skipped",
                       "not requested")

    # 6. If an offer letter was attached, check it for manipulation.
    if document_path:
        t0 = time.perf_counter()
        v.document = scan_pdf(document_path)
        trace.tool("groundtruth.integrity", "Inspect attached document",
                   inp=document_path,
                   out=f"verdict={v.document.verdict} "
                       f"findings={len(v.document.findings)}",
                   ms=int((time.perf_counter() - t0) * 1000))
        yield Progress("document", "The attached document", "done",
                       v.document.verdict,
                       int((time.perf_counter() - t0) * 1000),
                       v.document.max_severity.value,
                       positive=(v.document.verdict == "clean"))
    else:
        yield Progress("document", "The attached document", "skipped",
                       "nothing attached")

    v.headline, v.recommendation = _summarise(v)
    trace.step("final_answer", "Summarise for the candidate",
               output_summary=f"{v.max_severity.value}: {v.headline}")

    recorder.submit(trace, final_status="success")
    yield v


def verify(*args: Any, **kwargs: Any) -> Verification:
    """Run every check and return the result. Progress events are discarded."""
    result: Verification | None = None
    for item in verify_iter(*args, **kwargs):
        if isinstance(item, Verification):
            result = item
    assert result is not None, "verify_iter must yield a Verification last"
    return result
