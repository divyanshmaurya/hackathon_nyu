"""What is this recruiter actually asking you to do?

Domain analysis tells you whether the sender is who they claim. This module
asks the separate question: regardless of who they are, is what they are
*asking for* something a legitimate employer would ever ask?

That distinction matters because the worst harm in this space does not come
from obvious impostors. It comes from real, registered intermediaries making
requests that are illegal, or that are legal but transfer catastrophic risk
onto the job seeker — and the job seeker has no way to know which is which.

Three tiers, kept strictly separate:

  ILLEGAL   practices that are unlawful in the US (fee-charging, passing
            H-1B costs to the worker, fabricating employment records)
  HARMFUL   legal but transfers serious risk onto the candidate
  CONTEXT   worth knowing, not wrong by itself

We describe the practice and cite why it matters. We never conclude that an
organisation is fraudulent -- that is the reader's call, made with evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..integrity.findings import Finding, Layer, Severity


@dataclass(frozen=True)
class Practice:
    code: str
    title: str
    tier: str            # illegal | harmful | context
    severity: Severity
    rx: re.Pattern[str]
    detail: str
    remediation: str
    # Some requests are normal *after* an offer and alarming before one.
    only_before_offer: bool = False


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I | re.S)


PRACTICES: list[Practice] = [
    # ---------------------------------------------------------------- illegal
    Practice(
        "FEE_TO_CANDIDATE", "You are being asked to pay to get a job", "illegal",
        Severity.CRITICAL,
        _rx(r"\b(registration|processing|application|placement|training|onboarding|"
            r"security|refundable|admin(istrative)?)\s*(fee|charge|deposit|amount)\b"
            r"|\bpay\b[^.\n]{0,40}\b(fee|deposit|upfront|in advance)\b"
            r"|\bfee\b[^.\n]{0,30}\b(to be paid|payable|required|mandatory)\b"),
        "Charging a job seeker a fee to be placed in a job is prohibited or "
        "tightly restricted in most US states, and no legitimate employer or "
        "staffing firm charges candidates. The employer pays the agency, never "
        "the other way around.",
        "Do not pay. This is the single most reliable indicator of an "
        "exploitative arrangement, and it is reportable to your state labor "
        "department and the FTC.",
    ),
    Practice(
        "VISA_COST_SHIFTED", "You are being asked to pay your own visa costs", "illegal",
        Severity.CRITICAL,
        _rx(r"\b(h-?1-?b|green\s*card|perm|visa|sponsorship|petition|labor\s*cert\w*)\b"
            r"[^.\n]{0,60}\b(you\s+(will\s+)?pay|paid\s+by\s+(you|the\s+(candidate|employee))|"
            r"your\s+(cost|expense)|bear\s+the\s+cost|reimburse\s+us|fee\s+of\s*\$?\d)"
            r"|\bpay\b[^.\n]{0,40}\b(h-?1-?b|sponsorship|visa\s+process\w*)\b"),
        "US Department of Labor rules require the employer to pay H-1B filing "
        "and attorney costs. Passing them to the worker is a violation, and an "
        "employer willing to break this rule is signalling how they will treat "
        "the rest of the relationship.",
        "This is recoverable — workers have won back improperly charged fees. "
        "Keep this message.",
    ),
    Practice(
        "FABRICATED_EXPERIENCE", "You are being offered fabricated work history", "illegal",
        Severity.CRITICAL,
        _rx(r"\b(fake|fabricat\w+|create|generate|provide|arrange|build)\b[^.\n]{0,40}"
            r"\b(work\s+experience|employment\s+(history|record|verification)|"
            r"experience\s+letter|relieving\s+letter|past\s+experience)\b"
            r"|\bexperience\b[^.\n]{0,30}\b(will\s+be\s+(provided|created|arranged)|"
            r"no\s+experience\s+(needed|required)\s*[,-]?\s*we\s+will)\b"
            r"|\b(backdate|back-date)\b"),
        "Accepting fabricated employment records is visa fraud, and the "
        "consequences land on the worker, not the consultancy. Students have "
        "faced detention and removal years afterwards — including people who "
        "did not know the record was false and were by then lawfully employed.",
        "Walk away and keep the message. Speak to your school's international "
        "student office or an immigration attorney before doing anything else.",
    ),
    Practice(
        "MONEY_MULE", "You are being asked to move money", "illegal",
        Severity.CRITICAL,
        _rx(r"\b(deposit|cash)\s+(this|the)\s+check\b"
            r"|\b(wire|transfer|send|forward)\b[^.\n]{0,40}\b(remaining|balance|"
            r"difference|back\s+to\s+us|to\s+our\s+vendor)\b"
            r"|\breship\w*\b|\bpackage\s+forward\w*\b"),
        "Being asked to receive funds and pass part of them on makes you a money "
        "mule. The cheque will bounce after you have sent real money, and the "
        "criminal liability attaches to you.",
        "Do not deposit anything. Report to your bank and to the FTC.",
    ),

    # ---------------------------------------------------------------- harmful
    Practice(
        "PII_BEFORE_OFFER", "Sensitive documents requested before any offer", "harmful",
        Severity.HIGH,
        _rx(r"\b(ssn|social\s*security(\s*number)?|passport(\s*copy|\s*scan)?|"
            r"i-?20|ead(\s*card)?|driver'?s?\s*licen[sc]e|date\s+of\s+birth|"
            r"bank\s+(account|details)|routing\s+number|void(ed)?\s+che(ck|que))\b"),
        "An employer needs these eventually, but only after a written offer and "
        "through a secure onboarding system — never in an email thread during "
        "first contact. Collected early, this package is everything required to "
        "open credit or file a fraudulent tax return in your name.",
        "Supply nothing until you have a signed offer and have independently "
        "confirmed the company. Work authorisation can be discussed without "
        "sending documents.",
        only_before_offer=True,
    ),
    Practice(
        "UNTRACEABLE_PAYMENT", "Payment requested by an unrecoverable method", "harmful",
        Severity.CRITICAL,
        _rx(r"\b(bitcoin|btc|crypto(currency)?|usdt|ethereum|gift\s*card|"
            r"steam\s*card|western\s*union|moneygram|zelle|venmo|cash\s*app|"
            r"wire\s+transfer)\b"),
        "These payment methods are chosen because they cannot be reversed. No "
        "employment relationship requires any of them.",
        "There is no legitimate reason for this. Stop here.",
    ),
    Practice(
        "NO_INTERVIEW_OFFER", "A job is being offered without a real interview", "harmful",
        Severity.HIGH,
        _rx(r"\b(no\s+interview\s+(is\s+)?(needed|required|necessary)|"
            r"without\s+an?\s+interview|hired\s+immediately|instant\s+(offer|hire)|"
            r"congratulations[^.\n]{0,40}\b(selected|hired|offer)\b[^.\n]{0,60}"
            r"(without|no\s+need))\b"),
        "Offers made without assessment are not hiring decisions. The purpose is "
        "to move you quickly to whatever comes next — a fee, your documents, or "
        "a cheque.",
        "Ask what specifically about your background led to the offer. Vagueness "
        "is the answer.",
    ),
    Practice(
        "OFF_CHANNEL_ONLY", "The process happens only on a messaging app", "harmful",
        Severity.MEDIUM,
        _rx(r"\b(whatsapp|telegram|signal|wechat|skype\s*(chat|id))\b"
            r"[^.\n]{0,60}\b(interview|contact|reach|messag\w*|continue|discuss|chat)\b"
            r"|\b(interview|contact|reach|messag\w*|continue|discuss|onboard\w*|"
            r"connect|ping|text)\b[^.\n]{0,60}"
            r"\b(whatsapp|telegram|signal|wechat|skype)\b"),
        "Messaging apps leave the company no audit trail and leave you no proof. "
        "Legitimate recruiting happens on company email and a scheduled call. "
        "Some smaller firms do use these tools, so this matters most alongside "
        "other findings.",
        "Ask for a calendar invite from a company email address.",
    ),
    Practice(
        "URGENCY_PRESSURE", "You are being rushed", "harmful",
        Severity.MEDIUM,
        _rx(r"\bexpires?\s+(today|tomorrow|in\s+\d+\s*(hour|day|minute)s?)"
            r"|\bwithin\s+\d+\s*(hour|day)s?\b"
            r"|\b(immediately|urgently|asap)\b"
            r"|\bact\s+(now|fast)\b|\blimited\s+(time|slots?|seats?)\b"
            r"|\blast\s+chance\b|\bdon'?t\s+miss\b|\brespond\s+asap\b"
            r"|\bonly\s+\d+\s+(spots?|positions?)\s+left\b"),
        "Time pressure exists to stop you verifying. It is especially effective "
        "against students on a visa clock, which is exactly why it is used.",
        "A real employer will wait a day. Use the day.",
    ),
    Practice(
        "UNPAID_BENCH", "You may be placed on an unpaid 'bench'", "harmful",
        Severity.HIGH,
        _rx(r"\bbench\b[^.\n]{0,50}\b(period|time|unpaid|until|project|no\s+pay)\b"
            r"|\b(pay|salary|stipend)\b[^.\n]{0,50}\b(starts?|begins?|once)\b[^.\n]{0,40}"
            r"\b(project|client|placement|billing)\b"
            r"|\bno\s+(pay|salary)\b[^.\n]{0,40}\b(until|till)\b"),
        "A 'bench' arrangement means you are employed on paper but unpaid until "
        "they find you a client. For a visa holder this is doubly dangerous: "
        "you may be out of status while unpaid, and the paperwork filed on your "
        "behalf may claim work that is not happening.",
        "Ask in writing: am I paid from my start date regardless of client "
        "assignment? Get the answer before signing anything.",
    ),
    Practice(
        "EXCLUSIVITY_BEFORE_DISCLOSURE", "Exclusivity demanded before naming the client",
        "harmful", Severity.MEDIUM,
        _rx(r"\b(right\s+to\s+represent|exclusiv\w+|sign\s+(this|the)\s+(agreement|form))\b"
            r"[^.\n]{0,80}\b(before|prior\s+to|we\s+can(not|'t)?\s+(disclose|share|tell))\b"
            r"|\b(client|company)\s+name[^.\n]{0,40}\b(cannot|can'?t|won'?t)\s+"
            r"(be\s+)?(disclos\w+|shar\w+|reveal\w+)\b"),
        "Signing a right-to-represent before knowing the employer means you "
        "cannot verify the job exists, and you may be blocked from applying "
        "there yourself or through anyone else. Agencies do have a real interest "
        "in protecting a lead — but you are entitled to know where your resume "
        "is going before it goes.",
        "Ask for the client name before signing. It is reasonable, and refusal "
        "is informative.",
    ),
    Practice(
        "SUBMIT_WITHOUT_CONSENT", "Your resume may be sent without your approval",
        "harmful", Severity.MEDIUM,
        _rx(r"\b(we\s+(will|'ll|have)\s+(already\s+)?(submit|forward|send|shar\w+)"
            r"[^.\n]{0,40}\b(your\s+(resume|cv|profile|details))\b"
            r"|\byour\s+(resume|cv|profile)\s+(has\s+been|was)\s+(submitted|forwarded|shared)\b)"),
        "Submitting you without consent can burn you with that employer: a "
        "duplicate submission often disqualifies you, and the company may then "
        "be unable to hire you directly without owing a fee.",
        "State in writing that they must get your approval per submission, and "
        "keep a record of where you have been submitted.",
    ),

    # ---------------------------------------------------------------- context
    Practice(
        "MARKUP_OPACITY", "The pay arrangement is not being disclosed", "context",
        Severity.LOW,
        _rx(r"\b(bill\s+rate|markup|margin|pay\s+rate)\b[^.\n]{0,50}"
            r"\b(confidential|cannot\s+(be\s+)?(disclos|shar)|not\s+disclos\w+)\b"),
        "Agencies bill the client more than they pay you, which is how they earn "
        "a margin — that is normal. What is not normal is refusing to tell you "
        "your own rate or how it was set.",
        "Ask for your hourly rate in writing before you agree to anything.",
    ),
    Practice(
        "UNNAMED_EMPLOYER", "No identifiable employer is named", "context",
        Severity.LOW,
        _rx(r"\b(leading|top|fortune\s*\d+|major|reputed|well[-\s]known|premier|"
            r"renowned|global)\b[^.\n]{0,25}?"
            r"\b(client|company|firm|mnc|organi[sz]ation|brand|enterprise)\b"
            r"|\bconfidential\s+client\b|\bour\s+client\b(?![^.\n]{0,20}\b(is|,)\b)"),
        "Generic descriptions like 'a leading Fortune 500 client' appear in both "
        "legitimate agency outreach and fabricated roles. It is not wrong on its "
        "own — it simply means nothing here is verifiable yet.",
        "Ask for the company name. You can then check whether the role exists.",
    ),
]

TIER_ORDER = {"illegal": 0, "harmful": 1, "context": 2}


@dataclass
class PracticeReport:
    findings: list[Finding] = field(default_factory=list)
    tiers: dict[str, int] = field(default_factory=dict)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "max_severity": self.max_severity.value,
            "tiers": self.tiers,
            "findings": [f.to_dict() for f in self.findings],
        }


_OFFER_PRESENT = re.compile(
    r"\b(attached\s+(is|you'?ll\s+find)\s+[^.\n]{0,30}offer|offer\s+letter|"
    r"your\s+signed\s+offer|employment\s+agreement\s+attached)\b", re.I)


def scan(text: str, offer_received: bool | None = None) -> PracticeReport:
    """Scan recruiter outreach for the practices above.

    `offer_received` lets the caller say whether a written offer already exists;
    a few requests are normal afterwards and alarming before. When unset we
    infer it from the text and stay conservative.
    """
    if offer_received is None:
        offer_received = bool(_OFFER_PRESENT.search(text))

    findings: list[Finding] = []
    tiers: dict[str, int] = {}

    for pr in PRACTICES:
        m = pr.rx.search(text)
        if not m:
            continue

        sev = pr.severity
        note = ""
        if pr.only_before_offer and offer_received:
            sev = Severity.LOW
            note = (" A written offer appears to be present in this thread, so "
                    "this request is likely part of normal onboarding. Still send "
                    "it only through a secure portal, never by email.")

        lo, hi = max(0, m.start() - 70), min(len(text), m.end() + 70)
        tiers[pr.tier] = tiers.get(pr.tier, 0) + 1

        findings.append(Finding(
            code=f"PRACTICE_{pr.code}",
            title=pr.title,
            severity=sev,
            layer=Layer.VISIBLE,
            detail=pr.detail + note,
            evidence="…" + text[lo:hi].strip().replace("\n", " ") + "…",
            location=f"char offset {m.start()}",
            confidence=0.85,
            remediation=pr.remediation,
            meta={"tier": pr.tier, "matched": m.group()[:160]},
        ))

    findings.sort(key=lambda f: (TIER_ORDER[f.meta["tier"]], -f.severity.rank))
    return PracticeReport(findings=findings, tiers=tiers)
