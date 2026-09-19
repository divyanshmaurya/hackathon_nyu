"""Is the domain contacting you who it claims to be?

A job seeker receiving unsolicited recruiter outreach has almost nothing to go
on. The single most checkable fact available to them is the sender's domain,
and it is checkable *offline*, before they reply, before they send a document,
before they pay anyone.

This module answers one question: given a domain that contacted you and the
company it claims to represent, is that domain the company's real domain, a
confusable imitation of it, or something else entirely?

Design rule carried over from the integrity axis: we report what is verifiable
and name specific documented practices. We never label an organisation "a scam."
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ..integrity.findings import Finding, Layer, Severity
from ..integrity.unicode_checks import HOMOGLYPHS

# Reverse the homoglyph table: latin letter -> the characters that imitate it.
_CONFUSABLE_FOR: dict[str, list[str]] = {}
for _fake, _real in HOMOGLYPHS.items():
    _CONFUSABLE_FOR.setdefault(_real.lower(), []).append(_fake)

# Visually confusable ASCII pairs, which need no exotic Unicode at all.
ASCII_CONFUSABLES = {
    "l": ["1", "i"], "i": ["l", "1"], "1": ["l", "i"],
    "o": ["0"], "0": ["o"],
    "m": ["rn"], "rn": ["m"],
    "w": ["vv"], "d": ["cl"], "b": ["lb"],
}

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "mail.com", "zoho.com",
    "yandex.com", "rediffmail.com",
}

DISPOSABLE_MAIL = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "temp-mail.org", "getnada.com", "dispostable.com",
}

# TLDs that are cheap, bulk-registrable and heavily abused for throwaway
# infrastructure. Presence is a weak signal on its own -- plenty of legitimate
# sites use them -- so it is reported as context, never as an accusation.
HIGH_ABUSE_TLDS = {
    "top", "xyz", "icu", "cyou", "sbs", "cfd", "bond", "rest", "click",
    "link", "live", "shop", "buzz", "monster", "work", "support", "gq",
    "tk", "ml", "cf", "ga",
}

# Words a spoofed domain bolts onto a real brand name.
COMBO_TOKENS = {
    "careers", "career", "jobs", "job", "hiring", "hire", "recruit",
    "recruiting", "recruitment", "hr", "talent", "apply", "application",
    "onboarding", "onboard", "offer", "payroll", "staffing", "consultancy",
    "consulting", "portal", "official", "team", "global", "inc", "llc", "group",
}


@dataclass
class DomainVerdict:
    domain: str
    claimed_company: str | None
    verdict: str                 # matches_claim | lookalike | unrelated | unverifiable
    findings: list[Finding]

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "claimed_company": self.claimed_company,
            "verdict": self.verdict,
            "max_severity": self.max_severity.value,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def domain_of(address_or_url: str) -> str:
    """Pull a bare domain out of an email address or a URL."""
    s = address_or_url.strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = s.split("/")[0].split("?")[0].split(":")[0]
    return s.strip(". ")


def registrable_parts(domain: str) -> tuple[str, str]:
    """Split into (name, tld). Deliberately simple -- no PSL dependency."""
    bits = domain.split(".")
    if len(bits) < 2:
        return domain, ""
    # Handle the common two-part public suffixes without pulling in the full list.
    if len(bits) >= 3 and bits[-2] in {"co", "com", "org", "net", "ac", "gov"} and len(bits[-1]) == 2:
        return bits[-3], ".".join(bits[-2:])
    return bits[-2], bits[-1]


def _normalise(name: str) -> str:
    """Strip a company name down to a comparable token."""
    s = unicodedata.normalize("NFKD", name.lower())
    s = re.sub(r"\b(inc|llc|ltd|limited|corp|corporation|co|gmbh|plc|sa|bv|pvt)\b", "", s)
    return re.sub(r"[^a-z0-9]", "", s)


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _deconfuse(name: str) -> str:
    """Fold visually confusable characters to a canonical skeleton.

    'g00gle', 'gооgle' (Cyrillic) and 'google' all collapse to the same string,
    which is what lets us catch imitations that edit distance alone would miss.
    """
    out = []
    for ch in unicodedata.normalize("NFKD", name.lower()):
        out.append(HOMOGLYPHS.get(ch, ch).lower())
    s = "".join(out)
    for src, dst in (("0", "o"), ("1", "l"), ("rn", "m"), ("vv", "w"), ("5", "s"), ("3", "e")):
        s = s.replace(src, dst)
    return s


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _f(code, title, sev, detail, evidence="", remediation="", conf=1.0, **meta) -> Finding:
    return Finding(
        code=code, title=title, severity=sev, layer=Layer.VISIBLE,
        detail=detail, evidence=evidence, remediation=remediation,
        confidence=conf, meta=meta,
    )


def check_punycode(domain: str) -> list[Finding]:
    """IDN homograph: a domain that renders as a brand but encodes other scripts."""
    labels = [l for l in domain.split(".") if l.startswith("xn--")]
    if not labels:
        return []
    decoded = []
    for label in labels:
        try:
            decoded.append(label.encode("ascii").decode("idna"))
        except Exception:
            decoded.append(label)
    shown = ", ".join(f"{a} renders as {b!r}" for a, b in zip(labels, decoded))
    return [_f(
        "DOMAIN_PUNYCODE_IDN",
        "Domain uses internationalised characters that imitate Latin letters",
        Severity.CRITICAL,
        "This domain is encoded with Punycode (the 'xn--' prefix), meaning it "
        "contains non-Latin characters that your browser and mail client will "
        "display as ordinary letters. This is the standard technique for "
        "registering a domain that is visually indistinguishable from a real "
        "company's.",
        evidence=shown,
        remediation="Do not click links from this sender. Type the company's "
                    "address into your browser yourself instead.",
        labels=labels, decoded=decoded,
    )]


def check_brand_position(domain: str, company: str) -> list[Finding]:
    """Brand present, but not where it counts: brand.com.attacker.xyz"""
    token = _normalise(company)
    if not token or len(token) < 3:
        return []
    name, tld = registrable_parts(domain)
    # Only fire when the brand sits in the *subdomain*, i.e. outside the part
    # that actually determines who controls the domain. When the brand is in
    # the registrable name it is a typosquat or combosquat, handled below.
    subdomain = domain[: -len(f"{name}.{tld}")].rstrip(".")
    if token in re.sub(r"[^a-z0-9]", "", _deconfuse(name)):
        return []
    if subdomain and token in re.sub(r"[^a-z0-9]", "", _deconfuse(subdomain)):
        return [_f(
            "DOMAIN_BRAND_IN_SUBDOMAIN",
            f"'{company}' appears in the address but does not own it",
            Severity.CRITICAL,
            f"The name '{company}' appears in this address, but the domain that "
            f"actually receives the mail is '{name}.{tld}'. Everything to the "
            f"left of that is chosen freely by whoever registered it. A domain "
            f"like 'company.com.hiring-portal.xyz' is controlled by "
            f"'hiring-portal.xyz', not by the company.",
            evidence=f"full: {domain}  |  actually controlled by: {name}.{tld}",
            remediation=f"Read domains right to left. The real owner is the part "
                        f"immediately before the final suffix: {name}.{tld}",
            registrable=f"{name}.{tld}",
        )]
    return []


def check_confusable_with(domain: str, company: str) -> list[Finding]:
    """Typosquat / homoglyph imitation of the claimed company name."""
    token = _normalise(company)
    name, tld = registrable_parts(domain)
    if not token or len(token) < 4:
        return []

    skeleton = _deconfuse(name)
    if skeleton == token and name != token:
        return [_f(
            "DOMAIN_CONFUSABLE_IMITATION",
            f"Domain is a visual imitation of '{company}'",
            Severity.CRITICAL,
            f"'{name}' is not '{token}', but it is built to look identical. "
            f"Folding visually confusable characters (digit 0 for letter o, "
            f"Cyrillic lookalikes, 'rn' for 'm') collapses it to '{skeleton}'. "
            f"A human reading quickly cannot see the difference.",
            evidence=f"{name}.{tld}  →  folds to '{skeleton}'  (claimed: '{token}')",
            remediation="Treat as impersonation until proven otherwise.",
            skeleton=skeleton,
        )]

    dist = _edit_distance(skeleton, token)
    if 0 < dist <= max(1, len(token) // 6) and abs(len(skeleton) - len(token)) <= 2:
        return [_f(
            "DOMAIN_TYPOSQUAT",
            f"Domain is one small edit away from '{company}'",
            Severity.HIGH,
            f"'{name}' differs from '{token}' by {dist} character(s). Domains "
            f"this close to a real brand are registered specifically to catch "
            f"people who do not look closely.",
            evidence=f"{name}.{tld}  vs  {token}  (edit distance {dist})",
            remediation="Compare against the address on the company's own website.",
            distance=dist,
        )]

    # Combosquat: real brand plus a hiring-flavoured word. Separators are
    # stripped first so 'g00gle-careers' and 'googlecareers' both resolve.
    stripped = re.sub(r"[^a-z0-9]", "", skeleton)
    hit = None
    for tok in COMBO_TOKENS:
        if tok in stripped and stripped.replace(tok, "", 1) == token:
            hit = tok
            break
    if hit:
        return [_f(
            "DOMAIN_COMBOSQUAT",
            f"Domain bolts a hiring word onto '{company}'",
            Severity.HIGH,
            f"'{name}' is the company name combined with '{hit}'. Companies "
            f"normally run recruiting on a subdomain or path of their main "
            f"domain (careers.{token}.com), not on a separate registration. "
            f"A separate domain is trivial for anyone to buy.",
            evidence=f"{name}.{tld}  =  '{token}' + '{hit}'",
            remediation=f"Check whether the company's real site links to this "
                        f"domain. If it does not, it is not theirs.",
            token=hit,
        )]
    return []


def check_sender_type(domain: str, company: str | None) -> list[Finding]:
    name, tld = registrable_parts(domain)
    out: list[Finding] = []

    if domain in DISPOSABLE_MAIL:
        out.append(_f(
            "DOMAIN_DISPOSABLE_MAIL",
            "Sender is using a disposable email service",
            Severity.CRITICAL,
            "This address is from a throwaway mail provider designed to expire "
            "and leave no trace. No legitimate employer recruits from one.",
            evidence=domain,
            remediation="Do not send documents or personal information.",
        ))
    elif domain in FREE_MAIL:
        sev = Severity.HIGH if company else Severity.MEDIUM
        out.append(_f(
            "DOMAIN_FREE_MAIL",
            "Recruiter is writing from a personal email account",
            sev,
            (f"This message comes from {domain}, a free consumer mail provider, "
             + (f"while presenting itself as '{company}'. " if company else "")
             + "Anyone can create such an address in minutes, and it proves no "
             "connection to any organisation. Some very small firms do "
             "legitimately operate this way, so this is not proof of fraud — "
             "but it means the sender's identity is entirely unverified."),
            evidence=domain,
            remediation="Ask for correspondence from a company domain, and "
                        "verify that domain independently before replying.",
            conf=0.9,
        ))

    if tld.split(".")[-1] in HIGH_ABUSE_TLDS:
        out.append(_f(
            "DOMAIN_HIGH_ABUSE_TLD",
            f"Domain uses a bulk-registration suffix (.{tld})",
            Severity.LOW,
            f"'.{tld}' domains are cheap and registrable in bulk, which makes "
            f"them common for short-lived infrastructure. Many legitimate sites "
            f"use them too, so treat this as context rather than a red flag on "
            f"its own.",
            evidence=domain,
            remediation="Weigh alongside the other findings, not by itself.",
            conf=0.5,
        ))
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyse(sender: str, claimed_company: str | None = None,
            known_domain: str | None = None) -> DomainVerdict:
    """Assess a sender address/URL against the company it claims to represent.

    `known_domain` is the company's verified real domain when we have it (from
    the corroboration layer). Supplying it upgrades the analysis from heuristic
    to definitive for the match case.
    """
    domain = domain_of(sender)
    findings: list[Finding] = []

    findings += check_punycode(domain)
    findings += check_sender_type(domain, claimed_company)

    verdict = "unverifiable"

    if known_domain:
        kd = domain_of(known_domain)
        if domain == kd or domain.endswith("." + kd):
            return DomainVerdict(domain, claimed_company, "matches_claim", [_f(
                "DOMAIN_MATCHES_VERIFIED",
                f"Sender domain matches the verified domain for {claimed_company}",
                Severity.INFO,
                f"'{domain}' is {kd} or a subdomain of it. The sender controls "
                f"mail on the company's real domain.",
                evidence=f"{domain} ⊆ {kd}",
                remediation="Domain checks out. This does not by itself confirm "
                            "the offer terms or the individual's authority.",
            )])

    if claimed_company:
        brand = check_brand_position(domain, claimed_company)
        conf = check_confusable_with(domain, claimed_company)
        findings += brand + conf
        if brand or conf:
            verdict = "lookalike"
        elif _normalise(claimed_company) in _deconfuse(registrable_parts(domain)[0]):
            verdict = "unverifiable"
        else:
            verdict = "unrelated"
            findings.append(_f(
                "DOMAIN_UNRELATED_TO_CLAIM",
                f"Domain has no relationship to '{claimed_company}'",
                Severity.MEDIUM,
                f"The sender writes from '{domain}', which does not contain or "
                f"resemble '{claimed_company}'. This is normal when a recruiting "
                f"agency contacts you on behalf of a client — but it means you "
                f"are trusting an intermediary you have not verified, not the "
                f"company itself.",
                evidence=f"sender: {domain}  |  claimed: {claimed_company}",
                remediation=f"Ask which company they represent and confirm with "
                            f"{claimed_company} directly that this agency is "
                            f"authorised to recruit for them.",
                conf=0.8,
            ))

    if any(f.severity >= Severity.HIGH for f in findings) and verdict == "unverifiable":
        verdict = "lookalike"

    return DomainVerdict(domain, claimed_company,
                         verdict, sorted(findings, key=lambda f: -f.severity.rank))
