"""Signed recruiting attestations.

An attestation is a short string an employer attaches to outreach or to an
offer letter. It states, in a way that cannot be forged: *this message about
this role was issued by this domain, on this date, for this candidate.*

    gt1.<payload>.<signature>

Deliberate properties:

**The candidate's email is hashed, never carried.** A candidate can confirm an
attestation was issued for them (they know their own address), but a token
intercepted in transit, forwarded, or scraped from a mailing list reveals
nothing about who it was for. Putting the address in plaintext would make this
a privacy leak attached to every offer letter.

**Attestations expire.** A recruiting message is a statement about a moment. An
attestation that never expires is a credential waiting to be replayed against
someone else a year later.

**A valid signature is not a good job offer.** Verification proves origin only.
The employer is who they say they are; whether the role is real, the pay is
fair, or the recruiter has authority are separate questions the tool is careful
not to imply it answered.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature

from .keys import ALG, EmployerKey, b64u, b64u_decode, public_from_well_known

PREFIX = "gt1"
DEFAULT_TTL_DAYS = 30


def hash_recipient(email: str) -> str:
    """Salted-by-construction hash of a candidate address.

    The domain is included so the same address attested by two employers does
    not produce the same digest, which would let them correlate candidates.
    """
    norm = email.strip().lower()
    return hashlib.sha256(f"groundtruth-recipient:{norm}".encode()).hexdigest()[:32]


@dataclass
class Attestation:
    issuer: str                     # the employer's domain
    kid: str
    role: str
    recruiter: str                  # recruiter's email address
    recipient_hash: str | None
    issued_at: str
    expires_at: str
    jti: str = field(default_factory=lambda: secrets.token_hex(8))
    version: int = 1

    def payload(self) -> dict[str, Any]:
        return {
            "v": self.version, "iss": self.issuer, "kid": self.kid,
            "role": self.role, "rec": self.recruiter,
            "aud": self.recipient_hash, "iat": self.issued_at,
            "exp": self.expires_at, "jti": self.jti,
        }

    def signing_bytes(self) -> bytes:
        # Canonical form: sorted keys, no whitespace. Both sides must produce
        # byte-identical input or every signature fails.
        return json.dumps(self.payload(), sort_keys=True,
                          separators=(",", ":")).encode()

    @classmethod
    def from_payload(cls, d: dict[str, Any]) -> "Attestation":
        return cls(issuer=d["iss"], kid=d["kid"], role=d.get("role", ""),
                   recruiter=d.get("rec", ""), recipient_hash=d.get("aud"),
                   issued_at=d["iat"], expires_at=d["exp"],
                   jti=d.get("jti", ""), version=d.get("v", 1))


def issue(key: EmployerKey, role: str, recruiter: str,
          recipient_email: str | None = None,
          ttl_days: int = DEFAULT_TTL_DAYS) -> str:
    """Create a signed attestation token."""
    now = datetime.now(timezone.utc)
    att = Attestation(
        issuer=key.domain, kid=key.kid, role=role, recruiter=recruiter.strip().lower(),
        recipient_hash=hash_recipient(recipient_email) if recipient_email else None,
        issued_at=now.replace(microsecond=0).isoformat(),
        expires_at=(now + timedelta(days=ttl_days)).replace(microsecond=0).isoformat(),
    )
    body = att.signing_bytes()
    sig = key.private.sign(body)
    return f"{PREFIX}.{b64u(body)}.{b64u(sig)}"


@dataclass
class TokenCheck:
    valid: bool
    reason: str
    attestation: Attestation | None = None
    issuer: str | None = None
    expired: bool = False
    recipient_matches: bool | None = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid, "reason": self.reason, "issuer": self.issuer,
            "expired": self.expired, "recipient_matches": self.recipient_matches,
            "attestation": self.attestation.payload() if self.attestation else None,
        }


def parse(token: str) -> Attestation:
    """Decode without verifying. The issuer is needed to find the key."""
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise ValueError(f"Not a Groundtruth attestation (expected '{PREFIX}.…').")
    try:
        return Attestation.from_payload(json.loads(b64u_decode(parts[1])))
    except Exception as exc:
        raise ValueError(f"Malformed attestation payload: {exc}") from exc


def verify(token: str, well_known: dict,
           recipient_email: str | None = None,
           now: datetime | None = None) -> TokenCheck:
    """Verify a token against a well-known document fetched from the issuer.

    `well_known` must have come from the issuer's *own* domain. Fetching it
    from anywhere the token itself points to would defeat the entire scheme.
    """
    try:
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            return TokenCheck(False, f"Not a Groundtruth attestation.")
        body, sig = b64u_decode(parts[1]), b64u_decode(parts[2])
        att = Attestation.from_payload(json.loads(body))
    except Exception as exc:
        return TokenCheck(False, f"Could not read this attestation: {exc}")

    if well_known.get("domain", "").lower() != att.issuer.lower():
        return TokenCheck(
            False,
            f"The attestation claims to be from '{att.issuer}', but the key "
            f"document came from '{well_known.get('domain')}'. These must match.",
            att, att.issuer)

    pub = public_from_well_known(well_known, att.kid)
    if pub is None:
        return TokenCheck(
            False,
            f"'{att.issuer}' does not publish the key ({att.kid}) this "
            f"attestation was signed with. Either it was not issued by them, or "
            f"the key was retired.",
            att, att.issuer)

    try:
        pub.verify(sig, body)
    except InvalidSignature:
        return TokenCheck(
            False,
            f"The signature does not match. This attestation was not issued by "
            f"'{att.issuer}', or it has been altered since it was.",
            att, att.issuer)

    now = now or datetime.now(timezone.utc)
    expired = False
    try:
        expired = datetime.fromisoformat(att.expires_at) < now
    except ValueError:
        return TokenCheck(False, "Attestation has an unreadable expiry date.",
                          att, att.issuer)

    recipient_matches = None
    if recipient_email and att.recipient_hash:
        recipient_matches = hash_recipient(recipient_email) == att.recipient_hash

    if expired:
        return TokenCheck(
            False,
            f"The signature is genuine, but this attestation expired on "
            f"{att.expires_at[:10]}. Ask the sender for a current one.",
            att, att.issuer, expired=True, recipient_matches=recipient_matches)

    if recipient_matches is False:
        return TokenCheck(
            False,
            "The signature is genuine, but this attestation was issued for a "
            "different recipient. It may have been forwarded or reused.",
            att, att.issuer, recipient_matches=False)

    return TokenCheck(
        True,
        f"Signed by {att.issuer} and currently valid. This confirms the message "
        f"came from that domain — not that the role or the terms are what they "
        f"appear to be.",
        att, att.issuer, recipient_matches=recipient_matches)
