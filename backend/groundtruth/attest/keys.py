"""Employer signing keys, anchored to the employer's own domain.

The design decision that matters here: **Groundtruth is not the trust anchor.**

An employer generates a keypair and publishes the *public* half at a
well-known path on the domain candidates already know how to check:

    https://datadoghq.com/.well-known/groundtruth.json

A candidate verifying an attestation fetches that file from the company's real
domain and checks the signature against it. Our service is never consulted. If
Groundtruth disappeared tomorrow, every attestation ever issued would remain
verifiable, because the only things involved are the employer's domain and
public-key cryptography.

That is the difference between a trust signal and a trust intermediary. A
scammer cannot forge a signature without the employer's private key, and cannot
substitute their own key without controlling the employer's real domain — at
which point the candidate has much larger problems, and the domain check in
`outreach/domains.py` is what catches that case.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

WELL_KNOWN_PATH = "/.well-known/groundtruth.json"
ALG = "ed25519"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def key_id(public: Ed25519PublicKey) -> str:
    """Short stable identifier, so a domain can rotate keys without ambiguity."""
    raw = public.public_bytes(serialization.Encoding.Raw,
                             serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass
class EmployerKey:
    domain: str
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def kid(self) -> str:
        return key_id(self.public)

    @classmethod
    def generate(cls, domain: str) -> "EmployerKey":
        priv = Ed25519PrivateKey.generate()
        return cls(domain=domain.lower().strip(), private=priv, public=priv.public_key())

    # ---------------------------------------------------------------- storage

    def private_pem(self) -> str:
        return self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @classmethod
    def load_private_pem(cls, domain: str, pem: str) -> "EmployerKey":
        priv = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("Not an Ed25519 private key.")
        return cls(domain=domain.lower().strip(), private=priv, public=priv.public_key())

    # ------------------------------------------------------------ well-known

    def well_known(self, contact: str | None = None) -> dict:
        """The document the employer publishes on their own domain."""
        doc = {
            "version": 1,
            "domain": self.domain,
            "keys": [{
                "kid": self.kid,
                "alg": ALG,
                "public_key": b64u(self.public.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            }],
            "note": (
                "Public keys used to sign recruiting attestations for this "
                "domain. Verify an offer or recruiter message at "
                f"https://{self.domain}{WELL_KNOWN_PATH}"
            ),
        }
        if contact:
            doc["report_abuse"] = contact
        return doc

    def well_known_json(self, contact: str | None = None) -> str:
        return json.dumps(self.well_known(contact), indent=2)


def public_from_well_known(doc: dict, kid: str) -> Ed25519PublicKey | None:
    """Pull the named key out of a published well-known document."""
    for entry in doc.get("keys", []):
        if entry.get("kid") == kid and entry.get("alg") == ALG:
            try:
                return Ed25519PublicKey.from_public_bytes(
                    b64u_decode(entry["public_key"]))
            except Exception:
                return None
    return None
