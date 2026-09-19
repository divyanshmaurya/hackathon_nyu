"""Signed recruiting attestations.

The scheme's whole value rests on the trust anchor being the *employer's*
domain rather than Groundtruth, and on a signature meaning what a reader will
assume it means. The adversarial tests below are the specification.
"""
from __future__ import annotations

import base64
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.attest.keys import EmployerKey, public_from_well_known  # noqa: E402
from groundtruth.attest.resolver import (  # noqa: E402
    KeysUnavailable, LocalRegistry, OfflineResolver)
from groundtruth.attest.token import (  # noqa: E402
    hash_recipient, issue, parse, verify as verify_token)
from groundtruth.corroborate.transport import CassetteTransport  # noqa: E402
from groundtruth.integrity.findings import Severity  # noqa: E402
from groundtruth.verify import verify  # noqa: E402

HERE = pathlib.Path(__file__).parent
REGISTRY, CASSETTES = HERE / "registry", HERE / "cassettes"


@pytest.fixture(scope="module")
def key():
    return EmployerKey.generate("datadoghq.com")


@pytest.fixture(scope="module")
def token(key):
    return issue(key, "Senior Software Engineer", "a.chen@datadoghq.com",
                 "alex@example.com")


# ------------------------------------------------------------------- crypto ---

def test_genuine_token_verifies(key, token):
    c = verify_token(token, key.well_known(), "alex@example.com")
    assert c.valid and c.issuer == "datadoghq.com"


def test_attacker_key_on_same_domain_is_rejected(key, token):
    """An attacker who generates their own keypair cannot impersonate: their
    public key is not the one published on the real domain."""
    evil = EmployerKey.generate("datadoghq.com")
    c = verify_token(token, evil.well_known())
    assert not c.valid and "does not publish the key" in c.reason


def test_altered_payload_breaks_the_signature(key, token):
    att = parse(token)
    att.role = "VP Engineering"
    body = base64.urlsafe_b64encode(att.signing_bytes()).rstrip(b"=").decode()
    c = verify_token(f"gt1.{body}.{token.split('.')[2]}", key.well_known())
    assert not c.valid and "signature does not match" in c.reason


def test_well_known_domain_must_match_the_claim(key, token):
    doc = key.well_known()
    doc["domain"] = "evil.com"
    assert not verify_token(token, doc).valid


def test_expired_token_is_rejected_but_named_genuine(key):
    tok = issue(key, "Engineer", "hr@datadoghq.com", ttl_days=1)
    later = datetime.now(timezone.utc) + timedelta(days=3)
    c = verify_token(tok, key.well_known(), now=later)
    assert not c.valid and c.expired
    assert "signature is genuine" in c.reason


def test_token_issued_for_someone_else_is_rejected(key, token):
    c = verify_token(token, key.well_known(), "stranger@example.com")
    assert not c.valid and c.recipient_matches is False


# ------------------------------------------------------------------ privacy ---

def test_recipient_address_never_appears_in_the_token(token):
    """A token may be forwarded or scraped; it must not leak who it was for."""
    body = json.loads(base64.urlsafe_b64decode(
        token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)))
    assert "alex@example.com" not in json.dumps(body)
    assert body["aud"] == hash_recipient("alex@example.com")


def test_recipient_hash_is_case_and_space_insensitive():
    assert hash_recipient("  Alex@Example.COM ") == hash_recipient("alex@example.com")


# ---------------------------------------------------------------- resolution ---

def test_offline_resolver_refuses_rather_than_passing():
    with pytest.raises(KeysUnavailable):
        OfflineResolver().fetch("datadoghq.com")


def test_domain_without_published_keys_is_not_an_accusation():
    with pytest.raises(KeysUnavailable) as e:
        LocalRegistry(REGISTRY).fetch("some-small-company.com")
    assert "not a sign of anything wrong" in str(e.value)


# ------------------------------------------------------------ end to end ---

@pytest.fixture
def pipes():
    return CassetteTransport(CASSETTES), LocalRegistry(REGISTRY)


def demo_token() -> str:
    return (REGISTRY / "_demo_token.txt").read_text().strip()


def test_signed_message_from_the_issuing_domain_is_reassuring(pipes):
    tp, rs = pipes
    v = verify("a.chen@datadoghq.com", "Open to a chat?", "Datadog",
               attestation=demo_token(), recipient_email="alex@example.com",
               transport=tp, resolver=rs)
    assert v.max_severity is Severity.INFO
    assert "cryptographically signed" in v.headline
    # It must not overclaim what a signature proves.
    assert "does not confirm the role" in v.recommendation


def test_subdomain_of_the_issuer_is_accepted(pipes):
    tp, rs = pipes
    v = verify("hr@jobs.datadoghq.com", "Hello", "Datadog",
               attestation=demo_token(), recipient_email="alex@example.com",
               transport=tp, resolver=rs)
    assert any(f.code == "ATTEST_VALID" for f in v.findings)


@pytest.mark.parametrize("sender", [
    "hr@careers-portal-intl.com",   # unrelated domain
    "careers@dataddoghq.com",       # look-alike
])
def test_replayed_token_from_another_domain_is_critical(pipes, sender):
    """A valid signature proves who *issued* an attestation, not who sent the
    message carrying it. Without this binding, a leaked token would let a
    scammer's message be labelled 'signed by datadoghq.com'."""
    tp, rs = pipes
    v = verify(sender, "Please confirm your details.", "Datadog",
               attestation=demo_token(), recipient_email="alex@example.com",
               transport=tp, resolver=rs)
    assert v.max_severity is Severity.CRITICAL
    assert any(f.code == "ATTEST_ISSUER_MISMATCH" for f in v.findings)
    assert "cryptographically signed" not in v.headline


def test_unresolvable_keys_are_reported_as_unchecked(pipes):
    tp, _ = pipes
    v = verify("a.chen@datadoghq.com", "Hi", "Datadog", attestation=demo_token(),
               transport=tp, resolver=OfflineResolver())
    f = next(f for f in v.findings if f.code == "ATTEST_NOT_CHECKED")
    assert f.severity is Severity.INFO
    assert "not the same as the signature failing" in f.detail


def test_garbage_token_does_not_crash_the_run(pipes):
    tp, rs = pipes
    v = verify("a@b.com", "Hi", "Datadog", attestation="not-a-token",
               transport=tp, resolver=rs)
    assert any(f.code == "ATTEST_NOT_CHECKED" for f in v.findings)


def test_published_key_document_is_self_consistent(key):
    doc = key.well_known("security@datadoghq.com")
    assert doc["domain"] == "datadoghq.com"
    assert public_from_well_known(doc, key.kid) is not None
    assert public_from_well_known(doc, "0" * 16) is None


def test_attestation_findings_survive_serialisation(pipes):
    """Regression: attestation findings are not nested under any of the four
    check objects, so the API response dropped them entirely — the UI showed
    a CRITICAL verdict with the critical finding invisible."""
    tp, rs = pipes
    d = verify("hr@careers-portal-intl.com", "Confirm your details.", "Datadog",
               attestation=demo_token(), recipient_email="alex@example.com",
               transport=tp, resolver=rs).to_dict()
    codes = {f["code"] for f in d["attestation_findings"]}
    assert "ATTEST_ISSUER_MISMATCH" in codes
    # Everything counted in the headline must be reachable by a consumer.
    reachable = len(d["attestation_findings"]) + sum(
        len(d[k]["findings"]) for k in ("practices", "domain", "employer", "document")
        if d.get(k) and d[k].get("findings"))
    assert reachable == d["finding_count"]


def test_replayed_token_gets_its_own_headline(pipes):
    """The generic critical headline buried the point. A stolen signature is a
    specific, explainable thing and the summary should say it."""
    tp, rs = pipes
    v = verify("hr@careers-portal-intl.com", "Confirm your details.", "Datadog",
               attestation=demo_token(), recipient_email="alex@example.com",
               transport=tp, resolver=rs)
    assert "real signature from datadoghq.com" in v.headline
    assert "not sent by them" in v.headline
    assert "who created it, not who forwarded it" in v.recommendation
