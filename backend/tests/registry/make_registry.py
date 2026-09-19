"""Regenerate the demo attestation fixtures.

Run this if the demo token expires or you want fresh keys:

    python3 backend/tests/registry/make_registry.py

Writes the *public* well-known document and a sample token. The private key is
written to the same directory but is gitignored: a repository is not a place
for signing keys, even throwaway ones for a fictional domain, because the
pattern is what gets copied.

The demo token is deliberately long-lived. A 30-day default would quietly
expire and break the test suite on a date nobody chose, which is a poor trade
for a fixture that signs nothing real.
"""
from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from groundtruth.attest.keys import EmployerKey  # noqa: E402
from groundtruth.attest.token import issue  # noqa: E402

DEMO_DOMAIN = "datadoghq.com"
DEMO_TTL_DAYS = 3650


def main() -> None:
    key = EmployerKey.generate(DEMO_DOMAIN)
    (HERE / f"{DEMO_DOMAIN}.json").write_text(
        key.well_known_json(f"security@{DEMO_DOMAIN}"))
    priv = HERE / "_demo_signing_key.pem"
    priv.write_text(key.private_pem())
    priv.chmod(0o600)
    (HERE / "_demo_token.txt").write_text(
        issue(key, "Senior Software Engineer", f"a.chen@{DEMO_DOMAIN}",
              "alex@example.com", ttl_days=DEMO_TTL_DAYS))
    print(f"regenerated demo registry for {DEMO_DOMAIN} (kid {key.kid}, "
          f"token valid {DEMO_TTL_DAYS} days)")


if __name__ == "__main__":
    main()
