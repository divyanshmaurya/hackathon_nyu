"""Fetching an employer's published keys from their own domain.

The fetch target is derived from the *attestation's* issuer claim, and then the
document's own `domain` field must match it (checked in `token.verify`). That
loop is what stops a forged token pointing at a key file the attacker controls.

Same three-transport shape as corroboration: live, local registry, offline —
and offline refuses rather than reporting a clean result.
"""

from __future__ import annotations

import json
import pathlib
from typing import Protocol

from .keys import WELL_KNOWN_PATH


class KeysUnavailable(RuntimeError):
    """We could not retrieve the issuer's keys, as distinct from them being wrong."""


class KeyResolver(Protocol):
    def fetch(self, domain: str) -> dict: ...


class HttpsResolver:
    """Fetches https://<domain>/.well-known/groundtruth.json."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def fetch(self, domain: str) -> dict:
        import httpx  # lazy: only needed when actually going to the network

        url = f"https://{domain}{WELL_KNOWN_PATH}"
        try:
            r = httpx.get(url, timeout=self.timeout, follow_redirects=False)
        except Exception as exc:
            raise KeysUnavailable(f"Could not reach {url}: {exc}") from exc
        if r.status_code == 404:
            raise KeysUnavailable(
                f"{domain} does not publish recruiting attestation keys. Most "
                f"employers do not yet — this is not a sign of anything wrong.")
        if r.status_code >= 400:
            raise KeysUnavailable(f"{url} returned HTTP {r.status_code}.")
        try:
            return r.json()
        except Exception as exc:
            raise KeysUnavailable(f"{url} did not return valid JSON: {exc}") from exc


class LocalRegistry:
    """Serves well-known documents from a directory. Used for tests and demos.

    Files are named <domain>.json. This stands in for the network; it does not
    weaken verification, because signature checking is unchanged — only the
    delivery of the public key differs.
    """

    def __init__(self, directory: str | pathlib.Path):
        self.dir = pathlib.Path(directory)

    def fetch(self, domain: str) -> dict:
        path = self.dir / f"{domain.lower()}.json"
        if not path.is_file():
            raise KeysUnavailable(
                f"{domain} does not publish recruiting attestation keys. Most "
                f"employers do not yet — this is not a sign of anything wrong.")
        return json.loads(path.read_text())


class OfflineResolver:
    def fetch(self, domain: str) -> dict:
        raise KeysUnavailable(
            "Key lookup unavailable: no network and no local registry. The "
            "attestation was NOT checked — this is not the same as it failing.")


def default_resolver(registry_dir: str | pathlib.Path | None = None) -> KeyResolver:
    if registry_dir and pathlib.Path(registry_dir).is_dir():
        return LocalRegistry(registry_dir)
    return HttpsResolver()
