"""How corroboration calls reach the outside world.

Three transports behind one interface:

  LiveTransport      real Tavily API calls
  CassetteTransport  replays recorded responses from disk
  OfflineTransport   refuses honestly instead of inventing an answer

The cassette layer exists because this project is developed in an environment
whose egress policy blocks the Tavily API, and because a demo should not be one
flaky network call away from failing in front of an audience. Recording a real
response once and replaying it keeps the *code path* identical -- the same
parsing, the same scoring, the same findings -- while making the run
deterministic.

OfflineTransport is deliberately not a silent no-op. A verification tool that
quietly returns "nothing found" when it never actually looked would tell a job
seeker the most dangerous possible lie.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
from dataclasses import dataclass
from typing import Any, Protocol


class CorroborationUnavailable(RuntimeError):
    """Raised when we cannot check, as distinct from checking and finding nothing."""


@dataclass
class SearchResult:
    title: str
    url: str
    content: str
    score: float = 0.0

    @classmethod
    def from_tavily(cls, d: dict[str, Any]) -> "SearchResult":
        return cls(
            title=d.get("title", ""),
            url=d.get("url", ""),
            content=d.get("content", "") or d.get("raw_content", "") or "",
            score=float(d.get("score", 0) or 0),
        )


class Transport(Protocol):
    def search(self, query: str, **kw: Any) -> list[SearchResult]: ...
    @property
    def live(self) -> bool: ...


def _key(query: str, kw: dict[str, Any]) -> str:
    blob = json.dumps({"q": query.strip().lower(), **kw}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class LiveTransport:
    """Real Tavily calls. Optionally records responses as cassettes."""

    def __init__(self, api_key: str | None = None, record_dir: str | pathlib.Path | None = None):
        from tavily import TavilyClient  # imported lazily: optional dependency

        key = api_key or os.environ.get("TAVILY_API_KEY")
        if not key:
            raise CorroborationUnavailable(
                "TAVILY_API_KEY is not set. Redeem the hackathon coupon at "
                "https://app.tavily.com/redeem/HIRINGHACK and export the key."
            )
        self._client = TavilyClient(api_key=key, client_name="groundtruth")
        self._record_dir = pathlib.Path(record_dir) if record_dir else None
        if self._record_dir:
            self._record_dir.mkdir(parents=True, exist_ok=True)

    @property
    def live(self) -> bool:
        return True

    def search(self, query: str, **kw: Any) -> list[SearchResult]:
        kw.setdefault("max_results", 6)
        raw = self._client.search(query, **kw)
        if self._record_dir:
            path = self._record_dir / f"{_key(query, kw)}.json"
            path.write_text(json.dumps({"query": query, "kw": kw, "response": raw}, indent=2))
        return [SearchResult.from_tavily(r) for r in raw.get("results", [])]


class CassetteTransport:
    """Replays recorded Tavily responses. Deterministic, offline, honest."""

    def __init__(self, cassette_dir: str | pathlib.Path):
        self.dir = pathlib.Path(cassette_dir)
        self._index: dict[str, dict] = {}
        for p in sorted(self.dir.glob("*.json")):
            try:
                data = json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
            self._index[_key(data["query"], data.get("kw", {}))] = data
            # Also index by bare normalised query so hand-written cassettes
            # don't have to reproduce the kwargs exactly.
            self._index.setdefault(data["query"].strip().lower(), data)

    @property
    def live(self) -> bool:
        return False

    def search(self, query: str, **kw: Any) -> list[SearchResult]:
        kw.setdefault("max_results", 6)
        data = self._index.get(_key(query, kw)) or self._index.get(query.strip().lower())
        if data is None:
            raise CorroborationUnavailable(
                f"No cassette recorded for query {query!r}. Run with a live "
                f"TAVILY_API_KEY to record one."
            )
        return [SearchResult.from_tavily(r) for r in data["response"].get("results", [])]


class OfflineTransport:
    """No network, no cassettes. Says so rather than implying a clean result."""

    @property
    def live(self) -> bool:
        return False

    def search(self, query: str, **kw: Any) -> list[SearchResult]:
        raise CorroborationUnavailable(
            "Corroboration is unavailable: no Tavily key and no cassette. "
            "Nothing was checked — this is NOT the same as finding nothing."
        )


def default_transport(cassette_dir: str | pathlib.Path | None = None) -> Transport:
    """Live if a key exists, else cassettes, else an honest refusal."""
    if os.environ.get("TAVILY_API_KEY"):
        return LiveTransport(record_dir=os.environ.get("GROUNDTRUTH_RECORD_DIR"))
    if cassette_dir and pathlib.Path(cassette_dir).is_dir():
        return CassetteTransport(cassette_dir)
    return OfflineTransport()
