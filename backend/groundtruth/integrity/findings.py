"""Evidence model for the integrity axis.

Everything on this axis is deterministic: a finding is a statement about bytes
in a document, not an inference about a person. That distinction is load
bearing -- it is why this axis can be shown to a candidate verbatim.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered so that `max()` over a set of findings gives the headline."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    # NOTE: Severity subclasses `str`, so without these it would inherit str's
    # alphabetical ordering and CRITICAL >= MEDIUM would evaluate False.
    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class Layer(str, Enum):
    """Which layer of the document the evidence came from.

    This is the field that prevents false positives. The same string is
    innocuous in VISIBLE and damning in HIDDEN -- a candidate may legitimately
    write about prompt injection in a bullet point about their security work.
    They have no reason to write it in 1pt white text.
    """

    VISIBLE = "visible"      # rendered, human-readable
    HIDDEN = "hidden"        # present in the text stream, not rendered to a human
    METADATA = "metadata"    # document properties, XMP, producer strings
    UNKNOWN = "unknown"      # plain-text input: we cannot tell


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    severity: Severity
    layer: Layer
    detail: str
    evidence: str = ""
    location: str = ""
    confidence: float = 1.0
    remediation: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["layer"] = self.layer.value
        return d


def escape_invisibles(text: str, limit: int = 240) -> str:
    """Render a snippet so invisible characters become visible in the UI.

    A finding about invisible characters is useless if the evidence string
    renders as an empty box in the recruiter's browser. We replace every
    non-printing codepoint with its Unicode name so the evidence is legible.
    """
    out: list[str] = []
    for ch in text[:limit]:
        cat = unicodedata.category(ch)
        # Cf = format chars (zero-width, bidi, tags), Cc = control, Co = private use
        if cat in ("Cf", "Cc", "Co") and ch not in "\n\t":
            name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            out.append(f"⟦{name}⟧")
        elif ch == "\n":
            out.append("⏎")
        else:
            out.append(ch)
    s = "".join(out)
    if len(text) > limit:
        s += f" …(+{len(text) - limit} more chars)"
    return s
