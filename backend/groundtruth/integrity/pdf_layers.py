"""Split a PDF into what a human sees and what a text extractor sees.

This module is the reason the rest of the integrity axis can avoid false
positives. Everything else asks "is this string suspicious?". This asks the
question that actually separates fraud from discussion: *would a human ever
have seen it?*

A span is classified HIDDEN when any of the following hold:

  - render mode 3 (the PDF "invisible text" flag, used legitimately for OCR
    layers under scanned images, and illegitimately for payloads)
  - font size at or below 1pt
  - fill colour equal (or near-equal) to the page background
  - the span's bounding box falls outside the visible page area
  - the span has zero width or height
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    import pymupdf  # type: ignore
except ImportError:  # pragma: no cover
    try:
        import fitz as pymupdf  # type: ignore
    except ImportError:
        pymupdf = None  # type: ignore

# PDF text rendering mode 3 == "neither fill nor stroke": invisible.
RENDER_MODE_INVISIBLE = 3
TINY_FONT_PT = 1.01
# sRGB distance under which we treat a fill colour as "same as the page".
BACKGROUND_DELTA = 0.06


@dataclass
class Span:
    text: str
    page: int
    hidden: bool
    reasons: list[str]
    font: str = ""
    size: float = 0.0
    color: tuple[float, float, float] = (0.0, 0.0, 0.0)
    bbox: tuple[float, float, float, float] = (0, 0, 0, 0)


@dataclass
class PdfLayers:
    visible_text: str
    hidden_text: str
    metadata_text: str
    spans: list[Span]
    metadata: dict[str, Any]
    page_count: int
    available: bool = True
    note: str = ""


def _int_to_rgb(c: int) -> tuple[float, float, float]:
    return (((c >> 16) & 255) / 255, ((c >> 8) & 255) / 255, (c & 255) / 255)


def _near(a: tuple[float, float, float], b: tuple[float, float, float]) -> bool:
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5 <= BACKGROUND_DELTA * (3 ** 0.5)


def _classify(span: dict[str, Any], page_rect: Any, bg: tuple[float, float, float]) -> list[str]:
    """Return the reasons this span is invisible to a human. Empty == visible."""
    reasons: list[str] = []

    if span.get("text", "").strip() == "":
        return ["empty"]

    # PyMuPDF surfaces render mode 3 / transparent fills as alpha == 0 rather
    # than exposing the raw Tr operator, so alpha is the reliable signal.
    if span.get("alpha", 255) == 0:
        reasons.append("fully transparent (PDF render mode 3 / alpha 0)")
    if span.get("render_mode", 0) == RENDER_MODE_INVISIBLE:
        reasons.append("PDF render mode 3 (invisible text flag)")

    size = float(span.get("size", 0) or 0)
    if 0 < size <= TINY_FONT_PT:
        reasons.append(f"font size {size:.2f}pt is too small to read")

    rgb = _int_to_rgb(int(span.get("color", 0) or 0))
    if _near(rgb, bg):
        reasons.append(
            f"fill colour rgb{tuple(round(v, 2) for v in rgb)} matches the page background"
        )

    x0, y0, x1, y1 = span.get("bbox", (0, 0, 0, 0))
    if (x1 - x0) <= 0.01 or (y1 - y0) <= 0.01:
        reasons.append("zero-area bounding box")
    elif page_rect is not None:
        # Fully outside the page: rendered into the margin void.
        if x1 < page_rect.x0 - 1 or x0 > page_rect.x1 + 1 or y1 < page_rect.y0 - 1 or y0 > page_rect.y1 + 1:
            reasons.append("positioned outside the visible page area")

    return reasons


def extract(path_or_bytes: str | bytes) -> PdfLayers:
    """Extract per-layer text from a PDF.

    Degrades honestly: if PyMuPDF is unavailable we say so rather than
    silently reporting a document as clean.
    """
    if pymupdf is None:
        return PdfLayers(
            "", "", "", [], {}, 0,
            available=False,
            note="PyMuPDF not installed; PDF layer analysis unavailable. "
                 "Findings are limited to the flat text stream.",
        )

    if isinstance(path_or_bytes, bytes):
        doc = pymupdf.open(stream=path_or_bytes, filetype="pdf")
    else:
        doc = pymupdf.open(path_or_bytes)

    spans: list[Span] = []
    visible: list[str] = []
    hidden: list[str] = []

    for pno, page in enumerate(doc, start=1):
        rect = page.rect
        # Extract with a clip far larger than the page: PyMuPDF discards spans
        # outside the mediabox by default, which would silently drop exactly
        # the off-page payloads we need to catch.
        raw = page.get_text("dict", clip=pymupdf.Rect(-10000, -10000, 10000, 10000))
        for block in raw.get("blocks", []):
            for line in block.get("lines", []):
                for sp in line.get("spans", []):
                    reasons = _classify(sp, rect, bg=(1.0, 1.0, 1.0))
                    text = sp.get("text", "")
                    if reasons == ["empty"]:
                        continue
                    is_hidden = bool(reasons)
                    spans.append(
                        Span(
                            text=text,
                            page=pno,
                            hidden=is_hidden,
                            reasons=reasons,
                            font=sp.get("font", ""),
                            size=float(sp.get("size", 0) or 0),
                            color=_int_to_rgb(int(sp.get("color", 0) or 0)),
                            bbox=tuple(sp.get("bbox", (0, 0, 0, 0))),  # type: ignore
                        )
                    )
                    (hidden if is_hidden else visible).append(text)

    meta = dict(doc.metadata or {})
    meta_text = "\n".join(f"{k}: {v}" for k, v in meta.items() if v)
    page_count = doc.page_count
    doc.close()

    return PdfLayers(
        visible_text=" ".join(visible),
        hidden_text=" ".join(hidden),
        metadata_text=meta_text,
        spans=spans,
        metadata=meta,
        page_count=page_count,
    )
