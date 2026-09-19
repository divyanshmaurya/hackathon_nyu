"""A realistic, full-page offer letter -- for demos, not for isolating one bug.

Everything in offers/01-05 is a deliberately terse fixture, built to isolate
one tampering signature at a time. This one is for pitches: dense, multi-
section, the length and structure of an actual corporate offer letter, so it
reads as convincing on screen instead of as a test fixture. It is entirely
clean -- consistent font throughout, no forged fields -- so it should come
back from scan_pdf() as verdict=clean.

The company is fictional (Nimbus Cloud Systems), same convention as every
other sample in this directory: built for a demo of software we wrote, not
to impersonate anyone real.
"""
from __future__ import annotations

import pathlib

import pymupdf

OUT = pathlib.Path(__file__).parent / "offers"
OUT.mkdir(parents=True, exist_ok=True)

MARGIN = 58
PAGE_W = 595
PAGE_H = 842
BODY_SIZE = 10
LINEHEIGHT = 1.32
ACCENT = (0.09, 0.32, 0.27)
GREY = (0.4, 0.4, 0.38)
INK = (0.08, 0.08, 0.07)

_MEASURE_PAGE = pymupdf.open()  # scratch doc, never saved, purely for measurement


def _wrapped_height(text, width, fontsize=BODY_SIZE, fontname="helv",
                    lineheight=LINEHEIGHT):
    """How tall a rect needs to be for `text` to wrap and fit at this width.

    insert_textbox() does not partially render text that overflows its rect
    -- it silently drops the whole paragraph -- and a hand-rolled word-wrap
    estimate came out a hair short of what MuPDF's own wrapper actually
    needs, dropping a whole section without any error. So this asks MuPDF
    itself: render into a scratch page with a very tall rect, read back how
    much of it was unused, and derive the real height from that -- exact by
    construction instead of approximated.
    """
    tall = 400.0
    scratch = _MEASURE_PAGE.new_page(width=width + 1, height=tall)
    try:
        spare = scratch.insert_textbox(
            pymupdf.Rect(0, 0, width, tall), text,
            fontsize=fontsize, fontname=fontname, lineheight=lineheight)
        return tall - spare
    finally:
        _MEASURE_PAGE.delete_page(scratch.number)


def _heading(page, y, text, size=10.5):
    page.insert_text((MARGIN, y), text, fontsize=size, fontname="hebo", color=ACCENT)
    return y + size + 3


def _para(page, y, text, size=BODY_SIZE):
    width = PAGE_W - 2 * MARGIN
    height = _wrapped_height(text, width, size) + 2  # small safety margin
    rect = pymupdf.Rect(MARGIN, y, PAGE_W - MARGIN, y + height)
    page.insert_textbox(rect, text, fontsize=size, fontname="helv", color=INK,
                        lineheight=LINEHEIGHT)
    return y + height + 5


def build():
    doc = pymupdf.open()
    page = doc.new_page()  # A4, 595x842
    y = 48.0

    # Letterhead
    page.insert_text((MARGIN, y), "NIMBUS CLOUD SYSTEMS, INC.",
                     fontsize=16, fontname="hebo", color=ACCENT)
    y += 17
    page.insert_text((MARGIN, y),
                     "455 Market Street, Suite 1400, San Francisco, CA 94105",
                     fontsize=8.5, fontname="helv", color=GREY)
    y += 11
    page.insert_text((MARGIN, y),
                     "www.nimbuscloud.example   |   careers@nimbuscloud.example",
                     fontsize=8.5, fontname="helv", color=GREY)
    y += 9
    page.draw_line((MARGIN, y), (PAGE_W - MARGIN, y), color=ACCENT, width=1.1)
    y += 20

    page.insert_text((MARGIN, y), "September 19, 2026", fontsize=9.5, fontname="helv", color=INK)
    y += 20

    for line in ("Alex Morgan", "221 Greene Street, Apt 4B", "New York, NY 10012"):
        page.insert_text((MARGIN, y), line, fontsize=10, fontname="helv", color=INK)
        y += 13
    y += 10

    page.insert_text((MARGIN, y), "Dear Alex,", fontsize=10.5, fontname="helv", color=INK)
    y += 18

    page.insert_text((MARGIN, y), "RE: OFFER OF EMPLOYMENT - SENIOR SOFTWARE ENGINEER",
                     fontsize=10.5, fontname="hebo", color=ACCENT)
    y += 19

    y = _para(page, y,
        "On behalf of Nimbus Cloud Systems, Inc. (the \"Company\"), I am delighted "
        "to offer you the position of Senior Software Engineer, reporting to Jordan "
        "Reyes, Engineering Manager, Platform Infrastructure. We were impressed by "
        "your background and look forward to your contribution to our team.")

    y = _heading(page, y, "Compensation & Benefits")
    y = _para(page, y,
        "Your annual base salary will be $185,000, paid semi-monthly. You are "
        "eligible for an annual bonus target of 10% of base salary, subject to "
        "Company and individual performance, and an equity grant of 2,500 "
        "Restricted Stock Units (RSUs) vesting over four years. You may "
        "participate in the Company's health, dental, vision, and 401(k) plans "
        "on the same terms as other full-time employees.")

    y = _heading(page, y, "Start Date & Location")
    y = _para(page, y,
        "Your anticipated start date is March 3, 2026. This role is based at our "
        "San Francisco office under the Company's hybrid policy, currently three "
        "days per week in-office.")

    y = _heading(page, y, "Contingencies")
    y = _para(page, y,
        "This offer is contingent upon: (i) a satisfactory background check, "
        "(ii) verification of your right to work in the United States as "
        "required by federal law, and (iii) execution of the Company's standard "
        "Proprietary Information and Inventions Assignment Agreement.")

    y = _heading(page, y, "At-Will Employment")
    y = _para(page, y,
        "Your employment, if commenced, will be \"at will\": either you or the "
        "Company may terminate the relationship at any time, with or without "
        "cause or advance notice.")

    y = _heading(page, y, "Acceptance")
    y = _para(page, y,
        "This offer is open until 11:59 PM Eastern Time on September 26, 2026, "
        "after which it will be considered withdrawn unless extended in "
        "writing. To accept, sign and return a copy of this letter. We are "
        "excited about the possibility of you joining Nimbus.")
    y += 4

    page.insert_text((MARGIN, y), "Sincerely,", fontsize=10, fontname="helv", color=INK)
    y += 26
    page.insert_text((MARGIN, y), "Jordan Reyes", fontsize=10, fontname="hebo", color=INK)
    y += 12
    page.insert_text((MARGIN, y), "Director, Talent Acquisition",
                     fontsize=9, fontname="helv", color=GREY)
    y += 11
    page.insert_text((MARGIN, y), "Nimbus Cloud Systems, Inc.",
                     fontsize=9, fontname="helv", color=GREY)
    y += 22

    page.draw_line((MARGIN, y), (PAGE_W - MARGIN, y), color=GREY, width=0.6)
    y += 16
    page.insert_text((MARGIN, y), "ACCEPTANCE", fontsize=9.5, fontname="hebo", color=ACCENT)
    y += 15
    page.insert_text((MARGIN, y),
                     "I, Alex Morgan, accept the terms of this offer as outlined above.",
                     fontsize=9.5, fontname="helv", color=INK)
    y += 24
    page.insert_text((MARGIN, y),
                     "Signature: ______________________          Date: ______________",
                     fontsize=9.5, fontname="helv", color=INK)
    y += 20

    assert y < PAGE_H - 24, f"content overflowed the page: y={y:.1f} of {PAGE_H}"

    doc.set_metadata({
        "title": "Offer of Employment - Alex Morgan",
        "producer": "DocuSign Envelope Generator 24.3",
        "creator": "Workday Recruiting",
    })
    doc.save(OUT / "06_full_realistic_offer.pdf")
    doc.close()


if __name__ == "__main__":
    build()
    print("generated:", OUT / "06_full_realistic_offer.pdf")
