"""Offer-letter corpus: one genuine, three doctored, one template-filled control."""
from __future__ import annotations
import pathlib, pymupdf

OUT = pathlib.Path(__file__).parent / "offers"
OUT.mkdir(parents=True, exist_ok=True)

BODY = [
    ("Datadog, Inc.", 16, "helv"),
    ("620 8th Avenue, New York, NY 10018", 9, "helv"),
    ("", 11, "helv"),
    ("OFFER OF EMPLOYMENT", 13, "hebo"),
    ("", 11, "helv"),
]
PARA = [
    "Dear {name},",
    "",
    "We are pleased to offer you the position of Senior Software Engineer",
    "at Datadog, Inc. Your annual base salary will be {salary}, paid",
    "semi-monthly in accordance with company payroll practices.",
    "",
    "Your anticipated start date is {start}. This offer is contingent",
    "upon satisfactory completion of a background check.",
    "",
    "Sincerely,",
    "Talent Acquisition, Datadog, Inc.",
]

def _render(page, name, salary, start, *, tamper_field=None, tamper_font="tiro",
            tamper_size=None):
    y = 64.0
    for text, size, font in BODY:
        if text:
            page.insert_text((60, y), text, fontsize=size, fontname=font)
        y += size + 6

    for line in PARA:
        y += 15
        if not line:
            continue
        # Split the line around the placeholder so the substituted value is a
        # separate span, which is exactly what a real edit produces.
        for token, value in (("{name}", name), ("{salary}", salary), ("{start}", start)):
            if token in line:
                before, after = line.split(token)
                x = 60.0
                page.insert_text((x, y), before, fontsize=11, fontname="helv")
                x += pymupdf.get_text_length(before, fontname="helv", fontsize=11)
                if tamper_field == token:
                    fs = tamper_size or 11
                    page.insert_text((x, y), value, fontsize=fs, fontname=tamper_font)
                    x += pymupdf.get_text_length(value, fontname=tamper_font, fontsize=fs)
                else:
                    page.insert_text((x, y), value, fontsize=11, fontname="helv")
                    x += pymupdf.get_text_length(value, fontname="helv", fontsize=11)
                page.insert_text((x, y), after, fontsize=11, fontname="helv")
                break
        else:
            page.insert_text((60, y), line, fontsize=11, fontname="helv")


def genuine():
    doc = pymupdf.open(); page = doc.new_page()
    _render(page, "Alex Morgan", "$185,000", "March 3, 2026")
    doc.set_metadata({"title": "Offer of Employment",
                      "producer": "DocuSign Envelope Generator 24.3",
                      "creator": "Workday Recruiting"})
    doc.save(OUT / "01_genuine_offer.pdf"); doc.close()


def salary_tampered():
    doc = pymupdf.open(); page = doc.new_page()
    _render(page, "Alex Morgan", "$310,000", "March 3, 2026",
            tamper_field="{salary}", tamper_font="tiro", tamper_size=12)
    doc.set_metadata({"title": "Offer of Employment",
                      "producer": "Microsoft: Print To PDF", "creator": "Microsoft Word"})
    doc.save(OUT / "02_salary_tampered.pdf"); doc.close()


def name_tampered():
    doc = pymupdf.open(); page = doc.new_page()
    _render(page, "Priya Raghavan", "$185,000", "March 3, 2026",
            tamper_field="{name}", tamper_font="cour", tamper_size=11.5)
    doc.set_metadata({"producer": "iLovePDF", "creator": "Canva"})
    doc.save(OUT / "03_name_tampered.pdf"); doc.close()


def whiteout_overlay():
    """Original value covered with a white box and a new value typed over it."""
    doc = pymupdf.open(); page = doc.new_page()
    _render(page, "Alex Morgan", "$185,000", "March 3, 2026")
    # Find the salary and paint over it.
    hits = page.search_for("$185,000")
    if hits:
        r = hits[0]
        page.draw_rect(r, color=(1, 1, 1), fill=(1, 1, 1))
        page.insert_text((r.x0, r.y1 - 2), "$295,000", fontsize=11, fontname="helv")
    doc.set_metadata({"producer": "iLovePDF"})
    doc.save(OUT / "04_whiteout_overlay.pdf"); doc.close()


def hand_filled_control():
    """CONTROL: a real small employer filling a template by hand.

    Produces a font mismatch with an innocent cause. The tool must report the
    edit without asserting fraud, and severity must stay below the doctored
    documents.
    """
    doc = pymupdf.open(); page = doc.new_page()
    _render(page, "Sam Rivera", "$140,000", "April 1, 2026",
            tamper_field="{start}", tamper_font="helv", tamper_size=11.4)
    doc.set_metadata({"producer": "LibreOffice 7.6", "creator": "Writer"})
    doc.save(OUT / "05_control_hand_filled.pdf"); doc.close()


if __name__ == "__main__":
    for fn in (genuine, salary_tampered, name_tampered, whiteout_overlay, hand_filled_control):
        fn(); print("generated:", fn.__name__)
