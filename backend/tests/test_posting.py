"""Careers-page verification.

Runs against a local fixture site whose job listings are injected by
JavaScript, because that is how essentially every real careers page works. The
first test asserts the fixture actually has that property — without it, the
rest of the suite would pass against a static page and prove nothing about the
case this feature exists for.

Severity discipline here is asymmetric by design: finding a role is strong
evidence, not finding one is close to no evidence.
"""
from __future__ import annotations

import functools
import http.server
import pathlib
import socket
import sys
import threading
import urllib.request

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.corroborate.browser import (  # noqa: E402
    BrowsingUnavailable, LocalBrowser, OfflineBrowser, default_browser)
from groundtruth.corroborate.posting import (  # noqa: E402
    check_posting, role_present, role_tokens)
from groundtruth.integrity.findings import Severity  # noqa: E402
from groundtruth.outreach.domains import registrable_parts  # noqa: E402

SITE = pathlib.Path(__file__).parent / "fixtures" / "site"
CHROMIUM = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"


@pytest.fixture(scope="module")
def site():
    """Serve the fixture site on a free port for the duration of the module."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=str(SITE))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


@pytest.fixture(scope="module")
def browser():
    path = CHROMIUM if pathlib.Path(CHROMIUM).exists() else None
    try:
        b = LocalBrowser(path)
        b.render("about:blank", wait_ms=100)
        return b
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"no usable local browser: {exc}")


# ------------------------------------------------------- the premise itself ---

def test_fixture_listings_are_javascript_rendered(site):
    """If this fails the fixture is static and every other test here is vacuous."""
    raw = urllib.request.urlopen(f"{site}/careers.html").read().decode()
    visible_html = raw.split("<script>")[0]
    assert "Senior Robotics Engineer" not in visible_html
    assert "Senior Robotics Engineer" in raw  # present, but only inside the script


def test_browser_sees_what_a_plain_fetch_cannot(site, browser):
    page = browser.render(f"{site}/careers.html", wait_ms=1500)
    assert "Senior Robotics Engineer" in page.text
    assert any("robotics-eng" in href for _, href in page.links)


# ------------------------------------------------------------ role matching ---

def test_seniority_words_are_not_matched_on():
    assert "senior" not in role_tokens("Senior Software Engineer")
    assert {"software", "engineer"} <= role_tokens("Senior Software Engineer")


@pytest.mark.parametrize("role,expected", [
    ("Senior Robotics Engineer", True),
    ("Technical Program Manager", True),
    ("Robotics Engineer", True),            # partial: matches the senior listing
    ("Director of Sales", False),
    ("Senior Accountant", False),
])
def test_role_matching(site, browser, role, expected):
    page = browser.render(f"{site}/careers.html", wait_ms=1500)
    found, _ = role_present(page, role)
    assert found is expected


# --------------------------------------------------------------- end to end ---

def test_listed_role_is_positive_evidence(site, browser):
    ev = check_posting("northwind.test", "Senior Robotics Engineer", browser,
                       base_url=site)
    assert ev.checked and ev.found is True
    f = ev.findings[0]
    assert f.code == "POSTING_FOUND" and f.severity is Severity.INFO
    assert "nobody can publish a job on a company's own site" in f.detail


def test_careers_page_is_found_by_following_the_homepage_link(site, browser):
    """The fixture's careers page is at /careers.html, which is not in
    CAREERS_PATHS — it can only be reached via the homepage link."""
    ev = check_posting("northwind.test", "Technical Program Manager", browser,
                       base_url=site)
    assert ev.careers_url.endswith("/careers.html")


def test_absent_role_is_capped_at_medium_and_says_why(site, browser):
    """Roles get filled, go unposted, or sit behind search. A miss must not
    read as evidence of fraud."""
    ev = check_posting("northwind.test", "Director of Sales", browser, base_url=site)
    f = ev.findings[0]
    assert f.code == "POSTING_NOT_LISTED"
    assert f.severity is Severity.MEDIUM
    assert "not evidence of anything on its own" in f.detail
    for word in ("fraud", "fake", "scam"):
        assert word not in f.detail.lower()


def test_unreachable_site_is_reported_as_unchecked(browser):
    ev = check_posting("no-such-host.invalid", "Engineer", browser)
    assert ev.checked is False
    f = ev.findings[0]
    assert f.code == "POSTING_NOT_CHECKED" and f.severity is Severity.INFO
    assert "says nothing about the role" in f.detail


# ------------------------------------------------------------------ backends ---

def test_offline_browser_refuses_rather_than_returning_empty():
    with pytest.raises(BrowsingUnavailable) as e:
        OfflineBrowser().render("https://example.com")
    assert "not the same as the role being absent" in str(e.value)


def test_solari_backend_reports_a_missing_key_clearly(monkeypatch):
    from groundtruth.corroborate.browser import SolariBrowser
    monkeypatch.delenv("SOLARI_API_KEY", raising=False)
    with pytest.raises(BrowsingUnavailable) as e:
        SolariBrowser()
    assert "SOLARI_API_KEY" in str(e.value)


def test_solari_is_preferred_when_a_key_exists(monkeypatch):
    monkeypatch.setenv("SOLARI_API_KEY", "slr_live_test")
    assert default_browser().engine == "solari"


def test_ip_literal_is_not_split_into_a_registrable_name():
    """Regression: 127.0.0.1 parsed to ('0', '1') and was then compared against
    company names."""
    assert registrable_parts("127.0.0.1") == ("127.0.0.1", "")


def test_offline_when_browser_clients_are_not_installed(monkeypatch):
    """Serverless builds omit playwright and solari-browser because together
    they exceed the function size limit. Claiming a backend there would fail at
    render time instead of saying up front that the check cannot run."""
    import groundtruth.corroborate.browser as b
    monkeypatch.setenv("SOLARI_API_KEY", "slr_live_test")
    monkeypatch.setattr(b, "_importable", lambda name: False)
    assert b.default_browser().engine == "offline"


def test_a_chromium_binary_alone_is_not_enough(monkeypatch, tmp_path):
    """A browser on disk is useless without the client library that drives it."""
    import groundtruth.corroborate.browser as b
    fake = tmp_path / "chrome"
    fake.write_text("")
    monkeypatch.delenv("SOLARI_API_KEY", raising=False)
    monkeypatch.setenv("CHROMIUM_PATH", str(fake))
    monkeypatch.setattr(b, "_importable", lambda name: False)
    assert b.default_browser().engine == "offline"
