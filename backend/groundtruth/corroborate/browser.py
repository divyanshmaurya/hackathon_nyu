"""Rendering a page the way a person would see it.

Careers pages are the one check a scammer cannot defeat. They can forge an
email, register a look-alike domain, and doctor an offer letter — but they
cannot post a job on the real company's careers site. So "is this role actually
listed where the company lists its roles?" is the most decisive question
available to a candidate.

It is also the check that genuinely needs a browser. Careers pages are almost
universally client-rendered: a Greenhouse or Lever embed, a Workday SPA,
search that runs in JavaScript. An HTTP fetch returns an empty shell, so the
naive implementation concludes "no roles found" for every real employer —
precisely the false negative that would make this feature harmful.

Three backends behind one interface, matching the corroboration transport:

  SolariBrowser  managed stealth Chromium. Careers pages sit behind bot
                 protection (Cloudflare, PerimeterX, Datadome) that blocks
                 plain headless browsers, which is the specific problem a
                 managed stealth browser exists to solve.
  LocalBrowser   local Playwright Chromium. Fine for development and for sites
                 without bot protection.
  OfflineBrowser refuses, rather than reporting a page as empty when it was
                 never loaded.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
from dataclasses import dataclass, field
from typing import Protocol


class BrowsingUnavailable(RuntimeError):
    """We could not load the page, as distinct from loading it and finding nothing."""


@dataclass
class RenderedPage:
    url: str
    final_url: str
    title: str
    text: str
    links: list[tuple[str, str]] = field(default_factory=list)  # (text, href)
    status: int = 200
    engine: str = ""


def _run_async(coro, timeout: float = 90.0):
    """Run a coroutine from sync code, even if a loop is already running.

    FastAPI handlers are async and the CLI is not, so neither asyncio.run nor a
    bare await works in both. A dedicated thread with its own loop works in
    either, at the cost of one thread per check.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro)).result(timeout=timeout)


# --------------------------------------------------------------------------
# Shared page-scraping logic, used identically by both real backends.
# --------------------------------------------------------------------------

async def _harvest(page, url: str, engine: str, wait_ms: int) -> RenderedPage:
    resp = await page.goto(url, wait_until="domcontentloaded", timeout=45000)
    # Client-rendered job lists arrive after the initial paint. networkidle is
    # unreliable on pages with analytics beacons, so we settle for a fixed
    # grace period plus a best-effort idle wait.
    try:
        await page.wait_for_load_state("networkidle", timeout=wait_ms)
    except Exception:
        await page.wait_for_timeout(wait_ms)

    text = await page.evaluate("() => document.body ? document.body.innerText : ''")
    links = await page.evaluate(
        "() => Array.from(document.querySelectorAll('a[href]'))"
        ".slice(0, 400).map(a => [a.innerText.trim().slice(0,160), a.href])")
    return RenderedPage(
        url=url, final_url=page.url, title=await page.title(),
        text=text or "", links=[(t, h) for t, h in links if h],
        status=(resp.status if resp else 0), engine=engine,
    )


class Browser(Protocol):
    def render(self, url: str, wait_ms: int = 2500) -> RenderedPage: ...
    @property
    def engine(self) -> str: ...


class SolariBrowser:
    """Managed stealth Chromium via the Solari API."""

    def __init__(self, api_key: str | None = None, region: str = "us-west",
                 stealth: bool = True, captcha: bool = False):
        self.api_key = api_key or os.environ.get("SOLARI_API_KEY")
        if not self.api_key:
            raise BrowsingUnavailable(
                "SOLARI_API_KEY is not set. Redeem the hackathon promo code at "
                "console.getsolari.com (billing → HRHACK2026-DHKB2CEH) and "
                "export the key.")
        self.region, self.stealth, self.captcha = region, stealth, captcha

    @property
    def engine(self) -> str:
        return "solari"

    def render(self, url: str, wait_ms: int = 2500) -> RenderedPage:
        return _run_async(self._render(url, wait_ms))

    async def _render(self, url: str, wait_ms: int) -> RenderedPage:
        from solari_browser import Solari, SolariError

        try:
            async with Solari(api_key=self.api_key, region=self.region) as solari:
                async with await solari.launch(
                    stealth=self.stealth, captcha=self.captcha
                ) as browser:
                    page = await browser.new_page()
                    try:
                        return await _harvest(page, url, "solari", wait_ms)
                    finally:
                        await page.close()
        except SolariError as exc:
            raise BrowsingUnavailable(f"Solari could not load {url}: {exc}") from exc
        except Exception as exc:
            raise BrowsingUnavailable(f"Could not load {url}: {exc}") from exc


class LocalBrowser:
    """Local Playwright Chromium. No stealth; bot-protected sites will block it."""

    def __init__(self, executable_path: str | None = None):
        self.executable_path = executable_path or os.environ.get("CHROMIUM_PATH")

    @property
    def engine(self) -> str:
        return "local-chromium"

    def render(self, url: str, wait_ms: int = 2500) -> RenderedPage:
        return _run_async(self._render(url, wait_ms))

    async def _render(self, url: str, wait_ms: int) -> RenderedPage:
        from playwright.async_api import async_playwright

        kw = {"args": ["--no-sandbox"]}
        if self.executable_path:
            kw["executable_path"] = self.executable_path
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(**kw)
                try:
                    page = await browser.new_page()
                    return await _harvest(page, url, "local-chromium", wait_ms)
                finally:
                    await browser.close()
        except Exception as exc:
            raise BrowsingUnavailable(f"Could not load {url}: {exc}") from exc


class OfflineBrowser:
    @property
    def engine(self) -> str:
        return "offline"

    def render(self, url: str, wait_ms: int = 2500) -> RenderedPage:
        raise BrowsingUnavailable(
            "Page rendering is unavailable: no Solari key and no local browser. "
            "The careers page was NOT checked — that is not the same as the "
            "role being absent from it.")


def default_browser() -> Browser:
    """Solari when a key exists, local Chromium when one is installed, else offline."""
    if os.environ.get("SOLARI_API_KEY"):
        return SolariBrowser()
    for path in (os.environ.get("CHROMIUM_PATH"),
                 "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"):
        if path and os.path.exists(path):
            return LocalBrowser(path)
    try:
        import playwright  # noqa: F401
        return LocalBrowser()
    except ImportError:
        return OfflineBrowser()
