"""Loading credentials from a local .env file.

Exists so nobody is tempted to commit keys. A .env sitting next to the code is
as convenient as a file in the repo and does not end up on GitHub, where bots
scrape for exactly this and where anything committed survives in history after
you delete it.

Deliberately dependency-free and non-overriding: a variable already set in the
environment wins, so `TAVILY_API_KEY=x python3 -m ...` behaves as expected and
CI is never silently overridden by a stray file.
"""

from __future__ import annotations

import os
import pathlib
import sys

FILENAMES = (".env", ".env.local")

TRACKED = (
    "TAVILY_API_KEY",
    "PRISMTRACE_API_KEY",
    "PRISMTRACE_PROJECT_ID",
    "PRISMTRACE_HOST",
    "SOLARI_API_KEY",
)


class NotPlainText(RuntimeError):
    """The file is a rich-text document, not an env file."""


# TextEdit on macOS defaults to RTF, so "save your keys in a file" commonly
# produces one. Its markup parses into plausible-looking garbage rather than
# failing, which is the worst outcome: the keys appear loaded and every API
# call then 401s for no visible reason.
def _reject_rich_text(text: str, path: pathlib.Path) -> None:
    head = text.lstrip()[:20]
    if head.startswith("{\\rtf") or head.startswith("{\rtf"):
        raise NotPlainText(
            f"{path} is a Rich Text (RTF) document, not a plain-text env file. "
            f"Convert it with:\n\n    textutil -convert txt "
            f"{path} -output {path.parent / '.env'}\n")
    if text[:4] in ("PK\x03\x04",) or head.startswith("\xd0\xcf"):
        raise NotPlainText(f"{path} looks like a Word/Office document, not "
                           f"plain text. Re-save it as plain text.")


# Word processors substitute typographic quotes, which then become part of the
# value and produce authentication failures that look like a bad key.
_SMART_QUOTES = {"\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'"}


def _parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for smart, plain in _SMART_QUOTES.items():
        text = text.replace(smart, plain)
    for raw in text.splitlines():
        line = raw.lstrip("\ufeff").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not key:
            continue
        # Strip matched quotes; leave inner content alone.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            # An unquoted trailing comment is a comment; a quoted one is data.
            value = value.split(" #")[0].rstrip()
        out[key] = value
    return out


def load_env(start: str | pathlib.Path | None = None, override: bool = False) -> list[str]:
    """Load .env files found at or above `start`. Returns the names it set."""
    here = pathlib.Path(start or __file__).resolve()
    if here.is_file():
        here = here.parent

    loaded: list[str] = []
    for directory in [here, *here.parents]:
        for name in FILENAMES:
            path = directory / name
            if not path.is_file():
                continue
            try:
                raw = path.read_text(errors="replace")
                _reject_rich_text(raw, path)
                values = _parse(raw)
            except OSError:
                continue
            except NotPlainText as exc:
                # Loud, not silent: a mis-saved file that loads as nonsense is
                # harder to diagnose than one that refuses.
                print(f"\n  Cannot read credentials: {exc}", file=sys.stderr)
                continue
            for key, value in values.items():
                if override or key not in os.environ:
                    os.environ[key] = value
                    loaded.append(key)
        if (directory / ".git").exists():
            break  # stop at the repository root
    return loaded


def status() -> dict[str, bool]:
    """Which credentials are present. Never returns the values themselves."""
    return {k: bool(os.environ.get(k)) for k in TRACKED}
