"""Credential loading from .env."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.config import _parse, load_env, status  # noqa: E402


def test_parses_the_shapes_people_actually_write():
    got = _parse(
        "# comment line\n"
        "TAVILY_API_KEY=tvly-abc123\n"
        "export SOLARI_API_KEY=slr_live_x\n"
        'PRISMTRACE_API_KEY="quoted-value"\n'
        "PRISMTRACE_PROJECT_ID='single'\n"
        "SPACED = padded \n"
        "\n"
        "WITH_COMMENT=value # trailing note\n"
    )
    assert got["TAVILY_API_KEY"] == "tvly-abc123"
    assert got["SOLARI_API_KEY"] == "slr_live_x"      # `export ` prefix tolerated
    assert got["PRISMTRACE_API_KEY"] == "quoted-value"
    assert got["PRISMTRACE_PROJECT_ID"] == "single"
    assert got["SPACED"] == "padded"
    assert got["WITH_COMMENT"] == "value"


def test_hash_inside_a_quoted_value_is_kept():
    """Coupon codes contain '#'. Stripping it would corrupt the value."""
    assert _parse('COUPON="HACKBUILDER#3"')["COUPON"] == "HACKBUILDER#3"


def test_existing_environment_wins_by_default(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("TAVILY_API_KEY=from-file\n")
    monkeypatch.setenv("TAVILY_API_KEY", "from-shell")
    load_env(tmp_path)
    import os
    assert os.environ["TAVILY_API_KEY"] == "from-shell"


def test_override_is_available_when_asked(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("TAVILY_API_KEY=from-file\n")
    monkeypatch.setenv("TAVILY_API_KEY", "from-shell")
    load_env(tmp_path, override=True)
    import os
    assert os.environ["TAVILY_API_KEY"] == "from-file"


def test_missing_file_is_not_an_error(tmp_path):
    assert load_env(tmp_path) == []


def test_status_reports_presence_never_values(monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-secret-value")
    st = status()
    assert st["TAVILY_API_KEY"] is True
    assert all(isinstance(v, bool) for v in st.values())
    assert "tvly-secret-value" not in str(st)


def test_no_secrets_are_tracked_in_git():
    """Release gate: a key committed once survives in history forever."""
    import subprocess
    root = pathlib.Path(__file__).resolve().parents[2]
    out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True,
                         text=True).stdout
    SECRET_NAMES = {".env", ".env.local", "keys", "secrets", "credentials",
                    "api_keys", "api-keys"}
    # A stem match alone is too broad: attest/keys.py is source code. Only
    # treat a suspicious stem as a secret when the file is not code or docs.
    CODE_SUFFIXES = {".py", ".ts", ".js", ".tsx", ".jsx", ".md", ".json",
                     ".yaml", ".yml", ".toml", ".html", ".css", ".sh",
                     ".example", ".rst", ".txt.example"}
    tracked = []
    for f in out.splitlines():
        path = pathlib.Path(f)
        name, suffix = path.name, path.suffix.lower()
        stem = name.split(".")[0].lower()
        if suffix in CODE_SUFFIXES:
            continue
        if f.endswith(".pem") or name in SECRET_NAMES or stem in SECRET_NAMES:
            tracked.append(f)
    assert tracked == [], f"secret-shaped files are tracked: {tracked}"


def test_gitignore_covers_hand_made_credential_files():
    """The loader reads .env, but people create files called 'keys' while
    setting up, and nothing else would stop those being committed."""
    root = pathlib.Path(__file__).resolve().parents[2]
    ignored = (root / ".gitignore").read_text()
    for pattern in ("/keys", "/secrets", "/credentials", "*.pem", ".env"):
        assert pattern in ignored, f"{pattern} is not gitignored"


def test_source_files_named_keys_are_not_ignored():
    """Regression: an unanchored 'keys.*' pattern also matched
    groundtruth/attest/keys.py, quietly excluding source from the repo."""
    import subprocess
    root = pathlib.Path(__file__).resolve().parents[2]
    r = subprocess.run(["git", "check-ignore", "-q",
                        "backend/groundtruth/attest/keys.py"],
                       cwd=root, capture_output=True)
    assert r.returncode != 0, "attest/keys.py is being gitignored"


def test_rtf_file_is_rejected_with_the_conversion_command(tmp_path):
    """TextEdit defaults to RTF, so "save your keys in a file" commonly makes
    one. Its markup parses into plausible garbage rather than failing, so the
    keys look loaded and every API call then 401s for no visible reason."""
    from groundtruth.config import NotPlainText, _reject_rich_text
    f = tmp_path / "keys.rtf"
    f.write_text(r"{\rtf1\ansi\ansicpg1252 \f0\fs24 TAVILY_API_KEY=tvly-abc}")
    with pytest.raises(NotPlainText) as e:
        _reject_rich_text(f.read_text(), f)
    assert "textutil -convert txt" in str(e.value)


def test_rtf_env_file_does_not_load_garbage(tmp_path, monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    (tmp_path / ".env").write_text(
        r"{\rtf1\ansi\ansicpg1252 \f0\fs24 TAVILY_API_KEY=tvly-abc}")
    load_env(tmp_path)
    import os
    assert "TAVILY_API_KEY" not in os.environ


def test_typographic_quotes_are_normalised():
    """Word processors substitute curly quotes, which otherwise become part of
    the value and produce auth failures that look like a bad key."""
    assert _parse("TAVILY_API_KEY=“tvly-abc”")["TAVILY_API_KEY"] == "tvly-abc"
    assert _parse("K=‘v’")["K"] == "v"


def test_leading_byte_order_mark_is_stripped():
    assert _parse("﻿TAVILY_API_KEY=tvly-abc")["TAVILY_API_KEY"] == "tvly-abc"
