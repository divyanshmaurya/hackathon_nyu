"""Credential loading from .env."""
from __future__ import annotations

import pathlib
import sys

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
    tracked = [f for f in out.splitlines()
               if f.endswith(".pem") or pathlib.Path(f).name in (".env", ".env.local")]
    assert tracked == [], f"secret-shaped files are tracked: {tracked}"
