"""HTTP API + static hosting for the Groundtruth candidate tool.

    uvicorn app:app --reload --port 8000
"""
from __future__ import annotations

import json
import pathlib
import tempfile

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from groundtruth.config import load_env
load_env()

from groundtruth.attest.resolver import LocalRegistry, default_resolver
from groundtruth.corroborate.transport import CassetteTransport, default_transport
from groundtruth.observability.prism import PrismRecorder
from groundtruth.verify import STAGES, Progress, Verification, verify, verify_iter

HERE = pathlib.Path(__file__).resolve().parent
STATIC = HERE / "static"
CASSETTES = HERE / "tests" / "cassettes"
REGISTRY = HERE / "tests" / "registry"

app = FastAPI(title="Groundtruth", version="0.1.0",
              description="Verify who is recruiting you, before you hand over anything.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

_recorder = PrismRecorder()


def _transport():
    """Live when a Tavily key exists; cassettes otherwise so the demo runs."""
    t = default_transport(CASSETTES if CASSETTES.is_dir() else None)
    return t


@app.get("/api/health")
def health() -> dict:
    from groundtruth.corroborate.browser import default_browser
    t = _transport()
    return {
        "ok": True,
        "corroboration": "live" if t.live else type(t).__name__,
        "browser": default_browser().engine,
        "can_browse": default_browser().engine != "offline",
        "prism": "enabled" if _recorder.enabled else _recorder.why_disabled(),
    }


@app.post("/api/verify")
async def api_verify(
    sender: str = Form(...),
    message: str = Form(""),
    company: str = Form(""),
    attestation: str = Form(""),
    me: str = Form(""),
    role: str = Form(""),
    check_posting: bool = Form(False),
    document: UploadFile | None = File(None),
) -> JSONResponse:
    tmp_path = None
    try:
        if document is not None and document.filename:
            suffix = pathlib.Path(document.filename).suffix or ".pdf"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as fh:
                fh.write(await document.read())
                tmp_path = fh.name

        v = verify(
            sender=sender.strip(),
            message=message,
            claimed_company=(company.strip() or None),
            document_path=tmp_path,
            attestation=(attestation.strip() or None),
            recipient_email=(me.strip() or None),
            role=(role.strip() or None),
            check_posting_page=bool(check_posting),
            transport=_transport(),
            recorder=_recorder,
            resolver=(LocalRegistry(REGISTRY) if REGISTRY.is_dir()
                      else default_resolver()),
        )
        return JSONResponse(v.to_dict())
    finally:
        if tmp_path:
            pathlib.Path(tmp_path).unlink(missing_ok=True)


@app.post("/api/verify/stream")
async def api_verify_stream(
    sender: str = Form(...),
    message: str = Form(""),
    company: str = Form(""),
    attestation: str = Form(""),
    me: str = Form(""),
    role: str = Form(""),
    check_posting: bool = Form(False),
    document: UploadFile | None = File(None),
) -> StreamingResponse:
    """Same verification, streamed as newline-delimited JSON.

    Each line is a real event emitted when that check finished — not a
    completed result replayed on a timer.
    """
    tmp_path = None
    if document is not None and document.filename:
        suffix = pathlib.Path(document.filename).suffix or ".pdf"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as fh:
            fh.write(await document.read())
            tmp_path = fh.name

    def events():
        try:
            yield json.dumps({"event": "start",
                              "stages": [{"stage": k, "label": v}
                                         for k, v in STAGES]}) + "\n"
            for item in verify_iter(
                sender=sender.strip(), message=message,
                claimed_company=(company.strip() or None),
                document_path=tmp_path,
                attestation=(attestation.strip() or None),
                recipient_email=(me.strip() or None),
                role=(role.strip() or None),
                check_posting_page=bool(check_posting),
                transport=_transport(), recorder=_recorder,
                resolver=(LocalRegistry(REGISTRY) if REGISTRY.is_dir()
                          else default_resolver()),
            ):
                if isinstance(item, Progress):
                    yield json.dumps(item.to_dict()) + "\n"
                elif isinstance(item, Verification):
                    yield json.dumps({"event": "result",
                                      "result": item.to_dict()}) + "\n"
        except Exception as exc:  # surfaced to the client, not swallowed
            yield json.dumps({"event": "error", "detail": str(exc)}) + "\n"
        finally:
            if tmp_path:
                pathlib.Path(tmp_path).unlink(missing_ok=True)

    return StreamingResponse(events(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/demo-token")
def demo_token() -> dict:
    """The sample attestation used by the built-in examples."""
    f = REGISTRY / "_demo_token.txt"
    return {"token": f.read_text().strip() if f.is_file() else ""}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
