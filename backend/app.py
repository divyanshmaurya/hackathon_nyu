"""HTTP API + static hosting for the Groundtruth candidate tool.

    uvicorn app:app --reload --port 8000
"""
from __future__ import annotations

import pathlib
import tempfile

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from groundtruth.corroborate.transport import CassetteTransport, default_transport
from groundtruth.observability.prism import PrismRecorder
from groundtruth.verify import verify

HERE = pathlib.Path(__file__).resolve().parent
STATIC = HERE / "static"
CASSETTES = HERE / "tests" / "cassettes"

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
    t = _transport()
    return {
        "ok": True,
        "corroboration": "live" if t.live else type(t).__name__,
        "prism": "enabled" if _recorder.enabled else _recorder.why_disabled(),
    }


@app.post("/api/verify")
async def api_verify(
    sender: str = Form(...),
    message: str = Form(""),
    company: str = Form(""),
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
            transport=_transport(),
            recorder=_recorder,
        )
        return JSONResponse(v.to_dict())
    finally:
        if tmp_path:
            pathlib.Path(tmp_path).unlink(missing_ok=True)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
