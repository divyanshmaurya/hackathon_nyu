"""HTTP API + static hosting for the Groundtruth candidate tool.

    uvicorn app:app --reload --port 8000
"""
from __future__ import annotations

import json
import logging
import pathlib
import tempfile
import time
import uuid

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from groundtruth import config
from groundtruth.config import load_env
load_env()

from groundtruth.attest.resolver import LocalRegistry, default_resolver
from groundtruth.corroborate.transport import CassetteTransport, default_transport
from groundtruth.observability.prism import PrismRecorder
from groundtruth.ratelimit import FixedWindowLimiter, RateLimitExceeded
from groundtruth.verify import STAGES, Progress, Verification, verify, verify_iter

HERE = pathlib.Path(__file__).resolve().parent
STATIC = HERE / "static"
CASSETTES = HERE / "tests" / "cassettes"
REGISTRY = HERE / "tests" / "registry"

logging.basicConfig(level=logging.INFO,
                     format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("groundtruth.app")

app = FastAPI(title="Groundtruth", version="0.1.0",
              description="Verify who is recruiting you, before you hand over anything.")

_origins = config.allowed_origins()
if _origins == ["*"]:
    logger.warning("ALLOWED_ORIGINS not set; CORS is wide open. Fine for the "
                    "public demo, not for a deployment fronting anything "
                    "sensitive to a specific institution's domain.")
app.add_middleware(CORSMiddleware, allow_origins=_origins,
                   allow_methods=["GET", "POST"], allow_headers=["*"])

_recorder = PrismRecorder()
_verify_limiter = FixedWindowLimiter(limit=config.rate_limit_per_minute(), window_seconds=60.0)
_MAX_UPLOAD_BYTES = config.max_upload_bytes()


def _client_key(request: Request) -> str:
    """Best-effort client identity for rate limiting.

    Trusts X-Forwarded-For when present, which only means something behind a
    proxy that sets it honestly (a reverse proxy in front of this app). Behind
    no proxy, a client could spoof this header to dodge the limiter entirely
    -- acceptable for a single-instance demo, not for a hardened public edge;
    a real deployment should strip/overwrite this header at the load balancer.
    """
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request) -> None:
    try:
        _verify_limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail="Too many verification requests from this address. Try "
                   "again shortly.",
            headers={"Retry-After": str(int(exc.retry_after))},
        ) from exc


@app.middleware("http")
async def _observability(request: Request, call_next):
    """Structured request logging and baseline security headers.

    Deliberately does not log message/company/attestation/document content --
    only request metadata. A verification tool logging the outreach people
    paste in would be the same trust violation as the product it ships.
    """
    request_id = uuid.uuid4().hex[:12]
    t0 = time.perf_counter()
    response = await call_next(request)
    ms = int((time.perf_counter() - t0) * 1000)
    logger.info("request_id=%s method=%s path=%s status=%s ms=%s client=%s",
                request_id, request.method, request.url.path,
                response.status_code, ms, _client_key(request))

    response.headers["X-Request-Id"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
    # The page's own script and style are inline, so a strict CSP needs
    # 'unsafe-inline' for those two directives specifically -- everything
    # else stays locked to same-origin. Tightening this further means moving
    # the inline <script>/<style> in index.html to external files with a
    # nonce, which is a real follow-up, not done here.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "object-src 'none'",
    )
    return response


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """An uncaught error returns a generic message, never a stack trace.

    The real exception is logged server-side. Leaking internals in the
    response body is an information-disclosure risk on any public endpoint,
    and doubly so on one that processes uploaded documents.
    """
    logger.exception("unhandled_error method=%s path=%s",
                     request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Something went wrong on our side, and the check "
                            "did not complete. Nothing was verified for this "
                            "request -- that is not the same as a clean "
                            "result. Try again."},
    )


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
        "rate_limit_per_minute": config.rate_limit_per_minute(),
        "max_upload_mb": _MAX_UPLOAD_BYTES // (1024 * 1024),
    }


async def _save_upload_capped(document: UploadFile) -> str:
    """Stream an upload to a temp file, refusing past the configured cap.

    `UploadFile.read()` with no size argument buffers the whole file into
    memory regardless of how large it is, on an endpoint that requires no
    authentication -- a handful of concurrent large uploads is a cheap way to
    exhaust a small server's RAM. Reading in bounded chunks and aborting the
    moment the cap is crossed keeps the worst case fixed regardless of what a
    caller sends.
    """
    suffix = pathlib.Path(document.filename or "").suffix or ".pdf"
    total = 0
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as fh:
            tmp_path = fh.name
            while True:
                chunk = await document.read(256 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"That document is larger than the "
                               f"{_MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit.",
                    )
                fh.write(chunk)
    except Exception:
        if tmp_path:
            pathlib.Path(tmp_path).unlink(missing_ok=True)
        raise
    return tmp_path


# Bounds on form fields. Not about validity (an odd-shaped email is still
# worth checking) -- about keeping a single request's cost fixed regardless
# of what an unauthenticated caller sends: every field below feeds a regex
# scan, a search query, or a browser render.
_SENDER_MAX = 320          # RFC 5321 practical email-address ceiling
_COMPANY_MAX = 200
_MESSAGE_MAX = 20_000      # generous for a pasted email thread
_ROLE_MAX = 200
_TOKEN_MAX = 4_000
_EMAIL_MAX = 320


@app.post("/api/verify")
async def api_verify(
    request: Request,
    sender: str = Form(..., max_length=_SENDER_MAX),
    message: str = Form("", max_length=_MESSAGE_MAX),
    company: str = Form("", max_length=_COMPANY_MAX),
    attestation: str = Form("", max_length=_TOKEN_MAX),
    me: str = Form("", max_length=_EMAIL_MAX),
    role: str = Form("", max_length=_ROLE_MAX),
    check_posting: bool = Form(False),
    document: UploadFile | None = File(None),
) -> JSONResponse:
    _enforce_rate_limit(request)
    tmp_path = None
    try:
        if document is not None and document.filename:
            tmp_path = await _save_upload_capped(document)

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
    request: Request,
    sender: str = Form(..., max_length=_SENDER_MAX),
    message: str = Form("", max_length=_MESSAGE_MAX),
    company: str = Form("", max_length=_COMPANY_MAX),
    attestation: str = Form("", max_length=_TOKEN_MAX),
    me: str = Form("", max_length=_EMAIL_MAX),
    role: str = Form("", max_length=_ROLE_MAX),
    check_posting: bool = Form(False),
    document: UploadFile | None = File(None),
) -> StreamingResponse:
    """Same verification, streamed as newline-delimited JSON.

    Each line is a real event emitted when that check finished — not a
    completed result replayed on a timer.
    """
    _enforce_rate_limit(request)
    tmp_path = None
    if document is not None and document.filename:
        tmp_path = await _save_upload_capped(document)

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
            logger.exception("verify_stream_error")
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


@app.get("/privacy")
def privacy() -> FileResponse:
    return FileResponse(STATIC / "privacy.html")


@app.get("/terms")
def terms() -> FileResponse:
    return FileResponse(STATIC / "terms.html")


if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
