"""FastAPI backend for the triage web app.

Run it with:  uvicorn api.main:app --reload   (binds to 127.0.0.1 by default)

Routes:
  POST /api/triage[?live=true]  body: an Alert as JSON  →  a TriageResult
  GET  /api/samples             the sample alerts in alerts/
  GET  /api/health              ok, which API keys are set (booleans), live allowed?
  /                             the web app in web/, as static files

Demo mode is the default: lookups are served from the cache or marked
"demo: not looked up", and nothing touches the network. Live lookups need
?live=true on the request AND ALLOW_LIVE=1 in the server's environment.

API keys never leave the server: no response, log line or error message
contains one. Clients get short generic errors; details go to the server log.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from api.demo import DemoCache
from api.ratelimit import RateLimiter
from api.schemas import AlertRequest
from triage import triage

logger = logging.getLogger("api")

ROOT = Path(__file__).parent.parent
ALERTS_DIR = ROOT / "alerts"
WEB_DIR = ROOT / "web"

MAX_BODY_BYTES = 32 * 1024
API_KEY_NAMES = ["VT_API_KEY", "ABUSEIPDB_API_KEY"]

# Every triage counts against the first limiter. A live triage also counts
# against the second, because it spends real API quota (VirusTotal's free
# tier allows 4 lookups a minute, and one alert can need three).
triage_limiter = RateLimiter(limit=10, window_seconds=60)
live_limiter = RateLimiter(limit=2, window_seconds=60)

SECURITY_HEADERS = {
    # Only this origin's own files. No inline scripts or styles, no third-party
    # origins, no plugins, and nobody may frame the page.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",  # frame-ancestors for older browsers.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_dotenv()  # Once, at startup. Tests don't run this, so they never see .env.
    logging.basicConfig(level=logging.INFO)
    logger.info("Live lookups %s", "allowed" if live_allowed() else "disabled (demo only)")
    yield


# No /docs or /openapi.json: the docs page loads scripts from a CDN, which the
# CSP blocks anyway, and a public tool doesn't need to publish its schema.
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add the security headers to every response, including error responses."""
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        response = error("Internal server error", 500)
    response.headers.update(SECURITY_HEADERS)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def error(
    message: str, status_code: int, extra: dict | None = None, headers: dict | None = None
) -> JSONResponse:
    """A short, generic error for the client. Details belong in the server log."""
    return JSONResponse({"detail": message, **(extra or {})}, status_code=status_code, headers=headers)


def rate_limited(retry_after: int) -> JSONResponse:
    return error(
        "Rate limit reached", 429,
        extra={"retry_after": retry_after},
        headers={"Retry-After": str(retry_after)},
    )


def live_allowed() -> bool:
    return os.environ.get("ALLOW_LIVE", "").strip() == "1"


@app.post("/api/triage")
async def triage_alert(request: Request, live: bool = False):
    client = request.client.host if request.client else "unknown"

    retry_after = triage_limiter.check(client)
    if retry_after is not None:
        return rate_limited(retry_after)

    if live:
        if not live_allowed():
            return error("Live lookups are disabled on this server", 403)
        retry_after = live_limiter.check(client)
        if retry_after is not None:
            return rate_limited(retry_after)

    # Requiring JSON also blocks cross-site form posts: a browser can send a
    # text/plain form to any origin without asking, but application/json from
    # another origin needs a CORS preflight, which this server never approves.
    content_type = request.headers.get("content-type", "")
    if content_type.split(";")[0].strip().lower() != "application/json":
        return error("Content-Type must be application/json", 415)

    body = await read_limited_body(request)
    if body is None:
        return error(f"Request body is larger than {MAX_BODY_BYTES // 1024} KB", 413)

    try:
        alert = AlertRequest.model_validate_json(body).to_alert()
    except ValidationError as exc:
        if any(e["type"] == "json_invalid" for e in exc.errors()):
            return error("Request body is not valid JSON", 400)
        return error("Invalid alert", 422, extra={"errors": field_errors(exc)})

    cache = None if live else DemoCache()  # None → triage() uses the real Cache and live lookups.
    try:
        result = await run_in_threadpool(triage, alert, cache)
    except Exception:
        # triage() is designed never to raise; if it does, it's a bug, so log it.
        logger.exception("triage() raised")
        return error("Internal server error", 500)

    return JSONResponse(result.model_dump(mode="json"))


async def read_limited_body(request: Request) -> bytes | None:
    """Read the body, or return None as soon as it passes MAX_BODY_BYTES.

    Content-Length is checked first, but it can be missing (chunked uploads)
    or wrong, so the bytes are counted as they arrive too.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None

    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            return None
    return bytes(body)


def field_errors(exc: ValidationError) -> list[dict]:
    """Which fields were wrong and why. Never echoes the submitted values."""
    errors = []
    for e in exc.errors()[:10]:
        field = ".".join(str(part)[:64] for part in e["loc"]) or "(body)"
        errors.append({"field": field, "message": e["msg"]})
    return errors


@app.get("/api/samples")
def samples():
    """The sample alerts, so the page can offer them. Only files in alerts/ itself."""
    items = []
    for path in sorted(ALERTS_DIR.glob("*.json")):
        try:
            items.append({"name": path.stem, "alert": json.loads(path.read_text())})
        except (OSError, ValueError):
            logger.warning("Skipping unreadable sample %s", path.name)
    return items


@app.get("/api/health")
def health():
    """Which keys are configured, as booleans. The values never leave the server."""
    return {
        "status": "ok",
        "keys": {name: bool(os.environ.get(name, "").strip()) for name in API_KEY_NAMES},
        "live_allowed": live_allowed(),
    }


# Last, so the /api routes above take precedence over static files.
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
