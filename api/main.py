"""FastAPI backend for the triage web app.

Run it with:  uvicorn api.main:app --reload   (binds to 127.0.0.1 by default)

Routes:
  POST /api/triage[?live=true]  body: one alert as JSON (ours, an OCSF finding, or a
                                SentinelOne threat) → a TriageResult; or a list of them
                                (or a SentinelOne {"data": [...]} response) → a list
  GET  /api/samples             the sample alerts in alerts/
  GET  /api/health              ok, which API keys are set (booleans), live allowed?
  /                             the web app in web/, as static files

Demo mode is the default: lookups are served from the cache or marked
"demo: not looked up", and nothing touches the network. Live lookups need
?live=true on the request AND ALLOW_LIVE=1 in the server's environment.

PUBLIC_DEMO=1 is the public deploy (render.yaml): demo only, whatever
ALLOW_LIVE says, with cached intel from data/demo_cache.json in memory,
client IPs taken from the proxy's X-Forwarded-For, and HSTS. Locally it is
unset and none of that applies.

API keys never leave the server: no response, log line or error message
contains one. Clients get short generic errors; details go to the server log.
"""

import functools
import ipaddress
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

import adapters
from api.demo import DemoCache, FixtureCache
from api.ratelimit import RateLimiter
from api.schemas import AlertRequest
from cache import Cache
from models import Alert, InputFormat, TriageResult
from triage import triage

logger = logging.getLogger("api")

ROOT = Path(__file__).parent.parent
ALERTS_DIR = ROOT / "alerts"
WEB_DIR = ROOT / "web"

# OCSF findings carry much more than our Alert needs (metadata, device and
# agent details, several hashes, vendor "unmapped" fields): typically a few KB
# to a few tens of KB. 64 KB fits those with room to spare; the strict field
# caps in api/schemas.py still apply after conversion.
MAX_BODY_BYTES = 64 * 1024
# A list of alerts is triaged one by one in a single request.
MAX_ALERTS = 25
API_KEY_NAMES = ["VT_API_KEY", "ABUSEIPDB_API_KEY"]

# Every triage request counts once against the first limiter, however many
# alerts it holds: demo triage never leaves the machine. A live triage also
# counts against the second, once per alert, because each one spends real API
# quota (VirusTotal's free tier allows 4 lookups a minute, and one alert can
# need three).
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
# Only on the public deploy, which is always HTTPS. Locally it would make the
# browser insist on HTTPS for 127.0.0.1 for a year.
HSTS_HEADER = "max-age=31536000; includeSubDomains"

# How many proxies sit in front of the public deploy and append to
# X-Forwarded-For. Render's proxy is one; the client IP is the entry it added.
TRUSTED_PROXY_HOPS = 1


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_dotenv()  # Once, at startup. Tests don't run this, so they never see .env.
    logging.basicConfig(level=logging.INFO)
    if public_demo():
        logger.info("Public demo: live lookups off, %d cached results from the fixture", len(fixture_cache()))
        if any(os.environ.get(name, "").strip() for name in API_KEY_NAMES):
            logger.warning("API keys are set on a public demo; they are never used. Remove them.")
    else:
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
    if public_demo():
        response.headers["Strict-Transport-Security"] = HSTS_HEADER
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


def public_demo() -> bool:
    return os.environ.get("PUBLIC_DEMO", "").strip() == "1"


def live_allowed() -> bool:
    """ALLOW_LIVE=1, unless this is the public demo, which never looks anything up."""
    return not public_demo() and os.environ.get("ALLOW_LIVE", "").strip() == "1"


@functools.cache
def fixture_cache() -> FixtureCache:
    """The public demo's cached intel, read once (at startup, or on first use in tests)."""
    return FixtureCache()


def demo_cache() -> DemoCache:
    return fixture_cache() if public_demo() else DemoCache()


def client_ip(request: Request) -> str:
    """The address to rate-limit by.

    Locally that's the socket address. On the public demo every request comes
    from Render's proxy, which appends the address it saw to X-Forwarded-For.
    Everything to the left of that came from the client and can say anything,
    so only the entry the proxy added (TRUSTED_PROXY_HOPS from the right) is
    used, and only if it's a real IP address.
    """
    socket_ip = request.client.host if request.client else "unknown"
    if not public_demo():
        return socket_ip
    entries = [e.strip() for header in request.headers.getlist("x-forwarded-for") for e in header.split(",")]
    if len(entries) < TRUSTED_PROXY_HOPS:
        return socket_ip
    candidate = entries[-TRUSTED_PROXY_HOPS]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return socket_ip


@app.post("/api/triage")
async def triage_alert(request: Request, live: bool = False):
    client = client_ip(request)

    retry_after = triage_limiter.check(client)
    if retry_after is not None:
        return rate_limited(retry_after)

    if live and public_demo():
        return error("Live lookups are off on this public demo", 403)
    if live and not live_allowed():
        return error("Live lookups are disabled on this server", 403)

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
        data = json.loads(body)
    except (ValueError, RecursionError):  # Some Python builds raise RecursionError on [[[[... nesting.
        return error("Request body is not valid JSON", 400)

    items = adapters.split(data)
    if items is not None:
        if not items:
            return error("The list has no alerts in it", 422)
        if len(items) > MAX_ALERTS:
            return error(f"Too many alerts: at most {MAX_ALERTS} per request", 422)
        if live and len(items) > live_limiter.limit:
            return error(f"Live lookups take at most {live_limiter.limit} alerts per request", 422)

    alerts = []
    for index, item in enumerate(items if items is not None else [data]):
        try:
            alert = AlertRequest.model_validate(adapters.alert_fields(item)).to_alert()
        except ValidationError as exc:
            prefix = f"[{index}]" if items is not None else ""
            return error("Invalid alert", 422, extra={"errors": field_errors(exc, prefix)})
        alerts.append((adapters.detect_format(item), alert))

    if live:
        # Charged only now, so a live request that was refused above costs nothing.
        retry_after = live_limiter.check(client, cost=len(alerts))
        if retry_after is not None:
            return rate_limited(retry_after)

    cache = None if live else demo_cache()  # None → triage() uses the real Cache and live lookups.
    try:
        results = await run_in_threadpool(triage_all, alerts, cache)
    except Exception:
        # triage() is designed never to raise; if it does, it's a bug, so log it.
        logger.exception("triage() raised")
        return error("Internal server error", 500)

    body = [result.model_dump(mode="json") for result in results]
    return JSONResponse(body if items is not None else body[0])


def triage_all(alerts: list[tuple[InputFormat, Alert]], cache: Cache | None) -> list[TriageResult]:
    """Triage each alert in turn, noting the format it arrived in."""
    return [triage(alert, cache).model_copy(update={"input_format": input_format}) for input_format, alert in alerts]


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


def field_errors(exc: ValidationError, prefix: str = "") -> list[dict]:
    """Which fields were wrong and why. Never echoes the submitted values.

    `prefix` says which alert of a list, e.g. "[2]" → "[2].hostname".
    """
    errors = []
    for e in exc.errors()[:10]:
        field = ".".join(str(part)[:64] for part in e["loc"])
        field = ".".join(part for part in (prefix, field) if part) or "(body)"
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
        "public_demo": public_demo(),
    }


# Last, so the /api routes above take precedence over static files.
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
