# FastAPI entrypoint. Serves the UI at / and the API under /api/v1.
#
# F7: polling GETs get their own generous rate bucket; 429 carries Retry-After.
# F9: every visitor gets an opaque identity cookie used to scope scan history.
from __future__ import annotations

import logging
import re
import uuid
from collections import defaultdict
from pathlib import Path
from threading import Lock
from time import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

from app import __version__
from app.api.routes import router
from app.core.celery_app import celery
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
SID_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="Multi-layer anonymity and leak verification service.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class RateLimiter:
    """In-memory sliding window. Fine for single-instance deployments."""

    def __init__(self, max_requests=60, window_seconds=60):
        self.max = max_requests
        self.window = window_seconds
        self.buckets = defaultdict(list)
        self.lock = Lock()

    def allow(self, key):
        now = time()
        cutoff = now - self.window
        with self.lock:
            if len(self.buckets) > 1000:
                stale = [k for k, ts in self.buckets.items()
                         if not ts or max(ts) < cutoff]
                for k in stale:
                    self.buckets.pop(k, None)
            bucket = [t for t in self.buckets[key] if t > cutoff]
            if len(bucket) >= self.max:
                self.buckets[key] = bucket
                return False
            bucket.append(now)
            self.buckets[key] = bucket
            return True

    def retry_after(self, key):
        with self.lock:
            ts = self.buckets.get(key) or []
            if not ts:
                return 1
            return max(1, int(self.window - (time() - min(ts))) + 1)


write_limiter = RateLimiter(max_requests=60, window_seconds=60)
poll_limiter = RateLimiter(max_requests=300, window_seconds=60)
limiter = write_limiter  # backwards-compatible alias


def _client_key(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() or (
        request.client.host if request.client else "unknown"
    )


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
        is_poll = request.method == "GET" and (
            (path.startswith("/api/v1/scan/") and not path.endswith("/export"))
            or path == "/api/v1/history"
        )
        lim = poll_limiter if is_poll else write_limiter
        if not lim.allow(_client_key(request)):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded (" + str(lim.max) + " req/min)"},
                headers={"Retry-After": str(lim.retry_after(_client_key(request)))},
            )
    return await call_next(request)


# Registered last => outermost => request.state.lg_sid exists everywhere.
@app.middleware("http")
async def identity_middleware(request: Request, call_next):
    sid = request.cookies.get("lg_sid")
    if not sid or not SID_RE.match(sid):
        sid = uuid.uuid4().hex
    request.state.lg_sid = sid
    response = await call_next(request)
    if request.cookies.get("lg_sid") != sid:
        response.set_cookie(
            "lg_sid", sid,
            max_age=86400 * 30,
            httponly=True,
            samesite="lax",
            secure=(settings.environment == "production"),
            path="/",
        )
    return response


app.include_router(router)


@app.get("/", include_in_schema=False)
def serve_ui():
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return {"error": "UI missing", "path": str(index)}
    return FileResponse(index, headers={"Cache-Control": "no-cache, must-revalidate"})


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/info", tags=["meta"])
def info() -> dict:
    return {
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
    }


_health_lock = Lock()
_health_ts = 0.0
_health_value = False


def _check_workers() -> bool:
    global _health_ts, _health_value
    now = time()
    with _health_lock:
        if now - _health_ts < 5.0:
            return _health_value

    value = False
    try:
        from app.api.routes import _redis_or_none
        r = _redis_or_none()
        if r is not None:
            r.ping()  # fail fast instead of hanging inside a broker broadcast
            value = len(celery.control.ping(timeout=0.5)) > 0
    except Exception as exc:
        logger.warning("Celery ping failed: %s", exc)
        value = False

    with _health_lock:
        _health_ts = now
        _health_value = value
    return value


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {
        "status": "ok",
        "environment": settings.environment,
        "celery_workers": _check_workers(),
    }


@app.get("/ready", tags=["meta"])
def ready() -> dict:
    from app.api.routes import _redis_or_none
    r = _redis_or_none()
    redis_ok = False
    if r is not None:
        try:
            r.ping()
            redis_ok = True
        except Exception:
            redis_ok = False
    body = {"status": "ok" if redis_ok else "degraded", "redis": redis_ok}
    return JSONResponse(content=body, status_code=200 if redis_ok else 503)
