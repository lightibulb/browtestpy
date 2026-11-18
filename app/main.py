# FastAPI entrypoint. Serves the UI at / and the API under /api/v1.
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from threading import Lock
from time import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

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
    # Simple in-memory sliding window. Fine for single-instance deployments.
    def __init__(self, max_requests=60, window_seconds=60):
        self.max = max_requests
        self.window = window_seconds
        self.buckets = defaultdict(list)
        self.lock = Lock()

    def allow(self, key):
        now = time()
        cutoff = now - self.window
        with self.lock:
            # Bound memory: drop buckets whose newest request is stale.
            if len(self.buckets) > 1000:
                stale = [
                    k for k, ts in self.buckets.items()
                    if not ts or max(ts) < cutoff
                ]
                for k in stale:
                    self.buckets.pop(k, None)
            bucket = [t for t in self.buckets[key] if t > cutoff]
            if len(bucket) >= self.max:
                self.buckets[key] = bucket
                return False
            bucket.append(now)
            self.buckets[key] = bucket
            return True


limiter = RateLimiter(max_requests=60, window_seconds=60)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        xff = request.headers.get("x-forwarded-for", "")
        key = (
            xff.split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        if not limiter.allow(key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded (60 req/min)"},
            )
    return await call_next(request)


app.include_router(router)


@app.get("/", include_in_schema=False)
def serve_ui():
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return {"error": "UI missing", "path": str(index)}
    return FileResponse(index)


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
    # Cache the Celery ping for 5s so cold broker connections do not
    # push /health past Render's health-check budget.
    global _health_ts, _health_value
    now = time()
    with _health_lock:
        if now - _health_ts < 5.0:
            return _health_value
    try:
        pong = celery.control.ping(timeout=0.5)
        value = len(pong) > 0
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
    # Readiness: checks Redis reachability, not just liveness.
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
    status_code = 200 if redis_ok else 503
    return JSONResponse(content=body, status_code=status_code)
