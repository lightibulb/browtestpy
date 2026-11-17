# FastAPI entrypoint for the Anonymity Verifier web service.
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import router
from app.core.celery_app import celery
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

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

app.include_router(router)


@app.get("/", tags=["meta"])
def root() -> dict:
    return {
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["meta"])
def health() -> dict:
    # Liveness plus dependency probe used by Render health checks.
    try:
        pong = celery.control.ping(timeout=1.0)
        workers_online = len(pong) > 0
    except Exception as exc:
        logger.warning("Celery ping failed: %s", exc)
        workers_online = False

    return {
        "status": "ok",
        "environment": settings.environment,
        "celery_workers": workers_online,
    }
