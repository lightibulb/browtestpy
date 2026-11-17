#!/usr/bin/env bash
#
# g.sh -- generates the full Part 1 project (files + deploy config).
# Tested on: Termux (Android), Linux, macOS.
#
set -euo pipefail

echo "==> Anonymity Verifier - Part 1 generator"
echo "    Working directory: $(pwd)"
echo

# --- Safe on Termux? Detect and skip Playwright wheel if so ---
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || uname -o 2>/dev/null | grep -q Android; then
    IS_TERMUX=1
    echo "    Termux detected - Playwright wheel will be skipped."
fi

# --- Refuse to overwrite silently ---
if [ -d app ] && [ "${FORCE:-0}" != "1" ]; then
    echo "ERROR: app/ already exists here."
    echo "       Run in an empty directory, or re-run with FORCE=1."
    exit 1
fi

# ================================================================
# 1. Directories
# ================================================================
echo "==> Creating directory tree"
mkdir -p app/api app/core app/tasks app/models app/static tests

# ================================================================
# 2. Root config files
# ================================================================
echo "==> Writing root config files"

cat > .gitignore <<'EOF'
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.venv/
venv/
env/
.env
.env.*
!.env.example
.idea/
.vscode/
*.swp
.DS_Store
Thumbs.db
reports/
*.log
EOF

cat > .env.example <<'EOF'
APP_NAME=Anonymity Verifier
ENVIRONMENT=development
REDIS_URL=redis://localhost:6379/0
SCAN_RESULT_TTL=3600
EOF

cat > requirements.txt <<'EOF'
fastapi==0.115.0
uvicorn[standard]==0.32.0
celery[redis]==5.4.0
redis==5.1.1
pydantic==2.9.2
pydantic-settings==2.6.0
python-dotenv==1.0.1
httpx==0.27.2
pytest==8.3.3
pytest-asyncio==0.24.0
EOF

if [ "$IS_TERMUX" = "1" ]; then
    echo "    (Termux: playwright excluded from local requirements)"
else
    echo 'playwright==1.48.0' >> requirements.txt
fi

cat > pyproject.toml <<'EOF'
[project]
name = "anonymity-verifier"
version = "0.1.0"
description = "Multi-layer anonymity and leak verification service"
requires-python = ">=3.11"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "-ra -q"
EOF

cat > README.md <<'EOF'
# Anonymity Verifier

Multi-layer service that checks whether your VPN/Tor/proxy setup is
actually hiding what you think it is.

Part 1 delivers the deployable skeleton:

- FastAPI web service with /health and /api/v1/scan
- Celery worker consuming scan jobs
- Redis as broker and result backend
- Render Blueprint (render.yaml) provisioning all three
- Docker image based on the official Playwright image

## Local run (Linux / macOS / Termux)

    cp .env.example .env
    pip install -r requirements.txt
    redis-server &                # or: docker compose up redis -d
    uvicorn app.main:app --port 8000 --reload
    # in another terminal:
    celery -A app.core.celery_app.celery worker --loglevel=info

Then:

    curl http://localhost:8000/health
    curl -X POST http://localhost:8000/api/v1/scan -H "Content-Type: application/json" -d "{}"

## Docker run (Linux / macOS)

    docker compose up --build

## Deploy to Render

1. Push this repo to GitHub.
2. Render Dashboard -> New + -> Blueprint -> select the repo.
3. render.yaml provisions web service, background worker, Redis.
4. /health returns {"celery_workers": true} when ready.

## Roadmap

- Part 1 (this scaffold): stack up, health, placeholder scan.
- Part 2: Layer 1 (IP/DNS/STUN) + Layer 2 (Playwright fingerprint).
- Part 3: Orchestrator, result polling, HTML UI, Layer 3 local agent.
EOF

# ================================================================
# 3. Python package init files
# ================================================================
echo "==> Writing Python package files"

cat > app/__init__.py <<'EOF'
# Anonymity Verifier application package.
__version__ = "0.1.0"
EOF

: > app/core/__init__.py
: > app/api/__init__.py
: > app/models/__init__.py
: > tests/__init__.py

cat > app/tasks/__init__.py <<'EOF'
# Celery task modules. Imported by celery.autodiscover_tasks().
EOF

# ================================================================
# 4. app/core/config.py
# ================================================================
cat > app/core/config.py <<'EOF'
# Centralised application settings sourced from env vars / .env file.
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # All runtime configuration in one typed place.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Anonymity Verifier"
    environment: str = "development"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None
    scan_result_ttl: int = 3600

    @property
    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def result_backend(self) -> str:
        return self.celery_result_backend or self.redis_url


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
EOF

# ================================================================
# 5. app/core/celery_app.py
# ================================================================
cat > app/core/celery_app.py <<'EOF'
# Celery application shared by the web service and the worker.
from celery import Celery

from app.core.config import settings

celery = Celery(
    "anonymity_verifier",
    broker=settings.broker_url,
    backend=settings.result_backend,
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    result_expires=settings.scan_result_ttl,
    broker_connection_retry_on_startup=True,
)

celery.autodiscover_tasks(["app.tasks"])
EOF

# ================================================================
# 6. app/models/scan.py
# ================================================================
cat > app/models/scan.py <<'EOF'
# Pydantic schemas for scan requests and responses.
from enum import Enum

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class ScanRequest(BaseModel):
    # Payload accepted by POST /api/v1/scan.
    proxy_url: str | None = Field(
        default=None,
        description="Optional proxy URL (e.g. socks5://127.0.0.1:9050).",
    )


class ScanResponse(BaseModel):
    # Returned for both scan submission and status polling.
    scan_id: str
    status: ScanStatus
    result: dict | None = None
    error: str | None = None
EOF

# ================================================================
# 7. app/tasks/orchestrator.py
# ================================================================
cat > app/tasks/orchestrator.py <<'EOF'
# Orchestrator task (placeholder for Part 1).
# Part 2 replaces the body of execute_full_scan with the real
# Layer 1 (IP/DNS/STUN) + Layer 2 (Playwright fingerprint) chain.
from celery import shared_task


@shared_task(bind=True, name="tasks.execute_full_scan")
def execute_full_scan(self, proxy_url: str | None = None) -> dict:
    return {
        "scan_id": self.request.id,
        "status": "placeholder",
        "message": "Scaffold is healthy. Layers 1 and 2 land in Part 2.",
        "proxy_url": proxy_url,
    }
EOF

# ================================================================
# 8. app/api/routes.py
# ================================================================
cat > app/api/routes.py <<'EOF'
# HTTP routes for scan submission and status polling.
from __future__ import annotations

import logging
import uuid

from celery.result import AsyncResult
from fastapi import APIRouter, HTTPException

from app.core.celery_app import celery
from app.models.scan import ScanRequest, ScanResponse, ScanStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def submit_scan(request: ScanRequest) -> ScanResponse:
    # Enqueue a new scan job. Returns immediately with a scan_id.
    from app.tasks.orchestrator import execute_full_scan

    scan_id = str(uuid.uuid4())
    try:
        execute_full_scan.apply_async(
            kwargs={"proxy_url": request.proxy_url},
            task_id=scan_id,
        )
    except Exception as exc:
        logger.exception("Failed to enqueue scan %s", scan_id)
        raise HTTPException(status_code=503, detail="Queue unavailable: " + str(exc))

    return ScanResponse(scan_id=scan_id, status=ScanStatus.QUEUED)


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    # Poll the status / result of a previously submitted scan.
    result = AsyncResult(scan_id, app=celery)

    if result.state == "PENDING":
        return ScanResponse(scan_id=scan_id, status=ScanStatus.QUEUED)
    if result.state in ("STARTED", "RETRY"):
        return ScanResponse(scan_id=scan_id, status=ScanStatus.RUNNING)
    if result.state == "FAILURE":
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            error=str(result.result) if result.result else "unknown error",
        )
    if result.state == "SUCCESS":
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.COMPLETE,
            result=result.result,
        )
    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.FAILED,
        error="unexpected state: " + str(result.state),
    )
EOF

# ================================================================
# 9. app/api/dependencies.py
# ================================================================
cat > app/api/dependencies.py <<'EOF'
# Shared FastAPI dependencies.
from app.core.config import Settings, settings


def get_settings() -> Settings:
    return settings
EOF

# ================================================================
# 10. app/main.py
# ================================================================
cat > app/main.py <<'EOF'
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
EOF

# ================================================================
# 11. app/static/index.html
# ================================================================
cat > app/static/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Anonymity Verifier - API is live</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; max-width: 40rem;
           margin: 4rem auto; padding: 0 1.5rem; line-height: 1.6; color: #111; }
    code { background: #f2f2f2; padding: 0.15rem 0.35rem; border-radius: 4px; }
    a { color: #1f6feb; }
  </style>
</head>
<body>
  <h1>Anonymity Verifier</h1>
  <p>Part 1 scaffold is deployed. The API is responding.</p>
  <ul>
    <li><a href="/docs">/docs</a> - interactive OpenAPI docs</li>
    <li><a href="/health">/health</a> - liveness and worker probe</li>
    <li><code>POST /api/v1/scan</code> - enqueue a scan</li>
    <li><code>GET /api/v1/scan/{id}</code> - poll a scan</li>
  </ul>
  <p>The full verification UI lands in Part 3.</p>
</body>
</html>
EOF

# ================================================================
# 12. Tests
# ================================================================
cat > tests/test_health.py <<'EOF'
# Smoke tests that need no broker/Redis.
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "app" in r.json()


def test_health_returns_ok():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "celery_workers" in body
EOF

# ================================================================
# 13. Dockerfile
# ================================================================
cat > Dockerfile <<'EOF'
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8000
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# ================================================================
# 14. .dockerignore
# ================================================================
cat > .dockerignore <<'EOF'
.git
.gitignore
.env
.env.*
!.env.example
.venv
venv
__pycache__
*.pyc
.pytest_cache
.mypy_cache
.ruff_cache
reports
*.log
.idea
.vscode
.DS_Store
tests
EOF

# ================================================================
# 15. docker-compose.yml
# ================================================================
cat > docker-compose.yml <<'EOF'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  web:
    build: .
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    ports:
      - "8000:8000"
    environment:
      REDIS_URL: redis://redis:6379/0
    depends_on:
      redis:
        condition: service_healthy
    volumes:
      - ./app:/app/app

  worker:
    build: .
    command: celery -A app.core.celery_app.celery worker --loglevel=info
    environment:
      REDIS_URL: redis://redis:6379/0
    depends_on:
      redis:
        condition: service_healthy
EOF

# ================================================================
# 16. render.yaml
# ================================================================
cat > render.yaml <<'EOF'
services:
  - type: web
    name: anonymity-verifier-web
    runtime: docker
    dockerfilePath: ./Dockerfile
    dockerContext: .
    plan: free
    region: oregon
    healthCheckPath: /health
    autoDeploy: true
    envVars:
      - key: ENVIRONMENT
        value: production
      - key: REDIS_URL
        fromService:
          type: redis
          name: anonymity-verifier-redis
          property: connectionString
      - key: CELERY_BROKER_URL
        fromService:
          type: redis
          name: anonymity-verifier-redis
          property: connectionString
      - key: CELERY_RESULT_BACKEND
        fromService:
          type: redis
          name: anonymity-verifier-redis
          property: connectionString

  - type: worker
    name: anonymity-verifier-worker
    runtime: docker
    dockerfilePath: ./Dockerfile
    dockerContext: .
    dockerCommand: celery -A app.core.celery_app.celery worker --loglevel=info --concurrency=2
    plan: starter
    region: oregon
    autoDeploy: true
    envVars:
      - key: ENVIRONMENT
        value: production
      - key: REDIS_URL
        fromService:
          type: redis
          name: anonymity-verifier-redis
          property: connectionString
      - key: CELERY_BROKER_URL
        fromService:
          type: redis
          name: anonymity-verifier-redis
          property: connectionString
      - key: CELERY_RESULT_BACKEND
        fromService:
          type: redis
          name: anonymity-verifier-redis
          property: connectionString

  - type: redis
    name: anonymity-verifier-redis
    plan: free
    region: oregon
    ipAllowList: []
    maxmemoryPolicy: noeviction
EOF

# ================================================================
# 17. Makefile - use printf so TABs survive any editor
# ================================================================
{
    printf '.PHONY: install dev worker test clean\n\n'
    printf 'install:\n\tpip install -r requirements.txt\n\n'
    printf 'dev:\n\tuvicorn app.main:app --reload --host 0.0.0.0 --port 8000\n\n'
    printf 'worker:\n\tcelery -A app.core.celery_app.celery worker --loglevel=info\n\n'
    printf 'test:\n\tpytest\n\n'
    printf 'clean:\n\tfind . -type d -name __pycache__ -exec rm -rf {} +\n'
    printf '\trm -rf .pytest_cache .mypy_cache .ruff_cache reports\n'
} > Makefile

# ================================================================
# 18. Git init + initial commit
# ================================================================
if command -v git >/dev/null 2>&1; then
    if [ ! -d .git ]; then
        echo "==> Initializing git repository"
        git init -q
    fi
    git add -A
    git -c user.name="scaffold" -c user.email="scaffold@local" \
        commit -q -m "feat(part-1): scaffold FastAPI + Celery + Redis + Render Blueprint" \
        2>/dev/null || echo "    (nothing to commit)"
    echo "    Git commit done."
fi

# ================================================================
# 19. Summary
# ================================================================
echo
echo "================================================================"
echo "  Part 1 scaffold complete"
echo "================================================================"
echo
echo "Files generated:"
find . -type f -not -path './.git/*' | sort | sed 's/^/  /'
echo
echo "Next steps:"
echo "  1. cp .env.example .env"
if [ "$IS_TERMUX" = "1" ]; then
    echo "  2. pip install -r requirements.txt"
    echo "  3. redis-server &"
    echo "  4. uvicorn app.main:app --port 8000 &"
    echo "  5. celery -A app.core.celery_app.celery worker --loglevel=info &"
    echo "  6. curl http://localhost:8000/health"
else
    echo "  2. docker compose up --build"
    echo "  3. curl http://localhost:8000/health"
    echo "  4. pytest -q"
fi
echo "  7. Push to GitHub -> Render Dashboard -> New + -> Blueprint"
echo
