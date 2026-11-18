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

### Render deployment notes

- **Free web service sleeps after 15 minutes idle.** The first request
  after idle triggers a ~30s cold start (the Playwright base image is
  large). Keep an external uptime monitor pointed at `/ready` if you
  need the service always warm.
- **Worker must use `plan: starter` or higher.** Render does not offer
  a free background-worker plan. The web service can remain `free`;
  the worker cannot. The blueprint ships with `starter`.
- **Redis free tier is 25 MB with `allkeys-lru` eviction.** Celery
  results (7 day TTL), scan history, and agent reports share this
  budget. If you expect heavy usage, upgrade the Redis plan or lower
  the TTLs in `app/core/config.py` and `app/tasks/orchestrator.py`.
- **Health check paths:** `render.yaml` uses `healthCheckPath: /health`
  for liveness (fast, 5-second cached ping). Point an external uptime
  monitor at `/ready` instead — it returns `503` when Redis is
  unreachable and is the correct readiness probe. Do **not** use
  `/ready` as Render's `healthCheckPath`: a transient Redis blip would
  trigger restart loops.
- **Build time:** the `mcr.microsoft.com/playwright/python` base image
  is ~2 GB. First build takes 5-10 minutes; subsequent builds reuse
  the Docker layer cache as long as `requirements.txt` is unchanged.
- **Port binding:** the Dockerfile binds `${PORT:-8000}` so Render's
  injected `$PORT` is honoured. No `PORT` env var is needed in
  `render.yaml`.

## Roadmap

- Part 1 (this scaffold): stack up, health, placeholder scan.
- Part 2: Layer 1 (IP/DNS/STUN) + Layer 2 (Playwright fingerprint).
- Part 3: Orchestrator, result polling, HTML UI, Layer 3 local agent.
