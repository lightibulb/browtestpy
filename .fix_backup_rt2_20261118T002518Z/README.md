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
