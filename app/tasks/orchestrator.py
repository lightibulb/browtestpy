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
