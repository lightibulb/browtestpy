# Orchestrator: runs Layer 1 + Layer 2, enriches with geo, computes verdict.
import json
import time

from celery import shared_task

from app.services.analyzer import analyze
from app.services.geo import lookup as geo_lookup
from app.tasks.layer1 import check_dns, check_stun, get_public_ip
from app.tasks.layer2 import collect_fingerprint


def _persist_result(scan_id, result):
    # Store the full result so it survives Celery's result_expires TTL.
    try:
        import redis
        from app.core.config import settings
        r = redis.from_url(settings.result_backend)
        r.setex(
            "scan_result:" + scan_id,
            86400 * 7,
            json.dumps(result, default=str),
        )
    except Exception:
        pass


def _record_history(scan_id, summary):
    # Best-effort history append. Failure here must not fail the scan.
    try:
        import redis
        from app.core.config import settings
        r = redis.from_url(settings.result_backend)
        r.lpush("scan_history", scan_id)
        r.ltrim("scan_history", 0, 99)
        r.setex(
            "scan_summary:" + scan_id,
            86400 * 7,
            json.dumps(summary),
        )
    except Exception:
        pass


@shared_task(bind=True, name="tasks.execute_full_scan")
def execute_full_scan(self, proxy_url=None):
    layer1 = {
        "ip": get_public_ip(proxy_url=proxy_url),
        "dns": check_dns(),
        "stun": check_stun(),
    }
    layer2 = collect_fingerprint(proxy_url=proxy_url)

    public_ip = (layer1.get("ip") or {}).get("ipv4")
    geo = geo_lookup(public_ip) if public_ip else {"status": "skipped"}

    analysis = analyze(layer1, layer2, geo=geo)

    result = {
        "scan_id": self.request.id,
        "timestamp": time.time(),
        "verdict": analysis["verdict"],
        "score": analysis["score"],
        "findings": analysis["findings"],
        "layer1": layer1,
        "layer2": layer2,
        "layer3": None,
        "geo": geo,
    }

    _persist_result(self.request.id, result)
    _record_history(self.request.id, {
        "verdict": result["verdict"],
        "score": result["score"],
        "timestamp": result["timestamp"],
        "public_ip": public_ip,
    })

    return result
