# Orchestrator: Layer 1 + Layer 2, geo enrichment, verdict.
#
# F2: prefers fingerprint/网络 measurements supplied by the visitor's browser.
# F5: DNS/STUN are proxy-aware (they report 'skipped' rather than lie).
# F6: bounded redelivery so an OOM-killed task cannot loop forever.
from __future__ import annotations

import json
import time

import redis
from celery import shared_task

from app.core.config import settings
from app.services.analyzer import analyze
from app.services.geo import lookup as geo_lookup
from app.tasks.layer1 import check_dns, check_stun, get_public_ip
from app.tasks.layer2 import collect_fingerprint

RESULT_TTL = 86400 * 7
MAX_ATTEMPTS = 2


def _client():
    return redis.from_url(
        settings.result_backend,
        socket_connect_timeout=3,
        socket_timeout=3,
        health_check_interval=30,
    )


def _attempt_guard(scan_id):
    """F6: bound broker redelivery. Returns (may_run, attempt_number)."""
    if not scan_id:
        return True, 1
    try:
        r = _client()
        n = int(r.incr("scan_attempts:" + scan_id))
        if n == 1:
            r.expire("scan_attempts:" + scan_id, 3600)
        return n <= MAX_ATTEMPTS, n
    except Exception:
        return True, 1


def _persist_result(scan_id, result):
    if not scan_id:
        return
    try:
        _client().setex("scan_result:" + scan_id, RESULT_TTL,
                        json.dumps(result, default=str))
    except Exception:
        pass


def _record_history(scan_id, summary):
    # F9: no global history list. The web tier owns per-visitor lists; the
    # worker only writes the summary keyed by scan id.
    if not scan_id:
        return
    try:
        _client().setex("scan_summary:" + scan_id, RESULT_TTL, json.dumps(summary))
    except Exception:
        pass


def _aborted_result(scan_id, attempt, proxy_url):
    finding = {
        "id": "scan_aborted",
        "severity": "critical",
        "title": "Scan aborted after repeated worker failures",
        "detail": (
            "Task was redelivered " + str(max(0, attempt - 1)) + " time(s). "
            "This usually means the worker was OOM-killed while launching "
            "Chromium. Give the worker more memory, or keep the browser-side "
            "checks enabled so no server browser is needed."
        ),
    }
    return {
        "scan_id": scan_id,
        "timestamp": time.time(),
        "proxy_url": proxy_url,
        "verdict": "FAIL",
        "score": 0,
        "findings": [finding],
        "layer1": {"ip": {}, "dns": {}, "stun": {}, "client": {},
                   "proxy_used": bool(proxy_url)},
        "layer2": {"status": "skipped", "source": "server"},
        "layer3": None,
        "geo": {"status": "skipped"},
        "coverage": {"complete": False, "measured": 0, "applicable": 4, "checks": []},
    }


@shared_task(bind=True, name="tasks.execute_full_scan")
def execute_full_scan(self, proxy_url=None, client_fingerprint=None, client_network=None):
    scan_id = self.request.id

    may_run, attempt = _attempt_guard(scan_id)
    if not may_run:
        aborted = _aborted_result(scan_id, attempt, proxy_url)
        _persist_result(scan_id, aborted)
        _record_history(scan_id, {
            "verdict": aborted["verdict"], "score": aborted["score"],
            "timestamp": aborted["timestamp"], "public_ip": None,
        })
        return aborted

    if client_network:
        client_net = dict(client_network)
        client_net.setdefault("status", "ok" if client_net.get("public_ip") else "error")
    else:
        client_net = {"status": "skipped", "reason": "no browser measurements supplied"}

    layer1 = {
        "ip": get_public_ip(proxy_url=proxy_url),
        "dns": check_dns(proxy_url=proxy_url),
        "stun": check_stun(proxy_url=proxy_url),
        "client": client_net,
        "proxy_used": bool(proxy_url),
    }

    if client_fingerprint:
        layer2 = {"status": "ok", "source": "client",
                  "fingerprint": dict(client_fingerprint)}
    else:
        layer2 = collect_fingerprint(proxy_url=proxy_url)
        layer2.setdefault("source", "server")

    client_ip = client_net.get("public_ip")
    server_ip = (layer1.get("ip") or {}).get("ipv4")
    exit_ip = server_ip if proxy_url else (client_ip or server_ip)

    geo = geo_lookup(exit_ip) if exit_ip else {"status": "skipped"}
    analysis = analyze(layer1, layer2, geo=geo)

    result = {
        "scan_id": scan_id,
        "timestamp": time.time(),
        "proxy_url": proxy_url,
        "exit_ip": exit_ip,
        "verdict": analysis["verdict"],
        "score": analysis["score"],
        "findings": analysis["findings"],
        "coverage": analysis.get("coverage"),
        "layer1": layer1,
        "layer2": layer2,
        "layer3": None,
        "geo": geo,
    }

    _persist_result(scan_id, result)
    _record_history(scan_id, {
        "verdict": result["verdict"],
        "score": result["score"],
        "timestamp": result["timestamp"],
        "public_ip": exit_ip,
    })
    return result
