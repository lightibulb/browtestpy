# HTTP routes: scan submission, status, history, agent reports, export.
from __future__ import annotations

import json
import logging
import uuid
from functools import lru_cache

import redis
from celery.result import AsyncResult
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.core.celery_app import celery
from app.models.scan import ScanRequest, ScanResponse, ScanStatus
from app.services.analyzer import analyze

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scans"])


@lru_cache
def get_redis():
    from app.core.config import settings
    return redis.from_url(settings.redis_url)


def _redis_or_none():
    try:
        return get_redis()
    except Exception as exc:
        logger.warning("Redis unavailable: %s", exc)
        return None


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def submit_scan(request: ScanRequest) -> ScanResponse:
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
    if result.state != "SUCCESS":
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            error="unexpected state: " + str(result.state),
        )

    base = result.result or {}

    # Layer 3 may have been attached by the local agent after the scan.
    r = _redis_or_none()
    layer3 = None
    if r is not None:
        try:
            raw = r.get("agent:" + scan_id)
            if raw:
                layer3 = json.loads(raw)
        except Exception:
            layer3 = None

    if layer3 is not None:
        analysis = analyze(
            base.get("layer1", {}),
            base.get("layer2", {}),
            geo=base.get("geo"),
            layer3=layer3,
        )
        base = dict(base)
        base["verdict"] = analysis["verdict"]
        base["score"] = analysis["score"]
        base["findings"] = analysis["findings"]
        base["layer3"] = layer3

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.COMPLETE,
        result=base,
    )


@router.get("/scan/{scan_id}/export")
async def export_scan(scan_id: str) -> Response:
    result = AsyncResult(scan_id, app=celery)
    if result.state != "SUCCESS":
        raise HTTPException(status_code=404, detail="Scan not complete")
    body = json.dumps(result.result, indent=2, default=str)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="leakguard-'
            + scan_id[:8] + '.json"'
        },
    )


@router.post("/agent", status_code=202)
async def submit_agent(payload: dict):
    # Store a local agent report. Optional payload["scan_id"] attaches it
    # to an existing web scan so the merged view includes Layer 3.
    scan_id = payload.get("scan_id") or str(uuid.uuid4())
    r = _redis_or_none()
    if r is None:
        raise HTTPException(status_code=503, detail="Storage unavailable")

    stored = dict(payload)
    stored["scan_id"] = scan_id
    try:
        r.setex("agent:" + scan_id, 86400 * 7, json.dumps(stored))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Store failed: " + str(exc))

    return {
        "scan_id": scan_id,
        "view_url": "/api/v1/agent/" + scan_id,
    }


@router.get("/agent/{scan_id}")
async def get_agent(scan_id: str):
    r = _redis_or_none()
    if r is None:
        raise HTTPException(status_code=503, detail="Storage unavailable")
    try:
        raw = r.get("agent:" + scan_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Read failed: " + str(exc))
    if not raw:
        raise HTTPException(status_code=404, detail="Agent report not found")
    return json.loads(raw)


@router.get("/history")
async def get_history():
    r = _redis_or_none()
    if r is None:
        return {"scans": []}
    try:
        ids = r.lrange("scan_history", 0, 19)
    except Exception:
        return {"scans": []}

    scans = []
    for raw_id in ids:
        sid = raw_id.decode() if isinstance(raw_id, bytes) else str(raw_id)
        try:
            summary_raw = r.get("scan_summary:" + sid)
        except Exception:
            summary_raw = None
        if summary_raw:
            try:
                summary = json.loads(summary_raw)
            except Exception:
                summary = {}
            scans.append({
                "scan_id": sid,
                "verdict": summary.get("verdict"),
                "score": summary.get("score"),
                "timestamp": summary.get("timestamp"),
                "public_ip": summary.get("public_ip"),
            })
    return {"scans": scans}
