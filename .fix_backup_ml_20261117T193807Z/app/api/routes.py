# HTTP routes: scan submission, status, history, agent reports, export.
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from functools import lru_cache

import redis
from celery.result import AsyncResult
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.core.celery_app import celery
from app.models.scan import AgentReport, ScanRequest, ScanResponse, ScanStatus
from app.services.analyzer import analyze

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scans"])


@lru_cache
def get_redis():
    from app.core.config import settings
    return redis.from_url(settings.result_backend)


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
        await asyncio.to_thread(
            execute_full_scan.apply_async,
            kwargs={"proxy_url": request.proxy_url},
            task_id=scan_id,
        )
    except Exception as exc:
        logger.exception("Failed to enqueue scan %s", scan_id)
        raise HTTPException(status_code=503, detail="Queue unavailable: " + str(exc))
    return ScanResponse(scan_id=scan_id, status=ScanStatus.QUEUED)


def _load_persisted_result(scan_id: str) -> dict | None:
    # Used when the Celery result backend has expired (default TTL is 1h).
    r = _redis_or_none()
    if r is None:
        return None
    try:
        raw = r.get("scan_result:" + scan_id)
        if raw:
            return json.loads(raw)
    except Exception:
        return None
    return None


def _load_layer3(scan_id: str) -> dict | None:
    r = _redis_or_none()
    if r is None:
        return None
    try:
        raw = r.get("agent:" + scan_id)
        if raw:
            return json.loads(raw)
    except Exception:
        return None
    return None


def _merge_layer3(scan_id: str, base: dict) -> dict:
    # Layer 3 may have been attached by the local agent after the scan.
    layer3 = _load_layer3(scan_id)
    if layer3 is None:
        return base
    analysis = analyze(
        base.get("layer1", {}),
        base.get("layer2", {}),
        geo=base.get("geo"),
        layer3=layer3,
    )
    merged = dict(base)
    merged["verdict"] = analysis["verdict"]
    merged["score"] = analysis["score"]
    merged["findings"] = analysis["findings"]
    merged["layer3"] = layer3
    return merged


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    result = AsyncResult(scan_id, app=celery)

    if result.state == "SUCCESS":
        base = result.result or {}
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.COMPLETE,
            result=_merge_layer3(scan_id, base),
        )
    if result.state in ("STARTED", "RETRY"):
        return ScanResponse(scan_id=scan_id, status=ScanStatus.RUNNING)
    if result.state == "FAILURE":
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            error=str(result.result) if result.result else "unknown error",
        )
    if result.state == "PENDING":
        # Celery may have expired the result; fall back to Redis-persisted copy.
        persisted = _load_persisted_result(scan_id)
        if persisted is not None:
            return ScanResponse(
                scan_id=scan_id,
                status=ScanStatus.COMPLETE,
                result=_merge_layer3(scan_id, persisted),
            )
        return ScanResponse(scan_id=scan_id, status=ScanStatus.QUEUED)
    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.FAILED,
        error="unexpected state: " + str(result.state),
    )


@router.get("/scan/{scan_id}/export")
async def export_scan(scan_id: str) -> Response:
    result = AsyncResult(scan_id, app=celery)
    base = None
    if result.state == "SUCCESS":
        base = result.result or {}
    else:
        base = _load_persisted_result(scan_id)
    if base is None:
        raise HTTPException(status_code=404, detail="Scan not complete")
    merged = _merge_layer3(scan_id, base)
    body = json.dumps(merged, indent=2, default=str)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="leakguard-'
            + scan_id[:8] + '.json"'
        },
    )


@router.post("/agent", status_code=202)
async def submit_agent(payload: AgentReport):
    # Store a local agent report. Optional payload.scan_id attaches it
    # to an existing web scan so the merged view includes Layer 3.
    data = payload.model_dump()
    scan_id = data.pop("scan_id", None) or str(uuid.uuid4())
    stored = {k: v for k, v in data.items() if v is not None}
    stored["scan_id"] = scan_id

    r = _redis_or_none()
    if r is None:
        raise HTTPException(status_code=503, detail="Storage unavailable")

    try:
        r.setex("agent:" + scan_id, 86400 * 7, json.dumps(stored))
    except Exception:
        logger.exception("Failed to store agent report %s", scan_id)
        raise HTTPException(status_code=503, detail="Store failed")

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
