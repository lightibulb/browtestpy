# HTTP routes: scan submission, status, history, agent reports, export.
#
# F2/F8: accepts browser-side measurements, returns real error details.
# F9: history and scan reads are scoped to the visitor's identity cookie.
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from functools import lru_cache

import redis
from celery.result import AsyncResult
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from app.core.celery_app import celery
from app.core.config import settings
from app.models.scan import AgentReport, ScanRequest, ScanResponse, ScanStatus
from app.services.analyzer import analyze

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["scans"])

HISTORY_TTL = 86400 * 7
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


@lru_cache
def get_redis():
    return redis.from_url(
        settings.result_backend,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )


def _redis_or_none():
    # redis.from_url() is lazy: it builds a client, it does not connect.
    # Reachability is probed by /ready and guarded around every operation.
    try:
        return get_redis()
    except Exception as exc:
        logger.warning("Redis client could not be created: %s", exc)
        return None


def _check_scan_id(scan_id: str) -> None:
    if not SCAN_ID_RE.match(scan_id or ""):
        raise HTTPException(status_code=400, detail="invalid scan_id")


def _owner_of(request: Request) -> str | None:
    return getattr(request.state, "lg_sid", None) or request.cookies.get("lg_sid")


def _assert_owner(request: Request, scan_id: str) -> None:
    if settings.environment != "production":
        return
    r = _redis_or_none()
    if r is None:
        return
    try:
        raw = r.get("scan_owner:" + scan_id)
    except Exception:
        return
    if not raw:
        return
    owner = raw.decode() if isinstance(raw, bytes) else str(raw)
    if owner != (_owner_of(request) or ""):
        raise HTTPException(status_code=404, detail="Scan not found")


def _remember_owner(request: Request, scan_id: str) -> None:
    owner = _owner_of(request)
    if not owner:
        return
    r = _redis_or_none()
    if r is None:
        return
    try:
        key = "scan_history:" + owner
        r.lpush(key, scan_id)
        r.ltrim(key, 0, 49)
        r.expire(key, HISTORY_TTL)
        r.setex("scan_owner:" + scan_id, HISTORY_TTL, owner)
    except Exception:
        logger.warning("Could not record scan ownership", exc_info=True)


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def submit_scan(request: Request, payload: ScanRequest) -> ScanResponse:
    from app.tasks.orchestrator import execute_full_scan

    scan_id = str(uuid.uuid4())
    kwargs = {"proxy_url": payload.proxy_url}
    if payload.client_fingerprint is not None:
        kwargs["client_fingerprint"] = payload.client_fingerprint.model_dump()
    if payload.client_network is not None:
        kwargs["client_network"] = payload.client_network.model_dump()

    try:
        await asyncio.to_thread(
            execute_full_scan.apply_async, kwargs=kwargs, task_id=scan_id
        )
    except Exception:
        logger.exception("Failed to enqueue scan %s", scan_id)
        raise HTTPException(status_code=503, detail="Queue unavailable")

    _remember_owner(request, scan_id)
    return ScanResponse(scan_id=scan_id, status=ScanStatus.QUEUED)


def _load_persisted_result(scan_id: str) -> dict | None:
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
    merged["coverage"] = analysis.get("coverage")
    merged["layer3"] = layer3
    return merged


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(request: Request, scan_id: str) -> ScanResponse:
    _check_scan_id(scan_id)
    _assert_owner(request, scan_id)

    result = AsyncResult(scan_id, app=celery)

    if result.state == "SUCCESS":
        base = result.result or {}
        return ScanResponse(scan_id=scan_id, status=ScanStatus.COMPLETE,
                            result=_merge_layer3(scan_id, base))

    if result.state in ("STARTED", "RETRY"):
        return ScanResponse(scan_id=scan_id, status=ScanStatus.RUNNING)

    if result.state == "FAILURE":
        return ScanResponse(scan_id=scan_id, status=ScanStatus.FAILED,
                            error=str(result.result) if result.result else "unknown error")

    if result.state == "PENDING":
        persisted = _load_persisted_result(scan_id)
        if persisted is not None:
            return ScanResponse(scan_id=scan_id, status=ScanStatus.COMPLETE,
                                result=_merge_layer3(scan_id, persisted))
        return ScanResponse(scan_id=scan_id, status=ScanStatus.QUEUED)

    return ScanResponse(scan_id=scan_id, status=ScanStatus.FAILED,
                        error="unexpected state: " + str(result.state))


@router.get("/scan/{scan_id}/export")
async def export_scan(request: Request, scan_id: str) -> Response:
    _check_scan_id(scan_id)
    _assert_owner(request, scan_id)

    result = AsyncResult(scan_id, app=celery)
    base = result.result or {} if result.state == "SUCCESS" else _load_persisted_result(scan_id)
    if not base:
        raise HTTPException(status_code=404, detail="Scan not complete")

    merged = _merge_layer3(scan_id, base)
    body = json.dumps(merged, indent=2, default=str)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="leakguard-' + scan_id[:8] + '.json"'
        },
    )


@router.post("/agent", status_code=202)
async def submit_agent(payload: AgentReport):
    data = payload.model_dump()
    scan_id = data.pop("scan_id", None) or str(uuid.uuid4())
    _check_scan_id(scan_id)

    stored = {k: v for k, v in data.items() if v is not None}
    stored["scan_id"] = scan_id

    r = _redis_or_none()
    if r is None:
        raise HTTPException(status_code=503, detail="Storage unavailable")
    try:
        r.setex("agent:" + scan_id, HISTORY_TTL, json.dumps(stored))
    except Exception:
        logger.exception("Failed to store agent report %s", scan_id)
        raise HTTPException(status_code=503, detail="Store failed")

    body = {"scan_id": scan_id, "view_url": "/api/v1/agent/" + scan_id}
    if payload.scan_id and _load_persisted_result(scan_id) is None:
        body["warning"] = (
            "No completed scan found with this id yet. The report is stored and "
            "will merge automatically when that scan finishes."
        )
    return body


@router.get("/agent/{scan_id}")
async def get_agent(request: Request, scan_id: str):
    _check_scan_id(scan_id)
    _assert_owner(request, scan_id)

    r = _redis_or_none()
    if r is None:
        raise HTTPException(status_code=503, detail="Storage unavailable")
    try:
        raw = r.get("agent:" + scan_id)
    except Exception:
        raise HTTPException(status_code=503, detail="Read failed")
    if not raw:
        raise HTTPException(status_code=404, detail="Agent report not found")
    return json.loads(raw)


@router.get("/history")
async def get_history(request: Request):
    owner = _owner_of(request)
    if not owner:
        return {"scans": []}
    r = _redis_or_none()
    if r is None:
        return {"scans": []}
    try:
        ids = r.lrange("scan_history:" + owner, 0, 19)
    except Exception:
        return {"scans": []}

    scans = []
    for raw_id in ids:
        sid = raw_id.decode() if isinstance(raw_id, bytes) else str(raw_id)
        try:
            summary_raw = r.get("scan_summary:" + sid)
        except Exception:
            summary_raw = None
        summary = {}
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
            "pending": not bool(summary),
        })
    return {"scans": scans}
