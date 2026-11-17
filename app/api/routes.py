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
