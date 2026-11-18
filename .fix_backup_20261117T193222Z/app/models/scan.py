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
