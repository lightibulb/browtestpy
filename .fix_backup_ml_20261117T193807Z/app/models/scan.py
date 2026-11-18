# Pydantic schemas for scan requests and responses.
from enum import Enum

from urllib.parse import urlparse
from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    @field_validator("proxy_url")
    @classmethod
    def _validate_proxy_url(cls, v: str | None) -> str | None:
        # Prevent SSRF / arbitrary reverse-tunnel abuse.
        if v is None:
            return v
        if len(v) > 512:
            raise ValueError("proxy_url too long (max 512 chars)")
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https", "socks5", "socks5h"):
            raise ValueError(
                "proxy_url scheme must be http, https, socks5, or socks5h"
            )
        if not parsed.hostname:
            raise ValueError("proxy_url missing host")
        from app.core.config import settings
        if settings.environment == "production" and not settings.allow_private_proxies:
            try:
                ip = ip_address(parsed.hostname)
            except ValueError:
                return v  # hostname, not a literal IP — allowed
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(
                    "proxy_url host is private/loopback; set "
                    "ALLOW_PRIVATE_PROXIES=1 to permit in production"
                )
        return v


class ScanResponse(BaseModel):
    # Returned for both scan submission and status polling.
    scan_id: str
    status: ScanStatus
    result: dict | None = None
    error: str | None = None

class AgentReport(BaseModel):
    # Validated shape for POST /api/v1/agent. extra="allow" so forward-
    # compatible agent fields are preserved on storage.
    model_config = ConfigDict(extra="allow")

    scan_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z0-9_\-]+$",
        description="Optional scan_id to attach to an existing scan.",
    )
    agent_id: str | None = Field(default=None, max_length=128)
    platform: str | None = Field(default=None, max_length=64)
    platform_version: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    interfaces: list[dict] = Field(default_factory=list)
    vpn_interfaces: list[str] = Field(default_factory=list)
    dns_resolvers: list[str] = Field(default_factory=list)
    checks: list[dict] = Field(default_factory=list)

