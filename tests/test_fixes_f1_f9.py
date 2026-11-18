"""Regression tests for diagnosis findings F2..F9. No network required."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.api import routes
from app.core.celery_app import celery
from app.services.analyzer import analyze
from app.tasks import layer1

ROOT = Path(__file__).resolve().parent.parent


def _clean():
    return (
        {"ip": {"ipv4": "1.2.3.4", "ipv6": None},
         "dns": {"status": "ok", "resolver_seen_ip": "1.2.3.4"},
         "stun": {"status": "ok", "mapped_ip": "1.2.3.4"}},
        {"status": "ok", "fingerprint": {"webdriver": False}},
    )


# --------------------------------------------------------------------- F3 ----
def test_f3_clean_scan_still_passes():
    l1, l2 = _clean()
    a = analyze(l1, l2)
    assert a["verdict"] == "PASS"
    assert a["score"] == 100
    assert a["coverage"]["complete"] is True


def test_f3_unknown_ip_is_fail_not_pass():
    a = analyze({"ip": {"ipv4": None, "error": "boom"}}, {"status": "skipped"})
    assert a["verdict"] == "FAIL"
    assert "ip_unknown" in [f["id"] for f in a["findings"]]


def test_f3_unmeasured_checks_are_inconclusive():
    a = analyze(
        {"ip": {"ipv4": "1.2.3.4"},
         "dns": {"status": "error", "error": "timeout"},
         "stun": {"status": "error", "error": "timeout"}},
        {"status": "skipped"},
    )
    assert a["verdict"] == "INCONCLUSIVE"
    assert a["coverage"]["complete"] is False
    ids = [f["id"] for f in a["findings"]]
    assert "dns_unmeasured" in ids
    assert "stun_unmeasured" in ids
    assert "fingerprint_unmeasured" in ids


# --------------------------------------------------------------------- F2 ----
def test_f2_server_harness_artifacts_are_not_user_leaks():
    l1, _ = _clean()
    l2 = {"status": "ok", "source": "server",
          "fingerprint": {"webdriver": True, "timezone": "UTC"}}
    geo = {"status": "ok", "country": "US", "timezone": "America/Los_Angeles"}
    a = analyze(l1, l2, geo=geo)
    assert a["findings"] == []
    assert a["verdict"] == "PASS"


def test_f2_client_webrtc_leak_is_critical():
    l1, l2 = _clean()
    l1["client"] = {"status": "ok", "public_ip": "5.5.5.5",
                    "webrtc_status": "ok", "webrtc_ips": ["5.5.5.5", "9.9.9.9"]}
    a = analyze(l1, l2)
    assert a["verdict"] == "FAIL"
    assert "webrtc_leak_client" in [f["id"] for f in a["findings"]]


def test_f2_client_webrtc_clean_passes():
    l1, l2 = _clean()
    l1["client"] = {"status": "ok", "public_ip": "5.5.5.5",
                    "webrtc_status": "ok", "webrtc_ips": ["5.5.5.5"]}
    a = analyze(l1, l2)
    assert a["verdict"] == "PASS"


# --------------------------------------------------------------------- F4 ----
def test_f4_requirements_install_socks_extra():
    assert "httpx[socks]" in (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_f4_socks5h_and_credentials_are_handled():
    from app.tasks.layer2 import split_proxy
    proxy, err = split_proxy("socks5h://proxy.example.com:1080")
    assert err is None
    assert proxy["server"] == "socks5://proxy.example.com:1080"
    proxy, err = split_proxy("http://u:p@proxy.example.com:8080")
    assert err is None
    assert proxy["username"] == "u" and proxy["password"] == "p"
    proxy, err = split_proxy("socks5://u:p@proxy.example.com:1080")
    assert proxy is None and err


# --------------------------------------------------------------------- F5 ----
def test_f5_dns_and_stun_are_skipped_when_proxy_used():
    d = layer1.check_dns(proxy_url="socks5://1.2.3.4:1080")
    s = layer1.check_stun(proxy_url="socks5://1.2.3.4:1080")
    assert d["status"] == "skipped" and d["reason"]
    assert s["status"] == "skipped" and s["reason"]


def test_f5_proxy_scan_does_not_fabricate_leaks():
    a = analyze(
        {"ip": {"ipv4": "9.9.9.9"},
         "dns": {"status": "skipped", "reason": "proxy"},
         "stun": {"status": "skipped", "reason": "proxy"},
         "proxy_used": True},
        {"status": "ok", "source": "server", "fingerprint": {"webdriver": True}},
    )
    ids = [f["id"] for f in a["findings"]]
    assert "dns_leak" not in ids
    assert "webrtc_leak" not in ids
    assert a["verdict"] == "INCONCLUSIVE"


# --------------------------------------------------------------------- F6 ----
def test_f6_render_uses_volatile_lru_and_bigger_worker():
    t = (ROOT / "render.yaml").read_text(encoding="utf-8")
    assert "maxmemoryPolicy: volatile-lru" in t
    assert "plan: standard" in t


def test_f6_broker_has_visibility_timeout():
    opts = celery.conf.broker_transport_options or {}
    assert opts.get("visibility_timeout") == 900


def test_f6_redelivery_is_bounded(monkeypatch):
    from app.tasks import orchestrator as orch

    # State belongs to the "server", not the client object: _client() returns
    # a fresh client on every call, exactly like redis.from_url() does.
    server = {"n": 0}

    class R:
        def incr(self, key):
            server["n"] += 1
            return server["n"]

        def expire(self, key, ttl):
            return True

    monkeypatch.setattr(orch, "_client", lambda: R())
    assert orch._attempt_guard("sid") == (True, 1)
    assert orch._attempt_guard("sid") == (True, 2)
    assert orch._attempt_guard("sid")[0] is False
    assert orch._attempt_guard(None) == (True, 1)

def _mock_orch(monkeypatch, *, fp=None, dns=None, stun=None, ip=None):
    from app.tasks import orchestrator as orch
    monkeypatch.setattr(orch, "get_public_ip",
                        lambda proxy_url=None: ip or {"ipv4": "9.9.9.9", "ipv6": None})
    monkeypatch.setattr(orch, "check_dns",
                        lambda proxy_url=None: dns or {"status": "skipped", "reason": "proxy"})
    monkeypatch.setattr(orch, "check_stun",
                        lambda proxy_url=None, **kw: stun or {"status": "skipped", "reason": "proxy"})
    monkeypatch.setattr(orch, "geo_lookup", lambda ip: {"status": "skipped"})
    monkeypatch.setattr(orch, "_persist_result", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_record_history", lambda *a, **k: None)
    return orch


def test_f2_orchestrator_prefers_client_fingerprint(monkeypatch):
    orch = _mock_orch(monkeypatch)

    def boom(proxy_url=None):
        raise AssertionError("server browser must not launch when client data exists")

    monkeypatch.setattr(orch, "collect_fingerprint", boom)
    res = orch.execute_full_scan.apply(kwargs={
        "proxy_url": "socks5://1.2.3.4:1080",
        "client_fingerprint": {"userAgent": "UA", "timezone": "Asia/Karachi", "webdriver": False},
        "client_network": {"status": "ok", "public_ip": "5.5.5.5",
                           "webrtc_status": "ok", "webrtc_ips": ["5.5.5.5"]},
    })
    assert res.successful(), res.traceback
    d = res.result
    assert d["layer2"]["source"] == "client"
    assert d["verdict"] == "PASS"
    assert d["coverage"]["complete"] is True


# --------------------------------------------------------------------- F7 ----
def test_f7_ui_has_hardened_fetch_and_poll():
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    for needle in ("AbortController", "res.ok", "Retry-After", "429",
                   "300000", "RTCPeerConnection", "client_fingerprint"):
        assert needle in html, "missing in UI: " + needle


def test_f7_polling_is_not_rate_limited(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    ar = MagicMock()
    ar.state = "PENDING"
    ar.result = None
    monkeypatch.setattr(routes, "AsyncResult", lambda sid, app=None: ar)
    codes = {client.get("/api/v1/scan/poll-test").status_code for _ in range(70)}
    assert codes == {200}


def test_f7_rate_limit_sends_retry_after(client, monkeypatch):
    from app import main as m
    monkeypatch.setattr(m.write_limiter, "allow", lambda key: False)
    r = client.post("/api/v1/scan", json={})
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}


# --------------------------------------------------------------------- F8 ----
def test_f8_placeholder_is_not_loopback():
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    assert "socks5://127.0.0.1" not in html
    assert "ALLOW_PRIVATE_PROXIES" in html


def test_f8_validation_errors_carry_detail(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.post("/api/v1/scan", json={"proxy_url": "ftp://x.example.com:21"})
    assert r.status_code == 422
    assert r.json()["detail"]


def test_f8_client_payload_is_validated(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.post("/api/v1/scan", json={"client_network": {"public_ip": "not-an-ip"}})
    assert r.status_code == 422


def test_f2_client_payload_reaches_the_task(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    from app.tasks import orchestrator as orch

    class FakeTask:
        name = "tasks.execute_full_scan"

        def __init__(self):
            self.calls = []

        def apply_async(self, **kw):
            self.calls.append(kw)
            return MagicMock(id=kw.get("task_id"))

    fake = FakeTask()
    monkeypatch.setattr(orch, "execute_full_scan", fake)
    r = client.post("/api/v1/scan", json={
        "client_fingerprint": {"userAgent": "UA", "timezone": "Asia/Karachi"},
        "client_network": {"status": "ok", "public_ip": "5.5.5.5",
                           "webrtc_status": "ok", "webrtc_ips": ["5.5.5.5"]},
    })
    assert r.status_code == 202, r.text
    kw = fake.calls[0]["kwargs"]
    assert kw["client_fingerprint"]["timezone"] == "Asia/Karachi"
    assert kw["client_network"]["public_ip"] == "5.5.5.5"


# --------------------------------------------------------------------- F9 ----
def test_f9_history_is_owner_scoped(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    fake_redis.lpush("scan_history:owner-aaaa-1111", "aaa")
    fake_redis.setex("scan_summary:aaa", 60,
                     json.dumps({"verdict": "PASS", "score": 100, "public_ip": "1.1.1.1"}))
    client.cookies.set("lg_sid", "owner-aaaa-1111")
    assert len(client.get("/api/v1/history").json()["scans"]) == 1
    client.cookies.set("lg_sid", "owner-bbbb-2222")
    assert client.get("/api/v1/history").json()["scans"] == []


def test_f9_scan_submission_records_ownership(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    from app.tasks import orchestrator as orch

    class FakeTask:
        name = "tasks.execute_full_scan"

        def apply_async(self, **kw):
            return MagicMock(id=kw.get("task_id"))

    monkeypatch.setattr(orch, "execute_full_scan", FakeTask())
    client.cookies.set("lg_sid", "owner-cccc-3333")
    r = client.post("/api/v1/scan", json={})
    assert r.status_code == 202
    sid = r.json()["scan_id"]
    assert sid in fake_redis.lrange("scan_history:owner-cccc-3333", 0, 10)
    assert fake_redis.get("scan_owner:" + sid) == "owner-cccc-3333"


def test_f9_ui_exposes_full_scan_id_and_attach_command():
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'data-action="copy-id"' in html
    assert 'id="agent-cmd"' in html
    assert 'data-action="attach"' in html


def test_f9_bad_scan_id_is_rejected(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    assert client.get("/api/v1/agent/bad..id").status_code == 400
