# Orchestrator end-to-end with every external call mocked.
from app.tasks import orchestrator as orch


def _patch_layers(monkeypatch):
    monkeypatch.setattr(orch, "get_public_ip",
        lambda proxy_url=None: {"ipv4": "1.2.3.4", "ipv6": None, "error": None})
    monkeypatch.setattr(orch, "check_dns",
        lambda proxy_url=None: {"status": "ok", "resolver_seen_ip": "1.2.3.4"})
    monkeypatch.setattr(orch, "check_stun",
        lambda proxy_url=None, **kw: {"status": "ok", "mapped_ip": "1.2.3.4"})
    monkeypatch.setattr(orch, "collect_fingerprint",
        lambda proxy_url=None: {"status": "ok", "source": "server",
                                "fingerprint": {"webdriver": False, "timezone": "UTC"}})
    monkeypatch.setattr(orch, "geo_lookup", lambda ip: {"status": "skipped"})
    monkeypatch.setattr(orch, "_record_history", lambda *a, **kw: None)
    if hasattr(orch, "_persist_result"):
        monkeypatch.setattr(orch, "_persist_result", lambda *a, **kw: None)


def test_execute_full_scan_pass(monkeypatch):
    _patch_layers(monkeypatch)
    res = orch.execute_full_scan.apply(kwargs={"proxy_url": None})
    assert res.successful(), res.traceback
    data = res.result
    assert data["verdict"] == "PASS"
    assert data["score"] == 100
    assert data["layer1"]["ip"]["ipv4"] == "1.2.3.4"
    assert data["layer2"]["status"] == "ok"
    assert data["geo"]["status"] == "skipped"
    if "proxy_url" in data:
        assert data["proxy_url"] is None


def test_execute_full_scan_fail_on_dns_leak(monkeypatch):
    _patch_layers(monkeypatch)
    monkeypatch.setattr(orch, "check_dns",
        lambda proxy_url=None: {"status": "ok", "resolver_seen_ip": "9.9.9.9"})
    res = orch.execute_full_scan.apply(kwargs={"proxy_url": None})
    assert res.successful(), res.traceback
    data = res.result
    assert data["verdict"] == "FAIL"
    assert "dns_leak" in [f["id"] for f in data["findings"]]


def test_execute_full_scan_review_on_ipv6(monkeypatch):
    _patch_layers(monkeypatch)
    monkeypatch.setattr(orch, "get_public_ip",
        lambda proxy_url=None: {"ipv4": "1.2.3.4", "ipv6": "2001:db8::1", "error": None})
    res = orch.execute_full_scan.apply(kwargs={"proxy_url": None})
    assert res.successful(), res.traceback
    data = res.result
    assert data["verdict"] == "REVIEW"
    assert "ipv6_exposed" in [f["id"] for f in data["findings"]]
