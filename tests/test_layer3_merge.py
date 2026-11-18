import json
from unittest.mock import MagicMock
import pytest
from app.api import routes

try:
    from app.api.routes import _merge_layer3  # noqa: F401
    HAS_MERGE = True
except ImportError:
    HAS_MERGE = False

try:
    from app.api.routes import _load_persisted_result  # noqa: F401
    HAS_PERSIST = True
except ImportError:
    HAS_PERSIST = False


def _base(scan_id):
    return {
        "scan_id": scan_id, "verdict": "PASS", "score": 100, "findings": [],
        "layer1": {"ip": {"ipv4": "1.2.3.4"}, "dns": {}, "stun": {}},
        "layer2": {"status": "skipped"},
        "geo": {"status": "skipped"},
        "layer3": None,
    }


def _ar(state, result):
    ar = MagicMock(); ar.state = state; ar.result = result; return ar


@pytest.mark.skipif(not HAS_MERGE, reason="requires H1 fix (_merge_layer3)")
def test_scan_includes_layer3(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    layer3 = {
        "scan_id": "scan-abc", "hostname": "h",
        "interfaces": [{"name": "wlan0", "mac": "aa:bb:cc:dd:ee:ff", "randomized": False}],
        "vpn_interfaces": ["tun0"],
    }
    fake_redis.setex("agent:scan-abc", 60, json.dumps(layer3))
    monkeypatch.setattr(routes, "AsyncResult",
        lambda sid, app=None: _ar("SUCCESS", _base("scan-abc")))
    r = client.get("/api/v1/scan/scan-abc")
    assert r.status_code == 200
    body = r.json()
    assert body["result"]["layer3"]["hostname"] == "h"
    assert body["result"]["verdict"] in ("REVIEW", "INCONCLUSIVE")
    assert any(f["id"].startswith("mac_permanent_")
               for f in body["result"]["findings"])


@pytest.mark.skipif(not HAS_MERGE, reason="requires H1 fix (_merge_layer3)")
def test_export_includes_layer3(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    layer3 = {"scan_id": "scan-abc", "hostname": "h", "interfaces": []}
    fake_redis.setex("agent:scan-abc", 60, json.dumps(layer3))
    monkeypatch.setattr(routes, "AsyncResult",
        lambda sid, app=None: _ar("SUCCESS", _base("scan-abc")))
    r = client.get("/api/v1/scan/scan-abc/export")
    assert r.status_code == 200
    assert json.loads(r.content)["layer3"]["hostname"] == "h"


@pytest.mark.skipif(not HAS_PERSIST, reason="requires H2 fix (_load_persisted_result)")
def test_scan_falls_back_to_persisted(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    fake_redis.setex("scan_result:scan-x", 60, json.dumps(_base("scan-x")))
    monkeypatch.setattr(routes, "AsyncResult", lambda sid, app=None: _ar("PENDING", None))
    r = client.get("/api/v1/scan/scan-x")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "complete"
    assert body["result"]["verdict"] == "PASS"
