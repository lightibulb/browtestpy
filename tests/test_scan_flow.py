# Submit -> poll -> complete flow. Celery task and AsyncResult are mocked.
# The task is replaced at the MODULE attribute so the lazy
# `from app.tasks.orchestrator import execute_full_scan` inside submit_scan
# picks up the fake. Patching the PromiseProxy's .apply_async is unreliable.
from unittest.mock import MagicMock

from app.api import routes


class _FakeTask:
    name = "tasks.execute_full_scan"

    def __init__(self):
        self.calls = []

    def apply_async(self, **kwargs):
        self.calls.append(kwargs)
        return MagicMock(id=kwargs.get("task_id"))


def test_scan_submit_and_poll(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    from app.tasks import orchestrator as orch

    fake = _FakeTask()
    monkeypatch.setattr(orch, "execute_full_scan", fake)

    r = client.post("/api/v1/scan", json={})
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]
    assert r.json()["status"] == "queued"
    assert len(fake.calls) == 1
    assert fake.calls[0]["kwargs"] == {"proxy_url": None}
    assert fake.calls[0]["task_id"] == scan_id

    fake_ar = MagicMock()
    fake_ar.state = "SUCCESS"
    fake_ar.result = {
        "scan_id": scan_id,
        "verdict": "PASS",
        "score": 100,
        "findings": [],
        "layer1": {"ip": {"ipv4": "1.2.3.4"}, "dns": {}, "stun": {}},
        "layer2": {"status": "skipped"},
        "geo": {"status": "skipped"},
        "layer3": None,
    }
    monkeypatch.setattr(routes, "AsyncResult", lambda sid, app=None: fake_ar)

    r2 = client.get("/api/v1/scan/" + scan_id)
    assert r2.status_code == 200
    body = r2.json()
    assert body["status"] == "complete"
    assert body["result"]["verdict"] == "PASS"


def test_scan_submit_proxy_passthrough(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    from app.tasks import orchestrator as orch

    fake = _FakeTask()
    monkeypatch.setattr(orch, "execute_full_scan", fake)

    r = client.post("/api/v1/scan", json={"proxy_url": "socks5://127.0.0.1:9050"})
    assert r.status_code == 202, r.text
    assert fake.calls[0]["kwargs"] == {"proxy_url": "socks5://127.0.0.1:9050"}


def test_scan_submit_503_when_broker_down(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    from app.tasks import orchestrator as orch

    class _BrokenTask:
        name = "tasks.execute_full_scan"
        def apply_async(self, **kwargs):
            raise RuntimeError("broker unreachable")

    monkeypatch.setattr(orch, "execute_full_scan", _BrokenTask())
    r = client.post("/api/v1/scan", json={})
    assert r.status_code == 503
    assert r.json()["detail"] == "Queue unavailable"


def test_scan_pending(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    fake_ar = MagicMock()
    fake_ar.state = "PENDING"
    fake_ar.result = None
    monkeypatch.setattr(routes, "AsyncResult", lambda sid, app=None: fake_ar)
    r = client.get("/api/v1/scan/whatever")
    assert r.status_code == 200
    assert r.json()["status"] == "queued"


def test_scan_failure_state(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    fake_ar = MagicMock()
    fake_ar.state = "FAILURE"
    fake_ar.result = RuntimeError("boom")
    monkeypatch.setattr(routes, "AsyncResult", lambda sid, app=None: fake_ar)
    r = client.get("/api/v1/scan/x")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "failed"
    assert "boom" in body["error"]
