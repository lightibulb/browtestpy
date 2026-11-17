# API tests for /agent and /history. Redis is mocked.
import json

from app.api import routes


def test_post_agent_creates_id(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    payload = {"hostname": "test-host", "interfaces": []}
    r = client.post("/api/v1/agent", json=payload)
    assert r.status_code == 202
    body = r.json()
    assert "scan_id" in body
    assert body["view_url"].startswith("/api/v1/agent/")


def test_post_agent_with_attach(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.post(
        "/api/v1/agent",
        json={"scan_id": "fixed-id-123", "hostname": "h"},
    )
    assert r.status_code == 202
    assert r.json()["scan_id"] == "fixed-id-123"


def test_get_agent_round_trip(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    payload = {"hostname": "h", "interfaces": [{"name": "wlan0"}]}
    r = client.post("/api/v1/agent", json=payload)
    scan_id = r.json()["scan_id"]
    r2 = client.get("/api/v1/agent/" + scan_id)
    assert r2.status_code == 200
    assert r2.json()["hostname"] == "h"


def test_get_agent_missing(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.get("/api/v1/agent/does-not-exist")
    assert r.status_code == 404


def test_history_empty(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.get("/api/v1/history")
    assert r.status_code == 200
    assert r.json()["scans"] == []


def test_history_with_entries(client, fake_redis, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    fake_redis.lpush("scan_history", "abc")
    fake_redis.setex(
        "scan_summary:abc", 60,
        json.dumps({"verdict": "PASS", "score": 100, "public_ip": "1.2.3.4"}),
    )
    r = client.get("/api/v1/history")
    assert r.status_code == 200
    scans = r.json()["scans"]
    assert len(scans) == 1
    assert scans[0]["verdict"] == "PASS"


def test_agent_returns_503_when_redis_down(client, monkeypatch):
    monkeypatch.setattr(routes, "get_redis", lambda: None)
    r = client.post("/api/v1/agent", json={"hostname": "h"})
    assert r.status_code == 503
