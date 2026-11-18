def test_ready_redis_up(client, fake_redis, monkeypatch):
    from app.api import routes
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["redis"] is True


def test_ready_redis_down(client, monkeypatch):
    from app.api import routes
    monkeypatch.setattr(routes, "get_redis", lambda: None)
    r = client.get("/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["redis"] is False
