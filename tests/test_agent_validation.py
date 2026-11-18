import pytest

try:
    from app.models.scan import AgentReport
    HAS_MODEL = True
except ImportError:
    HAS_MODEL = False


@pytest.mark.skipif(not HAS_MODEL, reason="requires M6 fix (AgentReport model)")
def test_scan_id_pattern_valid():
    AgentReport(scan_id="abc-123_DEF")
    AgentReport(scan_id=None)


@pytest.mark.skipif(not HAS_MODEL, reason="requires M6 fix (AgentReport model)")
def test_scan_id_pattern_invalid():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        AgentReport(scan_id="bad/../id")
    with pytest.raises(ValidationError):
        AgentReport(scan_id="bad space")


@pytest.mark.skipif(not HAS_MODEL, reason="requires M6 fix (AgentReport model)")
def test_extra_fields_preserved():
    r = AgentReport(hostname="h", custom_field="value")
    d = r.model_dump()
    assert d["hostname"] == "h"
    assert d["custom_field"] == "value"


def test_post_agent_rejects_bad_scan_id(client, fake_redis, monkeypatch):
    if not HAS_MODEL:
        pytest.skip("requires M6 fix (AgentReport model)")
    from app.api import routes
    monkeypatch.setattr(routes, "get_redis", lambda: fake_redis)
    r = client.post("/api/v1/agent", json={"scan_id": "bad/../id"})
    assert r.status_code == 422
    assert not fake_redis.store
