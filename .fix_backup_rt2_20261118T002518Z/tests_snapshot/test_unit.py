# Unit tests from Parts 1-2. All external calls mocked.
# Note: analyzer coverage lives in tests/test_analyzer.py.
from unittest.mock import MagicMock, patch


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "celery_workers" in r.json()


def test_root_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


def test_layer1_ip_mocked():
    from app.tasks.layer1 import get_public_ip

    mock_response = MagicMock()
    mock_response.json.return_value = {"ip": "1.2.3.4"}
    mock_response.raise_for_status.return_value = None

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.return_value = mock_response

    with patch("app.tasks.layer1.httpx.Client", return_value=mock_client):
        result = get_public_ip()
    assert result["ipv4"] == "1.2.3.4"


def test_layer1_stun_returns_dict():
    from app.tasks.layer1 import check_stun
    result = check_stun(server="127.0.0.1", port=1, timeout=0.5)
    assert isinstance(result, dict)
    assert "status" in result


def test_layer2_skipped_when_no_playwright(monkeypatch):
    import app.tasks.layer2 as l2
    monkeypatch.setattr(l2, "PLAYWRIGHT_AVAILABLE", False)
    result = l2.collect_fingerprint()
    assert result["status"] == "skipped"
