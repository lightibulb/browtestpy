# Geo lookup tests with mocked httpx. No network.
from unittest.mock import MagicMock, patch

import app.services.geo as geo


def _mock_client(response_data):
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status.return_value = None
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get.return_value = mock_resp
    return client


def test_lookup_success_ipwhois():
    geo._cache.clear()
    payload = {
        "success": True,
        "country": "United States",
        "country_code": "US",
        "city": "Mountain View",
        "timezone": {"id": "America/Los_Angeles"},
        "connection": {"isp": "Google LLC"},
    }
    with patch("app.services.geo.httpx.Client",
               return_value=_mock_client(payload)):
        result = geo.lookup("8.8.8.8")
    assert result["status"] == "ok"
    assert result["country_code"] == "US"
    assert result["timezone"] == "America/Los_Angeles"


def test_lookup_cache_hit():
    geo._cache.clear()
    payload = {
        "success": True, "country": "X", "country_code": "XX",
        "city": "Y", "timezone": {"id": "Z"}, "connection": {"isp": "W"},
    }
    with patch("app.services.geo.httpx.Client",
               return_value=_mock_client(payload)) as mock:
        geo.lookup("1.1.1.1")
        geo.lookup("1.1.1.1")
    assert mock.call_count == 1


def test_lookup_skips_empty_ip():
    result = geo.lookup("")
    assert result["status"] == "skipped"


def test_lookup_all_providers_fail():
    geo._cache.clear()
    mock = MagicMock()
    mock.__enter__.return_value = mock
    mock.__exit__.return_value = False
    mock.get.side_effect = Exception("network down")
    with patch("app.services.geo.httpx.Client", return_value=mock):
        result = geo.lookup("9.9.9.9")
    assert result["status"] == "error"
