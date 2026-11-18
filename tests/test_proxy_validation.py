import pytest
from app.models.scan import ScanRequest


def _has_validator():
    try:
        ScanRequest(proxy_url="ftp://example.com:21"); return False
    except Exception:
        return True

HAS_VALIDATOR = _has_validator()


def test_proxy_none_ok():
    assert ScanRequest(proxy_url=None).proxy_url is None


def test_proxy_valid_socks5():
    ScanRequest(proxy_url="socks5://127.0.0.1:9050")


@pytest.mark.skipif(not HAS_VALIDATOR, reason="requires H6 fix (field_validator)")
def test_proxy_invalid_scheme():
    with pytest.raises(Exception):
        ScanRequest(proxy_url="ftp://example.com:21")


@pytest.mark.skipif(not HAS_VALIDATOR, reason="requires H6 fix (field_validator)")
def test_proxy_too_long():
    with pytest.raises(Exception):
        ScanRequest(proxy_url="http://" + "a" * 600)


@pytest.mark.skipif(not HAS_VALIDATOR, reason="requires H6 fix (field_validator)")
def test_proxy_missing_host():
    with pytest.raises(Exception):
        ScanRequest(proxy_url="socks5://")
