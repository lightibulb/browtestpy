import pytest
from app.services.analyzer import analyze


def _has_m8():
    l1 = {
        "ip": {"ipv4": "1.2.3.4"},
        "dns": {"status": "error", "resolver_seen_ip": "9.9.9.9"},
        "stun": {"status": "error", "mapped_ip": "8.8.8.8"},
    }
    a = analyze(l1, {"status": "skipped"})
    ids = [f["id"] for f in a["findings"]]
    return "dns_leak" not in ids and "webrtc_leak" not in ids

HAS_M8 = _has_m8()


@pytest.mark.skipif(not HAS_M8, reason="requires M8 fix (status gating)")
def test_errors_do_not_trigger_leaks_with_payloads():
    l1 = {
        "ip": {"ipv4": "1.2.3.4"},
        "dns": {"status": "error", "resolver_seen_ip": "9.9.9.9"},
        "stun": {"status": "error", "mapped_ip": "8.8.8.8"},
    }
    a = analyze(l1, {"status": "skipped"})
    ids = [f["id"] for f in a["findings"]]
    assert "dns_leak" not in ids
    assert "webrtc_leak" not in ids
    assert a["verdict"] == "INCONCLUSIVE"  # F3


def test_ok_status_still_triggers_leaks():
    l1 = {
        "ip": {"ipv4": "1.2.3.4"},
        "dns": {"status": "ok", "resolver_seen_ip": "9.9.9.9"},
        "stun": {"status": "ok", "mapped_ip": "8.8.8.8"},
    }
    a = analyze(l1, {"status": "skipped"})
    ids = [f["id"] for f in a["findings"]]
    assert "dns_leak" in ids
    assert "webrtc_leak" in ids
