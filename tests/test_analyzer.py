# Analyzer tests: every finding type, verdicts, scores.
from app.services.analyzer import analyze


def _clean_layers():
    return (
        {"ip": {"ipv4": "1.2.3.4", "ipv6": None},
         "dns": {"status": "ok", "resolver_seen_ip": "1.2.3.4"},
         "stun": {"status": "ok", "mapped_ip": "1.2.3.4"}},
        {"status": "ok", "fingerprint": {"webdriver": False}},
    )


def test_pass_when_clean():
    l1, l2 = _clean_layers()
    a = analyze(l1, l2)
    assert a["verdict"] == "PASS"
    assert a["score"] == 100
    assert a["findings"] == []


def test_dns_leak_critical():
    l1, l2 = _clean_layers()
    l1["dns"]["resolver_seen_ip"] = "5.6.7.8"
    a = analyze(l1, l2)
    assert a["verdict"] == "FAIL"
    assert any(f["id"] == "dns_leak" for f in a["findings"])
    assert a["score"] == 70


def test_webrtc_leak_critical():
    l1, l2 = _clean_layers()
    l1["stun"]["mapped_ip"] = "5.6.7.8"
    a = analyze(l1, l2)
    assert a["verdict"] == "FAIL"
    assert any(f["id"] == "webrtc_leak" for f in a["findings"])


def test_ipv6_warning():
    l1, l2 = _clean_layers()
    l1["ip"]["ipv6"] = "2001:db8::1"
    a = analyze(l1, l2)
    assert a["verdict"] == "REVIEW"
    assert any(f["id"] == "ipv6_exposed" for f in a["findings"])


def test_timezone_mismatch_warning():
    l1, l2 = _clean_layers()
    l2["fingerprint"]["timezone"] = "Asia/Karachi"
    geo = {"status": "ok", "country": "US", "timezone": "America/Los_Angeles"}
    a = analyze(l1, l2, geo=geo)
    assert any(f["id"] == "timezone_mismatch" for f in a["findings"])


def test_no_timezone_finding_when_geo_skipped():
    l1, l2 = _clean_layers()
    l2["fingerprint"]["timezone"] = "Asia/Karachi"
    a = analyze(l1, l2, geo={"status": "skipped"})
    assert not any(f["id"] == "timezone_mismatch" for f in a["findings"])


def test_webdriver_info():
    l1, l2 = _clean_layers()
    l2["fingerprint"]["webdriver"] = True
    a = analyze(l1, l2)
    assert any(f["id"] == "webdriver_flag" for f in a["findings"])
    assert a["verdict"] == "PASS"


def test_mac_permanent_warning():
    l1, l2 = _clean_layers()
    layer3 = {
        "interfaces": [
            {"name": "wlan0", "mac": "aa:bb:cc:dd:ee:ff", "randomized": False},
        ],
        "vpn_interfaces": ["tun0"],
    }
    a = analyze(l1, l2, layer3=layer3)
    assert a["verdict"] == "REVIEW"
    assert any(f["id"].startswith("mac_permanent") for f in a["findings"])


def test_no_vpn_interface_info():
    l1, l2 = _clean_layers()
    layer3 = {"interfaces": [], "vpn_interfaces": []}
    a = analyze(l1, l2, layer3=layer3)
    assert any(f["id"] == "no_vpn_interface" for f in a["findings"])


def test_errors_do_not_create_false_positives():
    l1 = {
        "ip": {"ipv4": "1.2.3.4", "ipv6": None},
        "dns": {"status": "error", "error": "timeout"},
        "stun": {"status": "error", "error": "timeout"},
    }
    a = analyze(l1, {"status": "skipped"})
    # F3: errors are not a clean bill of health.
    assert a["verdict"] == "INCONCLUSIVE"
    assert a["coverage"]["complete"] is False
    ids = [f["id"] for f in a["findings"]]
    assert "dns_leak" not in ids
    assert "webrtc_leak" not in ids
    assert "dns_unmeasured" in ids


def test_score_floors_at_zero():
    l1 = {
        "ip": {"ipv4": "1.2.3.4", "ipv6": "2001:db8::1"},
        "dns": {"resolver_seen_ip": "9.9.9.9"},
        "stun": {"mapped_ip": "8.8.8.8"},
    }
    l2 = {"status": "ok", "fingerprint": {"webdriver": True}}
    geo = {"status": "ok", "country": "US", "timezone": "X"}
    layer3 = {"interfaces": [
        {"name": "wlan0", "mac": "aa:bb:cc:dd:ee:ff", "randomized": False},
    ], "vpn_interfaces": []}
    a = analyze(l1, l2, geo=geo, layer3=layer3)
    assert a["score"] >= 0
    assert a["verdict"] == "FAIL"
