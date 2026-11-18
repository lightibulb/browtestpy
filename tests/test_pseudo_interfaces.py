import pytest
from app.services.analyzer import analyze

try:
    from app.services.analyzer import _is_pseudo_interface  # noqa: F401
    HAS_PSEUDO = True
except ImportError:
    HAS_PSEUDO = False


@pytest.mark.skipif(not HAS_PSEUDO, reason="requires H5 fix (_is_pseudo_interface)")
def test_loopback_skipped():
    layer3 = {
        "interfaces": [
            {"name": "lo", "mac": "00:00:00:00:00:00", "randomized": False},
            {"name": "wlan0", "mac": "aa:bb:cc:dd:ee:ff", "randomized": False},
        ],
        "vpn_interfaces": ["tun0"],
    }
    a = analyze({}, {"status": "skipped"}, layer3=layer3)
    ids = [f["id"] for f in a["findings"]]
    assert "mac_permanent_lo" not in ids
    assert "mac_permanent_wlan0" in ids


@pytest.mark.skipif(not HAS_PSEUDO, reason="requires H5 fix (_is_pseudo_interface)")
def test_virtual_interfaces_skipped():
    layer3 = {
        "interfaces": [
            {"name": "docker0", "mac": "02:42:ac:11:00:01", "randomized": True},
            {"name": "veth1234", "mac": "aa:bb:cc:dd:ee:ff", "randomized": False},
            {"name": "eth0", "mac": "aa:bb:cc:dd:ee:01", "randomized": False},
        ],
        "vpn_interfaces": ["wg0"],
    }
    a = analyze({}, {"status": "skipped"}, layer3=layer3)
    ids = [f["id"] for f in a["findings"]]
    assert "mac_permanent_docker0" not in ids
    assert "mac_permanent_veth1234" not in ids
    assert "mac_permanent_eth0" in ids


@pytest.mark.skipif(not HAS_PSEUDO, reason="requires H5 fix (_is_pseudo_interface)")
def test_zero_mac_skipped():
    layer3 = {
        "interfaces": [{"name": "weird0", "mac": "00:00:00:00:00:00", "randomized": False}],
        "vpn_interfaces": ["tun0"],
    }
    a = analyze({}, {"status": "skipped"}, layer3=layer3)
    assert not [f for f in a["findings"] if f["id"].startswith("mac_permanent_")]
