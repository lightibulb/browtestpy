# Agent parsing tests. Uses sample command output; no subprocess.
import importlib.util
import sys
from pathlib import Path

AGENT_PATH = Path(__file__).parent.parent / "agent" / "leakguard_agent.py"
spec = importlib.util.spec_from_file_location("leakguard_agent", AGENT_PATH)
agent = importlib.util.module_from_spec(spec)
sys.modules["leakguard_agent"] = agent
spec.loader.exec_module(agent)


def test_is_randomized_mac():
    # Second hex char in {2,6,A,E} => LAA bit set => randomized.
    assert agent.is_randomized_mac("02:bb:cc:dd:ee:ff") is True
    assert agent.is_randomized_mac("06:bb:cc:dd:ee:ff") is True
    assert agent.is_randomized_mac("a2:bb:cc:dd:ee:ff") is True
    assert agent.is_randomized_mac("a6:bb:cc:dd:ee:ff") is True
    assert agent.is_randomized_mac("ae:bb:cc:dd:ee:ff") is True
    # Second hex char in {0,4,8,C} => UAA bit set => OUI (permanent).
    assert agent.is_randomized_mac("00:bb:cc:dd:ee:ff") is False
    assert agent.is_randomized_mac("04:bb:cc:dd:ee:ff") is False
    assert agent.is_randomized_mac("a0:bb:cc:dd:ee:ff") is False
    assert agent.is_randomized_mac("ac:bb:cc:dd:ee:ff") is False
    assert agent.is_randomized_mac("") is None
    assert agent.is_randomized_mac("a") is None


LINUX_SAMPLE = (
    '1: lo: <LOOPBACK> mtu 65536 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n'
    '2: wlan0: <BROADCAST> mtu 1500 link/ether a2:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n'
    '3: tun0: <POINTOPOINT> mtu 1500 link/none\n'
)


def test_parse_linux_ip_link():
    ifaces = agent.parse_linux_ip_link(LINUX_SAMPLE)
    assert len(ifaces) == 2
    names = {i["name"]: i for i in ifaces}
    assert names["wlan0"]["mac"] == "a2:bb:cc:dd:ee:ff"
    assert names["wlan0"]["randomized"] is True


DARWIN_SAMPLE = (
    "lo0: flags=8049<UP>\n"
    "\tether 00:00:00:00:00:00\n"
    "en0: flags=8863<UP>\n"
    "\tether a6:11:22:33:44:55\n"
)


def test_parse_darwin_ifconfig():
    ifaces = agent.parse_darwin_ifconfig(DARWIN_SAMPLE)
    assert len(ifaces) == 2
    by_name = {i["name"]: i for i in ifaces}
    assert by_name["en0"]["randomized"] is True


# Wi-Fi uses 00 (permanent/OUI), Ethernet uses 02 (randomized/LAA).
WINDOWS_SAMPLE = (
    '"Wi-Fi","Realtek","00-BB-CC-DD-EE-FF","\\Device\\Tcpip_{...}"\n'
    '"Ethernet","Intel","02-11-22-33-44-55","\\Device\\Tcpip_{...}"\n'
)


def test_parse_windows_getmac():
    ifaces = agent.parse_windows_getmac(WINDOWS_SAMPLE)
    assert len(ifaces) == 2
    by_name = {i["name"]: i for i in ifaces}
    assert by_name["Wi-Fi"]["randomized"] is False
    assert by_name["Ethernet"]["randomized"] is True


def test_collect_vpn_interfaces():
    ifs = [{"name": "wlan0"}, {"name": "tun0"}, {"name": "wg0"}, {"name": "eth0"}]
    vpn = agent.collect_vpn_interfaces(ifs)
    assert "tun0" in vpn
    assert "wg0" in vpn
    assert "wlan0" not in vpn


def test_build_report_shape(monkeypatch):
    monkeypatch.setattr(agent, "collect_interfaces", lambda: [
        {"name": "wlan0", "mac": "00:bb:cc:dd:ee:ff", "randomized": False},
    ])
    monkeypatch.setattr(agent, "collect_dns_resolvers", lambda: ["1.1.1.1"])
    r = agent.build_report()
    assert "agent_id" in r
    assert r["interfaces"][0]["name"] == "wlan0"
    assert any(c["id"].startswith("mac_permanent") for c in r["checks"])
