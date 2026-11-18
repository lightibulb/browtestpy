# Weighted consistency analyzer. Returns findings, verdict, and score.
SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

SEVERITY_WEIGHTS = {
    SEVERITY_CRITICAL: 30,
    SEVERITY_WARNING: 15,
    SEVERITY_INFO: 5,
}


def _finding(fid, severity, title, detail):
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
    }


def _is_pseudo_interface(iface):
    # Loopback / virtual bridges / all-zero MACs are not trackable by observers.
    name_ = (iface.get("name") or "").lower()
    if (
        name_ == "lo"
        or name_.startswith("lo0")
        or name_.startswith(("veth", "docker", "br-", "virbr", "vmnet", "ifb"))
    ):
        return True
    mac = (iface.get("mac") or "").replace(":", "").replace("-", "").lower()
    if not mac or set(mac) == {"0"}:
        return True
    return False


def analyze(layer1, layer2, geo=None, layer3=None):
    # Signature is backward-compatible with Part 2 (geo/layer3 default to None).
    findings = []
    layer1 = layer1 or {}
    layer2 = layer2 or {}
    geo = geo or {}
    layer3 = layer3 or {}

    ip_data = layer1.get("ip", {}) or {}
    dns_data = layer1.get("dns", {}) or {}
    stun_data = layer1.get("stun", {}) or {}

    public_ip = ip_data.get("ipv4")
    public_v6 = ip_data.get("ipv6")
    resolver_ip = dns_data.get("resolver_seen_ip")
    mapped_ip = stun_data.get("mapped_ip")

    if public_ip and resolver_ip and public_ip != resolver_ip:
        findings.append(_finding(
            "dns_leak", SEVERITY_CRITICAL,
            "DNS resolver IP differs from public IP",
            "Public IP " + public_ip + " but resolver seen as " + resolver_ip,
        ))

    if public_ip and mapped_ip and public_ip != mapped_ip:
        findings.append(_finding(
            "webrtc_leak", SEVERITY_CRITICAL,
            "STUN/WebRTC leak detected",
            "Public IP " + public_ip + " but STUN sees " + mapped_ip,
        ))

    if public_v6:
        findings.append(_finding(
            "ipv6_exposed", SEVERITY_WARNING,
            "IPv6 address exposed",
            "IPv6 " + str(public_v6)
            + " leaked -- if VPN is IPv4-only, this bypasses the tunnel",
        ))

    if layer2.get("status") == "ok" and geo.get("status") == "ok":
        fp = layer2.get("fingerprint", {}) or {}
        browser_tz = fp.get("timezone")
        ip_tz = geo.get("timezone")
        if browser_tz and ip_tz and browser_tz != ip_tz:
            findings.append(_finding(
                "timezone_mismatch", SEVERITY_WARNING,
                "Browser timezone differs from IP location",
                "IP in " + str(geo.get("country")) + " (" + str(ip_tz)
                + ") but browser timezone is " + str(browser_tz),
            ))

    if layer2.get("status") == "ok":
        fp = layer2.get("fingerprint", {}) or {}
        if fp.get("webdriver"):
            findings.append(_finding(
                "webdriver_flag", SEVERITY_INFO,
                "Browser reports automation flag",
                "navigator.webdriver is true -- sites may classify this as a bot",
            ))

    if layer3 and layer3.get("interfaces"):
        for iface in layer3.get("interfaces", []):
            if _is_pseudo_interface(iface):
                continue
            if iface.get("randomized") is False:
                findings.append(_finding(
                    "mac_permanent_" + str(iface.get("name")),
                    SEVERITY_WARNING,
                    "Interface " + str(iface.get("name"))
                    + " uses a permanent MAC",
                    "MAC " + str(iface.get("mac"))
                    + " is not randomized -- trackable across networks",
                ))

    if layer3 and not layer3.get("vpn_interfaces"):
        findings.append(_finding(
            "no_vpn_interface", SEVERITY_INFO,
            "No VPN interface detected on host",
            "Expected a tun/wg/utun interface if a VPN is active",
        ))

    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHTS.get(f["severity"], 0)
    score = max(0, min(100, score))

    has_critical = any(f["severity"] == SEVERITY_CRITICAL for f in findings)
    has_warning = any(f["severity"] == SEVERITY_WARNING for f in findings)

    if has_critical:
        verdict = "FAIL"
    elif has_warning:
        verdict = "REVIEW"
    else:
        verdict = "PASS"

    return {"findings": findings, "verdict": verdict, "score": score}
