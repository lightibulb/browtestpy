# Weighted consistency analyzer with explicit measurement coverage.
#
# F3: a check that did not run is NOT a clean result. Unmeasured checks emit
#     findings and force INCONCLUSIVE (or FAIL when the IP itself is unknown).
# F2: artifacts of the server harness (headless navigator.webdriver, container
#     timezone) are not reported as user leaks when layer2["source"]=="server".
# F5: server-side DNS/STUN describe the host, not the visitor. They are only
#     scored when the server really is the subject of the test.
from __future__ import annotations

from ipaddress import ip_address

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

SEVERITY_WEIGHTS = {
    SEVERITY_CRITICAL: 30,
    SEVERITY_WARNING: 15,
    SEVERITY_INFO: 5,
}

VERDICT_PASS = "PASS"
VERDICT_REVIEW = "REVIEW"
VERDICT_FAIL = "FAIL"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"


def _finding(fid, severity, title, detail):
    return {"id": fid, "severity": severity, "title": title, "detail": detail}


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


def _is_ip(value):
    try:
        ip_address(str(value))
        return True
    except (ValueError, TypeError):
        return False


def _is_public_ip(value):
    try:
        a = ip_address(str(value))
    except (ValueError, TypeError):
        return False
    return not (
        a.is_private or a.is_loopback or a.is_link_local
        or a.is_reserved or a.is_multicast or a.is_unspecified
    )


def _measure_state(data, value_key):
    """Return 'ok' | 'missing' | 'n/a'.

    'n/a' means not applicable / not supplied (legacy payloads), which must not
    be penalised. 'missing' means the check was attempted and produced nothing.
    """
    if not data:
        return "n/a"
    status = data.get("status")
    if status in ("error", "skipped"):
        return "missing"
    if data.get(value_key):
        return "ok"
    if status == "ok":
        return "missing"
    return "n/a"


MISSING_SPEC = {
    "ip": ("ip_unknown", SEVERITY_CRITICAL,
           "Public IP could not be determined"),
    "dns": ("dns_unmeasured", SEVERITY_WARNING,
            "DNS leak check did not complete"),
    "stun": ("stun_unmeasured", SEVERITY_WARNING,
             "Server STUN check did not complete"),
    "browser": ("fingerprint_unmeasured", SEVERITY_WARNING,
                "Browser fingerprint not collected"),
    "client_webrtc": ("webrtc_unmeasured", SEVERITY_WARNING,
                      "Browser WebRTC check did not complete"),
}


def analyze(layer1, layer2, geo=None, layer3=None):
    findings = []
    layer1 = layer1 or {}
    layer2 = layer2 or {}
    geo = geo or {}
    layer3 = layer3 or {}

    ip_data = layer1.get("ip") or {}
    dns_data = layer1.get("dns") or {}
    stun_data = layer1.get("stun") or {}
    client = layer1.get("client") or {}

    server_ip = ip_data.get("ipv4")
    server_v6 = ip_data.get("ipv6")
    client_ip = client.get("public_ip")
    client_v6 = client.get("public_ipv6")
    proxy_used = bool(layer1.get("proxy_used"))
    has_client = bool(client_ip)
    exit_ip = server_ip if proxy_used else (client_ip or server_ip)

    l2_source = layer2.get("source")
    harness_browser = l2_source == "server"
    server_subject = not proxy_used and not has_client

    resolver_ip = dns_data.get("resolver_seen_ip")
    mapped_ip = stun_data.get("mapped_ip")

    # ---- server-path leaks: only when the server IS the subject -----------
    if (
        server_subject
        and _measure_state(dns_data, "resolver_seen_ip") == "ok"
        and server_ip and resolver_ip and server_ip != resolver_ip
    ):
        findings.append(_finding(
            "dns_leak", SEVERITY_CRITICAL,
            "DNS resolver IP differs from public IP",
            "Public IP " + str(server_ip) + " but resolver seen as " + str(resolver_ip),
        ))

    if (
        server_subject
        and _measure_state(stun_data, "mapped_ip") == "ok"
        and server_ip and mapped_ip and server_ip != mapped_ip
    ):
        findings.append(_finding(
            "webrtc_leak", SEVERITY_CRITICAL,
            "STUN/WebRTC leak detected",
            "Public IP " + str(server_ip) + " but STUN sees " + str(mapped_ip),
        ))

    # ---- client-path WebRTC: the real browser leak test -------------------
    if has_client and client.get("webrtc_status") == "ok":
        cand = [c for c in (client.get("webrtc_ips") or []) if _is_ip(c)]
        outside = sorted({c for c in cand if _is_public_ip(c) and c != client_ip})
        lan = sorted({c for c in cand if not _is_public_ip(c)})
        if outside:
            findings.append(_finding(
                "webrtc_leak_client", SEVERITY_CRITICAL,
                "Browser WebRTC exposes an IP outside your tunnel",
                "Browser egress " + str(client_ip)
                + " but WebRTC candidates " + ", ".join(outside),
            ))
        if lan:
            findings.append(_finding(
                "webrtc_lan_exposed", SEVERITY_WARNING,
                "Browser WebRTC exposes local network addresses",
                "Candidates " + ", ".join(lan)
                + " -- enable mDNS candidate obfuscation in your browser",
            ))

    # ---- IPv6 -------------------------------------------------------------
    v6 = client_v6 if has_client else (server_v6 if server_subject else None)
    if v6:
        findings.append(_finding(
            "ipv6_exposed", SEVERITY_WARNING,
            "IPv6 address exposed",
            "IPv6 " + str(v6)
            + " leaked -- if VPN is IPv4-only, this bypasses the tunnel",
        ))

    # ---- timezone (meaningless for the server harness) --------------------
    compare_tz = not harness_browser and (
        l2_source != "client" or has_client or proxy_used
    )
    if layer2.get("status") == "ok" and geo.get("status") == "ok" and compare_tz:
        fp = layer2.get("fingerprint") or {}
        browser_tz = fp.get("timezone")
        ip_tz = geo.get("timezone")
        if browser_tz and ip_tz and browser_tz != ip_tz:
            findings.append(_finding(
                "timezone_mismatch", SEVERITY_WARNING,
                "Browser timezone differs from IP location",
                "IP in " + str(geo.get("country")) + " (" + str(ip_tz)
                + ") but browser timezone is " + str(browser_tz),
            ))

    # ---- automation flag (always true in headless Chromium) ---------------
    if layer2.get("status") == "ok" and not harness_browser:
        fp = layer2.get("fingerprint") or {}
        if fp.get("webdriver"):
            findings.append(_finding(
                "webdriver_flag", SEVERITY_INFO,
                "Browser reports automation flag",
                "navigator.webdriver is true -- sites may classify this as a bot",
            ))

    # ---- Layer 3 ----------------------------------------------------------
    if layer3 and layer3.get("interfaces"):
        for iface in layer3.get("interfaces", []):
            if _is_pseudo_interface(iface):
                continue
            if iface.get("randomized") is False:
                findings.append(_finding(
                    "mac_permanent_" + str(iface.get("name")),
                    SEVERITY_WARNING,
                    "Interface " + str(iface.get("name")) + " uses a permanent MAC",
                    "MAC " + str(iface.get("mac"))
                    + " is not randomized -- trackable across networks",
                ))

    if layer3 and not layer3.get("vpn_interfaces"):
        findings.append(_finding(
            "no_vpn_interface", SEVERITY_INFO,
            "No VPN interface detected on host",
            "Expected a tun/wg/utun interface if a VPN is active",
        ))

    # ---- coverage (F3) ----------------------------------------------------
    net_applicable = not has_client
    checks = [
        ("ip", "ok" if exit_ip else "missing"),
        ("dns", _measure_state(dns_data, "resolver_seen_ip") if net_applicable else "n/a"),
        ("stun", _measure_state(stun_data, "mapped_ip") if net_applicable else "n/a"),
        ("browser", _measure_state(layer2, "fingerprint")),
        ("client_webrtc",
         ("ok" if client.get("webrtc_status") == "ok" else "missing") if has_client else "n/a"),
    ]

    detail_for = {
        "ip": ip_data.get("error") or client.get("error") or "no answer from IP providers",
        "dns": dns_data.get("error") or dns_data.get("reason") or "resolver not reachable",
        "stun": stun_data.get("error") or stun_data.get("reason") or "no STUN response",
        "browser": layer2.get("error") or layer2.get("reason") or "fingerprint unavailable",
        "client_webrtc": client.get("webrtc_error") or "ICE gathering failed or was blocked",
    }
    for name, state in checks:
        if state == "missing":
            fid, severity, title = MISSING_SPEC[name]
            findings.append(_finding(fid, severity, title, str(detail_for[name])))

    if geo.get("status") == "error":
        findings.append(_finding(
            "geo_unavailable", SEVERITY_INFO,
            "IP geolocation unavailable",
            geo.get("reason") or "all providers failed",
        ))

    # ---- score / verdict --------------------------------------------------
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHTS.get(f["severity"], 0)
    score = max(0, min(100, score))

    has_critical = any(f["severity"] == SEVERITY_CRITICAL for f in findings)
    has_warning = any(f["severity"] == SEVERITY_WARNING for f in findings)
    complete = all(s in ("ok", "n/a") for _, s in checks)

    if has_critical:
        verdict = VERDICT_FAIL
    elif not complete:
        verdict = VERDICT_INCONCLUSIVE
    elif has_warning:
        verdict = VERDICT_REVIEW
    else:
        verdict = VERDICT_PASS

    return {
        "findings": findings,
        "verdict": verdict,
        "score": score,
        "coverage": {
            "complete": complete,
            "measured": sum(1 for _, s in checks if s == "ok"),
            "applicable": sum(1 for _, s in checks if s != "n/a"),
            "checks": [{"name": n, "state": s} for n, s in checks],
        },
    }
