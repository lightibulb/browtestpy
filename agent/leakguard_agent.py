#!/usr/bin/env python3
# leakguard_agent.py -- Layer 3 local collector.
# Runs on Linux, Termux, macOS, Windows. Stdlib only.
#
# Usage:
#   python leakguard_agent.py                     # print report locally
#   python leakguard_agent.py --json              # print raw JSON
#   python leakguard_agent.py --report URL        # POST to server
#   python leakguard_agent.py --report URL --attach SCAN_ID
#
import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import uuid


def _run(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=5)
        return out
    except Exception:
        return None


def _looks_like_ip(text):
    if not text:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
        return True
    if ":" in text and re.match(r"^[0-9a-fA-F:]+$", text):
        return True
    return False


def _parse_windows_dns(out):
    # ipconfig /all lists one "DNS Servers" header (English) or a localized
    # equivalent, followed by indented continuation IPs.
    resolvers = []
    in_dns = False
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped:
            in_dns = False
            continue
        if ":" in line:
            _, _, tail = line.rpartition(":")
            tail = tail.strip()
            if _looks_like_ip(tail):
                if in_dns or "DNS" in line.upper():
                    resolvers.append(tail)
                    in_dns = True
                    continue
            if in_dns and _looks_like_ip(stripped):
                resolvers.append(stripped)
                continue
            in_dns = False
            continue
        if in_dns and _looks_like_ip(stripped):
            resolvers.append(stripped)
    return resolvers


def is_randomized_mac(mac):
    # Locally-administered bit is bit 1 of first octet.
    # In hex, that is the 2nd character being 2, 6, A, or E.
    if not mac or len(mac) < 2:
        return None
    try:
        return mac[1].upper() in {"2", "6", "A", "E"}
    except Exception:
        return None


def is_pseudo_interface(iface):
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


def parse_linux_ip_link(text):
    interfaces = []
    if not text:
        return interfaces
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name = parts[1].strip()
        m = re.search(r"link/(\w+)\s+([0-9a-fA-F:]{17})", line)
        if m:
            mac = m.group(2).lower()
            interfaces.append({
                "name": name,
                "mac": mac,
                "randomized": is_randomized_mac(mac),
            })
    return interfaces


def parse_darwin_ifconfig(text):
    interfaces = []
    if not text:
        return interfaces
    current = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t")) and ":" in line:
            current = line.split(":")[0]
            continue
        m = re.search(r"ether\s+([0-9a-fA-F:]{17})", line)
        if m and current:
            mac = m.group(1).lower()
            interfaces.append({
                "name": current,
                "mac": mac,
                "randomized": is_randomized_mac(mac),
            })
    return interfaces


def parse_windows_getmac(text):
    interfaces = []
    if not text:
        return interfaces
    for line in text.splitlines():
        parts = [p.strip().strip('"') for p in line.strip().split('","')]
        if len(parts) >= 3:
            name = parts[0].strip('"')
            mac_raw = parts[2].strip('"')
            mac_norm = mac_raw.replace("-", ":").lower()
            if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac_norm):
                interfaces.append({
                    "name": name,
                    "mac": mac_norm,
                    "randomized": is_randomized_mac(mac_norm),
                })
    return interfaces


def collect_interfaces():
    system = platform.system()
    if system == "Linux":
        out = _run(["ip", "-o", "link", "show"])
        return parse_linux_ip_link(out or "")
    if system == "Darwin":
        out = _run(["ifconfig"])
        return parse_darwin_ifconfig(out or "")
    if system == "Windows":
        out = _run(["getmac", "/v", "/fo", "csv", "/nh"])
        return parse_windows_getmac(out or "")
    return []


def collect_vpn_interfaces(interfaces):
    vpn = []
    for i in interfaces:
        name = i.get("name", "").lower()
        if name.startswith(("tun", "tap", "wg", "utun", "ppp", "ipsec")):
            vpn.append(i["name"])
    return vpn


def collect_dns_resolvers():
    system = platform.system()
    resolvers = []
    if system in ("Linux", "Darwin"):
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            resolvers.append(parts[1])
        except Exception:
            pass
    elif system == "Windows":
        out = _run(["ipconfig", "/all"])
        if out:
            resolvers.extend(_parse_windows_dns(out))
    return resolvers


def build_report():
    interfaces = collect_interfaces()
    report = {
        "agent_id": str(uuid.uuid4()),
        "platform": platform.system(),
        "platform_version": platform.version(),
        "hostname": socket.gethostname(),
        "interfaces": interfaces,
        "vpn_interfaces": collect_vpn_interfaces(interfaces),
        "dns_resolvers": collect_dns_resolvers(),
        "checks": [],
    }

    for iface in interfaces:
        if is_pseudo_interface(iface):
            continue
        if iface.get("randomized") is False:
            report["checks"].append({
                "id": "mac_permanent_" + iface["name"],
                "severity": "warning",
                "title": iface["name"] + " uses a permanent MAC",
                "detail": iface["mac"],
            })

    if not report["vpn_interfaces"]:
        report["checks"].append({
            "id": "no_vpn_interface",
            "severity": "info",
            "title": "No VPN interface detected",
            "detail": "Expected tun/wg/utun if a VPN is active",
        })

    if not interfaces:
        report["checks"].append({
            "id": "no_interfaces_collected",
            "severity": "warning",
            "title": "Could not enumerate network interfaces",
            "detail": "Required commands may be missing or unavailable",
        })

    return report


def submit(report, url, attach_id=None):
    if attach_id:
        report = dict(report)
        report["scan_id"] = attach_id
    body = json.dumps(report).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/api/v1/agent",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data
    except urllib.error.URLError as exc:
        print("ERROR: could not submit report: " + str(exc), file=sys.stderr)
        return None


def print_pretty(report):
    print("LeakGuard agent report")
    print("=" * 40)
    print("platform         : " + str(report.get("platform")) + " " + str(report.get("platform_version")))
    print("hostname         : " + str(report.get("hostname")))
    print("vpn interfaces   : " + (", ".join(report.get("vpn_interfaces", [])) or "none"))
    print("dns resolvers    : " + (", ".join(report.get("dns_resolvers", [])) or "n/a"))
    print()
    ifs = report.get("interfaces", [])
    if ifs:
        print("interfaces")
        for i in ifs:
            state = "randomized" if i.get("randomized") else "permanent"
            print("  " + i["name"].ljust(12) + " " + i["mac"] + "  (" + state + ")")
        print()
    checks = report.get("checks", [])
    if checks:
        print("findings")
        for c in checks:
            print("  [" + c["severity"].upper() + "] " + c["title"])
            print("      " + c["detail"])
    else:
        print("findings         : none")


def main():
    ap = argparse.ArgumentParser(description="LeakGuard local agent (Layer 3).")
    ap.add_argument("--report", metavar="URL", help="POST report to a LeakGuard server")
    ap.add_argument("--attach", metavar="SCAN_ID", help="attach to an existing web scan id")
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    args = ap.parse_args()

    report = build_report()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_pretty(report)

    if args.report:
        result = submit(report, args.report, args.attach)
        if result and result.get("scan_id"):
            print()
            print("Submitted. scan_id: " + result["scan_id"])
            print("View: " + args.report.rstrip("/") + "/api/v1/agent/" + result["scan_id"])
            if args.attach:
                print("Merged: " + args.report.rstrip("/") + " -> scan " + args.attach)


if __name__ == "__main__":
    main()
