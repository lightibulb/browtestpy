# Layer 1: network identity checks (IP, DNS, STUN).
#
# F4: SOCKS proxies need httpx[socks]; the error is now explained, not swallowed.
# F5: DNS and raw-UDP STUN cannot traverse a proxy from the server. When a proxy
#     is supplied they report 'skipped' instead of measuring the wrong machine.
from __future__ import annotations

import os
import socket
import struct
from ipaddress import ip_address

import httpx

IPV4_ECHO = "https://api.ipify.org?format=json"
IPV6_ECHO = "https://api6.ipify.org?format=json"

PROXY_SKIP_REASON = (
    "Not measurable through a proxy from the server: this would measure the "
    "host, not your tunnel. Use the browser-side WebRTC check or the local agent."
)


def _valid_ip(value, version=None):
    try:
        addr = ip_address(str(value))
    except (ValueError, TypeError):
        return None
    if version is not None and addr.version != version:
        return None
    return str(addr)


def _explain(exc):
    msg = str(exc) or exc.__class__.__name__
    if "socksio" in msg.lower():
        msg += " -- install httpx[socks] to use SOCKS proxies"
    return msg


def get_public_ip(proxy_url=None):
    result = {"ipv4": None, "ipv6": None, "error": None, "proxy_used": bool(proxy_url)}

    kwargs = {"timeout": 10.0, "follow_redirects": True}
    if proxy_url:
        kwargs["proxy"] = proxy_url
    try:
        with httpx.Client(**kwargs) as client:
            r = client.get(IPV4_ECHO)
            r.raise_for_status()
            result["ipv4"] = _valid_ip(r.json().get("ip"), 4)
            if result["ipv4"] is None:
                result["error"] = "IP provider returned an invalid IPv4 address"
    except Exception as exc:
        result["error"] = _explain(exc)

    v6_kwargs = {"timeout": 5.0, "follow_redirects": True}
    if proxy_url:
        v6_kwargs["proxy"] = proxy_url
    try:
        with httpx.Client(**v6_kwargs) as client:
            r = client.get(IPV6_ECHO)
            r.raise_for_status()
            result["ipv6"] = _valid_ip(r.json().get("ip"), 6)
    except Exception:
        pass

    return result


def check_dns(proxy_url=None):
    if proxy_url:
        return {"status": "skipped", "proxy_aware": False, "reason": PROXY_SKIP_REASON}
    try:
        import dns.resolver
    except ImportError:
        return {"status": "skipped", "reason": "dnspython not installed"}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        answers = resolver.resolve("whoami.akamai.net", "A", lifetime=5.0)
        ip = _valid_ip(str(answers[0]), 4)
        if not ip:
            return {"status": "error", "error": "resolver returned a non-IPv4 answer"}
        return {"status": "ok", "resolver_seen_ip": ip, "proxy_aware": False}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def check_stun(server="stun.l.google.com", port=19302, timeout=5.0, proxy_url=None):
    if proxy_url:
        return {"status": "skipped", "proxy_aware": False, "reason": PROXY_SKIP_REASON}

    sock = None
    data = b""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        txn_id = os.urandom(12)
        msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn_id
        sock.sendto(msg, (server, port))
        data, _ = sock.recvfrom(2048)
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        if sock is not None:
            sock.close()

    if len(data) < 20:
        return {"status": "error", "error": "STUN response too short"}

    msg_type, msg_len, _ = struct.unpack("!HHI", data[:8])
    if msg_type != 0x0101:
        return {"status": "error", "error": "unexpected STUN message type"}

    offset = 20
    end = min(20 + msg_len, len(data))
    mapped_ip = None
    mapped_port = None

    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        if offset + 4 + attr_len > len(data):
            break
        attr_val = data[offset + 4:offset + 4 + attr_len]

        if attr_type == 0x0001 and attr_len >= 8:
            family = attr_val[1]
            mapped_port = struct.unpack("!H", attr_val[2:4])[0]
            if family == 0x01:
                mapped_ip = ".".join(str(b) for b in attr_val[4:8])

        if attr_type == 0x0020 and attr_len >= 8:
            family = attr_val[1]
            xport = struct.unpack("!H", attr_val[2:4])[0]
            mapped_port = xport ^ 0x2112
            if family == 0x01:
                xip = attr_val[4:8]
                mapped_ip = ".".join(str(b) for b in (
                    xip[0] ^ 0x21, xip[1] ^ 0x12, xip[2] ^ 0xA4, xip[3] ^ 0x42,
                ))

        offset += 4 + attr_len
        if attr_len % 4:
            offset += 4 - (attr_len % 4)

    if mapped_ip is None:
        return {"status": "error", "error": "no mapped address in STUN response"}
    return {"status": "ok", "mapped_ip": mapped_ip, "mapped_port": mapped_port}
