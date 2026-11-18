# Layer 1: network identity checks (IP, DNS, STUN).
import os
import socket
import struct

import httpx


def get_public_ip(proxy_url=None):
    # Fetch the public IPv4 and (attempt) IPv6 as seen by external services.
    result = {"ipv4": None, "ipv6": None, "error": None}
    client_kwargs = {"timeout": 10.0}
    if proxy_url:
        client_kwargs["proxy"] = proxy_url
    try:
        with httpx.Client(**client_kwargs) as client:
            r = client.get("https://api.ipify.org?format=json")
            r.raise_for_status()
            result["ipv4"] = r.json().get("ip")
    except Exception as exc:
        result["error"] = str(exc)
    try:
        v6_kwargs = {"timeout": 5.0}
        if proxy_url:
            v6_kwargs["proxy"] = proxy_url
        with httpx.Client(**v6_kwargs) as client:
            r = client.get("https://api6.ipify.org?format=json")
            r.raise_for_status()
            result["ipv6"] = r.json().get("ip")
    except Exception:
        pass
    return result


def check_dns():
    # Query whoami.akamai.net: its A record reflects the resolver's public IP.
    try:
        import dns.resolver
    except ImportError:
        return {"status": "skipped", "reason": "dnspython not installed"}
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve("whoami.akamai.net", "A", lifetime=5.0)
        return {"status": "ok", "resolver_seen_ip": str(answers[0])}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def check_stun(server="stun.l.google.com", port=19302, timeout=5.0):
    # Minimal STUN binding request (RFC 5389) via raw UDP.
    sock = None
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
    end = 20 + msg_len
    mapped_ip = None
    mapped_port = None
    while offset < end:
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
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
                ip = bytes([
                    xip[0] ^ 0x21, xip[1] ^ 0x12,
                    xip[2] ^ 0xA4, xip[3] ^ 0x42,
                ])
                mapped_ip = ".".join(str(b) for b in ip)
        offset += 4 + attr_len
        if attr_len % 4:
            offset += 4 - (attr_len % 4)

    if mapped_ip is None:
        return {"status": "error", "error": "no mapped address in STUN response"}
    return {"status": "ok", "mapped_ip": mapped_ip, "mapped_port": mapped_port}
