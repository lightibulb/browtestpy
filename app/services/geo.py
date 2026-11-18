# IP geolocation lookup with dual-provider fallback and TTL cache.
import time

import httpx

CACHE_TTL = 3600
CACHE_MAX_ENTRIES = 1024
_cache = {}  # ip -> (timestamp, result)


def _cached(ip):
    hit = _cache.get(ip)
    if hit and (time.time() - hit[0]) < CACHE_TTL:
        return hit[1]
    if hit:
        _cache.pop(ip, None)
    return None


def _store(ip, result):
    if len(_cache) >= CACHE_MAX_ENTRIES:
        try:
            oldest = min(_cache.items(), key=lambda kv: kv[1][0])
            _cache.pop(oldest[0], None)
        except (ValueError, StopIteration):
            pass
    _cache[ip] = (time.time(), result)


def _try_ipwhois(ip, timeout):
    # Primary provider: https://ipwho.is/ -- free, HTTPS, no key.
    with httpx.Client(timeout=timeout) as c:
        r = c.get("https://ipwho.is/" + ip)
        r.raise_for_status()
        data = r.json()
    if not data.get("success"):
        raise RuntimeError("ipwho.is reported failure")
    tz = (data.get("timezone") or {}).get("id")
    return {
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "city": data.get("city"),
        "timezone": tz,
        "isp": (data.get("connection") or {}).get("isp"),
        "source": "ipwho.is",
    }


def _try_ipapi(ip, timeout):
    # Fallback: https://ipapi.co/ -- free, HTTPS, no key.
    with httpx.Client(timeout=timeout) as c:
        r = c.get("https://ipapi.co/" + ip + "/json/")
        r.raise_for_status()
        data = r.json()
    if data.get("error"):
        raise RuntimeError("ipapi.co reported error")
    return {
        "country": data.get("country_name"),
        "country_code": data.get("country_code"),
        "city": data.get("city"),
        "timezone": data.get("timezone"),
        "isp": data.get("org"),
        "source": "ipapi.co",
    }


def lookup(ip, timeout=5.0):
    # Best-effort geolocation. Always returns a dict; never raises.
    if not ip:
        return {"status": "skipped", "reason": "no IP provided"}
    cached = _cached(ip)
    if cached is not None:
        return cached
    for fn in (_try_ipwhois, _try_ipapi):
        try:
            result = fn(ip, timeout)
            result["status"] = "ok"
            _store(ip, result)
            return result
        except Exception:
            continue
    # Do NOT cache failures — let the next request retry.
    return {"status": "error", "reason": "all providers failed"}
