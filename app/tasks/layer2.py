# Layer 2: browser fingerprint collection via Playwright (SERVER fallback).
#
# F2: results are tagged source="server" so the analyzer does not report the
#     harness's own webdriver flag / container timezone as user leaks.
# F4: socks5h is normalised and proxy credentials are split out for Chromium.
# F6: launch args trimmed for small (512 MB) workers.
from __future__ import annotations

from urllib.parse import unquote, urlparse

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

FINGERPRINT_JS = (
    "() => { "
    "const c = document.createElement('canvas'); "
    "const ctx = c.getContext('2d'); "
    "ctx.textBaseline = 'top'; "
    "ctx.font = '14px Arial'; "
    "ctx.fillStyle = '#f60'; "
    "ctx.fillRect(0, 0, 100, 20); "
    "ctx.fillStyle = '#069'; "
    "ctx.fillText('fingerprint', 2, 2); "
    "const canvasHash = c.toDataURL().slice(-50); "
    "const glCanvas = document.createElement('canvas'); "
    "const gl = glCanvas.getContext('webgl'); "
    "let webglInfo = null; "
    "if (gl) { "
    "  const dbg = gl.getExtension('WEBGL_debug_renderer_info'); "
    "  if (dbg) { "
    "    webglInfo = { "
    "      vendor: gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL), "
    "      renderer: gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) "
    "    }; "
    "  } "
    "} "
    "return { "
    "  userAgent: navigator.userAgent, "
    "  language: navigator.language, "
    "  languages: navigator.languages, "
    "  platform: navigator.platform, "
    "  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, "
    "  screenWidth: screen.width, "
    "  screenHeight: screen.height, "
    "  colorDepth: screen.colorDepth, "
    "  hardwareConcurrency: navigator.hardwareConcurrency, "
    "  deviceMemory: navigator.deviceMemory, "
    "  webdriver: navigator.webdriver, "
    "  canvasHash: canvasHash, "
    "  webgl: webglInfo "
    "}; "
    "}"
)

LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--mute-audio",
    "--renderer-process-limit=2",
    "--js-flags=--max-old-space-size=192",
]


def split_proxy(proxy_url):
    """Return (playwright_proxy_dict, error_message)."""
    if not proxy_url:
        return None, None
    p = urlparse(proxy_url)
    scheme = (p.scheme or "").lower()
    if scheme == "socks5h":
        scheme = "socks5"  # Chromium does not understand socks5h
    if scheme not in ("http", "https", "socks5"):
        return None, "unsupported proxy scheme for Chromium: " + scheme
    if not p.hostname:
        return None, "proxy URL has no host"
    if scheme == "socks5" and (p.username or p.password):
        return None, (
            "Chromium cannot authenticate to SOCKS5 proxies; use an HTTP proxy "
            "or an unauthenticated local SOCKS5 listener"
        )
    server = scheme + "://" + p.hostname
    if p.port:
        server += ":" + str(p.port)
    out = {"server": server}
    if p.username:
        out["username"] = unquote(p.username)
    if p.password:
        out["password"] = unquote(p.password)
    return out, None


def collect_fingerprint(proxy_url=None):
    if not PLAYWRIGHT_AVAILABLE:
        return {"status": "skipped", "source": "server",
                "reason": "playwright module not installed"}

    proxy, proxy_err = split_proxy(proxy_url)
    if proxy_err:
        return {"status": "error", "source": "server", "error": proxy_err}

    browser = None
    context = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=LAUNCH_ARGS)
            ctx_opts = {}
            if proxy:
                ctx_opts["proxy"] = proxy
            context = browser.new_context(**ctx_opts)
            page = context.new_page()
            page.set_default_timeout(15000)
            page.goto("about:blank")
            fp = page.evaluate(FINGERPRINT_JS)
            return {"status": "ok", "source": "server", "fingerprint": fp}
    except Exception as exc:
        msg = str(exc)
        if "Executable doesn't exist" in msg or "playwright install" in msg:
            return {"status": "skipped", "source": "server",
                    "reason": "Playwright browsers not installed (playwright install chromium)"}
        return {"status": "error", "source": "server", "error": msg}
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
