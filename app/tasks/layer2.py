# Layer 2: browser fingerprint collection via Playwright.
# Skips gracefully if the playwright module or browsers are unavailable.

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# Built with explicit concatenation to avoid quote issues in generated files.
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


def collect_fingerprint(proxy_url=None):
    if not PLAYWRIGHT_AVAILABLE:
        return {"status": "skipped", "reason": "playwright module not installed"}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            ctx_opts = {}
            if proxy_url:
                ctx_opts["proxy"] = {"server": proxy_url}
            context = browser.new_context(**ctx_opts)
            page = context.new_page()
            page.goto("about:blank")
            fp = page.evaluate(FINGERPRINT_JS)
            browser.close()
            return {"status": "ok", "fingerprint": fp}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
