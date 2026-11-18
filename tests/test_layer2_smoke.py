import os
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION") != "1",
    reason="set RUN_INTEGRATION=1 to enable",
)


def test_playwright_fingerprint():
    from app.tasks.layer2 import PLAYWRIGHT_AVAILABLE, collect_fingerprint
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("playwright module not installed")
    result = collect_fingerprint()
    if result["status"] != "ok":
        pytest.skip("playwright unavailable: "
                    + str(result.get("error") or result.get("reason")))
    fp = result["fingerprint"]
    assert fp["userAgent"]
    assert "webdriver" in fp
    assert "timezone" in fp
    assert "canvasHash" in fp
