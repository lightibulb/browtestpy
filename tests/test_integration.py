# Integration tests: real network calls. Opt in with RUN_INTEGRATION=1.
import os
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION") != "1",
    reason="set RUN_INTEGRATION=1 to enable",
)


def test_real_public_ip():
    from app.tasks.layer1 import get_public_ip
    result = get_public_ip()
    assert result["ipv4"] is not None, "no public IP returned: " + str(result)


def test_real_dns():
    from app.tasks.layer1 import check_dns
    result = check_dns()
    assert result["status"] in ("ok", "error", "skipped")
