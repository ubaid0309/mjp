"""Runs the bundled Semgrep rules against the demo project and checks what they detect.

Skipped automatically when Semgrep is not installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from securematrix_worker.config import BUNDLED_RULES_DIR, settings

DEMO = Path(__file__).resolve().parents[2] / "demo" / "bytemart-vulnerable"
pytestmark = pytest.mark.skipif(not shutil.which(settings.semgrep_bin), reason="semgrep not installed")


@pytest.fixture(scope="module")
def results():
    targets = [str(p.relative_to(DEMO)) for p in DEMO.rglob("*") if p.is_file() and "node_modules" not in p.parts]
    (DEMO / ".semgrepignore").write_text("# test\n")
    try:
        out = subprocess.run([settings.semgrep_bin, "scan", "--json", "--metrics=off", "--no-git-ignore",
                              "--config", str(BUNDLED_RULES_DIR), *targets], cwd=DEMO, capture_output=True, text=True, timeout=300)
    finally:
        (DEMO / ".semgrepignore").unlink()
    data = json.loads(out.stdout)
    assert not data["errors"], data["errors"]
    return {(r["path"], r["start"]["line"], r["check_id"].split(".")[-1]) for r in data["results"]}


@pytest.mark.parametrize("path,line,rule", [
    ("shop/app.py", 27, "sm-python-sql-string-build"),
    ("shop/app.py", 38, "sm-python-sql-string-build"),
    ("shop/app.py", 48, "sm-python-xss-template-string"),
    ("shop/app.py", 54, "sm-python-command-injection"),
    ("shop/app.py", 62, "sm-python-path-traversal"),
    ("shop/app.py", 68, "sm-python-ssrf"),
    ("shop/app.py", 74, "sm-python-unrestricted-upload"),
    ("shop/app.py", 81, "sm-python-client-controlled-authorization"),
    ("shop/config.py", 6, "sm-secret-aws-access-key"),
    ("shop/security.py", 12, "sm-python-weak-password-hash"),
    ("shop/security.py", 21, "sm-python-weak-cipher"),
    ("api/server.js", 18, "sm-js-sql-string-build"),
    ("api/server.js", 29, "sm-js-command-injection"),
    ("api/server.js", 14, "sm-js-permissive-cors"),
    ("api/public/app.js", 6, "sm-js-dom-xss"),
    ("legacy/profile.php", 9, "sm-php-reflected-xss"),
    ("legacy/profile.php", 14, "sm-php-unrestricted-upload"),
    ("reports/src/main/java/com/bytemart/reports/ReportService.java", 19, "sm-java-sql-string-build"),
    (".env", 2, "sm-config-debug-enabled"),
])
def test_demo_vulnerability_detected(results, path, line, rule):
    assert (path, line, rule) in results


def test_no_false_positive_on_parameterized_query(results):
    # shop/app.py:92 uses a bound parameter and must not be reported as SQL injection
    assert not any(p == "shop/app.py" and l == 92 for p, l, _ in results)
