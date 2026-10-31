"""Normalisation, deduplication, redaction and risk scoring."""
from securematrix_worker import risk
from securematrix_worker.findings import (
    deduplicate, map_severity, parse_cwes, parse_owasp, parse_semgrep_results, redact,
)


def semgrep_result(rule, path, line, cwe, severity="ERROR", confidence="HIGH"):
    return {"check_id": rule, "path": path, "start": {"line": line}, "end": {"line": line},
            "extra": {"severity": severity, "message": f"{rule} message",
                      "metadata": {"cwe": [f"{cwe}: Something"], "owasp": ["A03:2021 - Injection", "A01:2017 - Injection"],
                                   "confidence": confidence}}}


def write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_parse_cwe_and_owasp():
    meta = {"cwe": ["CWE-89: SQL Injection", "CWE-89: dup", "CWE-564"], "owasp": ["A03:2021 - Injection", "A1:2017 - x"]}
    assert parse_cwes(meta) == ["CWE-89", "CWE-564"]
    assert parse_owasp(meta) == ["A03:2021-Injection"]


def test_severity_mapping():
    assert map_severity("ERROR", {"impact": "HIGH", "likelihood": "HIGH"}) == "critical"
    assert map_severity("ERROR", {}) == "high"
    assert map_severity("WARNING", {}) == "medium"
    assert map_severity("INFO", {}) == "low"
    assert map_severity("WARNING", {"securematrix_severity": "critical"}) == "critical"


def test_redaction_masks_common_secrets():
    text = '\n'.join([
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        'password = "hunter2hunter2"',
        'url = "postgres://admin:SuperSecret@db:5432/x"',
        'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"',
        '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----',
    ])
    out = redact(text)
    for secret in ["IOSFODNN7EXAMPLE", "hunter2hunter2", "SuperSecret", "dozjgNryP4J3", "MIIEow"]:
        assert secret not in out
    assert "AKIA" in out  # the prefix stays so the finding remains recognisable


def test_deduplicates_same_line_same_cwe_across_rules(tmp_path):
    write(tmp_path, "app.py", "a = 1\ncur.execute(f\"SELECT {x}\")\n")
    hits = parse_semgrep_results([
        semgrep_result("securematrix.sm-python-sql", "app.py", 2, "CWE-89"),
        semgrep_result("python.lang.security.sqli", "app.py", 2, "CWE-89", severity="WARNING"),
        semgrep_result("python.lang.security.other", "app.py", 2, "CWE-95"),
    ], tmp_path)
    findings = deduplicate(hits, {"app.py": "python"})
    assert len(findings) == 2
    sqli = next(f for f in findings if f.cwes == ["CWE-89"])
    assert sqli.rule_ids == ["python.lang.security.sqli", "securematrix.sm-python-sql"]
    assert sqli.severity == "high"  # the most severe hit wins
    assert "cur.execute" in sqli.snippet


def test_fingerprint_survives_line_shifts(tmp_path):
    write(tmp_path, "a.py", "cur.execute(f\"SELECT {x}\")\n")
    before = deduplicate(parse_semgrep_results([semgrep_result("r", "a.py", 1, "CWE-89")], tmp_path), {})
    write(tmp_path, "a.py", "import os\n\n\ncur.execute(f\"SELECT {x}\")\n")
    after = deduplicate(parse_semgrep_results([semgrep_result("r", "a.py", 4, "CWE-89")], tmp_path), {})
    assert before[0].fingerprint == after[0].fingerprint


def test_identical_lines_get_distinct_fingerprints(tmp_path):
    write(tmp_path, "a.py", "os.system(cmd)\nos.system(cmd)\n")
    hits = parse_semgrep_results([semgrep_result("r", "a.py", 1, "CWE-78"), semgrep_result("r", "a.py", 2, "CWE-78")], tmp_path)
    fps = {f.fingerprint for f in deduplicate(hits, {})}
    assert len(fps) == 2


def test_snippet_is_redacted(tmp_path):
    write(tmp_path, "c.py", 'API_KEY = "sk_live_abcdefghijklmnop123"\n')
    hits = parse_semgrep_results([semgrep_result("r", "c.py", 1, "CWE-798")], tmp_path)
    assert "abcdefghijklmnop123" not in hits[0].snippet


def test_risk_score_is_explained_and_bounded():
    value, priority, rationale = risk.score("critical", "high", ["CWE-89"], "src/routes/users.py")
    assert value == 95.0 and priority == "P1"
    assert [f["name"] for f in rationale["factors"]] == ["severity", "exploitability", "exposure", "confidence"]
    assert "not an official CVSS" in rationale["note"]
    test_value, _, _ = risk.score("critical", "high", ["CWE-89"], "tests/test_users.py")
    assert test_value < value
    low, p, _ = risk.score("info", "low", [], "lib/util.py")
    assert 0 <= low < 15 and p == "P4"
