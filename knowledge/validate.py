"""Validate knowledge-base entry files against knowledge/SCHEMA.md.

Usage: python3 knowledge/validate.py [files...]   (defaults to knowledge/entries/*.json)
Exits non-zero on any error so it can run in CI.
"""
import json
import re
import sys
from pathlib import Path

CATEGORIES = {
    "Injection", "Cross-Site Scripting", "Access Control", "Authentication",
    "Session Management", "Cryptography", "Secrets & Credentials", "Input Validation",
    "File Handling", "Deserialization", "Server-Side Request Forgery", "XML Processing",
    "Memory Safety", "Concurrency", "Resource Management & DoS", "Security Misconfiguration",
    "Logging & Monitoring", "Information Exposure", "Error Handling", "Supply Chain",
    "Web Security", "Business Logic", "AI/LLM Security",
}
OWASP_2021 = {
    "A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures", "A03:2021-Injection",
    "A04:2021-Insecure Design", "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures", "A10:2021-Server-Side Request Forgery",
}
OWASP_API_2023 = {
    "API1:2023-Broken Object Level Authorization", "API2:2023-Broken Authentication",
    "API3:2023-Broken Object Property Level Authorization",
    "API4:2023-Unrestricted Resource Consumption", "API5:2023-Broken Function Level Authorization",
    "API6:2023-Unrestricted Access to Sensitive Business Flows",
    "API7:2023-Server Side Request Forgery", "API8:2023-Security Misconfiguration",
    "API9:2023-Improper Inventory Management", "API10:2023-Unsafe Consumption of APIs",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
LIST_FIELDS = ["prerequisites", "impact", "detection_patterns", "remediation"]
STR_FIELDS = ["slug", "cwe_id", "title", "cwe_name", "category", "severity_default", "description"]


def validate_entry(e: dict, where: str) -> list[str]:
    errs = []
    for f in STR_FIELDS:
        if not isinstance(e.get(f), str) or not e[f].strip():
            errs.append(f"{where}: missing/empty string field '{f}'")
    if errs:
        return errs
    if not re.fullmatch(r"CWE-\d+", e["cwe_id"]):
        errs.append(f"{where}: bad cwe_id {e['cwe_id']!r}")
    num = e["cwe_id"].split("-")[1]
    if not re.fullmatch(rf"cwe-{num}-[a-z0-9]+(-[a-z0-9]+)*", e["slug"]):
        errs.append(f"{where}: slug {e['slug']!r} must look like cwe-{num}-short-name")
    if e["category"] not in CATEGORIES:
        errs.append(f"{where}: unknown category {e['category']!r}")
    if e["severity_default"] not in SEVERITIES:
        errs.append(f"{where}: bad severity {e['severity_default']!r}")
    for v in e.get("owasp_top10_2021", []):
        if v not in OWASP_2021:
            errs.append(f"{where}: bad OWASP 2021 value {v!r}")
    for v in e.get("owasp_api_2023", []):
        if v not in OWASP_API_2023:
            errs.append(f"{where}: bad OWASP API value {v!r}")
    for f in LIST_FIELDS:
        v = e.get(f)
        if not isinstance(v, list) or len(v) < 2 or not all(isinstance(x, str) and x.strip() for x in v):
            errs.append(f"{where}: '{f}' needs at least 2 non-empty strings")
    for f in ["vulnerable_example", "secure_example"]:
        v = e.get(f)
        if not isinstance(v, dict) or not v.get("language") or not v.get("code"):
            errs.append(f"{where}: '{f}' needs language and code")
    if not isinstance(e.get("languages"), list) or not e["languages"]:
        errs.append(f"{where}: 'languages' must be a non-empty list")
    for c in e.get("cve_examples", []):
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", c.get("id", "")):
            errs.append(f"{where}: bad CVE id {c!r}")
    refs = e.get("references")
    if not isinstance(refs, list) or not refs:
        errs.append(f"{where}: references required")
    else:
        cwe_url = f"https://cwe.mitre.org/data/definitions/{num}.html"
        if not any(r.get("url") == cwe_url for r in refs):
            errs.append(f"{where}: references must include {cwe_url}")
        for r in refs:
            if not str(r.get("url", "")).startswith("https://") or not r.get("title"):
                errs.append(f"{where}: bad reference {r!r}")
    return errs


def main(paths: list[str]) -> int:
    files = [Path(p) for p in paths] or sorted(Path(__file__).parent.joinpath("entries").glob("*.json"))
    errors, seen_cwe, seen_slug, total = [], {}, {}, 0
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path}: invalid JSON: {exc}")
            continue
        if not isinstance(data, list):
            errors.append(f"{path}: top level must be a JSON array")
            continue
        for i, e in enumerate(data):
            where = f"{path.name}[{i}] {e.get('cwe_id', '?')}"
            errors += validate_entry(e, where)
            total += 1
            for key, seen in (("cwe_id", seen_cwe), ("slug", seen_slug)):
                val = e.get(key)
                if val in seen:
                    errors.append(f"{where}: duplicate {key} {val} (also in {seen[val]})")
                seen[val] = where
    for err in errors:
        print("ERROR", err)
    print(f"{total} entries, {len(seen_cwe)} unique CWE IDs, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
