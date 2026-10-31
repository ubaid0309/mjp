"""Turn raw Semgrep results into deduplicated, redacted findings."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_ORDER = ["low", "medium", "high"]

# -- Secret redaction ----------------------------------------------------------
_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), r"\1****************"),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[0-9A-Za-z]{8,}"), r"\1_\2_****"),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}"), "gh*_****"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "xox*-****"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), "AIza****"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "sk-****"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[REDACTED JWT]"),
    (re.compile(r"(://[^:/\s]+:)[^@/\s]{3,}(@)"), r"\1****\2"),
    # key = "value" style assignments for sensitive-looking names
    (re.compile(r"""(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)[\w-]*["']?\s*[:=]>?\s*["'])([^"'\n]{3,})(["'])"""),
     lambda m: m.group(1) + m.group(2)[:2] + "****" + m.group(3)),
]


def redact(text: str | None) -> str | None:
    if not text:
        return text
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


# -- Metadata parsing ---------------------------------------------------------
_CWE_RE = re.compile(r"CWE-(\d+)")


def parse_cwes(meta: dict) -> list[str]:
    raw = meta.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        for num in _CWE_RE.findall(str(item)):
            cwe = f"CWE-{num}"
            if cwe not in out:
                out.append(cwe)
    return out


def parse_owasp(meta: dict) -> list[str]:
    raw = meta.get("owasp") or []
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for item in raw:
        m = re.match(r"\s*(A\d{2}):(\d{4})\s*-\s*(.+)", str(item))
        if m and m.group(2) == "2021":
            val = f"{m.group(1)}:2021-{m.group(3).strip()}"
            if val not in out:
                out.append(val)
    return out


def map_severity(semgrep_severity: str, meta: dict) -> str:
    explicit = str(meta.get("securematrix_severity", "")).lower()
    if explicit in SEVERITY_ORDER:
        return explicit
    sev = (semgrep_severity or "").upper()
    impact = str(meta.get("impact", "")).upper()
    likelihood = str(meta.get("likelihood", "")).upper()
    if sev in ("CRITICAL",):
        return "critical"
    if sev in ("ERROR", "HIGH"):
        return "critical" if impact == "HIGH" and likelihood == "HIGH" else "high"
    if sev in ("WARNING", "MEDIUM"):
        return "high" if impact == "HIGH" and likelihood in ("HIGH", "MEDIUM") else "medium"
    if sev in ("INFO", "LOW"):
        return "low"
    return "info"


def map_confidence(meta: dict) -> str:
    c = str(meta.get("confidence", "")).lower()
    return c if c in CONFIDENCE_ORDER else "medium"


def humanize_rule(rule_id: str) -> str:
    last = rule_id.split(".")[-1]
    words = re.sub(r"[-_]+", " ", last).strip()
    return words[:1].upper() + words[1:] if words else rule_id


# -- Findings -----------------------------------------------------------------
@dataclass
class RawHit:
    rule_id: str
    path: str
    start_line: int
    end_line: int
    severity_raw: str
    message: str
    meta: dict
    cwes: list[str]
    owasp: list[str]
    severity: str
    confidence: str
    snippet: str
    line_text: str


@dataclass
class Finding:
    fingerprint: str
    path: str
    start_line: int
    end_line: int
    language: str | None
    rule_ids: list[str]
    cwes: list[str]
    owasp: list[str]
    severity: str
    confidence: str
    message: str
    snippet: str
    hits: list[RawHit] = field(default_factory=list)
    title: str = ""
    category: str | None = None
    risk_score: float | None = None
    risk_rationale: dict = field(default_factory=dict)
    priority: str | None = None


def read_snippet(base: Path, rel_path: str, start: int, end: int, context: int = 2) -> tuple[str, str]:
    """Return (redacted snippet with line numbers, the redacted first matched line)."""
    try:
        lines = (base / rel_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", ""
    lo = max(start - 1 - context, 0)
    hi = min(max(end, start) + context, len(lines), lo + 40)
    width = len(str(hi))
    body = "\n".join(f"{i + 1:>{width}} | {lines[i]}" for i in range(lo, hi))
    first = lines[start - 1] if 0 < start <= len(lines) else ""
    return redact(body) or "", redact(first.strip()) or ""


def parse_semgrep_results(results: list[dict], base: Path) -> list[RawHit]:
    hits = []
    for r in results:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        start = int(r.get("start", {}).get("line", 0))
        end = int(r.get("end", {}).get("line", start))
        snippet, first_line = read_snippet(base, r["path"], start, end)
        hits.append(RawHit(
            rule_id=r.get("check_id", "unknown"),
            path=r["path"],
            start_line=start,
            end_line=end,
            severity_raw=extra.get("severity", ""),
            message=redact(extra.get("message", "")) or "",
            meta=meta,
            cwes=parse_cwes(meta),
            owasp=parse_owasp(meta),
            severity=map_severity(extra.get("severity", ""), meta),
            confidence=map_confidence(meta),
            snippet=snippet,
            line_text=first_line,
        ))
    return hits


def _fingerprint(path: str, key: str, line_text: str, occurrence: int) -> str:
    normalized = re.sub(r"\s+", " ", line_text).strip()
    return hashlib.sha256(f"{path}|{key}|{normalized}|{occurrence}".encode()).hexdigest()[:40]


def deduplicate(hits: list[RawHit], languages: dict[str, str | None]) -> list[Finding]:
    """Merge hits that describe the same weakness at the same place.

    Two rules flagging the same line for the same CWE (e.g. a registry rule and a
    bundled rule) become one finding with both rule IDs. The fingerprint ignores the
    line number so a finding keeps its identity when code above it moves.
    """
    groups: dict[tuple, list[RawHit]] = {}
    for h in hits:
        key = (h.path, h.start_line, h.cwes[0] if h.cwes else h.rule_id)
        groups.setdefault(key, []).append(h)

    findings: list[Finding] = []
    occurrences: dict[tuple, int] = {}
    for (path, line, weakness), group in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
        primary = max(group, key=lambda h: (SEVERITY_ORDER.index(h.severity), CONFIDENCE_ORDER.index(h.confidence)))
        occ_key = (path, weakness, re.sub(r"\s+", " ", primary.line_text))
        occurrences[occ_key] = occurrences.get(occ_key, 0) + 1
        cwes = list(dict.fromkeys(c for h in group for c in h.cwes))
        owasp = list(dict.fromkeys(o for h in group for o in h.owasp))
        findings.append(Finding(
            fingerprint=_fingerprint(path, weakness, primary.line_text, occurrences[occ_key]),
            path=path,
            start_line=line,
            end_line=max(h.end_line for h in group),
            language=languages.get(path),
            rule_ids=sorted({h.rule_id for h in group}),
            cwes=cwes,
            owasp=owasp,
            severity=primary.severity,
            confidence=max((h.confidence for h in group), key=CONFIDENCE_ORDER.index),
            message=primary.message,
            snippet=primary.snippet,
            hits=group,
        ))
    return findings
