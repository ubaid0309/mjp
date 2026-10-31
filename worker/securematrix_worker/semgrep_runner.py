"""Runs Semgrep CE on batches of files and reports exactly which rule sets were used."""
from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import BUNDLED_RULES_DIR, settings

log = logging.getLogger("securematrix.semgrep")


class ScannerUnavailable(RuntimeError):
    pass


@dataclass
class RuleSource:
    name: str
    path: Path | None
    status: str  # loaded | unavailable
    detail: str = ""


def semgrep_version() -> str | None:
    try:
        out = subprocess.run([settings.semgrep_bin, "--version"], capture_output=True, text=True, timeout=60,
                             env=_env())
        return out.stdout.strip().splitlines()[-1] if out.returncode == 0 and out.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _env() -> dict:
    env = dict(os.environ)
    env.update({"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
    return env


def prepare_rule_sources(rulesets: list[str], work: Path) -> list[RuleSource]:
    """Resolve bundled rules locally and download registry packs once per scan.
    A pack that cannot be downloaded is reported as unavailable, never silently dropped."""
    sources = []
    for name in rulesets:
        if name == "securematrix":
            count = len(list(BUNDLED_RULES_DIR.glob("*.y*ml")))
            sources.append(RuleSource(name, BUNDLED_RULES_DIR, "loaded", f"{count} bundled rule files"))
            continue
        target = work / f"rules-{name.replace('/', '_')}.yaml"
        try:
            r = httpx.get(f"{settings.semgrep_registry_url}/{name}", timeout=60, follow_redirects=True)
            # The registry answers with YAML or JSON depending on the client; Semgrep accepts both.
            if r.status_code != 200 or (b"rules:" not in r.content[:200] and b'"rules"' not in r.content[:200]):
                raise RuntimeError(f"HTTP {r.status_code}")
            target.write_bytes(r.content)
            sources.append(RuleSource(name, target, "loaded", f"downloaded from {settings.semgrep_registry_url}"))
        except Exception as exc:  # noqa: BLE001
            sources.append(RuleSource(name, None, "unavailable", f"could not download registry pack: {exc}"))
    return sources


def _rule_prefix(path: Path) -> str:
    base = path if path.is_dir() else path.parent
    return str(base.resolve()).strip("/\\").replace("/", ".").replace("\\", ".") + "."


def run_batch(root: Path, files: list[str], sources: list[RuleSource], max_target_bytes: int,
              timeout_s: int) -> tuple[list[dict], list[dict]]:
    """Run Semgrep over `files` (paths relative to root). Returns (results, errors)."""
    configs = [arg for s in sources if s.path for arg in ("--config", str(s.path))]
    # Without a .semgrepignore Semgrep applies built-in defaults that skip tests/ and similar folders.
    # SecureMatrix already excluded dependencies and build output, so scan everything it hands over.
    ignore = root / ".semgrepignore"
    if not ignore.exists():
        ignore.write_text("# SecureMatrix applies its own exclusions\n")
    if not configs:
        raise ScannerUnavailable("no rule sets could be loaded")
    cmd = [settings.semgrep_bin, "scan", "--json", "--metrics=off", "--disable-version-check",
           "--no-git-ignore", "--timeout", str(settings.semgrep_rule_timeout), "--jobs", str(settings.semgrep_jobs),
           "--max-target-bytes", str(max_target_bytes), *configs, "--", *files]
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=timeout_s, env=_env())
    except FileNotFoundError as exc:
        raise ScannerUnavailable(f"semgrep executable not found ({settings.semgrep_bin})") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerUnavailable(f"semgrep batch exceeded {timeout_s}s") from exc
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        log.error("semgrep exit %s stderr: %s", proc.returncode, proc.stderr[-2000:])
        raise ScannerUnavailable(f"semgrep failed (exit {proc.returncode})") from exc
    # Semgrep prefixes rule IDs with the config file's directory (e.g. "tmp.securematrix.<job>.").
    # Strip that so IDs are stable across scans and machines.
    prefixes = sorted({_rule_prefix(s.path) for s in sources if s.path}, key=len, reverse=True)
    for r in data.get("results", []):
        for prefix in prefixes:
            if r.get("check_id", "").startswith(prefix):
                r["check_id"] = r["check_id"][len(prefix):]
                break
    errors = [{"type": e.get("type"), "message": str(e.get("message", ""))[:300], "path": e.get("path")}
              for e in data.get("errors", [])]
    return data.get("results", []), errors
