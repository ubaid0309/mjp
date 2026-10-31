"""Safe ZIP extraction and source-file discovery.

Defences:
- entries with absolute paths, drive letters, '..' segments, NUL bytes or symlink modes reject the whole archive
- encrypted entries reject the archive
- limits on entry count, total uncompressed size and per-entry compression ratio (zip bombs)
- sizes are enforced while streaming, not taken from the (forgeable) ZIP headers
- dependency folders, build output, binaries and oversized files are recorded but never extracted
"""
from __future__ import annotations

import fnmatch
import hashlib
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

EXCLUDED_DIRS = {
    "node_modules", "bower_components", "jspm_packages", "vendor", ".git", ".svn", ".hg",
    "dist", "build", "out", "target", "bin", "obj", ".next", ".nuxt", ".svelte-kit", "coverage",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    ".gradle", ".idea", ".vscode", "Pods", "DerivedData", ".terraform", ".cache",
}

LANGUAGES = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".php": "php", ".phtml": "php",
    ".go": "go", ".rb": "ruby", ".rs": "rust", ".swift": "swift", ".cs": "csharp",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".sql": "sql", ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".sh": "bash", ".bash": "bash",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".xml": "xml", ".tf": "terraform", ".hcl": "terraform",
    ".ini": "config", ".cfg": "config", ".conf": "config", ".properties": "config", ".toml": "config",
    ".env": "dotenv",
}
SPECIAL_NAMES = {"dockerfile": "dockerfile", ".env": "dotenv", "makefile": "makefile"}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock", "-lock.json", ".bundle.js")
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock", "cargo.lock", "go.sum"}


class UnsafeArchiveError(Exception):
    """The archive is malformed or malicious; the scan must stop."""


@dataclass
class FileRecord:
    path: str
    size_bytes: int
    status: str  # queued | excluded
    language: str | None = None
    exclusion_reason: str | None = None
    sha256: str | None = None
    line_count: int | None = None


@dataclass
class ExtractionResult:
    files: list[FileRecord] = field(default_factory=list)
    excluded_dir_counts: dict[str, int] = field(default_factory=dict)
    total_entries: int = 0

    @property
    def scannable(self) -> list[FileRecord]:
        return [f for f in self.files if f.status == "queued"]


def classify(path: str) -> str | None:
    p = PurePosixPath(path)
    name = p.name.lower()
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    if name.startswith(".env"):
        return "dotenv"
    if name.startswith("dockerfile"):
        return "dockerfile"
    return LANGUAGES.get(p.suffix.lower())


def _safe_name(raw: str) -> str:
    if "\x00" in raw:
        raise UnsafeArchiveError("entry name contains a NUL byte")
    name = raw.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchiveError(f"absolute path in archive: {raw[:200]!r}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"path traversal entry in archive: {raw[:200]!r}")
    return "/".join(parts)


def _excluded_dir(parts: list[str]) -> str | None:
    for i, part in enumerate(parts[:-1]):
        if part in EXCLUDED_DIRS or part.endswith(".egg-info"):
            return "/".join(parts[: i + 1])
    return None


def extract_archive(zip_path: Path, dest: Path, *, max_file_bytes: int, max_files: int,
                    max_total_bytes: int, max_entries: int, max_ratio: int,
                    exclude_globs: list[str] | None = None) -> ExtractionResult:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    result = ExtractionResult()
    exclude_globs = exclude_globs or []

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise UnsafeArchiveError("the upload is not a valid ZIP archive") from exc

    with zf:
        infos = zf.infolist()
        result.total_entries = len(infos)
        if len(infos) > max_entries:
            raise UnsafeArchiveError(f"archive has {len(infos)} entries; the limit is {max_entries}")

        # Validate every entry before writing anything.
        for info in infos:
            _safe_name(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UnsafeArchiveError(f"symbolic link in archive: {info.filename[:200]!r}")
            if info.flag_bits & 0x1:
                raise UnsafeArchiveError("encrypted archive entries are not supported")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > max_ratio and info.file_size > 1 << 20:
                raise UnsafeArchiveError(f"suspicious compression ratio for {info.filename[:200]!r} (possible zip bomb)")

        total_written = 0
        queued = 0
        for info in infos:
            if info.is_dir():
                continue
            name = _safe_name(info.filename)
            if not name:
                continue
            parts = name.split("/")
            lower = parts[-1].lower()

            excluded_dir = _excluded_dir(parts)
            if excluded_dir:
                result.excluded_dir_counts[excluded_dir] = result.excluded_dir_counts.get(excluded_dir, 0) + 1
                continue

            reason = None
            language = classify(name)
            if any(fnmatch.fnmatch(name, g) for g in exclude_globs):
                reason = "matched an exclude pattern in scan settings"
            elif lower in LOCKFILES or lower.endswith(SKIP_SUFFIXES):
                reason = "generated or lock file"
            elif language is None:
                reason = "unsupported file type"
            elif info.file_size > max_file_bytes:
                reason = f"larger than the {max_file_bytes // 1024} KB file limit"
            elif queued >= max_files:
                reason = f"file-count limit of {max_files} reached"

            if reason:
                result.files.append(FileRecord(name, info.file_size, "excluded", language, reason))
                continue

            target = (root / name).resolve()
            if root not in target.parents:
                raise UnsafeArchiveError(f"entry escapes the extraction directory: {name[:200]!r}")
            target.parent.mkdir(parents=True, exist_ok=True)

            digest = hashlib.sha256()
            written = 0
            head = b""
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(1 << 16):
                    written += len(chunk)
                    total_written += len(chunk)
                    if written > max_file_bytes:
                        raise UnsafeArchiveError(f"{name[:200]!r} is larger than its header claims")
                    if total_written > max_total_bytes:
                        raise UnsafeArchiveError(f"archive expands beyond {max_total_bytes // (1 << 20)} MB")
                    if len(head) < 8192:
                        head += chunk[: 8192 - len(head)]
                    digest.update(chunk)
                    out.write(chunk)

            if b"\x00" in head:
                target.unlink()
                result.files.append(FileRecord(name, written, "excluded", language, "binary content"))
                continue

            with open(target, "rb") as fh:
                lines = sum(1 for _ in fh)
            result.files.append(FileRecord(name, written, "queued", language, None, digest.hexdigest(), lines))
            queued += 1

    return result
