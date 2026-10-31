"""The staged scan pipeline: extract -> discover -> scan (batched) -> deduplicate -> enrich (RAG) -> score -> persist."""
from __future__ import annotations

import hashlib
import logging
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import risk
from .archive import UnsafeArchiveError, extract_archive
from .config import settings
from .findings import Finding, deduplicate, humanize_rule, parse_semgrep_results
from .rag import FindingRetriever
from .semgrep_runner import ScannerUnavailable, prepare_rule_sources, run_batch, semgrep_version
from .supa import Supa

log = logging.getLogger("securematrix.pipeline")

LIMITATIONS = [
    "Static analysis reports code patterns; it cannot prove that a finding is exploitable at runtime.",
    "Business-logic flaws, authorization design issues and runtime configuration are only partly visible to pattern rules.",
    "Files that were excluded (dependencies, binaries, oversized or unsupported files) were not analysed.",
    "Dependency (SCA) vulnerability checks are not part of this scan.",
]


class Cancelled(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ScanRun:
    def __init__(self, db: Supa, job: dict) -> None:
        self.db = db
        self.job = job
        self.id = job["id"]
        self.config = job.get("config") or {}
        self.work = settings.work_dir / self.id
        self.started = time.monotonic()
        self.timeout_s = int(self.config.get("timeout_minutes", 30)) * 60

    # -- bookkeeping --------------------------------------------------------
    def event(self, stage: str, message: str, level: str = "info") -> None:
        log.info("[%s] %s: %s", self.id[:8], stage, message)
        self.db.insert("scan_job_events", {"scan_job_id": self.id, "stage": stage, "level": level, "message": message[:2000]})

    def update(self, **values) -> None:
        values["heartbeat_at"] = _now()
        self.db.update("scan_jobs", {"id": self.id}, values)

    def check_cancel_and_time(self) -> None:
        row = self.db.select("scan_jobs", {"id": f"eq.{self.id}", "select": "cancel_requested"})
        if row and row[0]["cancel_requested"]:
            raise Cancelled()
        if time.monotonic() - self.started > self.timeout_s:
            raise ScannerUnavailable(f"scan exceeded the {self.timeout_s // 60} minute time limit")

    # -- pipeline -----------------------------------------------------------
    def run(self) -> None:
        try:
            self._run()
        except Cancelled:
            self.event(self.job.get("stage", "scanning"), "Scan cancelled by user", "warning")
            self.update(status="cancelled", finished_at=_now())
        except (UnsafeArchiveError, ScannerUnavailable) as exc:
            self.event("finalizing", f"Scan failed: {exc}", "error")
            self.update(status="failed", error_message=str(exc)[:500], finished_at=_now())
        except Exception:  # noqa: BLE001
            ref = uuid.uuid4().hex[:8]
            log.exception("scan %s crashed (ref %s)", self.id, ref)
            self.event("finalizing", f"Internal worker error (reference {ref}); details are in the worker log", "error")
            self.update(status="failed", error_message=f"Internal worker error (reference {ref})", finished_at=_now())
        finally:
            shutil.rmtree(self.work, ignore_errors=True)

    def _run(self) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        cfg = self.config
        max_file_bytes = int(cfg.get("max_file_size_kb", 512)) * 1024

        # 1. Download and extract
        self.update(stage="extracting")
        self.event("extracting", "Downloading archive from private storage")
        zip_path = self.work / "upload.zip"
        with open(zip_path, "wb") as fh:
            size = self.db.download("project-uploads", self.job["archive_path"], fh, settings.max_archive_mb << 20)
        sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        self.update(archive_size_bytes=size, archive_sha256=sha)
        src = self.work / "src"
        result = extract_archive(
            zip_path, src, max_file_bytes=max_file_bytes, max_files=int(cfg.get("max_files", 5000)),
            max_total_bytes=settings.max_uncompressed_mb << 20, max_entries=settings.max_archive_entries,
            max_ratio=settings.max_compression_ratio, exclude_globs=list(cfg.get("exclude_globs") or []))
        zip_path.unlink(missing_ok=True)
        scannable = result.scannable
        excluded = [f for f in result.files if f.status == "excluded"]
        excluded_in_dirs = sum(result.excluded_dir_counts.values())
        self.event("extracting", f"Archive is safe: {result.total_entries} entries, {len(scannable)} source files "
                                 f"extracted, {len(excluded) + excluded_in_dirs} excluded")

        # 2. Discover and record file metadata
        self.update(stage="discovering")
        rows = [{"project_id": self.job["project_id"], "scan_job_id": self.id, "path": f.path, "language": f.language,
                 "size_bytes": f.size_bytes, "line_count": f.line_count, "sha256": f.sha256, "status": f.status,
                 "exclusion_reason": f.exclusion_reason} for f in result.files]
        rows += [{"project_id": self.job["project_id"], "scan_job_id": self.id, "path": d + "/", "language": None,
                  "size_bytes": 0, "line_count": None, "sha256": None, "status": "excluded",
                  "exclusion_reason": f"dependency/build directory ({n} files)"}
                 for d, n in sorted(result.excluded_dir_counts.items())]
        self.db.insert_many("project_files_metadata", rows)
        batch_size = int(cfg.get("batch_size", 200))
        batches = [scannable[i:i + batch_size] for i in range(0, len(scannable), batch_size)]
        self.update(files_total=len(scannable), files_excluded=len(excluded) + excluded_in_dirs,
                    batches_total=len(batches))
        if not scannable:
            raise ScannerUnavailable("no supported source files were found in the archive")
        langs = {}
        for f in scannable:
            langs[f.language] = langs.get(f.language, 0) + 1
        self.event("discovering", "Languages: " + ", ".join(f"{k} ({v})" for k, v in sorted(langs.items(), key=lambda kv: -kv[1])))

        # 3. Scan in batches
        self.update(stage="scanning")
        version = semgrep_version()
        if not version:
            raise ScannerUnavailable(f"Semgrep is not installed or not runnable ({settings.semgrep_bin})")
        sources = prepare_rule_sources(list(cfg.get("rulesets") or ["securematrix"]), self.work)
        for s in sources:
            self.event("scanning", f"Rule set {s.name}: {s.status} ({s.detail})", "info" if s.status == "loaded" else "warning")
        all_hits_raw: list[dict] = []
        scan_errors: list[dict] = []
        for i, batch in enumerate(batches, start=1):
            self.check_cancel_and_time()
            paths = [f.path for f in batch]
            remaining = max(self.timeout_s - int(time.monotonic() - self.started), 60)
            results, errors = run_batch(src, paths, sources, max_file_bytes, remaining)
            all_hits_raw.extend(results)
            scan_errors.extend(errors)
            failed_paths = {e["path"] for e in errors if e.get("path")}
            ok_paths = [p for p in paths if p not in failed_paths]
            for chunk_start in range(0, len(ok_paths), 100):
                chunk = ok_paths[chunk_start:chunk_start + 100]
                self.db.http.patch("/rest/v1/project_files_metadata",
                                   params={"scan_job_id": f"eq.{self.id}", "path": f"in.({','.join(map(_quote, chunk))})"},
                                   json={"status": "scanned"}, headers={"Prefer": "return=minimal"})
            if failed_paths:
                self.db.http.patch("/rest/v1/project_files_metadata",
                                   params={"scan_job_id": f"eq.{self.id}", "path": f"in.({','.join(map(_quote, failed_paths))})"},
                                   json={"status": "failed", "exclusion_reason": "scanner error"},
                                   headers={"Prefer": "return=minimal"})
            self.update(batches_done=i, files_scanned=sum(len(b) for b in batches[:i]))
            self.event("scanning", f"Batch {i}/{len(batches)}: {len(batch)} files, {len(results)} raw results"
                                   + (f", {len(errors)} scanner errors" if errors else ""))

        # 4. Deduplicate
        self.update(stage="deduplicating")
        hits = parse_semgrep_results(all_hits_raw, src)
        languages = {f.path: f.language for f in scannable}
        findings = deduplicate(hits, languages)
        self.event("deduplicating", f"{len(hits)} raw results merged into {len(findings)} unique findings")

        # 5. Enrich with knowledge-base evidence (RAG)
        self.update(stage="enriching")
        retriever = FindingRetriever(self.db)
        kb = retriever.docs_by_cwe()
        refs_by_fp: dict[str, tuple[list, str]] = {}
        for f in findings:
            primary_doc = next((kb[c] for c in f.cwes if c in kb), None)
            f.title = primary_doc["title"] if primary_doc else humanize_rule(f.rule_ids[0])
            f.category = primary_doc["category"] if primary_doc else None
            refs_by_fp[f.fingerprint] = retriever.for_finding(f.title, f.message, f.cwes, f.snippet, f.rule_ids[0])
        mode = f"pgvector ({retriever.model_id})" if retriever.model_id else "CWE metadata only (no embedding provider)"
        matched = sum(1 for r, s in refs_by_fp.values() if s == "matched")
        self.event("enriching", f"Knowledge retrieval via {mode}: evidence found for {matched}/{len(findings)} findings")

        # 6. Score
        self.update(stage="scoring")
        for f in findings:
            f.risk_score, f.priority, f.risk_rationale = risk.score(f.severity, f.confidence, f.cwes, f.path)

        # 7. Persist
        self.update(stage="finalizing")
        ids = self._persist(findings, refs_by_fp, retriever.model_id)
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        coverage = {
            "scanner": "semgrep", "scanner_version": version,
            "rulesets": [{"name": s.name, "status": s.status, "detail": s.detail} for s in sources],
            "languages": langs, "files_scanned": len(scannable),
            "files_excluded": len(excluded) + excluded_in_dirs,
            "excluded_directories": dict(sorted(result.excluded_dir_counts.items(), key=lambda kv: -kv[1])[:20]),
            "scanner_errors": len(scan_errors), "scanner_error_samples": scan_errors[:10],
            "raw_results": len(hits), "unique_findings": len(findings), "by_severity": by_sev,
            "retrieval": mode, "risk_model": risk.MODEL_VERSION,
            "limits": {k: cfg.get(k) for k in ("max_file_size_kb", "max_files", "batch_size", "timeout_minutes")},
            "limitations": LIMITATIONS,
        }
        self.update(status="completed", stage="done", findings_total=len(ids), coverage=coverage, finished_at=_now())
        self.event("done", f"Scan completed: {len(findings)} findings "
                           f"({', '.join(f'{v} {k}' for k, v in by_sev.items()) or 'none'})")

    def _persist(self, findings: list[Finding], refs_by_fp: dict, model_id: str | None) -> dict[str, str]:
        ids: dict[str, str] = {}
        payload = [{
            "fingerprint": f.fingerprint, "title": f.title, "description": f.message, "category": f.category,
            "severity": f.severity, "confidence": f.confidence, "detection_method": "semgrep",
            "rule_ids": f.rule_ids, "cwe_ids": f.cwes, "owasp_top10": f.owasp, "language": f.language,
            "file_path": f.path, "start_line": f.start_line, "end_line": f.end_line, "snippet": f.snippet,
            "requires_manual_review": f.confidence != "high", "risk_score": f.risk_score,
            "risk_rationale": f.risk_rationale, "priority": f.priority,
            "kb_evidence_status": refs_by_fp[f.fingerprint][1],
        } for f in findings]
        for i in range(0, len(payload), 200):
            for row in self.db.rpc("worker_upsert_findings", {"p_scan_job_id": self.id, "p_findings": payload[i:i + 200]}):
                ids[row["fingerprint"]] = row["vulnerability_id"]

        self.db.insert_many("scan_results", [{
            "scan_job_id": self.id, "project_id": self.job["project_id"], "vulnerability_id": ids.get(f.fingerprint),
            "scanner": "semgrep", "rule_id": h.rule_id, "file_path": h.path, "start_line": h.start_line,
            "end_line": h.end_line, "severity_raw": h.severity_raw, "message": h.message,
            "metadata": {k: h.meta.get(k) for k in ("cwe", "owasp", "confidence", "likelihood", "impact",
                                                     "category", "subcategory", "references", "technology") if k in h.meta},
            "fingerprint": f.fingerprint,
        } for f in findings for h in f.hits])

        vuln_ids = [ids[f.fingerprint] for f in findings if f.fingerprint in ids]
        for i in range(0, len(vuln_ids), 100):
            self.db.delete("finding_knowledge_refs", {"vulnerability_id": f"in.({','.join(vuln_ids[i:i + 100])})"})
        ref_rows = []
        for f in findings:
            refs, _ = refs_by_fp[f.fingerprint]
            for rank, r in enumerate(refs):
                ref_rows.append({"vulnerability_id": ids[f.fingerprint], "document_id": r.document_id,
                                 "chunk_id": r.chunk_id, "similarity": r.similarity, "match_type": r.match_type,
                                 "rank": rank,
                                 "retrieved_with": "cwe-metadata" if r.similarity is None else model_id})
        self.db.insert_many("finding_knowledge_refs", ref_rows)
        return ids
