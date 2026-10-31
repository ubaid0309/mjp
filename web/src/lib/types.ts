export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type FindingStatus =
  | "new" | "triaged" | "in_progress" | "fix_proposed" | "fix_applied"
  | "verification_pending" | "resolved" | "accepted_risk";

export const STATUS_LABEL: Record<FindingStatus, string> = {
  new: "New",
  triaged: "Triaged",
  in_progress: "In progress",
  fix_proposed: "Fix proposed",
  fix_applied: "Fix applied",
  verification_pending: "Verification pending",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
};

// Mirrors public.finding_transition_allowed in the database, which is the real enforcement.
export const TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  new: ["triaged", "in_progress", "fix_proposed", "accepted_risk"],
  triaged: ["in_progress", "fix_proposed", "accepted_risk"],
  in_progress: ["triaged", "fix_proposed", "accepted_risk"],
  fix_proposed: ["in_progress", "fix_applied"],
  fix_applied: ["verification_pending", "in_progress"],
  verification_pending: ["in_progress"],
  resolved: ["triaged", "in_progress"],
  accepted_risk: ["triaged"],
};

export interface Profile { id: string; email: string | null; full_name: string | null; role: "admin" | "analyst" | "viewer" }

export interface Project {
  id: string; owner_id: string; name: string; description: string | null; primary_language: string | null;
  source_type: string; repository_url: string | null; created_at: string; updated_at: string;
}

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export const SCAN_STAGES = ["queued", "extracting", "discovering", "scanning", "deduplicating", "enriching", "scoring", "finalizing", "done"] as const;
export type ScanStage = (typeof SCAN_STAGES)[number];

export interface RuleSetCoverage { name: string; status: string; detail: string }
export interface Coverage {
  scanner?: string; scanner_version?: string; rulesets?: RuleSetCoverage[]; languages?: Record<string, number>;
  files_scanned?: number; files_excluded?: number; excluded_directories?: Record<string, number>;
  scanner_errors?: number; raw_results?: number; unique_findings?: number; by_severity?: Record<string, number>;
  retrieval?: string; risk_model?: string; limits?: Record<string, number>; limitations?: string[];
}

export interface ScanJob {
  id: string; project_id: string; created_by: string | null; scan_type: string; status: ScanStatus; stage: ScanStage;
  archive_path: string | null; archive_size_bytes: number | null; archive_sha256: string | null;
  config: Record<string, unknown>; files_total: number; files_scanned: number; files_excluded: number;
  batches_total: number; batches_done: number; findings_total: number; coverage: Coverage;
  error_message: string | null; cancel_requested: boolean; queued_at: string; started_at: string | null;
  finished_at: string | null; created_at: string; projects?: { name: string } | null;
}

export interface ScanEvent { id: number; scan_job_id: string; stage: string; level: "info" | "warning" | "error"; message: string; created_at: string }

export interface RiskFactor { name: string; value: number; reason: string }
export interface Vulnerability {
  id: string; ref_no: number; project_id: string; fingerprint: string; title: string; description: string | null;
  category: string | null; severity: Severity; confidence: "high" | "medium" | "low"; source: "scanner_confirmed" | "ai_potential";
  detection_method: string; rule_ids: string[]; cwe_ids: string[]; owasp_top10: string[]; language: string | null;
  file_path: string; start_line: number | null; end_line: number | null; snippet: string | null;
  requires_manual_review: boolean; risk_score: number | null;
  risk_rationale: { model?: string; formula?: string; factors?: RiskFactor[]; note?: string };
  priority: "P1" | "P2" | "P3" | "P4" | null; status: FindingStatus; verification_status: string;
  kb_evidence_status: "pending" | "matched" | "insufficient" | "unavailable";
  first_seen_scan_id: string | null; last_seen_scan_id: string | null; occurrence_count: number; reopened_count: number;
  assignee_id: string | null; due_date: string | null; accepted_risk_justification: string | null;
  created_at: string; updated_at: string; projects?: { name: string } | null;
}

export interface CodeExample { language: string; code: string }
export interface KnowledgeDocument {
  id: string; slug: string; cwe_id: string | null; title: string; cwe_name: string | null; category: string;
  owasp_top10: string[]; owasp_api: string[]; severity_default: Severity; languages: string[]; description: string;
  prerequisites: string[]; impact: string[]; detection_patterns: string[]; remediation: string[];
  vulnerable_example: CodeExample | null; secure_example: CodeExample | null;
  cve_examples: { id: string; summary: string }[]; references: { title: string; url: string }[];
  source: string; is_enabled: boolean; version: number; index_status: string; index_error: string | null;
  indexed_at: string | null; embedding_model: string | null; chunk_count: number; updated_at: string;
}

export interface KnowledgeRef {
  id: string; vulnerability_id: string; document_id: string; chunk_id: string | null; similarity: number | null;
  match_type: "cwe_exact" | "semantic" | "cwe_and_semantic"; rank: number; retrieved_with: string | null;
  knowledge_documents: KnowledgeDocument; knowledge_chunks: { section: string; content: string } | null;
}

export interface DashboardStats {
  projects: number; projects_scanned: number; scans_total: number; scans_running: number; findings_total: number;
  findings_open: number; critical_open: number; high_open: number; verified_fixes: number; accepted_risks: number;
  open_remediation_tasks: number; threat_scenarios: number; severity: Partial<Record<Severity, number>>;
  status: Partial<Record<FindingStatus, number>>; categories: { category: string; count: number }[];
  top_files: { project_id: string; file_path: string; count: number; max_risk: number | null }[];
}

export interface WorkerStatus {
  worker_id: string; hostname: string | null; version: string | null; semgrep_version: string | null;
  embedding_provider: string | null; embedding_model: string | null; llm_provider: string | null; llm_model: string | null;
  capabilities: Record<string, unknown>; started_at: string; last_heartbeat_at: string;
}
