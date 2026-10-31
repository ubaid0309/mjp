import { supabase, unwrap } from "./supabase";
import type { ScanJob, Vulnerability } from "./types";
import { findingRef } from "./format";

interface RefRow { vulnerability_id: string; match_type: string; similarity: number | null; retrieved_with: string | null;
  knowledge_documents: { slug: string; cwe_id: string | null; title: string } }

/** Builds the machine-readable JSON report for one scan from stored data and downloads it. */
export async function downloadJsonReport(scan: ScanJob, projectName: string) {
  const findings = unwrap(await supabase.from("vulnerabilities").select("*").eq("last_seen_scan_id", scan.id)
    .order("risk_score", { ascending: false })) as Vulnerability[];
  const refs: RefRow[] = [];
  for (let i = 0; i < findings.length; i += 100) {
    const ids = findings.slice(i, i + 100).map((f) => f.id);
    refs.push(...(unwrap(await supabase.from("finding_knowledge_refs")
      .select("vulnerability_id, match_type, similarity, retrieved_with, knowledge_documents(slug, cwe_id, title)")
      .in("vulnerability_id", ids).order("rank")) as unknown as RefRow[]));
  }
  const bySeverity: Record<string, number> = {};
  findings.forEach((f) => { bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1; });

  const report = {
    report_format: "securematrix-scan-report/1",
    generated_at: new Date().toISOString(),
    project: { id: scan.project_id, name: projectName },
    scan: {
      id: scan.id, type: scan.scan_type, status: scan.status, started_at: scan.started_at, finished_at: scan.finished_at,
      archive_sha256: scan.archive_sha256, configuration: scan.config,
    },
    coverage: scan.coverage,
    summary: { total_findings: findings.length, by_severity: bySeverity },
    risk_scoring_methodology: {
      model: scan.coverage?.risk_model,
      formula: "100 x severity x exploitability x exposure x confidence",
      note: "SecureMatrix risk score is an internal prioritisation score. It is not an official CVSS score.",
    },
    definitions: {
      scanner_confirmed: "Reported by a static-analysis rule. Exploitability still needs manual confirmation where requires_manual_review is true.",
      knowledge_references: "Retrieved from the SecureMatrix knowledge base by CWE match and/or vector similarity. Guidance, not proof.",
      inferred_threats: "Not included in this report version (threat analysis is a planned module).",
      fixes: "No fix in this report has been verified by a re-scan unless verification_status is verified_resolved.",
    },
    findings: findings.map((f) => ({
      id: findingRef(f.ref_no), uuid: f.id, title: f.title, severity: f.severity, confidence: f.confidence, source: f.source,
      status: f.status, verification_status: f.verification_status, cwe: f.cwe_ids, owasp_top10_2021: f.owasp_top10,
      file: f.file_path, start_line: f.start_line, end_line: f.end_line, language: f.language,
      detection: { method: f.detection_method, rules: f.rule_ids }, description: f.description,
      snippet_redacted: f.snippet, risk_score: f.risk_score, priority: f.priority, risk_rationale: f.risk_rationale,
      requires_manual_review: f.requires_manual_review, knowledge_evidence: f.kb_evidence_status,
      knowledge_references: refs.filter((r) => r.vulnerability_id === f.id).map((r) => ({
        cwe: r.knowledge_documents.cwe_id, title: r.knowledge_documents.title, slug: r.knowledge_documents.slug,
        match: r.match_type, similarity: r.similarity, retrieved_with: r.retrieved_with,
      })),
    })),
    limitations: scan.coverage?.limitations ?? [],
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `securematrix-${projectName.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-${scan.id.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}
