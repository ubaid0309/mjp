import { Link } from "react-router-dom";
import { PageHeader, Panel } from "@/components/ui";

const MODULES: Record<string, { title: string; phase: string; summary: string; scope: string[]; foundation: string[] }> = {
  threats: {
    title: "Threat analysis", phase: "Phase 3",
    summary: "Inferred threat scenarios built from project structure, entry points and detected weaknesses, categorised with STRIDE.",
    scope: ["Attack-surface extraction (routes, handlers, config files)", "STRIDE scenarios with likelihood and impact",
      "Links between each scenario and the findings that enable it", "Mitigation recommendations from the knowledge base",
      "Every scenario labelled as inferred: no live traffic is monitored"],
    foundation: ["threat_scenarios table with STRIDE, likelihood, impact and basis = 'inferred'", "Findings already carry CWE, OWASP and file location"],
  },
  remediation: {
    title: "Remediation center", phase: "Phase 2",
    summary: "Turns findings into reviewed fixes: root cause, patch diff, side effects and supporting references.",
    scope: ["Patch suggestions generated from retrieved knowledge and the actual code", "Review and approval before anything is applied",
      "Patches applied to a copy; the original upload is never modified", "Patch history with rollback", "Downloadable .patch files"],
    foundation: ["remediation_suggestions and remediation_history tables", "Lifecycle statuses fix_proposed and fix_applied", "Knowledge-base remediation guidance is already shown on each finding"],
  },
  verification: {
    title: "Fix verification", phase: "Phase 2",
    summary: "Re-runs the relevant scanner rules on the patched code and records whether the finding is really gone.",
    scope: ["Targeted re-scan of changed files with the original rule IDs", "Results: verified, still detected, partially resolved, failed, manual review",
      "Only a verification re-scan can mark a finding resolved"],
    foundation: ["Database constraint: status resolved requires verification_status verified_resolved", "Stable fingerprints match findings across scans", "Re-detected resolved findings are reopened automatically"],
  },
  reports: {
    title: "Security reports", phase: "Phase 3",
    summary: "Downloadable PDF reports for each scan, alongside the existing JSON export.",
    scope: ["Executive summary and severity breakdown", "Scanner configuration, coverage and limitations", "Detailed findings with CWE/OWASP and RAG references",
      "Risk methodology, verification results, accepted risks", "Clear separation of detected findings, inferred threats and unverified suggestions"],
    foundation: ["JSON report export is available now on every completed scan", "Private reports storage bucket with project-scoped access"],
  },
  team: {
    title: "Team and assignments", phase: "Phase 2",
    summary: "Shared projects, finding assignment, due dates and overdue tracking.",
    scope: ["Invite members to a project as maintainer or viewer", "Assign findings with due dates", "Overdue and time-to-remediate tracking"],
    foundation: ["project_members table and membership-based RLS", "finding_assignments and finding_comments tables", "Notes and status history on each finding work today"],
  },
};

export default function PlannedPage({ module }: { module: keyof typeof MODULES }) {
  const m = MODULES[module];
  return (
    <>
      <PageHeader title={m.title} description={m.summary} />
      <Panel>
        <p className="text-[13px]"><span className="rounded border border-line px-1.5 py-0.5 text-xs text-fg-muted">{m.phase}</span>
          <span className="ml-2 text-fg-muted">This module is not built yet. Nothing on this page is simulated.</span></p>
        <div className="mt-5 grid gap-6 md:grid-cols-2">
          <div>
            <h2 className="mb-2 text-[13px] font-semibold">What it will do</h2>
            <ul className="list-disc space-y-1.5 pl-5 text-[13px] text-fg-muted">{m.scope.map((s) => <li key={s}>{s}</li>)}</ul>
          </div>
          <div>
            <h2 className="mb-2 text-[13px] font-semibold">Already in place</h2>
            <ul className="list-disc space-y-1.5 pl-5 text-[13px] text-fg-muted">{m.foundation.map((s) => <li key={s}>{s}</li>)}</ul>
          </div>
        </div>
        <p className="mt-6 text-[13px]"><Link to="/findings">Go to vulnerabilities</Link></p>
      </Panel>
    </>
  );
}
