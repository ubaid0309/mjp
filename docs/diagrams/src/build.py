"""Builds the hand-laid-out SVG figures: python3 docs/diagrams/src/build.py
PNG versions are rendered from these SVGs by render.cjs (Playwright, 3x scale)."""
from pathlib import Path

from svgfig import Fig

OUT = Path(__file__).resolve().parent.parent


def fig1_architecture() -> Fig:
    f = Fig(1400, 770)
    f.pill(600, 14, 200, 48, "Security analyst / developer", ["(web browser)"])
    f.group(30, 82, 1340, 110, "Presentation layer")
    f.box(50, 110, 1300, 66, "SecureMatrix web app (React + TypeScript, Vite, Tailwind CSS)",
          ["Dashboard, Projects, Upload and scan, Scan results, Vulnerability explorer, Finding detail, Knowledge base, Settings"])
    f.edge([(700, 62), (700, 110)])

    f.group(30, 270, 480, 480, "Supabase platform")
    f.box(50, 310, 200, 78, "Auth", ["email + password", "JWT sessions"])
    f.box(290, 310, 200, 78, "Storage", ["private buckets:", "project-uploads, reports"], kind="data")
    f.box(50, 430, 440, 72, "PostgREST API + RPC", ["Row Level Security on every table,", "security-definer functions for writes"])
    f.cyl(80, 545, 380, 185, "PostgreSQL 17 + pgvector",
          ["projects, members, scan jobs, events,", "files, raw results, findings,", "knowledge documents + vector chunks,",
           "remediation, threats, comments,", "audit log, worker status"])
    f.edge([(270, 502), (270, 545)])

    f.edge([(150, 176), (150, 310)], "sign in", at=(150, 245))
    f.edge([(270, 176), (270, 430)], "queries, RPC\n(JWT + RLS)", at=(270, 238))
    f.edge([(430, 176), (430, 310)], "upload ZIP", at=(430, 245))
    f.edge([(980, 176), (980, 310)], "semantic search,\nAsk (JWT)", at=(980, 238))

    f.group(640, 270, 420, 480, "SecureMatrix worker (Python, Docker)")
    f.box(660, 310, 380, 78, "RAG API (FastAPI)", ["/api/rag/search, /api/rag/ask, /health", "user JWT verified with Supabase Auth"])
    f.box(660, 410, 380, 78, "Knowledge indexer", ["imports 116 CWE seed records (JSON),", "chunks and embeds pending / stale documents"])
    f.box(660, 512, 380, 60, "Job loop", ["claims queued scans (FOR UPDATE SKIP LOCKED)"])
    f.box(660, 598, 380, 132, "Scan pipeline",
          ["safe extraction and file discovery", "batched Semgrep analysis", "normalise, deduplicate, redact secrets",
           "RAG enrichment (query embeddings)", "risk scoring, persist findings"])
    f.edge([(850, 572), (850, 598)])

    # one service-role connector between worker and Supabase
    f.edge([(640, 640), (510, 640)], both=True)
    for i, line in enumerate(["service role:", "claim jobs,", "download archives,", "write findings,", "store vectors,", "vector search"]):
        f.label(575, 548 + i * 15, line)

    f.group(1100, 270, 270, 480, "External services")
    f.box(1120, 310, 230, 178, "OpenAI API",
          ["text-embedding-3-small", "(384 dimensions)", "", "gpt-4o-mini", "(grounded answers)"], kind="ext")
    f.box(1120, 598, 230, 132, "Semgrep CE",
          ["53 bundled SecureMatrix rules", "+ registry rule packs", "(security-audit, secrets)"], kind="ext")
    f.edge([(1040, 349), (1120, 349)], "embed, chat", at=(1080, 341))
    f.edge([(1040, 449), (1120, 449)], "embed", at=(1080, 441))
    f.edge([(1040, 664), (1120, 664)], "run rules", at=(1080, 656))
    return f


def fig3_scan_pipeline() -> Fig:
    f = Fig(1400, 730)
    f.group(20, 20, 420, 690, "1. Ingest")
    f.group(470, 20, 490, 690, "2. Batched static analysis")
    f.group(990, 20, 390, 690, "3. Enrich and persist")

    # column 1
    f.cyl(155, 55, 160, 62, "scan_jobs", ["status = queued"])
    f.box(70, 140, 330, 60, "Claim job", ["claim_next_scan_job(), SKIP LOCKED"])
    f.box(70, 225, 330, 60, "Download archive", ["size limit enforced while streaming"])
    f.diamond(280, 365, 260, 120, ["Archive safe?", "no absolute paths, '..',", "symlinks, encryption,", "zip bombs, size limits"])
    f.box(30, 335, 85, 60, "Scan failed", ["reason shown"], kind="bad")
    f.box(70, 450, 330, 60, "Extract and classify files", ["language by extension, binary sniffing"])
    f.box(70, 535, 330, 76, "Record exclusions", ["dependencies, build output, lock files,", "binaries, oversized, unsupported"])
    f.edge([(235, 117), (235, 140)])
    f.edge([(235, 200), (235, 225)])
    f.edge([(235, 285), (280, 285), (280, 305)])
    f.edge([(150, 365), (115, 365)], "no", at=(133, 357))
    f.edge([(280, 425), (280, 450)], "yes", at=(298, 442))
    f.edge([(235, 510), (235, 535)])
    f.edge([(400, 573), (455, 573), (455, 85), (525, 85)])

    # column 2
    f.box(525, 55, 380, 60, "Split into batches", ["default 200 files per batch"])
    f.box(525, 140, 380, 70, "Load rule sets", ["bundled rules + registry packs", "(unavailable packs are reported)"])
    f.diamond(715, 270, 190, 64, ["Next batch"])
    f.diamond(715, 375, 240, 92, ["Cancel requested", "or time limit?"])
    f.box(850, 350, 100, 52, "Stopped", ["cancelled / failed"], kind="bad")
    f.box(525, 455, 380, 70, "Run Semgrep on the batch", ["update batches_done and heartbeat"])
    f.diamond(715, 590, 210, 70, ["More batches?"])
    f.edge([(715, 115), (715, 140)])
    f.edge([(715, 210), (715, 238)])
    f.edge([(715, 302), (715, 329)])
    f.edge([(835, 375), (850, 375)])
    f.label(842, 366, "yes")
    f.edge([(715, 421), (715, 455)], "no", at=(730, 442))
    f.edge([(715, 525), (715, 555)])
    f.edge([(610, 590), (500, 590), (500, 270), (620, 270)], "yes", at=(515, 430))
    f.edge([(715, 625), (715, 668), (975, 668), (975, 90), (1030, 90)], "no", at=(730, 650))

    # column 3
    steps = [
        ("Normalise results", ["CWE / OWASP mapping, severity,", "confidence, redacted snippet"]),
        ("Deduplicate", ["same file + line + CWE across rules;", "line-independent fingerprint"]),
        ("Retrieve knowledge per finding", ["exact CWE match +", "pgvector cosine similarity"]),
        ("Risk score 0-100", ["severity x exploitability", "x exposure x confidence"]),
        ("Upsert findings", ["new / existing / reopened"]),
        ("Save coverage report", ["scanner version, rule sets,", "exclusions, limitations"]),
    ]
    y = 55
    for i, (title, lines) in enumerate(steps):
        f.box(1030, y, 310, 70, title, lines)
        if i:
            f.edge([(1185, y - 15), (1185, y)])
        y += 85
    f.cyl(1105, y, 160, 62, "scan_jobs", ["status = completed"])
    f.edge([(1185, y - 15), (1185, y)])
    return f


def fig4_rag() -> Fig:
    f = Fig(1760, 575)
    f.group(20, 20, 1720, 245, "A. Offline indexing (on import, on edit, or when the embedding model changes)")
    f.para(45, 70, 210, 110, "Knowledge seed", ["116 CWE records (JSON),", "OWASP Top 10 / API", "mappings, examples"])
    f.box(300, 80, 200, 90, "Import and upsert", ["keyed by slug; content", "hash and version tracked"])
    f.box(545, 65, 230, 120, "Chunk per section", ["overview, detection,", "remediation; at most", "1,600 characters; CWE", "header on every chunk"])
    f.box(820, 80, 230, 90, "Embed chunks", ["text-embedding-3-small,", "384 dims; model id stored"])
    f.cyl(1095, 60, 230, 130, "knowledge_chunks", ["pgvector, HNSW", "cosine index"])
    f.box(300, 195, 200, 52, "Admin edit or re-index", ["marks document stale"])
    f.edge([(255, 125), (300, 125)])
    f.edge([(500, 125), (545, 125)])
    f.edge([(775, 125), (820, 125)])
    f.edge([(1050, 125), (1095, 125)])
    f.edge([(500, 221), (660, 221), (660, 185)])

    f.group(20, 295, 1720, 260, "B. Online retrieval and grounded generation")
    f.box(45, 365, 210, 100, "Query", ["scanner finding (title,", "CWE, message, code)", "or a user question"])
    f.box(300, 335, 200, 70, "Embed query", ["same model as the index"])
    f.box(300, 445, 200, 70, "Exact CWE match", ["metadata filter"])
    f.box(545, 335, 230, 70, "Top-k cosine similarity", ["match_knowledge_chunks()"])
    f.box(820, 395, 200, 70, "Merge and rank", ["CWE + semantic matches first"])
    f.diamond(1150, 430, 200, 110, ["Similarity", "above threshold?"])
    f.box(1280, 325, 210, 70, "Evidence attached", ["references, guidance,", "secure code example"])
    f.box(1280, 450, 210, 62, "Insufficient evidence", ["stated explicitly, no guess"], kind="warn")
    f.box(1540, 315, 185, 90, "Grounded answer", ["gpt-4o-mini, numbered", "excerpts only, cited,", "labelled AI-generated"])
    f.edge([(255, 395), (278, 395), (278, 370), (300, 370)])
    f.edge([(255, 435), (278, 435), (278, 480), (300, 480)])
    f.edge([(500, 370), (545, 370)])
    f.edge([(775, 370), (797, 370), (797, 418), (820, 418)])
    f.edge([(500, 480), (797, 480), (797, 445), (820, 445)])
    f.edge([(1020, 430), (1050, 430)])
    f.edge([(1150, 375), (1150, 360), (1280, 360)], "yes", at=(1215, 352))
    f.edge([(1250, 430), (1265, 430), (1265, 481), (1280, 481)])
    f.label(1262, 452, "no")
    f.edge([(1490, 360), (1540, 360)])
    f.text(1515, 338, "Ask /", size=11.5)
    f.text(1515, 352, "Explain", size=11.5)
    f.edge([(1210, 190), (1210, 280), (660, 280), (660, 335)], "nearest vectors (same model only)", at=(935, 284), dashed=True)
    f.text(1150, 535, "threshold: 0.30 (OpenAI) / 0.62 (local model)", size=11.5, color="#475569")
    return f


def fig6_lifecycle() -> Fig:
    f = Fig(1340, 400)
    y, h = 175, 50
    boxes = {
        "new": (60, 100, "New"), "triaged": (210, 110, "Triaged"), "prog": (380, 120, "In progress"),
        "prop": (560, 130, "Fix proposed"), "appl": (750, 120, "Fix applied"),
        "ver": (930, 170, "Verification pending"), "res": (1170, 120, "Resolved"),
    }
    for key, (x, w, label) in boxes.items():
        kind = "data" if key == "res" else "core"
        f.box(x, y, w, h, label, [], kind=kind)
    f.box(180, 45, 170, 50, "Accepted risk", [], kind="dec")
    f.text(265, 34, "requires written justification", size=11.5, color="#475569", italic=True)
    f.text(1230, 150, "only when a verification re-scan", size=11.5, color="#475569", italic=True)
    f.text(1230, 164, "sets verified_resolved", size=11.5, color="#475569", italic=True)

    f.front.append('<circle cx="22" cy="200" r="7" fill="#3F4B5B"/>')
    f.edge([(29, 200), (60, 200)])
    f.text(22, 224, "scan", size=11.5, color="#475569")
    mid = y + h / 2
    f.edge([(160, mid), (210, mid)])
    f.edge([(320, mid - 9), (380, mid - 9)])
    f.edge([(380, mid + 9), (320, mid + 9)])
    f.edge([(500, mid), (560, mid)])
    f.edge([(690, mid), (750, mid)])
    f.edge([(870, mid), (930, mid)])
    f.edge([(1100, mid), (1170, mid)], "re-scan", at=(1135, mid - 10))

    f.edge([(110, y), (110, 70), (180, 70)])
    f.edge([(245, y), (245, 95)])
    f.edge([(440, y), (440, 70), (350, 70)])
    f.edge([(300, 95), (300, y)])
    f.label(314, 140, "revoked", anchor="start")

    f.edge([(625, y + h), (625, 265), (470, 265), (470, y + h)])
    f.edge([(810, y + h), (810, 290), (455, 290), (455, y + h)])
    f.edge([(1015, y + h), (1015, 315), (440, 315), (440, y + h)], "still detected", at=(730, 319))
    f.edge([(1230, y + h), (1230, 350), (265, 350), (265, y + h)], "reopened when a later scan detects it again", at=(745, 354))
    f.text(670, 388, "Simplified: New, Triaged and In progress may also move directly to Fix proposed (full rules in Table 1).",
           size=11.5, color="#475569", italic=True)
    return f


if __name__ == "__main__":
    for name, fn in [("01-system-architecture", fig1_architecture), ("03-scan-pipeline", fig3_scan_pipeline),
                     ("04-rag-pipeline", fig4_rag), ("06-finding-lifecycle", fig6_lifecycle)]:
        (OUT / f"{name}.svg").write_text(fn().svg(), encoding="utf-8")
        print("wrote", name)
