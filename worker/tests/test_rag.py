"""Knowledge-base content and chunking (no network or database needed)."""
from securematrix_worker.rag import build_chunks, load_entries, min_similarity


def test_seed_has_100_plus_unique_cwes():
    entries = load_entries()
    cwes = [e["cwe_id"] for e in entries]
    assert len(entries) >= 100
    assert len(set(cwes)) == len(cwes)
    assert len({e["slug"] for e in entries}) == len(entries)


def test_required_categories_are_covered():
    cwes = {e["cwe_id"] for e in load_entries()}
    required = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502", "CWE-918", "CWE-284", "CWE-639", "CWE-287",
                "CWE-384", "CWE-798", "CWE-327", "CWE-338", "CWE-434", "CWE-1395", "CWE-942", "CWE-352", "CWE-611",
                "CWE-362", "CWE-400"}
    assert required <= cwes


def test_chunks_are_self_describing_and_bounded():
    entry = next(e for e in load_entries() if e["cwe_id"] == "CWE-89")
    doc = {**entry, "owasp_top10": entry["owasp_top10_2021"], "owasp_api": entry["owasp_api_2023"]}
    chunks = build_chunks(doc)
    assert list(dict.fromkeys(c["section"] for c in chunks)) == ["overview", "detection", "remediation"]
    assert all(c["content"].startswith("CWE-89") for c in chunks)
    assert all(len(c["content"]) <= 1600 for c in chunks)
    assert [c["chunk_index"] for c in chunks] == list(range(len(chunks)))


def test_similarity_threshold_depends_on_model():
    assert min_similarity("local/BAAI/bge-small-en-v1.5@384") > min_similarity("openai/text-embedding-3-small@384")
