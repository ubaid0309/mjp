# Knowledge-base record format

Each file in `knowledge/entries/` is a JSON array of records. One record = one weakness class, keyed by a unique CWE ID. `worker` imports these into `knowledge_documents`, splits them into section chunks and embeds them into `knowledge_chunks`.

```jsonc
{
  "slug": "cwe-89-sql-injection",            // "cwe-<n>-<kebab-short-name>", unique
  "cwe_id": "CWE-89",                        // unique across the whole knowledge base
  "title": "SQL Injection",                  // short human title
  "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", // official MITRE name
  "category": "Injection",                   // one of the categories below
  "owasp_top10_2021": ["A03:2021-Injection"],
  "owasp_api_2023": [],                      // e.g. ["API1:2023-Broken Object Level Authorization"]
  "severity_default": "critical",            // critical | high | medium | low | info
  "languages": ["python", "javascript", "java", "php", "go"],
  "description": "2-4 sentences: what the weakness is and why it happens.",
  "prerequisites": ["What an attacker needs for this to be exploitable", "..."],
  "impact": ["Concrete consequence", "..."],
  "detection_patterns": ["What to look for in source code / config", "..."],
  "remediation": ["Specific, actionable secure-coding step", "..."],
  "vulnerable_example": { "language": "python", "code": "short snippet" },
  "secure_example": { "language": "python", "code": "the fixed snippet" },
  "cve_examples": [ { "id": "CVE-2021-44228", "summary": "one line" } ], // only well-known, verified CVEs; [] if unsure
  "references": [ { "title": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html" } ]
}
```

Categories: `Injection`, `Cross-Site Scripting`, `Access Control`, `Authentication`, `Session Management`, `Cryptography`, `Secrets & Credentials`, `Input Validation`, `File Handling`, `Deserialization`, `Server-Side Request Forgery`, `XML Processing`, `Memory Safety`, `Concurrency`, `Resource Management & DoS`, `Security Misconfiguration`, `Logging & Monitoring`, `Information Exposure`, `Error Handling`, `Supply Chain`, `Web Security`, `Business Logic`, `AI/LLM Security`.

OWASP Top 10 2021 values: `A01:2021-Broken Access Control`, `A02:2021-Cryptographic Failures`, `A03:2021-Injection`, `A04:2021-Insecure Design`, `A05:2021-Security Misconfiguration`, `A06:2021-Vulnerable and Outdated Components`, `A07:2021-Identification and Authentication Failures`, `A08:2021-Software and Data Integrity Failures`, `A09:2021-Security Logging and Monitoring Failures`, `A10:2021-Server-Side Request Forgery`.

OWASP API Security Top 10 2023 values: `API1:2023-Broken Object Level Authorization`, `API2:2023-Broken Authentication`, `API3:2023-Broken Object Property Level Authorization`, `API4:2023-Unrestricted Resource Consumption`, `API5:2023-Broken Function Level Authorization`, `API6:2023-Unrestricted Access to Sensitive Business Flows`, `API7:2023-Server Side Request Forgery`, `API8:2023-Security Misconfiguration`, `API9:2023-Improper Inventory Management`, `API10:2023-Unsafe Consumption of APIs`.

Rules:
- Content must describe genuine, documented security concepts. No invented CWE IDs, CVEs or URLs.
- References: the CWE page is required; add OWASP Cheat Sheet Series / OWASP Top 10 / vendor docs only when the URL is one you are certain exists.
- CVEs: only include famous, unambiguous ones (Log4Shell, Heartbleed, Shellshock, ...). An empty list is fine.
- Run `python3 knowledge/validate.py` after editing.
