"""SecureMatrix risk score (sm-risk-v1).

This is an internal prioritisation score from 0 to 100. It is NOT a CVSS score and
the UI never presents it as one.

    score = 100 * severity_weight * exploitability * exposure * confidence

Every factor and the reason it was chosen are stored in `risk_rationale`, so the
number can always be explained.
"""
from __future__ import annotations

import re

MODEL_VERSION = "sm-risk-v1"

SEVERITY_WEIGHT = {"critical": 0.95, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.05}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.7}

# Weakness classes that commonly lead to direct remote compromise or data access.
HIGH_EXPLOITABILITY = {
    "CWE-77", "CWE-78", "CWE-88", "CWE-89", "CWE-94", "CWE-95", "CWE-502", "CWE-22", "CWE-23", "CWE-918",
    "CWE-611", "CWE-434", "CWE-798", "CWE-321", "CWE-306", "CWE-287", "CWE-639", "CWE-862", "CWE-917",
    "CWE-1336", "CWE-943", "CWE-90", "CWE-643", "CWE-347",
}
MEDIUM_EXPLOITABILITY = {
    "CWE-79", "CWE-352", "CWE-601", "CWE-942", "CWE-327", "CWE-328", "CWE-916", "CWE-330", "CWE-338",
    "CWE-295", "CWE-319", "CWE-384", "CWE-614", "CWE-1004", "CWE-73", "CWE-200", "CWE-209", "CWE-532",
    "CWE-1321", "CWE-915", "CWE-400", "CWE-770", "CWE-1333", "CWE-113", "CWE-117",
}

_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|examples?|samples?|fixtures?|mocks?)(/|$)|(_test|\.test|\.spec)\.\w+$", re.I)
_ENTRY_PATH = re.compile(r"(^|/)(routes?|controllers?|api|views?|handlers?|endpoints?|server|app|main|index|web|public)([/._]|$)", re.I)
_CONFIG_PATH = re.compile(r"(\.(ya?ml|json|toml|ini|cfg|conf|properties|env|tf)$)|dockerfile|settings\.py$|config", re.I)


def exploitability(cwes: list[str]) -> tuple[float, str]:
    if any(c in HIGH_EXPLOITABILITY for c in cwes):
        return 1.0, "weakness class is commonly exploitable remotely with direct impact"
    if any(c in MEDIUM_EXPLOITABILITY for c in cwes):
        return 0.8, "weakness class usually needs extra conditions (user interaction, network position, chaining)"
    if cwes:
        return 0.65, "weakness class is rarely exploitable on its own"
    return 0.6, "no CWE mapping; exploitability unknown"


def exposure(path: str) -> tuple[float, str]:
    if _TEST_PATH.search(path):
        return 0.4, "file looks like test, example or fixture code"
    if _ENTRY_PATH.search(path):
        return 1.0, "file looks like an entry point (route, controller, handler, server)"
    if _CONFIG_PATH.search(path):
        return 0.9, "configuration file affecting deployed behaviour"
    return 0.8, "application code; exposure not determined statically"


def score(severity: str, confidence: str, cwes: list[str], path: str) -> tuple[float, str, dict]:
    sev_w = SEVERITY_WEIGHT.get(severity, 0.5)
    expl, expl_reason = exploitability(cwes)
    expo, expo_reason = exposure(path)
    conf = CONFIDENCE_FACTOR.get(confidence, 0.85)
    value = round(100 * sev_w * expl * expo * conf, 1)
    priority = "P1" if value >= 65 else "P2" if value >= 40 else "P3" if value >= 15 else "P4"
    rationale = {
        "model": MODEL_VERSION,
        "formula": "100 x severity x exploitability x exposure x confidence",
        "factors": [
            {"name": "severity", "value": sev_w, "reason": f"scanner severity mapped to '{severity}'"},
            {"name": "exploitability", "value": expl, "reason": expl_reason},
            {"name": "exposure", "value": expo, "reason": expo_reason},
            {"name": "confidence", "value": conf, "reason": f"rule confidence '{confidence}'"},
        ],
        "note": "Internal prioritisation score, not an official CVSS score.",
    }
    return value, priority, rationale
