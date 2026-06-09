from __future__ import annotations

import math
import re
from typing import Any

from .findings import crash_artifact_count
from .manifest import TargetManifest


TIER_ORDER = {
    "report_candidate": 4,
    "product_plausible": 3,
    "valid_target_bug": 2,
    "needs_repro": 1,
    "noise": 0,
}

TIER_LABELS = {
    "report_candidate": "Report Candidate",
    "product_plausible": "Product Plausible",
    "valid_target_bug": "Valid Target Bug",
    "needs_repro": "Needs Repro",
    "noise": "Noise",
}


def crash_class(item: dict[str, Any]) -> str:
    ctype = str(item.get("type") or "unknown-crash").lower()
    access = str(item.get("access") or "unknown").lower()
    if "use-after" in ctype or "double-free" in ctype or "bad-free" in ctype or "invalid-free" in ctype:
        return "lifetime-corruption"
    if "buffer-overflow" in ctype and access == "write":
        return "out-of-bounds-write"
    if "buffer-overflow" in ctype:
        return "out-of-bounds-read"
    if "integer" in ctype:
        return "integer-undefined-behavior"
    if "undefined" in ctype:
        return "undefined-behavior"
    if "memory-leak" in ctype or "leak" in ctype:
        return "memory-leak"
    if "null" in ctype or ctype == "segv":
        return "crash-dos"
    return "unknown"


def product_mapping(manifest: TargetManifest, root: dict[str, Any] | None) -> dict[str, Any]:
    _ = (manifest, root)
    return {
        "vendor": "unknown",
        "component": "unknown",
        "status": "unmapped",
        "verification": "not_verified",
        "notes": "No product mapping rule exists for this target yet.",
    }


def harness_suspicion(frames: list[dict[str, Any]], root: dict[str, Any] | None, trace: str) -> dict[str, Any]:
    first = frames[0] if frames else {}
    root_rel = str((root or {}).get("rel_file") or "")
    first_rel = str(first.get("rel_file") or first.get("file") or "")
    reasons: list[str] = []
    score = 0
    if "fuzz_harnesses/" in first_rel:
        score += 70
        reasons.append("top crashing frame is harness glue")
    if "fuzz_harnesses/" in root_rel:
        score += 60
        reasons.append("root frame is harness glue")
    if re.search(r"frame\s+#0.*fuzz_harnesses|in main .*fuzz_harnesses", trace, re.I | re.S):
        score += 10
        reasons.append("ASan stack object belongs to the harness frame")
    if "Clients/dns-sd.c" in root_rel:
        score += 20
        reasons.append("root frame is a command-line client parser path")
    return {"score": min(score, 100), "reasons": reasons, "suspect": score >= 60}


def base_score(item: dict[str, Any], crash_kind: str) -> int:
    access = str(item.get("access") or "unknown").lower()
    ctype = str(item.get("type") or "").lower()
    if crash_kind in {"out-of-bounds-write", "lifetime-corruption"}:
        return 88
    if crash_kind == "out-of-bounds-read":
        return 62 if access == "read" else 55
    if crash_kind == "integer-undefined-behavior":
        return 42
    if crash_kind == "crash-dos":
        return 30
    if crash_kind == "memory-leak":
        return 12
    if "undefined" in ctype:
        return 18
    return 8


def quality_bonus(item: dict[str, Any]) -> int:
    score = 0
    artifacts = crash_artifact_count(item)
    if artifacts > 1:
        score += min(10, int(math.log2(artifacts)) + 1)
    if item.get("minimized_path"):
        score += 5
    if item.get("report"):
        score += 3
    return score


def tier_and_blocker(
    item: dict[str, Any],
    crash_kind: str,
    root: dict[str, Any] | None,
    harness: dict[str, Any],
    product: dict[str, Any],
) -> tuple[str, str]:
    if not item.get("reproducible"):
        return "needs_repro", "Reproduce under ASan/UBSan and capture a symbolized trace."
    if crash_kind in {"memory-leak", "undefined-behavior", "unknown"}:
        return "noise", "Prove product-triggerable security impact; otherwise keep as low-value noise."
    if harness["suspect"]:
        return "noise", "Replace or harden the harness shim, then prove the same root cause through a production API."
    if root is None:
        return "needs_repro", "Capture a symbolized stack trace with a target root frame."
    if not item.get("minimized_path"):
        return "valid_target_bug", "Minimize the testcase before any report-quality analysis."
    if product["status"] == "source_mapped_product_plausible":
        if product["verification"] == "verified":
            return "report_candidate", "Write the final report with product reproduction and attacker-control evidence."
        return "product_plausible", "Verify this input or equivalent input against a shipped product path."
    if product["status"] == "source_mapped_cli_or_tooling":
        return "valid_target_bug", "Find a non-CLI shipped path or document this as a client-tool-only bug."
    return "valid_target_bug", "Map the root frame to a shipped product surface and attacker-controlled input path."


def primitive_for(crash_kind: str, access: str) -> str:
    if crash_kind == "out-of-bounds-write":
        return "memory-corruption-write"
    if crash_kind == "lifetime-corruption":
        return "lifetime-corruption"
    if crash_kind == "out-of-bounds-read":
        return "out-of-bounds-read"
    if crash_kind == "crash-dos":
        return "denial-of-service"
    if crash_kind == "integer-undefined-behavior":
        return "integer-ub"
    return access if access != "unknown" else "unproven"


def claim_for(tier: str, crash_kind: str, product: dict[str, Any]) -> str:
    if tier == "noise":
        return "Do not report until stronger evidence exists."
    if tier == "product_plausible":
        return "Potential product-relevant bug; product verification still required."
    if tier == "report_candidate":
        return "Report-ready candidate after final human review."
    if product["status"] == "source_mapped_cli_or_tooling":
        return "Source bug in tooling path; service/product impact not proven."
    if crash_kind == "out-of-bounds-read":
        return "Likely DoS/read primitive; do not claim RCE without stronger primitive evidence."
    return "Valid sanitizer bug; reachability and product impact still need proof."
