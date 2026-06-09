from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .crash_value_frames import parse_frames, root_frame, safe_read
from .crash_value_scoring import (
    TIER_LABELS,
    TIER_ORDER,
    base_score,
    claim_for,
    crash_class,
    harness_suspicion,
    primitive_for,
    product_mapping,
    quality_bonus,
    tier_and_blocker,
)
from .findings import crash_artifact_count, duplicate_count, severity_value, target_findings
from .manifest import TargetManifest
from .util import read_json, rel_to, write_json


def crash_value_path(workspace: Path, target: str) -> Path:
    return workspace / "state" / "crash_value" / f"{target}.json"


def load_crash_value(workspace: Path, target: str) -> dict[str, Any] | None:
    path = crash_value_path(workspace, target)
    if not path.exists():
        return None
    try:
        return read_json(path)
    except Exception:
        return None


def analyze_crash_item(workspace: Path, manifest: TargetManifest, item: dict[str, Any]) -> dict[str, Any]:
    source_dir = manifest.source_dir(workspace)
    trace = safe_read(item.get("trace_path"))
    frames = parse_frames(trace, source_dir)
    root = root_frame(frames)
    crash_kind = crash_class(item)
    harness = harness_suspicion(frames, root, trace)
    product = product_mapping(manifest, root)
    tier, blocker = tier_and_blocker(item, crash_kind, root, harness, product)

    score = base_score(item, crash_kind) + quality_bonus(item)
    if product["status"] == "source_mapped_product_plausible":
        score += 14
    if tier == "product_plausible":
        score += 8
    if tier == "report_candidate":
        score += 20
    if harness["suspect"]:
        score -= 45
    if product["status"] == "source_mapped_cli_or_tooling":
        score -= 18
    if not item.get("minimized_path"):
        score -= 8
    score = max(0, min(100, score))

    return {
        "id": item.get("id"),
        "target": manifest.name,
        "run_id": item.get("run_id"),
        "run_path": item.get("run_path"),
        "tier": tier,
        "tier_label": TIER_LABELS[tier],
        "score": score,
        "next_required_proof": blocker,
        "crash_class": crash_kind,
        "type": item.get("type"),
        "severity": item.get("severity"),
        "access": item.get("access"),
        "harness": item.get("harness"),
        "raw_artifacts": crash_artifact_count(item),
        "duplicates": duplicate_count(item),
        "occurrences": item.get("occurrences", 1),
        "reproducible": bool(item.get("reproducible")),
        "minimized_path": item.get("minimized_path"),
        "minimized_size": item.get("minimized_size"),
        "original_path": item.get("original_path"),
        "original_size": item.get("original_size"),
        "binary": item.get("binary"),
        "profile": item.get("profile"),
        "repro_cmd": item.get("repro_cmd"),
        "trace_path": item.get("trace_path"),
        "report": item.get("report"),
        "state": item.get("state"),
        "root_cause": {
            "function": root.get("function") if root else None,
            "file": root.get("rel_file") if root else None,
            "line": root.get("line") if root else None,
            "column": root.get("column") if root else None,
        },
        "harness_assessment": harness,
        "product_mapping": product,
        "exploitability": {
            "attacker_control": "input-bytes-control" if item.get("reproducible") else "unproven",
            "primitive": primitive_for(crash_kind, str(item.get("access") or "unknown")),
            "claim": claim_for(tier, crash_kind, product),
        },
        "frames": frames[:8],
    }


def analyze_target_crash_value(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    write: bool = False,
) -> dict[str, Any]:
    findings = target_findings(workspace, manifest.name)
    records = []
    for item in findings.get("findings", []):
        if run_id and str(item.get("run_id")) != run_id and run_id not in list(item.get("run_ids", [])):
            continue
        records.append(analyze_crash_item(workspace, manifest, item))

    records.sort(
        key=lambda item: (
            TIER_ORDER.get(str(item.get("tier")), -1),
            int(item.get("score", 0)),
            severity_value(item.get("severity")),
            int(item.get("raw_artifacts", 0)),
        ),
        reverse=True,
    )
    tier_counts = {tier: 0 for tier in TIER_ORDER}
    for record in records:
        tier_counts[str(record.get("tier"))] = tier_counts.get(str(record.get("tier")), 0) + 1

    result = {
        "schema": 1,
        "target": manifest.name,
        "run_id": run_id,
        "source_path": manifest.source_path,
        "summary": {
            "total": len(records),
            "tier_counts": tier_counts,
            "report_candidates": tier_counts.get("report_candidate", 0),
            "product_plausible": tier_counts.get("product_plausible", 0),
            "valid_target_bugs": tier_counts.get("valid_target_bug", 0),
            "noise": tier_counts.get("noise", 0),
            "top_score": records[0]["score"] if records else 0,
        },
        "tools": {
            "casr_available": bool(shutil.which("casr-san") or shutil.which("casr-gdb") or shutil.which("casr-afl")),
            "fuzz_introspector_available": bool(shutil.which("fuzz-introspector")),
        },
        "records": records,
    }
    if write:
        write_json(crash_value_path(workspace, manifest.name), result)
    return result


def print_crash_value(result: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(__import__("json").dumps(result, indent=2, sort_keys=True))
        return
    summary = result.get("summary", {})
    print(
        f"crash value {result.get('target')}: total={summary.get('total', 0)} "
        f"product_plausible={summary.get('product_plausible', 0)} "
        f"report_candidates={summary.get('report_candidates', 0)} "
        f"noise={summary.get('noise', 0)}"
    )
    for record in result.get("records", [])[:15]:
        root = record.get("root_cause") or {}
        location = root.get("file") or "unknown"
        if root.get("line"):
            location += f":{root.get('line')}"
        print(
            f"{record.get('id')} {record.get('tier')} score={record.get('score')} "
            f"{record.get('crash_class')} {location} next={record.get('next_required_proof')}"
        )


def rel_record_paths(record: dict[str, Any], workspace: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("minimized_path", "trace_path"):
        value = record.get(key)
        if value:
            out[key] = rel_to(Path(str(value)), workspace)
    if record.get("report"):
        out["report"] = str(record.get("report"))
    return out
