from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import read_json, rel_to


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def severity_value(severity: object) -> int:
    return SEVERITY_RANK.get(str(severity).upper(), -1)


def duplicate_count(item: dict[str, Any]) -> int:
    try:
        return max(0, int(item.get("duplicates", 0) or 0))
    except (TypeError, ValueError):
        return 0


def crash_artifact_count(item: dict[str, Any]) -> int:
    try:
        explicit = int(item.get("raw_artifacts", 0) or 0)
    except (TypeError, ValueError):
        explicit = 0
    if explicit > 0:
        return explicit
    return duplicate_count(item) + 1


def normalize_crash_item(item: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(item)
    artifacts = crash_artifact_count(normalized)
    duplicates = max(0, artifacts - 1)
    normalized["raw_artifacts"] = artifacts
    normalized["duplicates"] = duplicates
    normalized["duplicate_artifacts"] = duplicates
    return normalized


def load_run_findings(workspace: Path, target: str, triage_path: Path) -> list[dict[str, Any]]:
    try:
        data = read_json(triage_path)
    except Exception:
        return []

    run_dir = triage_path.parents[1]
    findings = []
    for crash in data.get("crashes", []):
        item = normalize_crash_item(crash)
        item["run_id"] = run_dir.name
        item["run_path"] = rel_to(run_dir, workspace)
        report_path = run_dir / "reports" / f"{item.get('id')}.md"
        if report_path.exists():
            item["report"] = rel_to(report_path, workspace)
        item["target"] = target
        findings.append(item)
    return findings


def _dedupe_key(item: dict[str, Any]) -> str:
    state = str(item.get("state") or "").strip()
    if state:
        return f"state:{state}"
    crash_id = str(item.get("id") or "").strip()
    if crash_id:
        return f"id:{crash_id}"
    return "|".join(
        [
            str(item.get("type", "unknown")),
            str(item.get("access", "unknown")),
            str(item.get("harness", "unknown")),
            str(item.get("trace_path", "")),
        ]
    )


def _size_score(item: dict[str, Any]) -> int:
    for key in ("minimized_size", "original_size"):
        try:
            value = int(item.get(key, 0) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return -value
    return 0


def _representative_score(item: dict[str, Any]) -> tuple[int, int, int, int, str, int]:
    return (
        1 if item.get("reproducible") else 0,
        severity_value(item.get("severity")),
        1 if item.get("report") else 0,
        1 if item.get("minimized_path") else 0,
        str(item.get("run_id", "")),
        _size_score(item),
    )


def _merge_group(group: dict[str, Any], item: dict[str, Any]) -> None:
    run_id = str(item.get("run_id", ""))
    if run_id and run_id not in group["run_ids"]:
        group["run_ids"].append(run_id)
    report = item.get("report")
    if report and report not in group["reports"]:
        group["reports"].append(report)

    group["items"].append(item)
    group["raw_artifacts"] += crash_artifact_count(item)
    group["run_duplicate_artifacts"] += duplicate_count(item)
    group["reproducible"] = bool(group["reproducible"] or item.get("reproducible"))

    best = group.get("representative")
    if best is None or _representative_score(item) > _representative_score(best):
        group["representative"] = item


def _finalize_group(group: dict[str, Any]) -> dict[str, Any]:
    representative = dict(group["representative"])
    run_ids = sorted(group["run_ids"])
    raw_artifacts = max(1, int(group["raw_artifacts"]))
    duplicate_artifacts = max(0, raw_artifacts - 1)
    representative["occurrences"] = len(group["items"])
    representative["run_ids"] = run_ids
    representative["reports"] = sorted(group["reports"])
    representative["first_seen"] = run_ids[0] if run_ids else representative.get("run_id")
    representative["last_seen"] = run_ids[-1] if run_ids else representative.get("run_id")
    representative["raw_artifacts"] = raw_artifacts
    representative["run_duplicate_artifacts"] = int(group["run_duplicate_artifacts"])
    representative["cross_run_duplicates"] = max(0, len(group["items"]) - 1)
    representative["duplicate_artifacts"] = duplicate_artifacts
    representative["duplicates"] = duplicate_artifacts
    return representative


def target_findings(workspace: Path, target: str) -> dict[str, Any]:
    target_runs = workspace / "runs" / target
    if not target_runs.exists():
        return {
            "total": 0,
            "triaged": 0,
            "triaged_artifacts": 0,
            "reproducible": 0,
            "high_or_critical": 0,
            "raw_artifacts": 0,
            "duplicate_artifacts": 0,
            "cross_run_duplicates": 0,
            "findings": [],
        }

    run_items: list[dict[str, Any]] = []
    for triage_path in sorted(target_runs.glob("*/triage/unique_crashes.json")):
        run_items.extend(load_run_findings(workspace, target, triage_path))

    groups: dict[str, dict[str, Any]] = {}
    for item in run_items:
        key = _dedupe_key(item)
        group = groups.setdefault(
            key,
            {
                "items": [],
                "run_ids": [],
                "reports": [],
                "raw_artifacts": 0,
                "run_duplicate_artifacts": 0,
                "reproducible": False,
                "representative": None,
            },
        )
        _merge_group(group, item)

    grouped = [_finalize_group(group) for group in groups.values() if group.get("representative")]
    reproducible = [item for item in grouped if item.get("reproducible")]
    reproducible.sort(
        key=lambda item: (
            severity_value(item.get("severity")),
            str(item.get("last_seen", item.get("run_id", ""))),
            int(item.get("raw_artifacts", 1) or 1),
        ),
        reverse=True,
    )
    high_or_critical = [
        item for item in reproducible
        if str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    return {
        "total": len(reproducible),
        "triaged": len(run_items),
        "triaged_artifacts": sum(crash_artifact_count(item) for item in run_items),
        "reproducible": len(reproducible),
        "high_or_critical": len(high_or_critical),
        "raw_artifacts": sum(crash_artifact_count(item) for item in reproducible),
        "duplicate_artifacts": sum(max(0, int(item.get("raw_artifacts", 1) or 1) - 1) for item in reproducible),
        "cross_run_duplicates": sum(max(0, int(item.get("occurrences", 1) or 1) - 1) for item in reproducible),
        "findings": reproducible,
    }
