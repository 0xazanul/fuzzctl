from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .harness_metrics import _build_artifacts, _coverage_target_total, _review_data, _seed_count
from .manifest import TargetManifest
from .readiness_gates import (
    advanced_gates,
    campaign_gates,
    compact_snapshot,
    core_harness_gates,
    coverage_gate,
    overall_status,
    triage_gates,
)
from .util import FuzzCtlError, ensure_dir, find_latest_run, rel_to, write_json


def _latest_run_optional(workspace: Path, target: str, run_id: str | None) -> Path | None:
    if run_id:
        run_dir = workspace / "runs" / target / run_id
        if not run_dir.exists():
            raise FuzzCtlError(f"run not found: {rel_to(run_dir, workspace)}")
        return run_dir
    try:
        return find_latest_run(workspace, target)
    except FuzzCtlError:
        return None


def target_readiness(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    as_json: bool = False,
    write: bool = True,
) -> dict[str, Any]:
    run_dir = _latest_run_optional(workspace, manifest.name, run_id)
    review = _review_data(workspace, manifest)
    builds = _build_artifacts(workspace, manifest)
    seed_count = _seed_count(workspace, manifest)
    coverage = _coverage_target_total(run_dir)
    campaign, snap = campaign_gates(workspace, run_dir)
    gates = [
        *core_harness_gates(workspace, manifest, review, builds, seed_count),
        *campaign,
        coverage_gate(run_dir, coverage),
        *triage_gates(run_dir, snap),
        *advanced_gates(workspace, manifest, run_dir, builds),
    ]
    result = {
        "target": manifest.name,
        "run": str(run_dir) if run_dir else None,
        "status": overall_status(gates),
        "summary": _summary(gates),
        "seed_count": seed_count,
        "build_artifacts": builds,
        "coverage": coverage,
        "snapshot": compact_snapshot(snap),
        "gates": gates,
    }
    if write:
        out = ensure_dir(workspace / "workorders" / manifest.name / "readiness")
        write_json(out / "target-readiness.json", result)
        _write_readiness_markdown(workspace, out / "README.md", result)
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_readiness(result)
    return result


def _summary(gates: list[dict[str, str]]) -> dict[str, int]:
    return {
        "gates": len(gates),
        "pass": sum(1 for gate in gates if gate["status"] == "pass"),
        "warn": sum(1 for gate in gates if gate["status"] == "warn"),
        "fail": sum(1 for gate in gates if gate["status"] == "fail"),
        "not_configured": sum(1 for gate in gates if gate["status"] == "not_configured"),
        "not_applicable": sum(1 for gate in gates if gate["status"] == "not_applicable"),
    }


def _write_readiness_markdown(workspace: Path, path: Path, result: dict[str, Any]) -> None:
    lines = [
        f"# Target Readiness: {result['target']}",
        "",
        f"- Status: `{result['status']}`",
        f"- Run: `{rel_to(Path(result['run']), workspace) if result.get('run') else '-'}`",
        "",
        "## Gates",
        "",
        "| Section | Gate | Status | Evidence | Action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for gate in result["gates"]:
        lines.append(
            f"| {gate['section']} | {gate['name']} | `{gate['status']}` | "
            f"{gate['evidence']} | {gate.get('action') or '-'} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_readiness(result: dict[str, Any]) -> None:
    summary = result["summary"]
    print(
        f"readiness {result['target']}: {result['status']} "
        f"pass={summary['pass']} warn={summary['warn']} fail={summary['fail']} "
        f"not_configured={summary['not_configured']}"
    )
    for gate in result["gates"]:
        marker = {
            "pass": "ok",
            "warn": "warn",
            "fail": "fail",
            "not_configured": "skip",
            "not_applicable": "n/a",
        }.get(gate["status"], gate["status"])
        print(f"{marker:4} {gate['section']}/{gate['name']}: {gate['evidence']}")
        if gate.get("action") and gate["status"] in {"fail", "warn"}:
            print(f"     action: {gate['action']}")
