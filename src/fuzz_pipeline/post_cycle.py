from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from .corpus import corpus_sync
from .coverage import coverage_run
from .coverage_guidance import coverage_guidance
from .crash_value import analyze_target_crash_value
from .advanced_triage import advanced_triage_run
from .harness import harness_blockers, harness_qa, suspicious_points
from .manifest import TargetManifest
from .monitor import monitor_once
from .reporting import report_run
from .triage import minimize_run, triage_run
from .util import FuzzCtlError, ensure_dir, find_latest_run, read_json, rel_to, write_json


def _triage_counts(run_dir: Path) -> dict[str, int]:
    path = run_dir / "triage" / "unique_crashes.json"
    if not path.exists():
        return {"raw_crashes": 0, "unique_crashes": 0, "duplicate_crashes": 0}
    try:
        data = read_json(path)
    except Exception:
        return {"raw_crashes": 0, "unique_crashes": 0, "duplicate_crashes": 0}
    return {
        "raw_crashes": int(data.get("raw_crashes", 0) or 0),
        "unique_crashes": int(data.get("unique_crashes", len(data.get("crashes", []))) or 0),
        "duplicate_crashes": int(data.get("duplicate_crashes", 0) or 0),
    }


def _step_result(name: str, status: str, started: float, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "seconds": round(time.monotonic() - started, 3),
        **extra,
    }


def post_cycle_run(
    workspace: Path,
    manifest: TargetManifest,
    run_id: str | None = None,
    *,
    coverage_inputs: int = 5000,
    corpus_inputs: int = 20000,
    webhook: str | None = None,
    no_alerts: bool = False,
    continue_on_error: bool = True,
) -> dict[str, Any]:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    out = ensure_dir(run_dir / "post_cycle")
    steps: list[dict[str, Any]] = []

    def run_step(name: str, fn: Callable[[], Any]) -> Any:
        started = time.monotonic()
        try:
            value = fn()
        except Exception as exc:
            steps.append(_step_result(name, "failed", started, error=str(exc), error_type=type(exc).__name__))
            if not continue_on_error:
                raise
            return None
        result: dict[str, Any] = {}
        if isinstance(value, Path):
            result["path"] = rel_to(value, workspace)
        elif isinstance(value, dict):
            result["summary"] = value.get("summary", value)
        elif value is not None:
            result["value"] = str(value)
        steps.append(_step_result(name, "ok", started, **result))
        return value

    def skip_step(name: str, reason: str) -> None:
        steps.append({"name": name, "status": "skipped", "reason": reason, "seconds": 0})

    run_step(
        "monitor",
        lambda: monitor_once(
            workspace,
            manifest,
            run_id=run_dir.name,
            webhook=webhook,
            no_alerts=no_alerts,
            triage=True,
        ),
    )
    run_step("triage", lambda: triage_run(workspace, manifest, run_dir.name))
    counts = _triage_counts(run_dir)

    if counts["unique_crashes"] > 0:
        run_step("minimize", lambda: minimize_run(workspace, manifest, run_dir.name))
        run_step("report", lambda: report_run(workspace, manifest, run_dir.name))
    else:
        skip_step("minimize", "no unique crashes")
        skip_step("report", "no unique crashes")

    run_step("crash-value", lambda: analyze_target_crash_value(workspace, manifest, run_id=run_dir.name, write=True))
    run_step("advanced-triage", lambda: advanced_triage_run(workspace, manifest, run_id=run_dir.name))
    run_step("corpus-sync", lambda: corpus_sync(workspace, manifest, run_dir.name, max_inputs=corpus_inputs))
    run_step("coverage", lambda: coverage_run(workspace, manifest, run_dir.name, max_inputs=coverage_inputs))
    run_step("coverage-guidance", lambda: coverage_guidance(workspace, manifest, run_dir.name))
    run_step("harness-blockers", lambda: harness_blockers(workspace, manifest, run_id=run_dir.name, as_json=False))
    run_step("suspicious-points", lambda: suspicious_points(workspace, manifest, run_id=run_dir.name, as_json=False))
    run_step("harness-qa", lambda: harness_qa(workspace, manifest, run_id=run_dir.name, as_json=False))

    failed = [step for step in steps if step.get("status") == "failed"]
    result = {
        "target": manifest.name,
        "run_id": run_dir.name,
        "run": str(run_dir),
        "status": "partial" if failed else "ok",
        "coverage_inputs": coverage_inputs,
        "corpus_inputs": corpus_inputs,
        "triage": _triage_counts(run_dir),
        "steps": steps,
        "failed_steps": [step["name"] for step in failed],
        "updated_at": int(time.time()),
    }
    write_json(out / "post_cycle.json", result)
    lines = [f"# Post-Cycle: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace)}`", "", f"Status: `{result['status']}`", ""]
    lines.append("## Steps")
    lines.append("")
    for step in steps:
        detail = step.get("path") or step.get("reason") or step.get("error") or ""
        lines.append(f"- `{step['status']}` `{step['name']}` {detail}")
    (out / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"post-cycle: {rel_to(out, workspace)}")
    if failed:
        print(f"failed steps: {', '.join(result['failed_steps'])}")
        if not continue_on_error:
            raise FuzzCtlError(f"post-cycle failed: {', '.join(result['failed_steps'])}")
    return result
