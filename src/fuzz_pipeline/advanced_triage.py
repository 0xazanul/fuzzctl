from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .advanced_tools import advanced_tool_status
from .manifest import TargetManifest
from .triage import triage_run
from .util import ensure_dir, find_latest_run, read_json, rel_to, run_cmd, write_json


def _load_crashes(workspace: Path, manifest: TargetManifest, run_id: str | None) -> tuple[Path, list[dict[str, Any]]]:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    triage_file = run_dir / "triage" / "unique_crashes.json"
    if not triage_file.exists():
        triage_run(workspace, manifest, run_dir.name)
    data = read_json(triage_file)
    return run_dir, list(data.get("crashes", []))


def _casr_sanitizer_reports(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path,
    crashes: list[dict[str, Any]],
    out: Path,
    casr_san: str | None,
) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    if not casr_san:
        return [{"status": "skipped", "reason": "casr-san is not installed"}]
    casr_dir = ensure_dir(out / "casr")
    for crash in crashes:
        repro_cmd = [str(part) for part in crash.get("repro_cmd", [])]
        if not repro_cmd:
            reports.append({"id": crash.get("id"), "status": "skipped", "reason": "missing repro_cmd"})
            continue
        report = casr_dir / f"{crash['id']}.casrep"
        cmd = [casr_san, "-o", str(report), "--", *repro_cmd]
        result = run_cmd(cmd, cwd=manifest.source_dir(workspace), timeout=max(20, manifest.timeout_ms // 1000 + 20), print_cmd=True)
        log = casr_dir / f"{crash['id']}.log"
        log.write_text(result.output, encoding="utf-8", errors="replace")
        reports.append(
            {
                "id": crash.get("id"),
                "status": "ok" if report.exists() else "failed",
                "returncode": result.returncode,
                "report": str(report) if report.exists() else None,
                "log": str(log),
            }
        )
    return reports


def _exploitable_reports(
    workspace: Path,
    manifest: TargetManifest,
    crashes: list[dict[str, Any]],
    out: Path,
    exploitable_py: str | None,
) -> list[dict[str, Any]]:
    if not exploitable_py:
        return [{"status": "skipped", "reason": "exploitable.py is not installed or EXPLOITABLE_PY is not set"}]
    reports: list[dict[str, Any]] = []
    gdb_dir = ensure_dir(out / "exploitable")
    for crash in crashes:
        repro_cmd = [str(part) for part in crash.get("repro_cmd", [])]
        if not repro_cmd:
            reports.append({"id": crash.get("id"), "status": "skipped", "reason": "missing repro_cmd"})
            continue
        log = gdb_dir / f"{crash['id']}.gdb.log"
        cmd = [
            "gdb",
            "-q",
            "-batch",
            "-ex",
            f"source {exploitable_py}",
            "-ex",
            "run",
            "-ex",
            "exploitable",
            "--args",
            *repro_cmd,
        ]
        result = run_cmd(cmd, cwd=manifest.source_dir(workspace), timeout=max(30, manifest.timeout_ms // 1000 + 30), print_cmd=True)
        log.write_text(result.output, encoding="utf-8", errors="replace")
        reports.append(
            {
                "id": crash.get("id"),
                "status": "ok" if "Exploitability Classification" in result.output or "exploitable" in result.output.lower() else "unknown",
                "returncode": result.returncode,
                "log": str(log),
            }
        )
    return reports


def advanced_triage_run(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    use_exploitable: bool = True,
    as_json: bool = False,
) -> dict[str, Any]:
    run_dir, crashes = _load_crashes(workspace, manifest, run_id)
    out = ensure_dir(run_dir / "advanced_triage")
    status = advanced_tool_status(workspace)
    casr_commands = status["casr"]["commands"]
    casr_reports = _casr_sanitizer_reports(
        workspace,
        manifest,
        run_dir,
        crashes,
        out,
        casr_commands.get("casr-san"),
    )
    exploitable_reports = (
        _exploitable_reports(workspace, manifest, crashes, out, status["exploitable"].get("path"))
        if use_exploitable
        else [{"status": "skipped", "reason": "disabled"}]
    )
    result = {
        "target": manifest.name,
        "run": str(run_dir),
        "crashes": len(crashes),
        "tool_status": {
            "casr": status["casr"],
            "exploitable": status["exploitable"],
        },
        "casr": casr_reports,
        "exploitable": exploitable_reports,
        "summary": {
            "casr_ok": sum(1 for item in casr_reports if item.get("status") == "ok"),
            "exploitable_ok": sum(1 for item in exploitable_reports if item.get("status") == "ok"),
            "skipped": sum(1 for item in [*casr_reports, *exploitable_reports] if item.get("status") == "skipped"),
        },
    }
    write_json(out / "advanced-triage.json", result)
    md = [f"# Advanced Triage: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace)}`", ""]
    md.append(f"- Crashes: `{len(crashes)}`")
    md.append(f"- CASR reports: `{result['summary']['casr_ok']}`")
    md.append(f"- Exploitable reports: `{result['summary']['exploitable_ok']}`")
    md.append("")
    if result["summary"]["skipped"]:
        md.append("Some tools were skipped because they are not installed. Run `fuzzctl tools advanced` for setup.")
    (out / "README.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"advanced triage: {rel_to(out, workspace)}")
        print(f"casr_ok={result['summary']['casr_ok']} exploitable_ok={result['summary']['exploitable_ok']} skipped={result['summary']['skipped']}")
    return result
