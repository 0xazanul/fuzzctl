from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .advanced_tools import advanced_tool_status
from .builder import build_profile, harness_binary
from .campaign_common import _file_target_argv, _merge_harness_env
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, ensure_dir, find_latest_run, read_json, rel_to, run_cmd, write_json


def _text_tail(path: Path, limit: int = 6000) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[-limit:]


def _eligible_harnesses(manifest: TargetManifest) -> list[Harness]:
    return [
        h
        for h in manifest.harnesses
        if h.type in {"file", "stdin"} and (not h.profiles or "afl_asan_ubsan" in h.profiles or "symcc" in h.profiles)
    ]


def _afl_instances(run_dir: Path, harness: Harness) -> list[str]:
    root = run_dir / "aflpp" / harness.name / "findings"
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "fuzzer_stats").exists())


def _choose_instance(instances: list[str], requested: str | None) -> str:
    if requested:
        if requested not in instances:
            raise FuzzCtlError(f"AFL instance {requested!r} not found; available: {', '.join(instances) or 'none'}")
        return requested
    for item in instances:
        if item.startswith("sec"):
            return item
    if "main" in instances:
        return "main"
    if not instances:
        raise FuzzCtlError("no AFL++ instances found for hybrid run")
    return instances[0]


def _resolve_run_dir(workspace: Path, manifest: TargetManifest, run_id: str | None) -> Path:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    if not (run_dir / "aflpp").exists():
        raise FuzzCtlError(f"run has no AFL++ output for hybrid sync: {rel_to(run_dir, workspace)}")
    return run_dir


def _select_harnesses(manifest: TargetManifest, harness_name: str | None, all_harnesses: bool) -> list[Harness]:
    harnesses = _eligible_harnesses(manifest)
    if harness_name:
        selected = [h for h in harnesses if h.name == harness_name]
        if not selected:
            raise FuzzCtlError(f"AFL++/SymCC-eligible file/stdin harness not found: {harness_name}")
        return selected
    return harnesses if all_harnesses else harnesses[:1]


def _symcc_helper_cmd(symcc: dict[str, Any], run_dir: Path, harness: Harness, instance: str, binary: Path) -> list[str]:
    findings = run_dir / "aflpp" / harness.name / "findings"
    return [
        str(symcc["helper"]),
        "-o",
        str(findings),
        "-a",
        instance,
        "-n",
        f"symcc-{harness.name}",
        "--",
        *_file_target_argv(binary, harness, "@@"),
    ]


def _missing_tool_packet(workspace: Path, manifest: TargetManifest, symcc: dict[str, Any]) -> dict[str, Any]:
    out = ensure_dir(workspace / "workorders" / manifest.name / "hybrid")
    result = {
        "target": manifest.name,
        "status": "skipped",
        "reason": "SymCC is not installed or symcc_fuzzing_helper is missing",
        "required": symcc,
    }
    write_json(out / "symcc-hybrid.json", result)
    print(f"SymCC hybrid skipped: {result['reason']}")
    print(f"setup packet: {rel_to(out / 'symcc-hybrid.json', workspace)}")
    return result


def _dry_run_plan(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path,
    out: Path,
    harnesses: list[Harness],
    symcc: dict[str, Any],
    afl_instance: str | None,
    seconds: int,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for harness in harnesses:
        binary = harness_binary(workspace, manifest, "symcc", harness)
        instances = _afl_instances(run_dir, harness)
        instance = _choose_instance(instances, afl_instance) if instances else None
        item: dict[str, Any] = {
            "harness": harness.name,
            "status": "ready_to_attempt" if instances else "blocked",
            "reason": None if instances else "no AFL++ fuzzer_stats instance found",
            "afl_instances": instances,
            "afl_instance": instance,
            "symcc_binary": str(binary),
            "symcc_binary_exists": binary.exists(),
            "build_required": not binary.exists(),
            "cmd_preview": _symcc_helper_cmd(symcc, run_dir, harness, instance, binary) if instance else None,
        }
        results.append(item)

    payload = {
        "target": manifest.name,
        "run": str(run_dir),
        "engine": "symcc-hybrid",
        "mode": "dry_run",
        "seconds": seconds,
        "results": results,
        "status": "ready_to_attempt" if any(item["status"] == "ready_to_attempt" for item in results) else "blocked",
    }
    write_json(out / "symcc-hybrid-plan.json", payload)
    print(f"SymCC hybrid dry-run: {rel_to(out / 'symcc-hybrid-plan.json', workspace)}")
    return payload


def _build_symcc_or_packet(workspace: Path, manifest: TargetManifest, run_dir: Path, out: Path) -> dict[str, Any] | None:
    try:
        build_profile(workspace, manifest, "symcc")
        return None
    except FuzzCtlError as exc:
        build_log = workspace / "build" / manifest.name / "symcc" / "build.log"
        payload = {
            "target": manifest.name,
            "run": str(run_dir),
            "engine": "symcc-hybrid",
            "status": "build_failed",
            "reason": str(exc),
            "build_log": str(build_log) if build_log.exists() else None,
            "build_log_tail": _text_tail(build_log),
            "action": "Keep the AFL++/libFuzzer campaign running; isolate the unsupported SymCC compile unit before retrying hybrid mode.",
        }
        write_json(out / "symcc-hybrid.json", payload)
        print(f"SymCC hybrid build failed: {rel_to(out / 'symcc-hybrid.json', workspace)}")
        return payload


def _run_one_harness(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path,
    out: Path,
    harness: Harness,
    symcc: dict[str, Any],
    afl_instance: str | None,
    seconds: int,
) -> dict[str, Any]:
    binary = harness_binary(workspace, manifest, "symcc", harness)
    if not binary.exists():
        raise FuzzCtlError(f"SymCC binary missing after build: {binary}")
    instances = _afl_instances(run_dir, harness)
    if not instances:
        return {"harness": harness.name, "status": "skipped", "reason": "no AFL++ fuzzer_stats instance found"}

    instance = _choose_instance(instances, afl_instance)
    harness_out = ensure_dir(out / harness.name)
    symcc_output = ensure_dir(harness_out / "generated")
    cmd = _symcc_helper_cmd(symcc, run_dir, harness, instance, binary)
    env = _merge_harness_env(os.environ.copy(), harness)
    env["SYMCC_OUTPUT_DIR"] = str(symcc_output)
    result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=env, timeout=seconds, print_cmd=True)
    log = harness_out / "symcc.log"
    log.write_text(result.output, encoding="utf-8", errors="replace")
    generated = sorted(p for p in symcc_output.rglob("*") if p.is_file())
    return {
        "harness": harness.name,
        "afl_instance": instance,
        "status": "timeout_complete" if result.returncode == 124 else ("ok" if result.returncode == 0 else "error"),
        "returncode": result.returncode,
        "seconds": round(result.duration_s, 3),
        "generated_inputs": len(generated),
        "log": str(log),
        "cmd": cmd,
    }


def symcc_hybrid_run(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    seconds: int = 1800,
    harness_name: str | None = None,
    afl_instance: str | None = None,
    all_harnesses: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    status = advanced_tool_status(workspace)
    symcc = status["symcc"]
    if not symcc.get("installed"):
        return _missing_tool_packet(workspace, manifest, symcc)

    if seconds <= 0:
        raise FuzzCtlError("--seconds must be greater than zero")

    run_dir = _resolve_run_dir(workspace, manifest, run_id)
    harnesses = _select_harnesses(manifest, harness_name, all_harnesses)
    out = ensure_dir(run_dir / "hybrid" / "symcc")
    if dry_run:
        return _dry_run_plan(workspace, manifest, run_dir, out, harnesses, symcc, afl_instance, seconds)

    build_failure = _build_symcc_or_packet(workspace, manifest, run_dir, out)
    if build_failure:
        return build_failure

    results = [
        _run_one_harness(workspace, manifest, run_dir, out, harness, symcc, afl_instance, seconds)
        for harness in harnesses
    ]
    payload = {
        "target": manifest.name,
        "run": str(run_dir),
        "engine": "symcc-hybrid",
        "seconds": seconds,
        "results": results,
        "status": "ok" if any(item.get("status") in {"ok", "timeout_complete"} for item in results) else "skipped",
    }
    write_json(out / "symcc-hybrid.json", payload)
    print(f"SymCC hybrid output: {rel_to(out, workspace)}")
    return payload
