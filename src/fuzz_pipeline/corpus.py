from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .builder import build_profile, harness_binary
from .campaign_common import _asan_env, _file_target_argv
from .corpus_enrichment import (
    _builtin_seed_cases,
    _config_seed_cases,
    _ddns_settings_seed_cases,
    _dnssd_proxy_config_seed_cases,
    _dnssd_relay_config_seed_cases,
    _dns_name,
    _dns_query,
    _dns_response_a,
    _dns_rdata_seed_cases,
    _dns_wire_seed_cases,
    _dnssec_rdata_seed_cases,
    _generic_seed_cases,
    _responder_readline_seed_cases,
    _run_radamsa,
    _srp_filedata_seed_cases,
    _srp_key_config_seed_cases,
    _srp_replication_seed_cases,
    _srp_replication_tlv,
    _write_seed,
    corpus_enrich,
)
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, ensure_dir, find_latest_run, iter_files, rel_to, run_cmd, sha256_file, which, write_json


def _quarantine_input(path: Path, quarantine_dir: Path) -> Path:
    digest = sha256_file(path)[:16]
    suffix = path.suffix if len(path.suffix) <= 16 else ""
    name = f"{path.stem}-{digest}{suffix}"
    destination = quarantine_dir / name
    index = 1
    while destination.exists():
        destination = quarantine_dir / f"{path.stem}-{digest}-{index}{suffix}"
        index += 1
    ensure_dir(quarantine_dir)
    shutil.move(str(path), str(destination))
    return destination


def corpus_prune_crashers(
    workspace: Path,
    manifest: TargetManifest,
    *,
    harness_names: list[str] | None = None,
    timeout_seconds: float = 2.0,
) -> Path:
    root = ensure_dir(workspace / "corpora" / manifest.name)
    selected = set(harness_names or [])
    report: dict[str, Any] = {
        "target": manifest.name,
        "timeout_seconds": timeout_seconds,
        "harnesses": [],
    }

    for harness in manifest.harnesses:
        if harness.type != "file":
            continue
        if selected and harness.name not in selected:
            continue
        current = root / harness.name / "current"
        binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
        summary: dict[str, Any] = {
            "harness": harness.name,
            "input": rel_to(current, workspace),
            "checked": 0,
            "quarantined": 0,
            "skipped": None,
            "crashers": [],
        }
        if not current.exists():
            summary["skipped"] = "corpus directory missing"
            report["harnesses"].append(summary)
            continue
        if not binary.exists():
            summary["skipped"] = f"missing binary {rel_to(binary, workspace)}"
            report["harnesses"].append(summary)
            continue

        env = _asan_env()
        env.update(harness.env)
        quarantine = root / harness.name / "quarantine"
        for path in iter_files([current]):
            summary["checked"] += 1
            result = run_cmd(
                _file_target_argv(binary, harness, str(path)),
                cwd=manifest.source_dir(workspace),
                env=env,
                timeout=timeout_seconds,
            )
            if result.returncode == 0:
                continue
            moved = _quarantine_input(path, quarantine)
            summary["quarantined"] += 1
            summary["crashers"].append(
                {
                    "from": rel_to(path, workspace),
                    "to": rel_to(moved, workspace),
                    "returncode": result.returncode,
                    "output_tail": result.output[-1200:],
                }
            )
        report["harnesses"].append(summary)

    write_json(root / "prune-crashers.json", report)
    print(f"corpus prune output: {rel_to(root, workspace)}")
    return root


def _sample_paths(paths: list[Path], limit: int) -> list[Path]:
    if limit <= 0:
        return []
    if len(paths) <= limit:
        return paths
    head = max(1, limit // 2)
    tail = max(0, limit - head)
    out: list[Path] = []
    seen: set[Path] = set()
    for path in [*paths[:head], *paths[-tail:]]:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out[:limit]


def _harness_inputs(workspace: Path, manifest: TargetManifest, run_dir: Path, harness: Harness, max_inputs: int) -> tuple[list[Path], dict[str, Any]]:
    sources: list[tuple[str, list[Path], bool]] = []
    seed_dir = manifest.seed_dir(workspace)
    if seed_dir.exists():
        sources.append(("seed", iter_files([seed_dir]), True))
    curated = workspace / "corpora" / manifest.name / harness.name / "current"
    if curated.exists():
        sources.append(("curated", iter_files([curated]), True))
    if harness.type == "file":
        afl_root = run_dir / "aflpp" / harness.name / "findings"
        if afl_root.exists():
            sources.append(("afl_queue", sorted(afl_root.glob("*/queue/id:*")), False))
    if harness.type == "libfuzzer":
        lf_root = run_dir / "libfuzzer" / harness.name / "corpus"
        if lf_root.exists():
            sources.append(("libfuzzer_corpus", iter_files([lf_root]), False))

    selected: list[Path] = []
    seen_hashes: set[str] = set()
    summary: dict[str, Any] = {"harness": harness.name, "sources": {}, "selected": 0, "deduped": 0}

    for label, paths, force in sources:
        source = {"discovered": len(paths), "selected": 0, "deduped": 0}
        remaining = max_inputs - len(selected)
        candidates = paths if force else _sample_paths(paths, remaining)
        for path in candidates:
            if len(selected) >= max_inputs and not force:
                break
            if not path.is_file():
                continue
            digest = sha256_file(path)
            if digest in seen_hashes:
                source["deduped"] += 1
                summary["deduped"] += 1
                continue
            seen_hashes.add(digest)
            selected.append(path)
            source["selected"] += 1
        summary["sources"][label] = source
    summary["selected"] = len(selected)
    return selected, summary


def _copy_inputs(inputs: list[Path], out_dir: Path) -> None:
    ensure_dir(out_dir)
    for index, path in enumerate(inputs):
        digest = sha256_file(path)
        suffix = path.suffix if len(path.suffix) <= 16 else ""
        shutil.copy2(path, out_dir / f"{index:06d}-{digest[:16]}{suffix}")


def _replace_dir(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    ensure_dir(dst.parent)
    shutil.copytree(src, dst)


def _run_afl_cmin(workspace: Path, manifest: TargetManifest, harness: Harness, in_dir: Path, out_dir: Path) -> dict[str, Any]:
    binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
    if not binary.exists():
        return {"tool": "afl-cmin", "used": False, "reason": f"missing binary {binary}"}
    if not which("afl-cmin"):
        return {"tool": "afl-cmin", "used": False, "reason": "afl-cmin not installed"}
    env = _asan_env()
    env.update(harness.env)
    cmd = [
        "afl-cmin",
        "-i",
        str(in_dir),
        "-o",
        str(out_dir),
        "-m",
        "none",
        "-t",
        f"{manifest.timeout_ms}+",
        "--",
        *_file_target_argv(binary, harness),
    ]
    result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=env, timeout=900, print_cmd=True)
    return {"tool": "afl-cmin", "used": result.returncode == 0, "returncode": result.returncode, "output_tail": result.output[-4000:]}


def _run_libfuzzer_merge(workspace: Path, manifest: TargetManifest, harness: Harness, in_dir: Path, out_dir: Path) -> dict[str, Any]:
    binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", harness)
    if not binary.exists():
        return {"tool": "libfuzzer-merge", "used": False, "reason": f"missing binary {binary}"}
    env = _asan_env()
    env.update(harness.env)
    cmd = [str(binary), "-merge=1", str(out_dir), str(in_dir), f"-max_len={manifest.max_len}"]
    result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=env, timeout=900, print_cmd=True)
    return {"tool": "libfuzzer-merge", "used": result.returncode == 0, "returncode": result.returncode, "output_tail": result.output[-4000:]}


def corpus_sync(workspace: Path, manifest: TargetManifest, run_id: str | None = None, *, max_inputs: int = 20000) -> Path:
    if max_inputs <= 0:
        raise FuzzCtlError("--max-inputs must be greater than zero")
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    out = ensure_dir(run_dir / "corpus_sync")
    report: dict[str, Any] = {"target": manifest.name, "run": str(run_dir), "max_inputs": max_inputs, "harnesses": []}

    if any(h.type == "file" for h in manifest.harnesses):
        build_profile(workspace, manifest, "afl_asan_ubsan")
    if any(h.type == "libfuzzer" for h in manifest.harnesses):
        try:
            build_profile(workspace, manifest, "libfuzzer_asan_ubsan")
        except FuzzCtlError as exc:
            print(f"warning: libFuzzer profile unavailable for corpus merge: {exc}")

    for harness in manifest.harnesses:
        inputs, summary = _harness_inputs(workspace, manifest, run_dir, harness, max_inputs)
        if not inputs:
            summary["status"] = "skipped"
            summary["reason"] = "no corpus inputs found"
            report["harnesses"].append(summary)
            continue

        harness_dir = ensure_dir(out / harness.name)
        all_dir = harness_dir / "all"
        minimized_dir = harness_dir / "minimized"
        if all_dir.exists():
            shutil.rmtree(all_dir)
        if minimized_dir.exists():
            shutil.rmtree(minimized_dir)
        _copy_inputs(inputs, all_dir)

        tool_result: dict[str, Any]
        if harness.type == "file":
            tool_result = _run_afl_cmin(workspace, manifest, harness, all_dir, minimized_dir)
        elif harness.type == "libfuzzer":
            ensure_dir(minimized_dir)
            tool_result = _run_libfuzzer_merge(workspace, manifest, harness, all_dir, minimized_dir)
        else:
            tool_result = {"tool": "copy", "used": False, "reason": f"unsupported harness type {harness.type}"}

        if not minimized_dir.exists() or not any(minimized_dir.iterdir()):
            if minimized_dir.exists():
                shutil.rmtree(minimized_dir)
            shutil.copytree(all_dir, minimized_dir)
            tool_result["fallback"] = "deduped-copy"

        current = workspace / "corpora" / manifest.name / harness.name / "current"
        _replace_dir(minimized_dir, current)
        summary["status"] = "synced"
        summary["tool"] = tool_result
        summary["output"] = rel_to(current, workspace)
        summary["output_files"] = len([p for p in current.iterdir() if p.is_file()])
        report["harnesses"].append(summary)

    write_json(out / "corpus_sync.json", report)
    print(f"corpus sync output: {rel_to(out, workspace)}")
    return out
