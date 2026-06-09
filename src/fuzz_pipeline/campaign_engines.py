from __future__ import annotations

import time
from pathlib import Path

from .builder import build_profile, harness_binary
from .campaign_aflpp import run_aflpp
from .campaign_common import (
    _asan_env,
    _copy_seed_corpus,
    _count_crash_artifacts,
    _harnesses,
    _merge_harness_env,
    _prepare_harness_seed_corpus,
    _run_dir,
)
from .manifest import TargetManifest
from .util import FuzzCtlError, ensure_dir, rel_to, run_cmd, write_json


def run_libfuzzer(
    workspace: Path,
    manifest: TargetManifest,
    seconds: int,
    label: str = "libfuzzer",
    *,
    detect_leaks: bool | None = None,
) -> Path:
    harnesses = _harnesses(manifest, "libfuzzer")
    if not harnesses:
        raise FuzzCtlError(f"target {manifest.name} has no libFuzzer harness")
    build_profile(workspace, manifest, "libfuzzer_asan_ubsan")
    run_dir = _run_dir(workspace, manifest.name, label)
    harness_results = []
    write_json(
        run_dir / "run.json",
        {
            "target": manifest.name,
            "engine": "libfuzzer",
            "seconds": seconds,
            "status": "running",
            "started_at": int(time.time()),
        },
    )
    for harness in harnesses:
        binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", harness)
        if not binary.exists():
            raise FuzzCtlError(f"libFuzzer binary missing: {binary}")
        crashes = ensure_dir(run_dir / "libfuzzer" / harness.name / "crashes")
        harness_seed = _prepare_harness_seed_corpus(workspace, manifest, run_dir, harness)
        corpus = _copy_seed_corpus(harness_seed, ensure_dir(run_dir / "libfuzzer" / harness.name / "corpus"))
        cmd = [
            str(binary),
            str(corpus),
            f"-max_total_time={seconds}",
            f"-max_len={manifest.max_len}",
            f"-rss_limit_mb={manifest.memory_mb}",
            f"-artifact_prefix={crashes}/",
        ]
        dictionary = manifest.dictionary_path(workspace)
        if dictionary:
            cmd.append(f"-dict={dictionary}")
        env = _merge_harness_env(_asan_env(), harness, detect_leaks=detect_leaks)
        result = run_cmd(cmd, env=env, timeout=seconds + 30, print_cmd=True)
        log = run_dir / "libfuzzer" / harness.name / "run.log"
        log.write_text(result.output, encoding="utf-8", errors="replace")
        crash_count = len([p for p in crashes.iterdir() if p.is_file()])
        harness_results.append(
            {
                "harness": harness.name,
                "returncode": result.returncode,
                "crashes": crash_count,
                "log": str(log),
            }
        )
        print(f"libFuzzer {harness.name} exited {result.returncode}; log: {rel_to(log, workspace)}")
    total_crashes = _count_crash_artifacts(run_dir)
    status = "crash_found" if total_crashes else "complete"
    if any(item["returncode"] != 0 and item["crashes"] == 0 for item in harness_results):
        status = "error"
    total_crashes = _count_crash_artifacts(run_dir)
    write_json(
        run_dir / "run.json",
        {
            "target": manifest.name,
            "engine": "libfuzzer",
            "seconds": seconds,
            "detect_leaks": detect_leaks,
            "status": status,
            "raw_crashes": total_crashes,
            "harness_results": harness_results,
            "finished_at": int(time.time()),
        },
    )
    return run_dir


def run_fuzztest(
    workspace: Path,
    manifest: TargetManifest,
    seconds: int,
    label: str = "fuzztest",
    *,
    test_filter: str | None = None,
) -> Path:
    harnesses = [h for h in _harnesses(manifest, "fuzztest") if not h.profiles or "fuzztest_asan_ubsan" in h.profiles]
    if not harnesses:
        raise FuzzCtlError(f"target {manifest.name} has no FuzzTest harness")
    build_profile(workspace, manifest, "fuzztest_asan_ubsan")
    run_dir = _run_dir(workspace, manifest.name, label)
    harness_results = []
    write_json(
        run_dir / "run.json",
        {
            "target": manifest.name,
            "engine": "fuzztest",
            "seconds": seconds,
            "test_filter": test_filter,
            "status": "running",
            "started_at": int(time.time()),
        },
    )
    for harness in harnesses:
        binary = harness_binary(workspace, manifest, "fuzztest_asan_ubsan", harness)
        if not binary.exists():
            raise FuzzCtlError(f"FuzzTest binary missing: {binary}")
        logs = ensure_dir(run_dir / "fuzztest" / harness.name / "logs")
        cmd = [str(binary), f"--fuzz_for={seconds}s"]
        if test_filter:
            cmd.append(f"--fuzz={test_filter}")
        env = _merge_harness_env(_asan_env(), harness)
        result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=env, timeout=seconds + 30, print_cmd=True)
        log = logs / "run.log"
        log.write_text(result.output, encoding="utf-8", errors="replace")
        harness_results.append(
            {
                "harness": harness.name,
                "returncode": result.returncode,
                "failure": result.returncode != 0,
                "log": str(log),
            }
        )
        print(f"FuzzTest {harness.name} exited {result.returncode}; log: {rel_to(log, workspace)}")
    failures = sum(1 for item in harness_results if item["failure"])
    write_json(
        run_dir / "run.json",
        {
            "target": manifest.name,
            "engine": "fuzztest",
            "seconds": seconds,
            "test_filter": test_filter,
            "status": "failure_found" if failures else "complete",
            "failures": failures,
            "raw_crashes": 0,
            "harness_results": harness_results,
            "finished_at": int(time.time()),
        },
    )
    return run_dir
