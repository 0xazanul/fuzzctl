from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import IO

from .builder import build_profile, harness_binary
from .campaign_common import (
    _asan_env,
    _count_crash_artifacts,
    _file_target_argv,
    _harnesses,
    _merge_harness_env,
    _prepare_grammar_trees,
    _prepare_harness_seed_corpus,
    _run_dir,
    _worker_counts,
)
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, cpu_default_workers, ensure_dir, rel_to, write_json


ProcLog = tuple[subprocess.Popen[bytes], IO[bytes]]


def _afl_file_harnesses(manifest: TargetManifest) -> list[Harness]:
    harnesses = [h for h in _harnesses(manifest, "file") if "afl_asan_ubsan" in h.profiles]
    if not harnesses:
        raise FuzzCtlError(f"target {manifest.name} has no file harness for AFL++")
    return harnesses


def _build_afl_profiles(workspace: Path, manifest: TargetManifest) -> None:
    build_profile(workspace, manifest, "afl_asan_ubsan")
    try:
        build_profile(workspace, manifest, "afl_lto_cmplog")
    except FuzzCtlError as exc:
        print(f"warning: CMPLOG profile unavailable: {exc}")


def _write_run_json(
    run_dir: Path,
    manifest: TargetManifest,
    *,
    seconds: int,
    workers: int,
    requested_workers: int,
    worker_counts: dict[str, int],
    status: str,
    raw_crashes: int | None = None,
) -> None:
    payload = {
        "target": manifest.name,
        "engine": "aflpp",
        "seconds": seconds,
        "workers": workers,
        "requested_workers": requested_workers,
        "worker_counts": worker_counts,
        "status": status,
    }
    if raw_crashes is None:
        payload["started_at"] = int(time.time())
    else:
        payload["raw_crashes"] = raw_crashes
        payload["finished_at"] = int(time.time())
    write_json(run_dir / "run.json", payload)


def _afl_worker_cmd(
    workspace: Path,
    manifest: TargetManifest,
    harness: Harness,
    *,
    binary: Path,
    cmplog_binary: Path,
    harness_seed: Path,
    findings: Path,
    role: str,
    index: int,
) -> list[str]:
    schedules = ["fast", "explore", "rare", "seek", "coe", "lin"]
    mode = ["-M", role] if index == 0 else ["-S", role, "-p", schedules[index % len(schedules)]]
    cmd = [
        "afl-fuzz",
        "-i",
        str(harness_seed),
        "-o",
        str(findings),
        *mode,
        "-m",
        "none",
        "-t",
        f"{manifest.timeout_ms}+",
    ]
    if manifest.afl_cmplog and index > 0 and cmplog_binary.exists():
        cmd.extend(["-c", str(cmplog_binary)])
    dictionary = manifest.dictionary_path(workspace)
    if dictionary:
        cmd.extend(["-x", str(dictionary)])
    cmd.extend(["--", *_file_target_argv(binary, harness)])
    return cmd


def _start_harness_workers(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path,
    harness: Harness,
    *,
    harness_workers: int,
    base_env: dict[str, str],
) -> list[ProcLog]:
    binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
    if not binary.exists():
        raise FuzzCtlError(f"AFL++ binary missing: {binary}")

    cmplog_binary = harness_binary(workspace, manifest, "afl_lto_cmplog", harness)
    harness_seed = _prepare_harness_seed_corpus(workspace, manifest, run_dir, harness)
    findings = ensure_dir(run_dir / "aflpp" / harness.name / "findings")
    logs = ensure_dir(run_dir / "aflpp" / harness.name / "logs")
    env = _merge_harness_env(base_env, harness)
    procs: list[ProcLog] = []

    for index in range(harness_workers):
        role = "main" if index == 0 else f"sec{index}"
        cmd = _afl_worker_cmd(
            workspace,
            manifest,
            harness,
            binary=binary,
            cmplog_binary=cmplog_binary,
            harness_seed=harness_seed,
            findings=findings,
            role=role,
            index=index,
        )
        copied_trees = _prepare_grammar_trees(workspace, manifest, harness, findings, role)
        if copied_trees:
            print(f"grammar trees for {harness.name}/{role}: {copied_trees}")
        log = (logs / f"{role}.log").open("wb")
        print("$ " + " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            cwd=str(manifest.source_dir(workspace)),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        procs.append((proc, log))
    return procs


def _start_afl_workers(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path,
    harnesses: list[Harness],
    worker_counts: dict[str, int],
) -> list[ProcLog]:
    base_env = os.environ.copy()
    base_env.update(_asan_env())
    procs: list[ProcLog] = []
    for harness in harnesses:
        harness_workers = worker_counts.get(harness.name, 0)
        if harness_workers <= 0:
            continue
        procs.extend(
            _start_harness_workers(
                workspace,
                manifest,
                run_dir,
                harness,
                harness_workers=harness_workers,
                base_env=base_env,
            )
        )
    return procs


def _wait_for_workers(procs: list[ProcLog], seconds: int) -> bool:
    stop = {"requested": False}

    def request_stop(signum: int, frame: object) -> None:
        stop["requested"] = True

    deadline = time.monotonic() + seconds
    old_sigterm = signal.getsignal(signal.SIGTERM)
    old_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        while time.monotonic() < deadline and not stop["requested"]:
            if all(proc.poll() is not None for proc, _ in procs):
                break
            time.sleep(1)
    finally:
        _stop_workers(procs)
        signal.signal(signal.SIGTERM, old_sigterm)
        signal.signal(signal.SIGINT, old_sigint)
    return stop["requested"]


def _stop_workers(procs: list[ProcLog]) -> None:
    for proc, _ in procs:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    for proc, log in procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


def run_aflpp(
    workspace: Path,
    manifest: TargetManifest,
    seconds: int,
    *,
    workers: int | None = None,
    label: str = "aflpp",
) -> Path:
    file_harnesses = _afl_file_harnesses(manifest)
    _build_afl_profiles(workspace, manifest)

    requested_workers = workers or cpu_default_workers()
    worker_counts = _worker_counts(file_harnesses, requested_workers)
    actual_workers = sum(worker_counts.values())
    run_dir = _run_dir(workspace, manifest.name, label)
    _write_run_json(
        run_dir,
        manifest,
        seconds=seconds,
        workers=actual_workers,
        requested_workers=requested_workers,
        worker_counts=worker_counts,
        status="running",
    )

    procs = _start_afl_workers(workspace, manifest, run_dir, file_harnesses, worker_counts)
    stop_requested = _wait_for_workers(procs, seconds)
    total_crashes = _count_crash_artifacts(run_dir)
    status = "stopped" if stop_requested else ("crash_found" if total_crashes else "complete")
    _write_run_json(
        run_dir,
        manifest,
        seconds=seconds,
        workers=actual_workers,
        requested_workers=requested_workers,
        worker_counts=worker_counts,
        status=status,
        raw_crashes=total_crashes,
    )
    print(f"AFL++ run complete: {rel_to(run_dir, workspace)}")
    return run_dir
