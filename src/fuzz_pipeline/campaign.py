from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .builder import build_profile, harness_binary
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, cpu_default_workers, ensure_dir, find_latest_run, now_id, rel_to, run_cmd, write_json


def _run_dir(workspace: Path, name: str, label: str) -> Path:
    return ensure_dir(workspace / "runs" / name / f"{now_id()}-{label}")


def _seed_dir(workspace: Path, manifest: TargetManifest, run_dir: Path) -> Path:
    seed_dir = manifest.seed_dir(workspace)
    if seed_dir.exists() and any(p.is_file() for p in seed_dir.iterdir()):
        return seed_dir
    fallback = ensure_dir(run_dir / "generated_seed")
    (fallback / "seed").write_bytes(b"\x00")
    print(f"warning: seed corpus missing or empty, using generated seed at {fallback}")
    return fallback


def _copy_seed_corpus(seed_dir: Path, destination: Path) -> Path:
    ensure_dir(destination)
    for seed in sorted(seed_dir.iterdir()):
        if seed.is_file():
            shutil.copy2(seed, destination / seed.name)
    return destination


def _count_crash_artifacts(run_dir: Path) -> int:
    count = 0
    for path in run_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.name.startswith("id:") and "/crashes/" in path.as_posix():
            count += 1
        elif path.name.startswith(("crash-", "leak-", "oom-", "timeout-")):
            count += 1
    return count


def _harnesses(manifest: TargetManifest, kind: str) -> list[Harness]:
    return [h for h in manifest.harnesses if h.type == kind]


def _worker_counts(harnesses: list[Harness], workers: int) -> dict[str, int]:
    if not harnesses:
        return {}
    counts = {h.name: 0 for h in harnesses}
    for index in range(workers):
        counts[harnesses[index % len(harnesses)].name] += 1
    return counts


def _asan_env() -> dict[str, str]:
    return {
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_UI": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "ASAN_OPTIONS": (
            "abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:"
            "strict_string_checks=1:symbolize=0"
        ),
        "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
    }


def _file_target_argv(binary: Path, harness: Harness, testcase: str = "@@") -> list[str]:
    argv = [str(binary)]
    if harness.argv:
        argv.extend(testcase if part == "@@" else part for part in harness.argv)
    else:
        argv.append(testcase)
    return argv


def run_libfuzzer(workspace: Path, manifest: TargetManifest, seconds: int, label: str = "libfuzzer") -> Path:
    harnesses = _harnesses(manifest, "libfuzzer")
    if not harnesses:
        raise FuzzCtlError(f"target {manifest.name} has no libFuzzer harness")
    build_profile(workspace, manifest, "libfuzzer_asan_ubsan")
    run_dir = _run_dir(workspace, manifest.name, label)
    harness_results = []
    write_json(
        run_dir / "run.json",
        {"target": manifest.name, "engine": "libfuzzer", "seconds": seconds, "status": "running", "started_at": int(time.time())},
    )
    seed = _seed_dir(workspace, manifest, run_dir)
    for harness in harnesses:
        binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", harness)
        if not binary.exists():
            raise FuzzCtlError(f"libFuzzer binary missing: {binary}")
        crashes = ensure_dir(run_dir / "libfuzzer" / harness.name / "crashes")
        corpus = _copy_seed_corpus(seed, ensure_dir(run_dir / "libfuzzer" / harness.name / "corpus"))
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
        env = _asan_env()
        env.update(harness.env)
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
            "status": status,
            "raw_crashes": total_crashes,
            "harness_results": harness_results,
            "finished_at": int(time.time()),
        },
    )
    return run_dir


def run_aflpp(
    workspace: Path,
    manifest: TargetManifest,
    seconds: int,
    *,
    workers: int | None = None,
    label: str = "aflpp",
) -> Path:
    stop_requested = False

    def _request_stop(signum: int, frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True

    file_harnesses = _harnesses(manifest, "file")
    if not file_harnesses:
        raise FuzzCtlError(f"target {manifest.name} has no file harness for AFL++")
    build_profile(workspace, manifest, "afl_asan_ubsan")
    try:
        build_profile(workspace, manifest, "afl_lto_cmplog")
    except FuzzCtlError as exc:
        print(f"warning: CMPLOG profile unavailable: {exc}")
    workers = workers or cpu_default_workers()
    run_dir = _run_dir(workspace, manifest.name, label)
    worker_counts = _worker_counts(file_harnesses, workers)
    write_json(
        run_dir / "run.json",
        {
            "target": manifest.name,
            "engine": "aflpp",
            "seconds": seconds,
            "workers": workers,
            "worker_counts": worker_counts,
            "status": "running",
            "started_at": int(time.time()),
        },
    )
    seed = _seed_dir(workspace, manifest, run_dir)
    procs: list[tuple[subprocess.Popen[bytes], object]] = []
    base_env = os.environ.copy()
    base_env.update(_asan_env())
    schedules = ["fast", "explore", "rare", "seek", "coe", "lin"]
    for harness in file_harnesses:
        harness_workers = worker_counts.get(harness.name, 0)
        if harness_workers <= 0:
            continue
        binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
        if not binary.exists():
            raise FuzzCtlError(f"AFL++ binary missing: {binary}")
        cmplog_binary = harness_binary(workspace, manifest, "afl_lto_cmplog", harness)
        findings = ensure_dir(run_dir / "aflpp" / harness.name / "findings")
        logs = ensure_dir(run_dir / "aflpp" / harness.name / "logs")
        env = base_env.copy()
        env.update(harness.env)
        for index in range(harness_workers):
            role = "main" if index == 0 else f"sec{index}"
            mode = ["-M", role] if index == 0 else ["-S", role, "-p", schedules[index % len(schedules)]]
            cmd = [
                "afl-fuzz",
                "-i",
                str(seed),
                "-o",
                str(findings),
                *mode,
                "-m",
                "none",
                "-t",
                f"{manifest.timeout_ms}+",
            ]
            if index > 0 and cmplog_binary.exists():
                cmd.extend(["-c", str(cmplog_binary)])
            cmd.extend(["--", *_file_target_argv(binary, harness)])
            log = (logs / f"{role}.log").open("wb")
            print("$ " + " ".join(cmd))
            proc = subprocess.Popen(cmd, cwd=str(manifest.source_dir(workspace)), env=env, stdout=log, stderr=subprocess.STDOUT)
            procs.append((proc, log))

    deadline = time.monotonic() + seconds
    old_sigterm = signal.getsignal(signal.SIGTERM)
    old_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    try:
        while time.monotonic() < deadline and not stop_requested:
            if all(proc.poll() is not None for proc, _ in procs):
                break
            time.sleep(1)
    finally:
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
        signal.signal(signal.SIGTERM, old_sigterm)
        signal.signal(signal.SIGINT, old_sigint)
    total_crashes = _count_crash_artifacts(run_dir)
    status = "stopped" if stop_requested else ("crash_found" if total_crashes else "complete")
    write_json(
        run_dir / "run.json",
        {
            "target": manifest.name,
            "engine": "aflpp",
            "seconds": seconds,
            "workers": workers,
            "worker_counts": worker_counts,
            "status": status,
            "raw_crashes": total_crashes,
            "finished_at": int(time.time()),
        },
    )
    print(f"AFL++ run complete: {rel_to(run_dir, workspace)}")
    return run_dir


def smoke(workspace: Path, manifest: TargetManifest, seconds: int) -> Path:
    if _harnesses(manifest, "libfuzzer"):
        return run_libfuzzer(workspace, manifest, seconds, label="smoke-libfuzzer")
    return run_aflpp(workspace, manifest, seconds, workers=1, label="smoke-aflpp")


def run_campaign(workspace: Path, manifest: TargetManifest, engine: str, hours: float, workers: int | None) -> list[Path]:
    seconds = max(1, int(hours * 3600))
    run_dirs: list[Path] = []
    if engine in {"libfuzzer", "all"}:
        run_dirs.append(run_libfuzzer(workspace, manifest, seconds, label="campaign-libfuzzer"))
    if engine in {"aflpp", "all"}:
        run_dirs.append(run_aflpp(workspace, manifest, seconds, workers=workers, label="campaign-aflpp"))
    return run_dirs


def status(workspace: Path, name: str, run_id: str | None = None) -> None:
    run_dir = workspace / "runs" / name / run_id if run_id else find_latest_run(workspace, name)
    print(f"run: {rel_to(run_dir, workspace)}")
    stats = sorted(run_dir.rglob("fuzzer_stats"))
    if not stats:
        print("no AFL++ fuzzer_stats found")
        crash_count = len([
            p for p in run_dir.rglob("*")
            if p.is_file() and p.name.startswith(("crash-", "leak-", "oom-", "timeout-"))
        ])
        print(f"libFuzzer-style crash artifacts: {crash_count}")
        return
    for stat in stats:
        data: dict[str, str] = {}
        for line in stat.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()
        rel = rel_to(stat.parent, workspace)
        print(
            f"{rel}: execs={data.get('execs_done', '?')} "
            f"exec/s={data.get('execs_per_sec', '?')} "
            f"paths={data.get('corpus_count', data.get('paths_total', '?'))} "
            f"crashes={data.get('saved_crashes', '?')} hangs={data.get('saved_hangs', '?')}"
        )
