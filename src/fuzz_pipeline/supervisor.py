from __future__ import annotations

import fcntl
import os
import re
import signal
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .campaign import _harnesses, _worker_counts, run_campaign, smoke
from .corpus import corpus_sync
from .coverage import coverage_run
from .manifest import TargetManifest
from .reporting import report_run
from .triage import minimize_run, triage_run
from .util import cpu_default_workers, ensure_dir, free_disk_bytes, human_bytes, read_json, write_json


def _classify_cmdline(args: list[str], workspace: Path, target: str) -> str | None:
    if not args:
        return None
    run_marker = f"/runs/{target}/"
    joined = " ".join(args)
    if any(Path(arg).name == "afl-fuzz" for arg in args) and run_marker in joined:
        return "afl-fuzz"
    if "-m" in args and "fuzz_pipeline" in args and "run" in args and target in args:
        return "fuzzctl-run"
    workspace_text = str(workspace)
    if "fuzz_pipeline" in joined and " run " in f" {joined} " and target in args and workspace_text in joined:
        return "fuzzctl-run"
    return None


def active_fuzz_processes(workspace: Path, target: str) -> list[dict[str, object]]:
    current_pid = os.getpid()
    proc_root = Path("/proc")
    processes: list[dict[str, object]] = []
    if not proc_root.exists():
        return processes
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == current_pid:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if not raw:
            continue
        args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
        kind = _classify_cmdline(args, workspace, target)
        if kind:
            item: dict[str, object] = {"pid": pid, "kind": kind, "cmd": " ".join(args)}
            run_match = re.search(rf"/runs/{re.escape(target)}/([^/\s]+)/", item["cmd"])
            if run_match:
                item["run_id"] = run_match.group(1)
            harness_match = re.search(rf"/runs/{re.escape(target)}/[^/\s]+/aflpp/([^/\s]+)/findings", item["cmd"])
            if harness_match:
                item["harness"] = harness_match.group(1)
            processes.append(item)
    return sorted(processes, key=lambda item: int(item["pid"]))


def _expected_afl_worker_counts(manifest: TargetManifest, workers: int | None) -> dict[str, int]:
    file_harnesses = _harnesses(manifest, "file")
    if not file_harnesses:
        return {}
    return _worker_counts(file_harnesses, workers or cpu_default_workers())


def _active_afl_worker_counts(active: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for proc in active:
        if proc.get("kind") != "afl-fuzz":
            continue
        harness = proc.get("harness")
        if not harness:
            continue
        counts[str(harness)] = counts.get(str(harness), 0) + 1
    return counts


def _campaign_mismatch_reason(
    active: list[dict[str, object]],
    manifest: TargetManifest,
    *,
    engine: str,
    workers: int | None,
) -> str | None:
    if engine not in {"aflpp", "all"}:
        return None
    expected = _expected_afl_worker_counts(manifest, workers)
    if not expected:
        return None
    observed = _active_afl_worker_counts(active)
    if not observed:
        return None
    if observed != expected:
        return f"active AFL++ worker plan {observed} does not match expected {expected}"
    return None


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _terminate_processes(active: list[dict[str, object]], *, timeout: int) -> dict[str, object]:
    fuzzctl = [int(proc["pid"]) for proc in active if proc.get("kind") == "fuzzctl-run"]
    afl = [int(proc["pid"]) for proc in active if proc.get("kind") == "afl-fuzz"]
    signaled: list[int] = []
    forced: list[int] = []

    for pid in [*fuzzctl, *afl]:
        try:
            os.kill(pid, signal.SIGTERM)
            signaled.append(pid)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(_process_alive(pid) for pid in [*fuzzctl, *afl]):
            break
        time.sleep(1)

    for pid in [*fuzzctl, *afl]:
        if not _process_alive(pid):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            forced.append(pid)
        except ProcessLookupError:
            pass
    return {"signaled": signaled, "forced": forced}


@contextmanager
def _target_lock(workspace: Path, target: str) -> Iterator[bool]:
    lock_dir = ensure_dir(workspace / "state" / "locks")
    lock_path = lock_dir / f"{target}.campaign.lock"
    with lock_path.open("w", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        lock_file.write(f"{os.getpid()}\n")
        lock_file.flush()
        try:
            yield True
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _state_path(workspace: Path, target: str) -> Path:
    return ensure_dir(workspace / "state" / "supervisor") / f"{target}.json"


def _write_state(workspace: Path, target: str, data: dict[str, object]) -> None:
    payload = {
        "target": target,
        "updated_at": int(time.time()),
        **data,
    }
    write_json(_state_path(workspace, target), payload)


def supervisor_status(workspace: Path, manifest: TargetManifest | None = None, *, as_json: bool = False) -> dict[str, object]:
    targets = [manifest.name] if manifest else sorted(p.name for p in (workspace / "targets").iterdir() if p.is_dir())
    result: dict[str, object] = {"workspace": str(workspace), "targets": {}}
    target_map: dict[str, object] = {}
    for target in targets:
        state_file = _state_path(workspace, target)
        state = read_json(state_file) if state_file.exists() else {}
        target_map[target] = {
            "active_processes": active_fuzz_processes(workspace, target),
            "state": state,
        }
    result["targets"] = target_map
    if as_json:
        import json

        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"workspace: {workspace}")
        for target, item in target_map.items():
            active = item["active_processes"]  # type: ignore[index]
            state = item["state"]  # type: ignore[index]
            print(f"{target}: active_processes={len(active)} supervisor_state={state.get('status', 'unknown') if isinstance(state, dict) else 'unknown'}")
            for proc in active:  # type: ignore[assignment]
                print(f"  pid={proc['pid']} kind={proc['kind']}")
    return result


def campaign_loop(
    workspace: Path,
    manifest: TargetManifest,
    *,
    engine: str,
    hours: float,
    workers: int | None,
    wait_interval: int = 60,
    max_cycles: int | None = None,
    post_cycle: bool = True,
    coverage_inputs: int = 5000,
    replace_mismatched: bool = False,
    replace_timeout: int = 90,
    leak_smoke_seconds: int = 0,
) -> int:
    target = manifest.name
    with _target_lock(workspace, target) as locked:
        if not locked:
            print(f"supervisor for {target} is already running; exiting")
            return 0
        cycle = 0
        while max_cycles is None or cycle < max_cycles:
            active = active_fuzz_processes(workspace, target)
            if active:
                mismatch = _campaign_mismatch_reason(active, manifest, engine=engine, workers=workers)
                if mismatch and replace_mismatched:
                    _write_state(
                        workspace,
                        target,
                        {
                            "status": "replacing_mismatched_campaign",
                            "reason": mismatch,
                            "active_processes": active,
                            "replace_timeout": replace_timeout,
                        },
                    )
                    print(f"{target}: replacing mismatched fuzzing: {mismatch}")
                    termination = _terminate_processes(active, timeout=replace_timeout)
                    _write_state(
                        workspace,
                        target,
                        {
                            "status": "mismatched_campaign_replaced",
                            "reason": mismatch,
                            "termination": termination,
                        },
                    )
                    time.sleep(2)
                    continue
                _write_state(
                    workspace,
                    target,
                    {
                        "status": "waiting_existing_campaign",
                        "reason": mismatch,
                        "active_processes": active,
                        "next_check_seconds": wait_interval,
                    },
                )
                print(f"{target}: existing fuzzing is active ({len(active)} processes); waiting {wait_interval}s")
                time.sleep(wait_interval)
                continue

            cycle += 1
            leak_run_ids: list[str] = []
            if leak_smoke_seconds > 0:
                _write_state(
                    workspace,
                    target,
                    {
                        "status": "running_leak_smoke",
                        "cycle": cycle,
                        "seconds_per_harness": leak_smoke_seconds,
                    },
                )
                leak_run = smoke(workspace, manifest, leak_smoke_seconds, leak_check=True)
                leak_run_ids.append(leak_run.name)
                try:
                    triage_run(workspace, manifest, leak_run.name)
                    minimize_run(workspace, manifest, leak_run.name)
                    report_run(workspace, manifest, leak_run.name)
                except Exception as exc:
                    _write_state(
                        workspace,
                        target,
                        {
                            "status": "leak_smoke_error",
                            "cycle": cycle,
                            "run_id": leak_run.name,
                            "error": str(exc),
                        },
                    )
                    raise
            _write_state(
                workspace,
                target,
                {
                    "status": "running_campaign",
                    "cycle": cycle,
                    "engine": engine,
                    "hours": hours,
                    "workers": workers,
                    "leak_smoke_run_ids": leak_run_ids,
                },
            )
            run_dirs = run_campaign(workspace, manifest, engine, hours, workers)
            run_ids = [run_dir.name for run_dir in run_dirs]
            _write_state(
                workspace,
                target,
                {
                    "status": "post_cycle" if post_cycle else "cycle_complete",
                    "cycle": cycle,
                    "run_ids": run_ids,
                    "leak_smoke_run_ids": leak_run_ids,
                },
            )
            if post_cycle:
                for run_dir in run_dirs:
                    run_id = run_dir.name
                    try:
                        triage_run(workspace, manifest, run_id)
                        minimize_run(workspace, manifest, run_id)
                        report_run(workspace, manifest, run_id)
                        corpus_sync(workspace, manifest, run_id)
                        coverage_run(workspace, manifest, run_id, max_inputs=coverage_inputs)
                    except Exception as exc:
                        _write_state(
                            workspace,
                            target,
                            {
                                "status": "post_cycle_error",
                                "cycle": cycle,
                                "run_id": run_id,
                                "error": str(exc),
                            },
                        )
                        raise
            _write_state(
                workspace,
                target,
                {
                    "status": "cycle_complete",
                    "cycle": cycle,
                    "run_ids": run_ids,
                    "leak_smoke_run_ids": leak_run_ids,
                    "disk_free": human_bytes(free_disk_bytes(workspace)),
                },
            )
        _write_state(workspace, target, {"status": "max_cycles_complete", "cycles": cycle})
    return 0
