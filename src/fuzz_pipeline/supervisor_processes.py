from __future__ import annotations

import os
import re
import signal
import time
from pathlib import Path

from .campaign_common import _harnesses, _worker_counts
from .manifest import TargetManifest
from .util import cpu_default_workers


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


def campaign_mismatch_reason(
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


def terminate_processes(active: list[dict[str, object]], *, timeout: int) -> dict[str, object]:
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
