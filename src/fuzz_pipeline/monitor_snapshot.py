from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .findings import duplicate_count, normalize_crash_item
from .triage import _crash_files
from .util import free_disk_bytes, read_json, rel_to


def _parse_stats(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def _unique_crashes(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "triage" / "unique_crashes.json"
    if not path.exists():
        return []
    return [normalize_crash_item(item) for item in read_json(path).get("crashes", [])]


def _alive_afl_workers(run_dir: Path) -> int:
    root = str(run_dir)
    proc_root = Path("/proc")
    alive = 0
    if not proc_root.exists():
        return 0
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        cmdline = entry / "cmdline"
        try:
            raw = cmdline.read_bytes()
        except OSError:
            continue
        if b"afl-fuzz" not in raw:
            continue
        text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
        if root in text:
            alive += 1
    return alive


def _snapshot(workspace: Path, run_dir: Path) -> dict[str, Any]:
    run_json = run_dir / "run.json"
    active = True
    if run_json.exists():
        try:
            active = read_json(run_json).get("status") == "running"
        except Exception:
            active = False
    stats_files = sorted(run_dir.rglob("fuzzer_stats"))
    stats = [_parse_stats(path) | {"path": rel_to(path.parent, workspace)} for path in stats_files]
    execs = 0
    paths = 0
    crashes = 0
    hangs = 0
    now = int(time.time())
    stale_stats = []
    for item in stats:
        execs += int(float(item.get("execs_done", "0") or 0))
        paths += int(float(item.get("corpus_count", item.get("paths_total", "0")) or 0))
        crashes += int(float(item.get("saved_crashes", "0") or 0))
        hangs += int(float(item.get("saved_hangs", "0") or 0))
        try:
            last_update = int(float(item.get("last_update", "0") or 0))
        except ValueError:
            last_update = 0
        if last_update and now - last_update > 180:
            stale_stats.append(item["path"])

    raw_crashes = _crash_files(run_dir)
    logs = sorted(run_dir.rglob("*.log"))
    failed_logs = []
    for log in logs:
        text = log.read_text(encoding="utf-8", errors="replace")[-8000:]
        if "PROGRAM ABORT" in text or ("ERROR:" in text and "AddressSanitizer" not in text):
            failed_logs.append(rel_to(log, workspace))

    queue_files = sorted(run_dir.glob("aflpp/*/findings/*/queue/id:*"))
    queue_by_harness: dict[str, int] = {}
    for path in queue_files:
        try:
            harness = path.relative_to(run_dir / "aflpp").parts[0]
        except (ValueError, IndexError):
            harness = "unknown"
        queue_by_harness[harness] = queue_by_harness.get(harness, 0) + 1

    unique_crashes = _unique_crashes(run_dir)
    duplicate_crashes = sum(duplicate_count(item) for item in unique_crashes)
    triaged_raw_crashes = len(unique_crashes) + duplicate_crashes

    return {
        "run": str(run_dir),
        "active": active,
        "stats": stats,
        "execs": execs,
        "paths": paths,
        "afl_saved_crashes": crashes,
        "afl_saved_hangs": hangs,
        "raw_crashes": len(raw_crashes),
        "raw_crash_files": [rel_to(path, workspace) for path in raw_crashes[-10:]],
        "unique_crashes": unique_crashes,
        "unique_crash_count": len(unique_crashes),
        "duplicate_crashes": duplicate_crashes,
        "triaged_raw_crashes": triaged_raw_crashes,
        "workers_expected": len(stats_files),
        "workers_alive": _alive_afl_workers(run_dir),
        "stale_stats": stale_stats,
        "queue_files": len(queue_files),
        "queue_by_harness": queue_by_harness,
        "failed_logs": failed_logs,
        "disk_free": free_disk_bytes(workspace),
    }
