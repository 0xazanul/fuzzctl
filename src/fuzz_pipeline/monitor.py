from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .alerts import AlertEvent, send_discord, webhook_url
from .manifest import TargetManifest
from .triage import _crash_files, triage_run
from .util import ensure_dir, find_latest_run, free_disk_bytes, human_bytes, read_json, rel_to, write_json


def _parse_stats(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def _load_state(path: Path) -> dict[str, Any]:
    if path.exists():
        return read_json(path)
    return {
        "alerted_keys": [],
        "last_execs": 0,
        "last_paths": 0,
        "last_raw_crashes": 0,
        "last_unique_crashes": 0,
        "last_raw_alert_at": 0,
        "last_reproducible_alerts": [],
        "stall_count": 0
    }


def _unique_crashes(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "triage" / "unique_crashes.json"
    if not path.exists():
        return []
    return list(read_json(path).get("crashes", []))


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
    stats = [_parse_stats(p) | {"path": rel_to(p.parent, workspace)} for p in stats_files]
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

    return {
        "run": str(run_dir),
        "active": active,
        "stats": stats,
        "execs": execs,
        "paths": paths,
        "afl_saved_crashes": crashes,
        "afl_saved_hangs": hangs,
        "raw_crashes": len(raw_crashes),
        "raw_crash_files": [rel_to(p, workspace) for p in raw_crashes[-10:]],
        "unique_crashes": _unique_crashes(run_dir),
        "workers_expected": len(stats_files),
        "workers_alive": _alive_afl_workers(run_dir),
        "stale_stats": stale_stats,
        "queue_files": len(queue_files),
        "queue_by_harness": queue_by_harness,
        "failed_logs": failed_logs,
        "disk_free": free_disk_bytes(workspace)
    }


def _raw_crash_events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], state: dict[str, Any]) -> list[AlertEvent]:
    raw_count = int(snapshot.get("raw_crashes", 0))
    previous = int(state.get("last_raw_crashes", 0) or 0)
    if raw_count <= previous:
        return []
    key = f"raw-crash:{run_dir.name}:{raw_count}"
    alerted = set(state.get("alerted_keys", []))
    if key in alerted:
        return []
    return [
        AlertEvent(
            key=key,
            title="raw fuzz crash observed",
            description="A crash artifact appeared. Triage will confirm whether it is sanitizer-reproducible and security-relevant.",
            severity="HIGH",
            fields={
                "run": rel_to(run_dir, workspace),
                "raw_crashes": raw_count,
                "previous_raw_crashes": previous,
                "recent_files": "\n".join(snapshot.get("raw_crash_files", [])[-5:]) or "none",
            },
        )
    ]


def _events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], state: dict[str, Any]) -> list[AlertEvent]:
    events: list[AlertEvent] = []
    alerted = set(state.get("alerted_keys", []))
    for crash in snapshot.get("unique_crashes", []):
        if not crash.get("reproducible", False):
            continue
        key = f"crash:{crash['id']}"
        if key in alerted:
            continue
        severity = str(crash.get("severity", "INFO"))
        events.append(
            AlertEvent(
                key=key,
                title=f"{severity} fuzz crash: {crash.get('type', 'unknown')}",
                description=str(crash.get("impact", "New reproducible fuzz crash.")),
                severity=severity,
                fields={
                    "run": rel_to(run_dir, workspace),
                    "harness": crash.get("harness"),
                    "id": crash.get("id"),
                    "minimized": rel_to(Path(crash["minimized_path"]), workspace) if crash.get("minimized_path") else "not minimized yet"
                }
            )
        )

    if snapshot.get("active") and snapshot.get("workers_expected", 0) and snapshot.get("workers_alive", 0) < snapshot.get("workers_expected", 0):
        key = f"workers:missing:{snapshot.get('workers_alive')}:{snapshot.get('workers_expected')}"
        if key not in alerted:
            events.append(
                AlertEvent(
                    key=key,
                    title="fuzz workers are missing",
                    description="The monitor sees fewer live AFL++ processes than fuzzer_stats files for this run.",
                    severity="ERROR",
                    fields={
                        "run": rel_to(run_dir, workspace),
                        "alive": snapshot.get("workers_alive"),
                        "expected": snapshot.get("workers_expected"),
                    },
                )
            )

    if snapshot.get("active") and snapshot.get("stale_stats") and "campaign:stale-stats" not in alerted:
        events.append(
            AlertEvent(
                key="campaign:stale-stats",
                title="fuzz worker stats appear stale",
                description="One or more AFL++ fuzzer_stats files have not updated for more than three minutes.",
                severity="ERROR",
                fields={"run": rel_to(run_dir, workspace), "stale": "\n".join(snapshot["stale_stats"][:8])},
            )
        )

    if snapshot["disk_free"] < 3 * 1024 * 1024 * 1024 and "disk:low" not in alerted:
        events.append(
            AlertEvent(
                key="disk:low",
                title="fuzz-pipeline disk danger",
                description=f"Free disk is {human_bytes(snapshot['disk_free'])}. Stop or clean old runs before long campaigns.",
                severity="ERROR",
                fields={"workspace": str(workspace)}
            )
        )

    if snapshot["failed_logs"] and "campaign:failed-log" not in alerted:
        events.append(
            AlertEvent(
                key="campaign:failed-log",
                title="fuzz campaign failure signal",
                description="A campaign log contains an abort/error marker.",
                severity="ERROR",
                fields={"logs": "\n".join(snapshot["failed_logs"][:5])}
            )
        )

    if snapshot["execs"] == state.get("last_execs") and snapshot["paths"] == state.get("last_paths") and snapshot["stats"]:
        state["stall_count"] = int(state.get("stall_count", 0)) + 1
    else:
        state["stall_count"] = 0
    if state["stall_count"] >= 3 and "campaign:stalled" not in alerted:
        events.append(
            AlertEvent(
                key="campaign:stalled",
                title="fuzz campaign appears stalled",
                description="AFL++ exec/path counters did not move for three monitor intervals.",
                severity="ERROR",
                fields={"run": rel_to(run_dir, workspace), "execs": snapshot["execs"], "paths": snapshot["paths"]}
            )
        )

    return events


def monitor_once(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    webhook: str | None = None,
    no_alerts: bool = False,
    triage: bool = True
) -> dict[str, Any]:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    state_dir = ensure_dir(run_dir / "monitor")
    state_path = state_dir / "state.json"
    state = _load_state(state_path)
    alerted = set(state.get("alerted_keys", []))

    pre_snapshot = _snapshot(workspace, run_dir)
    raw_events = _raw_crash_events(workspace, run_dir, pre_snapshot, state)
    for event in raw_events:
        if not no_alerts and webhook_url(webhook):
            send_discord(event, url=webhook)
        elif not no_alerts:
            print(f"alert not sent; DISCORD_WEBHOOK_URL is not set: {event.title}")
        alerted.add(event.key)
        state["last_raw_alert_at"] = int(time.time())
        print(f"event: {event.severity} {event.title} [{event.key}]")

    if triage and pre_snapshot["raw_crashes"]:
        triage_run(workspace, manifest, run_dir.name)

    snapshot = _snapshot(workspace, run_dir)
    events = _events(workspace, run_dir, snapshot, state)
    for event in events:
        if not no_alerts and webhook_url(webhook):
            send_discord(event, url=webhook)
        elif not no_alerts:
            print(f"alert not sent; DISCORD_WEBHOOK_URL is not set: {event.title}")
        alerted.add(event.key)
        print(f"event: {event.severity} {event.title} [{event.key}]")

    state["alerted_keys"] = sorted(alerted)
    state["last_execs"] = snapshot["execs"]
    state["last_paths"] = snapshot["paths"]
    state["last_raw_crashes"] = snapshot["raw_crashes"]
    state["last_unique_crashes"] = len(snapshot["unique_crashes"])
    state["last_reproducible_alerts"] = [
        crash.get("id") for crash in snapshot["unique_crashes"] if crash.get("reproducible", False)
    ]
    state["last_snapshot"] = snapshot
    state["updated_at"] = int(time.time())
    write_json(state_path, state)

    print(
        f"monitor {rel_to(run_dir, workspace)}: execs={snapshot['execs']} paths={snapshot['paths']} "
        f"raw_crashes={snapshot['raw_crashes']} unique={len(snapshot['unique_crashes'])} "
        f"disk={human_bytes(snapshot['disk_free'])}"
    )
    return snapshot


def monitor_loop(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None,
    interval: int,
    max_loops: int | None,
    webhook: str | None,
    no_alerts: bool,
    triage: bool
) -> None:
    loops = 0
    while True:
        monitor_once(workspace, manifest, run_id=run_id, webhook=webhook, no_alerts=no_alerts, triage=triage)
        loops += 1
        if max_loops is not None and loops >= max_loops:
            break
        time.sleep(interval)
