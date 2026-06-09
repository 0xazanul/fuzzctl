from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .alerts import send_discord, webhook_url
from .manifest import TargetManifest
from .monitor_events import _events, _raw_crash_events
from .monitor_snapshot import _snapshot
from .triage import triage_run
from .util import ensure_dir, find_latest_run, human_bytes, read_json, rel_to, write_json


def _load_state(path: Path) -> dict[str, Any]:
    if path.exists():
        return read_json(path)
    return {
        "alerted_keys": [],
        "last_execs": 0,
        "last_paths": 0,
        "last_raw_crashes": 0,
        "last_unique_crashes": 0,
        "last_duplicate_crashes": 0,
        "last_triaged_raw_crashes": 0,
        "last_raw_alert_at": 0,
        "last_reproducible_alerts": [],
        "stall_count": 0
    }


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
    if triage and pre_snapshot["raw_crashes"]:
        triage_run(workspace, manifest, run_dir.name)

    snapshot = _snapshot(workspace, run_dir)
    raw_events = _raw_crash_events(workspace, run_dir, snapshot, state)
    for event in raw_events:
        if not no_alerts and webhook_url(webhook):
            send_discord(event, url=webhook)
        elif not no_alerts:
            print(f"alert not sent; DISCORD_WEBHOOK_URL is not set: {event.title}")
        alerted.add(event.key)
        state["last_raw_alert_at"] = int(time.time())
        print(f"event: {event.severity} {event.title} [{event.key}]")

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
    state["last_unique_crashes"] = snapshot.get("unique_crash_count", len(snapshot["unique_crashes"]))
    state["last_duplicate_crashes"] = snapshot.get("duplicate_crashes", 0)
    state["last_triaged_raw_crashes"] = snapshot.get("triaged_raw_crashes", 0)
    state["last_reproducible_alerts"] = [
        crash.get("id") for crash in snapshot["unique_crashes"] if crash.get("reproducible", False)
    ]
    state["last_snapshot"] = snapshot
    state["updated_at"] = int(time.time())
    write_json(state_path, state)

    print(
        f"monitor {rel_to(run_dir, workspace)}: execs={snapshot['execs']} paths={snapshot['paths']} "
        f"raw_crashes={snapshot['raw_crashes']} unique={snapshot.get('unique_crash_count', len(snapshot['unique_crashes']))} "
        f"duplicates={snapshot.get('duplicate_crashes', 0)} "
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
