from __future__ import annotations

from pathlib import Path
from typing import Any

from .alerts import AlertEvent
from .util import human_bytes, read_json, rel_to


def _raw_crash_events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], state: dict[str, Any]) -> list[AlertEvent]:
    raw_count = int(snapshot.get("raw_crashes", 0))
    previous = int(state.get("last_raw_crashes", 0) or 0)
    if raw_count <= previous:
        return []
    key = f"raw-crash:{run_dir.name}:{raw_count}"
    if key in set(state.get("alerted_keys", [])):
        return []

    unique_count = int(snapshot.get("unique_crash_count", len(snapshot.get("unique_crashes", []))) or 0)
    duplicate_count_now = int(snapshot.get("duplicate_crashes", 0) or 0)
    previous_unique = int(state.get("last_unique_crashes", 0) or 0)
    previous_duplicates = int(state.get("last_duplicate_crashes", 0) or 0)
    unique_known = "unique_crash_count" in snapshot or "unique_crashes" in snapshot
    duplicate_only = unique_known and unique_count <= previous_unique and duplicate_count_now > previous_duplicates
    return [_raw_crash_event(workspace, run_dir, snapshot, raw_count, previous, unique_count, duplicate_count_now, duplicate_only)]


def _raw_crash_event(
    workspace: Path,
    run_dir: Path,
    snapshot: dict[str, Any],
    raw_count: int,
    previous: int,
    unique_count: int,
    duplicate_count: int,
    duplicate_only: bool,
) -> AlertEvent:
    return AlertEvent(
        key=f"raw-crash:{run_dir.name}:{raw_count}",
        title="duplicate raw fuzz crash observed" if duplicate_only else "raw fuzz crash observed",
        description=(
            "A new crash artifact collapsed into an already-known sanitizer state for this run."
            if duplicate_only
            else "A crash artifact appeared. Triage will confirm whether it is sanitizer-reproducible and security-relevant."
        ),
        severity="INFO" if duplicate_only else "HIGH",
        fields={
            "run": rel_to(run_dir, workspace),
            "raw_crashes": raw_count,
            "previous_raw_crashes": previous,
            "unique_crashes": unique_count,
            "duplicate_crashes": duplicate_count,
            "recent_files": "\n".join(snapshot.get("raw_crash_files", [])[-5:]) or "none",
        },
    )


def _previous_crash_runs(workspace: Path, run_dir: Path, crash: dict[str, Any]) -> list[str]:
    target = run_dir.parent.name
    crash_id = str(crash.get("id") or "")
    state = str(crash.get("state") or "")
    previous: list[str] = []
    for triage_path in sorted((workspace / "runs" / target).glob("*/triage/unique_crashes.json")):
        other_run = triage_path.parents[1]
        if other_run == run_dir:
            continue
        try:
            data = read_json(triage_path)
        except Exception:
            continue
        if _triage_contains_same_crash(data, crash_id, state):
            previous.append(other_run.name)
    return previous[-5:]


def _triage_contains_same_crash(data: dict[str, Any], crash_id: str, state: str) -> bool:
    for item in data.get("crashes", []):
        if not item.get("reproducible", False):
            continue
        same_id = crash_id and str(item.get("id") or "") == crash_id
        same_state = state and str(item.get("state") or "") == state
        if same_id or same_state:
            return True
    return False


def _reproducible_crash_events(
    workspace: Path,
    run_dir: Path,
    snapshot: dict[str, Any],
    alerted: set[str],
) -> list[AlertEvent]:
    events: list[AlertEvent] = []
    for crash in snapshot.get("unique_crashes", []):
        if not crash.get("reproducible", False):
            continue
        key = f"crash:{crash['id']}"
        if key in alerted:
            continue
        previous_runs = _previous_crash_runs(workspace, run_dir, crash)
        known_duplicate = bool(previous_runs)
        severity = str(crash.get("severity", "INFO"))
        events.append(
            AlertEvent(
                key=key,
                title=(
                    f"known duplicate fuzz crash: {crash.get('type', 'unknown')}"
                    if known_duplicate
                    else f"{severity} fuzz crash: {crash.get('type', 'unknown')}"
                ),
                description=(
                    "This sanitizer state already exists in an earlier run, so it is tracked as a duplicate occurrence."
                    if known_duplicate
                    else str(crash.get("impact", "New reproducible fuzz crash."))
                ),
                severity="INFO" if known_duplicate else severity,
                fields={
                    "run": rel_to(run_dir, workspace),
                    "harness": crash.get("harness"),
                    "id": crash.get("id"),
                    "duplicate_of_runs": "\n".join(previous_runs) if previous_runs else "none",
                    "raw_artifacts": crash.get("raw_artifacts", 1),
                    "duplicates": crash.get("duplicates", 0),
                    "minimized": (
                        rel_to(Path(crash["minimized_path"]), workspace)
                        if crash.get("minimized_path")
                        else "not minimized yet"
                    ),
                },
            )
        )
    return events


def _worker_events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], alerted: set[str]) -> list[AlertEvent]:
    if not snapshot.get("active") or not snapshot.get("workers_expected", 0):
        return []
    if snapshot.get("workers_alive", 0) >= snapshot.get("workers_expected", 0):
        return []
    key = f"workers:missing:{snapshot.get('workers_alive')}:{snapshot.get('workers_expected')}"
    if key in alerted:
        return []
    return [
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
    ]


def _stale_stats_events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], alerted: set[str]) -> list[AlertEvent]:
    if not snapshot.get("active") or not snapshot.get("stale_stats") or "campaign:stale-stats" in alerted:
        return []
    return [
        AlertEvent(
            key="campaign:stale-stats",
            title="fuzz worker stats appear stale",
            description="One or more AFL++ fuzzer_stats files have not updated for more than three minutes.",
            severity="ERROR",
            fields={"run": rel_to(run_dir, workspace), "stale": "\n".join(snapshot["stale_stats"][:8])},
        )
    ]


def _disk_events(workspace: Path, snapshot: dict[str, Any], alerted: set[str]) -> list[AlertEvent]:
    if snapshot["disk_free"] >= 3 * 1024 * 1024 * 1024 or "disk:low" in alerted:
        return []
    return [
        AlertEvent(
            key="disk:low",
            title="fuzz-pipeline disk danger",
            description=f"Free disk is {human_bytes(snapshot['disk_free'])}. Stop or clean old runs before long campaigns.",
            severity="ERROR",
            fields={"workspace": str(workspace)},
        )
    ]


def _failed_log_events(snapshot: dict[str, Any], alerted: set[str]) -> list[AlertEvent]:
    if not snapshot["failed_logs"] or "campaign:failed-log" in alerted:
        return []
    return [
        AlertEvent(
            key="campaign:failed-log",
            title="fuzz campaign failure signal",
            description="A campaign log contains an abort/error marker.",
            severity="ERROR",
            fields={"logs": "\n".join(snapshot["failed_logs"][:5])},
        )
    ]


def _stall_events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], state: dict[str, Any], alerted: set[str]) -> list[AlertEvent]:
    if snapshot["execs"] == state.get("last_execs") and snapshot["paths"] == state.get("last_paths") and snapshot["stats"]:
        state["stall_count"] = int(state.get("stall_count", 0)) + 1
    else:
        state["stall_count"] = 0
    if state["stall_count"] < 3 or "campaign:stalled" in alerted:
        return []
    return [
        AlertEvent(
            key="campaign:stalled",
            title="fuzz campaign appears stalled",
            description="AFL++ exec/path counters did not move for three monitor intervals.",
            severity="ERROR",
            fields={"run": rel_to(run_dir, workspace), "execs": snapshot["execs"], "paths": snapshot["paths"]},
        )
    ]


def _events(workspace: Path, run_dir: Path, snapshot: dict[str, Any], state: dict[str, Any]) -> list[AlertEvent]:
    alerted = set(state.get("alerted_keys", []))
    events: list[AlertEvent] = []
    events.extend(_reproducible_crash_events(workspace, run_dir, snapshot, alerted))
    events.extend(_worker_events(workspace, run_dir, snapshot, alerted))
    events.extend(_stale_stats_events(workspace, run_dir, snapshot, alerted))
    events.extend(_disk_events(workspace, snapshot, alerted))
    events.extend(_failed_log_events(snapshot, alerted))
    events.extend(_stall_events(workspace, run_dir, snapshot, state, alerted))
    return events
