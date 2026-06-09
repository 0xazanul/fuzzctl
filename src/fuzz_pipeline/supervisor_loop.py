from __future__ import annotations

import time
from pathlib import Path

from .campaign import run_campaign, smoke
from .manifest import TargetManifest
from .post_cycle import post_cycle_run
from .reporting import report_run
from .supervisor_processes import active_fuzz_processes, campaign_mismatch_reason, terminate_processes
from .supervisor_state import target_lock, write_state
from .triage import minimize_run, triage_run
from .util import free_disk_bytes, human_bytes


def _handle_active_campaign(
    workspace: Path,
    manifest: TargetManifest,
    *,
    engine: str,
    workers: int | None,
    wait_interval: int,
    replace_mismatched: bool,
    replace_timeout: int,
) -> bool:
    target = manifest.name
    active = active_fuzz_processes(workspace, target)
    if not active:
        return False

    mismatch = campaign_mismatch_reason(active, manifest, engine=engine, workers=workers)
    if mismatch and replace_mismatched:
        write_state(
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
        termination = terminate_processes(active, timeout=replace_timeout)
        write_state(
            workspace,
            target,
            {
                "status": "mismatched_campaign_replaced",
                "reason": mismatch,
                "termination": termination,
            },
        )
        time.sleep(2)
        return True

    write_state(
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
    return True


def _run_leak_smoke_if_needed(
    workspace: Path,
    manifest: TargetManifest,
    *,
    cycle: int,
    leak_smoke_seconds: int,
) -> list[str]:
    if leak_smoke_seconds <= 0:
        return []

    write_state(
        workspace,
        manifest.name,
        {
            "status": "running_leak_smoke",
            "cycle": cycle,
            "seconds_per_harness": leak_smoke_seconds,
        },
    )
    leak_run = smoke(workspace, manifest, leak_smoke_seconds, leak_check=True)
    try:
        triage_run(workspace, manifest, leak_run.name)
        minimize_run(workspace, manifest, leak_run.name)
        report_run(workspace, manifest, leak_run.name)
    except Exception as exc:
        write_state(
            workspace,
            manifest.name,
            {
                "status": "leak_smoke_error",
                "cycle": cycle,
                "run_id": leak_run.name,
                "error": str(exc),
            },
        )
        raise
    return [leak_run.name]


def _run_supervised_campaign(
    workspace: Path,
    manifest: TargetManifest,
    *,
    cycle: int,
    engine: str,
    hours: float,
    workers: int | None,
    leak_run_ids: list[str],
) -> list[Path]:
    write_state(
        workspace,
        manifest.name,
        {
            "status": "running_campaign",
            "cycle": cycle,
            "engine": engine,
            "hours": hours,
            "workers": workers,
            "leak_smoke_run_ids": leak_run_ids,
        },
    )
    return run_campaign(workspace, manifest, engine, hours, workers)


def _run_post_cycles(
    workspace: Path,
    manifest: TargetManifest,
    *,
    cycle: int,
    run_dirs: list[Path],
    coverage_inputs: int,
) -> None:
    for run_dir in run_dirs:
        run_id = run_dir.name
        try:
            post_cycle_run(
                workspace,
                manifest,
                run_id,
                coverage_inputs=coverage_inputs,
                continue_on_error=False,
            )
        except Exception as exc:
            write_state(
                workspace,
                manifest.name,
                {
                    "status": "post_cycle_error",
                    "cycle": cycle,
                    "run_id": run_id,
                    "error": str(exc),
                },
            )
            raise


def _write_cycle_complete(
    workspace: Path,
    manifest: TargetManifest,
    *,
    cycle: int,
    run_ids: list[str],
    leak_run_ids: list[str],
) -> None:
    write_state(
        workspace,
        manifest.name,
        {
            "status": "cycle_complete",
            "cycle": cycle,
            "run_ids": run_ids,
            "leak_smoke_run_ids": leak_run_ids,
            "disk_free": human_bytes(free_disk_bytes(workspace)),
        },
    )


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
    with target_lock(workspace, target) as locked:
        if not locked:
            print(f"supervisor for {target} is already running; exiting")
            return 0
        cycle = 0
        while max_cycles is None or cycle < max_cycles:
            if _handle_active_campaign(
                workspace,
                manifest,
                engine=engine,
                workers=workers,
                wait_interval=wait_interval,
                replace_mismatched=replace_mismatched,
                replace_timeout=replace_timeout,
            ):
                continue

            cycle += 1
            leak_run_ids = _run_leak_smoke_if_needed(
                workspace,
                manifest,
                cycle=cycle,
                leak_smoke_seconds=leak_smoke_seconds,
            )
            run_dirs = _run_supervised_campaign(
                workspace,
                manifest,
                cycle=cycle,
                engine=engine,
                hours=hours,
                workers=workers,
                leak_run_ids=leak_run_ids,
            )
            run_ids = [run_dir.name for run_dir in run_dirs]
            write_state(
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
                _run_post_cycles(
                    workspace,
                    manifest,
                    cycle=cycle,
                    run_dirs=run_dirs,
                    coverage_inputs=coverage_inputs,
                )
            _write_cycle_complete(workspace, manifest, cycle=cycle, run_ids=run_ids, leak_run_ids=leak_run_ids)
        write_state(workspace, target, {"status": "max_cycles_complete", "cycles": cycle})
    return 0
