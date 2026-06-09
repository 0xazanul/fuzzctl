from __future__ import annotations

from pathlib import Path

from .manifest import TargetManifest
from .supervisor_loop import campaign_loop
from .supervisor_processes import (
    _active_afl_worker_counts,
    _classify_cmdline,
    active_fuzz_processes,
    campaign_mismatch_reason,
)
from .supervisor_state import state_path
from .util import read_json


_campaign_mismatch_reason = campaign_mismatch_reason


def supervisor_status(
    workspace: Path,
    manifest: TargetManifest | None = None,
    *,
    as_json: bool = False,
) -> dict[str, object]:
    targets = (
        [manifest.name]
        if manifest
        else sorted(p.name for p in (workspace / "targets").iterdir() if p.is_dir())
    )
    result: dict[str, object] = {"workspace": str(workspace), "targets": {}}
    target_map: dict[str, object] = {}
    for target in targets:
        state_file = state_path(workspace, target)
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
            status = state.get("status", "unknown") if isinstance(state, dict) else "unknown"
            print(f"{target}: active_processes={len(active)} supervisor_state={status}")
            for proc in active:  # type: ignore[assignment]
                print(f"  pid={proc['pid']} kind={proc['kind']}")
    return result
