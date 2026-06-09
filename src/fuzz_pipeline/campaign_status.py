from __future__ import annotations

from pathlib import Path

from .util import find_latest_run, rel_to


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
