from __future__ import annotations

from pathlib import Path

from .campaign_common import _harnesses
from .campaign_engines import run_aflpp, run_fuzztest, run_libfuzzer
from .campaign_status import status
from .manifest import TargetManifest


def smoke(workspace: Path, manifest: TargetManifest, seconds: int, *, leak_check: bool = False) -> Path:
    if _harnesses(manifest, "libfuzzer"):
        label = "smoke-libfuzzer-leaks" if leak_check else "smoke-libfuzzer"
        return run_libfuzzer(workspace, manifest, seconds, label=label, detect_leaks=True if leak_check else None)
    if _harnesses(manifest, "fuzztest"):
        return run_fuzztest(workspace, manifest, seconds, label="smoke-fuzztest")
    return run_aflpp(workspace, manifest, seconds, workers=1, label="smoke-aflpp")


def run_campaign(workspace: Path, manifest: TargetManifest, engine: str, hours: float, workers: int | None) -> list[Path]:
    seconds = max(1, int(hours * 3600))
    run_dirs: list[Path] = []
    if engine in {"libfuzzer", "all"}:
        run_dirs.append(run_libfuzzer(workspace, manifest, seconds, label="campaign-libfuzzer"))
    if engine == "fuzztest":
        run_dirs.append(run_fuzztest(workspace, manifest, seconds, label="campaign-fuzztest"))
    elif engine == "all" and _harnesses(manifest, "fuzztest"):
        run_dirs.append(run_fuzztest(workspace, manifest, seconds, label="campaign-fuzztest"))
    if engine in {"aflpp", "all"}:
        run_dirs.append(run_aflpp(workspace, manifest, seconds, workers=workers, label="campaign-aflpp"))
    return run_dirs
