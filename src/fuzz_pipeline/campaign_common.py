from __future__ import annotations

import shutil
from pathlib import Path

from .manifest import Harness, TargetManifest
from .util import ensure_dir, now_id, rel_to


def _run_dir(workspace: Path, name: str, label: str) -> Path:
    return ensure_dir(workspace / "runs" / name / f"{now_id()}-{label}")


def _seed_dir(workspace: Path, manifest: TargetManifest, run_dir: Path) -> Path:
    seed_dir = manifest.seed_dir(workspace)
    if seed_dir.exists() and any(p.is_file() for p in seed_dir.iterdir()):
        return seed_dir
    fallback = ensure_dir(run_dir / "generated_seed")
    (fallback / "seed").write_bytes(b"\x00")
    print(f"warning: seed corpus missing or empty, using generated seed at {fallback}")
    return fallback


def _copy_seed_corpus(seed_dir: Path, destination: Path, *, prefix: str = "") -> Path:
    ensure_dir(destination)
    index = 0
    for seed in sorted(seed_dir.iterdir()):
        if seed.is_file():
            name = f"{prefix}{seed.name}" if prefix else seed.name
            target = destination / name
            while target.exists():
                index += 1
                target = destination / f"{prefix}{index:04d}-{seed.name}"
            shutil.copy2(seed, target)
    return destination


def _prepare_harness_seed_corpus(workspace: Path, manifest: TargetManifest, run_dir: Path, harness: Harness) -> Path:
    destination = ensure_dir(run_dir / "seeds" / harness.name)
    base_seed = _seed_dir(workspace, manifest, run_dir)
    _copy_seed_corpus(base_seed, destination, prefix="base-")
    curated = workspace / "corpora" / manifest.name / harness.name / "current"
    if curated.exists() and any(p.is_file() for p in curated.iterdir()):
        _copy_seed_corpus(curated, destination, prefix="curated-")
    if not any(destination.iterdir()):
        (destination / "seed").write_bytes(b"\x00")
    return destination


def _count_crash_artifacts(run_dir: Path) -> int:
    count = 0
    for path in run_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.name.startswith("id:") and "/crashes/" in path.as_posix():
            count += 1
        elif path.name.startswith(("crash-", "leak-", "oom-", "timeout-")):
            count += 1
    return count


def _harnesses(manifest: TargetManifest, kind: str) -> list[Harness]:
    return [h for h in manifest.harnesses if h.type == kind]


def _worker_counts(harnesses: list[Harness], workers: int) -> dict[str, int]:
    if not harnesses:
        return {}
    counts = {h.name: 0 for h in harnesses}
    if workers <= 0:
        return counts
    effective_workers = max(workers, len(harnesses))
    for index in range(effective_workers):
        counts[harnesses[index % len(harnesses)].name] += 1
    return counts


def _asan_env() -> dict[str, str]:
    return {
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_UI": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "ASAN_OPTIONS": (
            "abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:"
            "strict_string_checks=1:symbolize=0"
        ),
        "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
    }


def _merge_harness_env(base: dict[str, str], harness: Harness, *, detect_leaks: bool | None = None) -> dict[str, str]:
    env = base.copy()
    env.update(harness.env)
    if detect_leaks is not None:
        options = env.get("ASAN_OPTIONS", "")
        parts = [part for part in options.split(":") if part and not part.startswith("detect_leaks=")]
        parts.append(f"detect_leaks={1 if detect_leaks else 0}")
        env["ASAN_OPTIONS"] = ":".join(parts)
    return env


def _file_target_argv(binary: Path, harness: Harness, testcase: str = "@@") -> list[str]:
    argv = [str(binary)]
    if harness.argv:
        argv.extend(testcase if part == "@@" else part for part in harness.argv)
    else:
        argv.append(testcase)
    return argv


def _prepare_grammar_trees(workspace: Path, manifest: TargetManifest, harness: Harness, findings: Path, role: str) -> str | None:
    tree_dir = harness.env.get("AFL_GRAMMAR_TREE_DIR")
    if not tree_dir:
        return None
    source = Path(tree_dir).expanduser()
    if not source.is_absolute():
        source = (workspace / source).resolve()
    if not source.exists():
        print(f"warning: AFL_GRAMMAR_TREE_DIR missing for {harness.name}: {source}")
        return None
    destination = ensure_dir(findings / role) / "trees"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    return rel_to(destination, workspace)
