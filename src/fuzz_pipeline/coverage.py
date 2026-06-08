from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .builder import build_profile, harness_binary
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, ensure_dir, find_latest_run, iter_files, now_id, rel_to, run_cmd, sha256_file, which_any, write_json


def _llvm_tool(name: str) -> str:
    found = which_any([name, f"{name}-18", f"{name}-17", f"{name}-16", f"{name}-15"])
    if not found:
        raise FuzzCtlError(f"missing {name}; install LLVM tools or use Docker runtime")
    return found


def _sample_paths(paths: list[Path], limit: int) -> list[Path]:
    if limit <= 0:
        return []
    if len(paths) <= limit:
        return paths
    head = max(1, limit // 2)
    tail = max(0, limit - head)
    sampled: list[Path] = []
    seen: set[Path] = set()
    for path in [*paths[:head], *paths[-tail:]]:
        if path not in seen:
            sampled.append(path)
            seen.add(path)
    return sampled[:limit]


def _input_sources(workspace: Path, manifest: TargetManifest, run_dir: Path, harness: Harness) -> list[tuple[str, list[Path], bool]]:
    seed_dir = manifest.seed_dir(workspace)
    minimized = run_dir / "minimized"
    curated = workspace / "corpora" / manifest.name / harness.name / "current"
    afl_queue = run_dir / "aflpp" / harness.name / "findings"
    libfuzzer_corpus = run_dir / "libfuzzer" / harness.name / "corpus"
    return [
        ("seed", iter_files([seed_dir]) if seed_dir.exists() else [], True),
        ("minimized", iter_files([minimized]) if minimized.exists() else [], True),
        ("curated", iter_files([curated]) if curated.exists() else [], True),
        ("afl_queue", sorted(afl_queue.glob("*/queue/id:*")) if afl_queue.exists() else [], False),
        ("libfuzzer_corpus", iter_files([libfuzzer_corpus]) if libfuzzer_corpus.exists() else [], False),
    ]


def collect_coverage_inputs(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path,
    harness: Harness,
    *,
    max_inputs: int = 5000,
) -> tuple[list[Path], dict[str, Any]]:
    if max_inputs <= 0:
        raise FuzzCtlError("--max-inputs must be greater than zero")

    selected: list[Path] = []
    seen_hashes: set[str] = set()
    summary: dict[str, Any] = {
        "harness": harness.name,
        "max_inputs": max_inputs,
        "sources": {},
        "deduped": 0,
        "selected": 0,
    }

    def add(label: str, paths: list[Path], force: bool) -> None:
        nonlocal selected
        source = summary["sources"].setdefault(label, {"discovered": len(paths), "selected": 0, "deduped": 0})
        remaining = max_inputs - len(selected)
        candidates = paths if force else _sample_paths(paths, remaining)
        for path in candidates:
            if not path.is_file():
                continue
            if len(selected) >= max_inputs and not force:
                break
            digest = sha256_file(path)
            if digest in seen_hashes:
                source["deduped"] += 1
                summary["deduped"] += 1
                continue
            seen_hashes.add(digest)
            selected.append(path)
            source["selected"] += 1

    for label, paths, force in _input_sources(workspace, manifest, run_dir, harness):
        add(label, paths, force)

    summary["selected"] = len(selected)
    summary["sha256"] = hashlib.sha256("\n".join(str(p) for p in selected).encode("utf-8")).hexdigest()
    return selected, summary


def coverage_run(
    workspace: Path,
    manifest: TargetManifest,
    run_id: str | None = None,
    *,
    max_inputs: int = 5000,
) -> Path:
    build_profile(workspace, manifest, "coverage")
    if run_id:
        run_dir = workspace / "runs" / manifest.name / run_id
    else:
        run_dir = ensure_dir(workspace / "runs" / manifest.name / f"{now_id()}-coverage")
    out = ensure_dir(run_dir / "coverage")
    profraw = ensure_dir(out / "profraw")
    harness_reports = []
    input_summaries = []
    for harness in manifest.harnesses:
        if harness.type != "file":
            continue
        binary = harness_binary(workspace, manifest, "coverage", harness)
        if not binary.exists():
            continue
        inputs, input_summary = collect_coverage_inputs(workspace, manifest, run_dir, harness, max_inputs=max_inputs)
        input_summaries.append(input_summary)
        if not inputs:
            print(f"warning: no coverage inputs available for {harness.name}")
            continue
        for index, inp in enumerate(inputs):
            env = os.environ.copy()
            env["LLVM_PROFILE_FILE"] = str(profraw / f"{harness.name}-{index}-%p.profraw")
            env.update(harness.env)
            argv = [str(binary)]
            if harness.argv:
                argv.extend(str(inp) if part == "@@" else part for part in harness.argv)
            else:
                argv.append(str(inp))
            run_cmd(argv, cwd=manifest.source_dir(workspace), env=env, timeout=max(5, manifest.timeout_ms // 1000 + 5))

        raw_files = sorted(profraw.glob(f"{harness.name}-*.profraw"))
        if not raw_files:
            continue
        profdata = out / f"{harness.name}.profdata"
        report_txt = out / f"{harness.name}.report.txt"
        html_dir = ensure_dir(out / f"{harness.name}.html")
        llvm_profdata = _llvm_tool("llvm-profdata")
        llvm_cov = _llvm_tool("llvm-cov")
        run_cmd([llvm_profdata, "merge", "-sparse", "-o", str(profdata), *map(str, raw_files)], check=True, print_cmd=True)
        report = run_cmd([llvm_cov, "report", str(binary), f"-instr-profile={profdata}"], check=True, print_cmd=True)
        report_txt.write_text(report.output, encoding="utf-8", errors="replace")
        run_cmd(
            [
                llvm_cov,
                "show",
                str(binary),
                f"-instr-profile={profdata}",
                "-format=html",
                f"-output-dir={html_dir}",
            ],
            check=True,
            print_cmd=True,
        )
        harness_reports.append(
            {
                "harness": harness.name,
                "binary": str(binary),
                "profdata": str(profdata),
                "report": str(report_txt),
                "html": str(html_dir),
                "inputs": len(inputs),
                "input_summary": input_summary,
            }
        )
    if not harness_reports:
        raise FuzzCtlError("no file harnesses produced coverage; check harness builds and input corpus")
    write_json(out / "inputs.json", {"target": manifest.name, "run": str(run_dir), "harnesses": input_summaries})
    write_json(out / "coverage.json", {"target": manifest.name, "reports": harness_reports, "inputs": input_summaries})
    print(f"coverage output: {rel_to(out, workspace)}")
    return out
