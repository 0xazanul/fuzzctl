from __future__ import annotations

from pathlib import Path
from typing import Any

from .advanced_tools import advanced_tool_status
from .manifest import Harness, TargetManifest
from .monitor_snapshot import _snapshot
from .triage import _crash_files
from .util import read_json, rel_to


def gate(section: str, name: str, status: str, evidence: str, action: str = "") -> dict[str, str]:
    return {
        "section": section,
        "name": name,
        "status": status,
        "evidence": evidence,
        "action": action,
    }


def core_harness_gates(
    workspace: Path,
    manifest: TargetManifest,
    review: dict[str, Any],
    builds: dict[str, int],
    seed_count: int,
) -> list[dict[str, str]]:
    file_harnesses = [h for h in manifest.harnesses if h.type in {"file", "stdin"}]
    libfuzzer_harnesses = [h for h in manifest.harnesses if h.type == "libfuzzer"]
    source_backed = [
        h for h in manifest.harnesses
        if h.source and (manifest.source_dir(workspace) / h.source).exists()
    ]
    return [
        gate(
            "core",
            "harness review",
            "pass" if not review["errors"] else "fail",
            f"errors={len(review['errors'])} warnings={len(review['warnings'])}",
            "Run `fuzzctl harness review <target>` and fix blocking errors." if review["errors"] else "",
        ),
        gate(
            "core",
            "source-backed harnesses",
            "pass" if source_backed else "fail",
            f"{len(source_backed)} source-backed harnesses",
            "Add or wire real harness source files." if not source_backed else "",
        ),
        gate(
            "core",
            "AFL++ file/stdin harness",
            "pass" if file_harnesses else "fail",
            f"{len(file_harnesses)} file/stdin harnesses",
            "Add at least one file/stdin harness for AFL++ campaigns." if not file_harnesses else "",
        ),
        gate(
            "core",
            "libFuzzer harness",
            "pass" if libfuzzer_harnesses else "warn",
            f"{len(libfuzzer_harnesses)} libFuzzer harnesses",
            "Add libFuzzer when an in-process parser/API entrypoint exists." if not libfuzzer_harnesses else "",
        ),
        gate(
            "core",
            "seed corpus",
            "pass" if seed_count > 0 else "fail",
            f"{seed_count} seeds across base and curated corpora",
            "Collect seeds from examples, tests, docs, or generated structure-aware inputs." if seed_count == 0 else "",
        ),
        gate(
            "core",
            "AFL++ ASan+UBSan build",
            "pass" if builds.get("afl_asan_ubsan", 0) > 0 else "fail",
            f"{builds.get('afl_asan_ubsan', 0)} artifacts",
            "Run `fuzzctl build <target> --profile afl_asan_ubsan`." if builds.get("afl_asan_ubsan", 0) == 0 else "",
        ),
        gate(
            "core",
            "libFuzzer ASan+UBSan build",
            "pass" if builds.get("libfuzzer_asan_ubsan", 0) > 0 else "warn",
            f"{builds.get('libfuzzer_asan_ubsan', 0)} artifacts",
            "Run `fuzzctl build <target> --profile libfuzzer_asan_ubsan` when libFuzzer harnesses exist."
            if libfuzzer_harnesses and builds.get("libfuzzer_asan_ubsan", 0) == 0 else "",
        ),
    ]


def campaign_gates(workspace: Path, run_dir: Path | None) -> tuple[list[dict[str, str]], dict[str, Any] | None]:
    if run_dir is None:
        return [
            gate(
                "campaign",
                "latest run",
                "fail",
                "no run found",
                "Run smoke or AFL++ campaign after sanitizer builds pass.",
            )
        ], None
    snap = _snapshot(workspace, run_dir)
    gates = [
        gate("campaign", "run selected", "pass", rel_to(run_dir, workspace)),
        gate(
            "campaign",
            "worker liveness",
            "pass" if snap["workers_alive"] >= min(1, snap["workers_expected"]) else "warn",
            f"alive={snap['workers_alive']} expected={snap['workers_expected']}",
            "Check supervisor status and AFL++ logs if workers are not alive." if snap["workers_expected"] and not snap["workers_alive"] else "",
        ),
        gate(
            "campaign",
            "queue growth",
            "pass" if snap["queue_files"] > 0 or snap["paths"] > 0 else "warn",
            f"queue_files={snap['queue_files']} paths={snap['paths']}",
            "Improve seeds or harness entrypoint if AFL++ is not growing a queue." if snap["queue_files"] == 0 and snap["paths"] == 0 else "",
        ),
        gate(
            "campaign",
            "stale workers",
            "pass" if not snap["stale_stats"] else "warn",
            f"stale_stats={len(snap['stale_stats'])}",
            "Inspect stale fuzzer_stats paths and restart via supervisor if needed." if snap["stale_stats"] else "",
        ),
    ]
    return gates, snap


def compact_snapshot(snap: dict[str, Any] | None) -> dict[str, Any] | None:
    if snap is None:
        return None
    return {
        "active": snap.get("active"),
        "execs": snap.get("execs", 0),
        "paths": snap.get("paths", 0),
        "queue_files": snap.get("queue_files", 0),
        "queue_by_harness": snap.get("queue_by_harness", {}),
        "raw_crashes": snap.get("raw_crashes", 0),
        "unique_crash_count": snap.get("unique_crash_count", 0),
        "duplicate_crashes": snap.get("duplicate_crashes", 0),
        "workers_expected": snap.get("workers_expected", 0),
        "workers_alive": snap.get("workers_alive", 0),
        "stale_stats": snap.get("stale_stats", []),
        "failed_logs": snap.get("failed_logs", []),
        "disk_free": snap.get("disk_free"),
    }


def coverage_gate(run_dir: Path | None, coverage: dict[str, Any] | None) -> dict[str, str]:
    if run_dir is None:
        return gate("coverage", "target coverage evidence", "warn", "no run selected", "Run coverage after a smoke/campaign run.")
    if not coverage:
        return gate(
            "coverage",
            "target coverage evidence",
            "warn",
            "no target-source coverage report found",
            "Run `fuzzctl coverage <target> --run <run-id>`.",
        )
    status = "pass" if coverage["line"] >= 40 and coverage["function"] >= 50 else "warn"
    return gate(
        "coverage",
        "target coverage evidence",
        status,
        f"line={coverage['line']}% function={coverage['function']}% region={coverage['region']}%",
        "Use harness blockers/suspicious-points before adding more workers." if status == "warn" else "",
    )


def triage_gates(run_dir: Path | None, snap: dict[str, Any] | None) -> list[dict[str, str]]:
    if run_dir is None:
        return [gate("triage", "crash triage", "not_applicable", "no run selected")]
    triage_file = run_dir / "triage" / "unique_crashes.json"
    raw_crashes = int(snap.get("raw_crashes", len(_crash_files(run_dir))) if snap else len(_crash_files(run_dir)))
    if raw_crashes == 0:
        return [gate("triage", "crash triage", "not_applicable", "no raw crashes in selected run")]
    if not triage_file.exists():
        return [
            gate(
                "triage",
                "crash triage",
                "fail",
                f"raw_crashes={raw_crashes} triage=missing",
                "Run `fuzzctl triage <target> --run <run-id>`.",
            )
        ]
    unique = len(read_json(triage_file).get("crashes", []))
    return [gate("triage", "crash triage", "pass", f"raw_crashes={raw_crashes} unique={unique}")]


def _afl_instances(run_dir: Path | None, harness: Harness) -> list[str]:
    if run_dir is None:
        return []
    root = run_dir / "aflpp" / harness.name / "findings"
    if not root.exists():
        return []
    return sorted(path.name for path in root.iterdir() if path.is_dir() and (path / "fuzzer_stats").exists())


def advanced_gates(
    workspace: Path,
    manifest: TargetManifest,
    run_dir: Path | None,
    builds: dict[str, int],
) -> list[dict[str, str]]:
    tools = advanced_tool_status(workspace)
    file_harnesses = [h for h in manifest.harnesses if h.type in {"file", "stdin"} and (not h.profiles or "afl_asan_ubsan" in h.profiles)]
    symcc_instances = {h.name: _afl_instances(run_dir, h) for h in file_harnesses}
    symcc_ready = bool(tools["ready"]["hybrid_symcc"] and any(symcc_instances.values()))
    symcc_last: dict[str, Any] = {}
    if run_dir is not None:
        symcc_last_path = run_dir / "hybrid" / "symcc" / "symcc-hybrid.json"
        if symcc_last_path.exists():
            symcc_last = read_json(symcc_last_path)
    symcc_failed = symcc_last.get("status") == "build_failed"
    fuzztest_harnesses = [h for h in manifest.harnesses if h.type == "fuzztest"]
    grammar_configured = [h.name for h in manifest.harnesses if h.env.get("AFL_CUSTOM_MUTATOR_LIBRARY")]
    return [
        gate(
            "advanced",
            "SymCC hybrid",
            "pass" if symcc_ready and builds.get("symcc", 0) > 0 and not symcc_failed else ("warn" if symcc_ready else "not_configured"),
            (
                f"installed={tools['ready']['hybrid_symcc']} "
                f"eligible_harnesses={sum(1 for v in symcc_instances.values() if v)} "
                f"symcc_artifacts={builds.get('symcc', 0)}"
                + (f" last_status={symcc_last.get('status')}" if symcc_last else "")
            ),
            (
                "SymCC build failed for this target; keep AFL++/libFuzzer as core and isolate unsupported compile units before retrying."
                if symcc_failed
                else (
                    "Run `fuzzctl hybrid symcc <target> --dry-run`, then build/run SymCC for selected harnesses."
                    if symcc_ready and builds.get("symcc", 0) == 0 else ""
                )
            ),
        ),
        gate(
            "advanced",
            "FuzzTest properties",
            "pass" if fuzztest_harnesses and builds.get("fuzztest_asan_ubsan", 0) > 0 else "not_configured",
            f"harnesses={len(fuzztest_harnesses)} artifacts={builds.get('fuzztest_asan_ubsan', 0)}",
            "Use `fuzzctl harness fuzztest-plan` for invariant/roundtrip candidates." if not fuzztest_harnesses else "",
        ),
        gate(
            "advanced",
            "OSS-Fuzz-Gen",
            "pass" if tools["ready"]["oss_fuzz_gen_local_execution"] else "warn",
            f"workorders={tools['ready']['oss_fuzz_gen_workorders']} local_execution={tools['ready']['oss_fuzz_gen_local_execution']}",
            "Keep using Codex workorders unless local OSS-Fuzz-Gen execution is deliberately enabled.",
        ),
        gate(
            "advanced",
            "Grammar-Mutator",
            "pass" if grammar_configured else ("warn" if tools["ready"]["grammar_mutator_campaigns"] else "not_configured"),
            f"tool_ready={tools['ready']['grammar_mutator_campaigns']} configured_harnesses={len(grammar_configured)}",
            "Attach a grammar mutator only for structured formats where it improves depth." if not grammar_configured else "",
        ),
        gate(
            "advanced",
            "CASR/exploitable",
            "pass" if tools["ready"]["casr_triage"] and tools["ready"]["exploitable_gdb"] else "warn",
            f"casr={tools['ready']['casr_triage']} exploitable={tools['ready']['exploitable_gdb']}",
            "Advanced triage is useful only after reproducible crashes exist.",
        ),
    ]


def overall_status(gates: list[dict[str, str]]) -> str:
    core = [item for item in gates if item["section"] in {"core", "campaign"}]
    if any(item["status"] == "fail" for item in core):
        return "not_ready"
    if any(item["status"] in {"fail", "warn"} for item in gates):
        return "ready_with_warnings"
    return "ready"
