from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .manifest import TargetManifest
from .util import FuzzCtlError, find_latest_run, read_json, rel_to


BANNED_PATTERNS = [
    ("error", re.compile(r"\b(exit|abort)\s*\("), "do not terminate the fuzz process for ordinary malformed input"),
    ("error", re.compile(r"\b(system|popen)\s*\("), "do not spawn shell commands from a harness"),
    ("error", re.compile(r"\b(sleep|usleep|nanosleep)\s*\("), "do not sleep in the fuzz loop"),
    ("error", re.compile(r"\b(socket|connect|listen|accept)\s*\("), "do not require network services in the fuzz loop"),
    ("warning", re.compile(r"\b(signal|sigaction)\s*\("), "avoid signal handlers that can hide crashes"),
    ("warning", re.compile(r"\b(rand|srand|random|time)\s*\("), "avoid nondeterminism unless it is fully derived from input bytes"),
    ("warning", re.compile(r"catch\s*\(\s*\.\.\.\s*\)"), "do not hide target failures with broad catch-all handlers"),
    ("warning", re.compile(r"strlen\s*\(\s*(?:\([^)]*\)\s*)?data\s*\)"), "do not treat arbitrary fuzz bytes as a C string unless the API is string-only"),
]


def _review_data(workspace: Path, manifest: TargetManifest) -> dict[str, Any]:
    source_dir = manifest.source_dir(workspace)
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    checks: list[str] = []

    if not manifest.harnesses:
        errors.append({"harness": manifest.name, "message": "manifest has no harnesses"})

    for harness in manifest.harnesses:
        label = harness.name
        if harness.source is None:
            warnings.append({"harness": label, "message": "manifest harness has no source; this is usually only acceptable for an existing CLI target"})
            continue
        source = (source_dir / harness.source).resolve()
        if not source.exists():
            errors.append({"harness": label, "message": f"source missing: {harness.source}"})
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        checks.append(f"{label}: reviewed {rel_to(source, workspace)}")
        if harness.type == "libfuzzer" and "LLVMFuzzerTestOneInput" not in text:
            errors.append({"harness": label, "message": "libFuzzer harness is missing LLVMFuzzerTestOneInput"})
        if harness.type == "fuzztest" and "FUZZ_TEST" not in text:
            errors.append({"harness": label, "message": "FuzzTest harness is missing FUZZ_TEST"})
        if harness.type in {"file", "stdin"} and not re.search(r"\bint\s+main\s*\(", text):
            warnings.append({"harness": label, "message": "file/stdin harness does not define an obvious main()"})
        if harness.type == "file" and "@@" not in " ".join(harness.argv):
            errors.append({"harness": label, "message": "file harness argv should include @@"})
        if harness.type == "libfuzzer" and text.count("size") < 2:
            warnings.append({"harness": label, "message": "size parameter is not obviously used beyond the signature"})
        for severity, pattern, message in BANNED_PATTERNS:
            if pattern.search(text):
                item = {"harness": label, "message": message}
                if severity == "error":
                    errors.append(item)
                else:
                    warnings.append(item)

    if not any(h.type == "libfuzzer" for h in manifest.harnesses):
        warnings.append({"harness": manifest.name, "message": "no libFuzzer harness; add one for fast sanitizer smoke/repro if an in-process API exists"})
    if not any(h.type in {"file", "stdin"} for h in manifest.harnesses):
        warnings.append({"harness": manifest.name, "message": "no file/stdin harness; AFL++ needs one unless using a compatible driver"})
    if not manifest.dictionary:
        warnings.append({"harness": manifest.name, "message": "no dictionary configured; extract format tokens after the first harness builds"})

    return {
        "target": manifest.name,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }


def _print_review(data: dict[str, Any]) -> None:
    print(f"harness review: {data['target']}")
    for check in data["checks"]:
        print(f"check: {check}")
    for warning in data["warnings"]:
        print(f"warning: {warning['harness']}: {warning['message']}")
    for error in data["errors"]:
        print(f"error: {error['harness']}: {error['message']}")
    if not data["errors"]:
        print("harness review passed")


def review_harnesses(workspace: Path, manifest: TargetManifest, *, as_json: bool = False) -> int:
    data = _review_data(workspace, manifest)
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        _print_review(data)
    return 2 if data["errors"] else 0


def _seed_count(workspace: Path, manifest: TargetManifest) -> int:
    count = 0
    seed_dir = manifest.seed_dir(workspace)
    if seed_dir.exists():
        count += sum(1 for path in seed_dir.iterdir() if path.is_file())

    for harness in manifest.harnesses:
        curated = workspace / "corpora" / manifest.name / harness.name / "current"
        if curated.exists():
            count += sum(1 for path in curated.iterdir() if path.is_file())
    return count


def _build_artifacts(workspace: Path, manifest: TargetManifest) -> dict[str, int]:
    out: dict[str, int] = {}
    for profile in ["afl_asan_ubsan", "afl_lto_cmplog", "libfuzzer_asan_ubsan", "fuzztest_asan_ubsan", "symcc", "coverage"]:
        build_json = workspace / "build" / manifest.name / profile / "build.json"
        expected_binaries = 0
        for harness in manifest.harnesses:
            if harness.profiles and profile not in harness.profiles:
                continue
            if profile == "libfuzzer_asan_ubsan" and harness.type != "libfuzzer":
                continue
            if profile == "fuzztest_asan_ubsan" and harness.type != "fuzztest":
                continue
            if profile == "symcc" and harness.type not in {"file", "stdin"}:
                continue
            if profile not in {"libfuzzer_asan_ubsan", "fuzztest_asan_ubsan"} and harness.type in {"libfuzzer", "fuzztest"}:
                continue
            if harness.source and (workspace / "build" / manifest.name / profile / harness.name).exists():
                expected_binaries += 1
        if not build_json.exists():
            out[profile] = expected_binaries
            continue
        try:
            metadata_artifacts = len(read_json(build_json).get("artifacts", []))
        except Exception:
            metadata_artifacts = 0
        out[profile] = max(metadata_artifacts, expected_binaries)
    return out


def _latest_fuzz_run(workspace: Path, name: str) -> Path | None:
    run_root = workspace / "runs" / name
    if not run_root.exists():
        return None
    runs = sorted([p for p in run_root.iterdir() if p.is_dir() and p.name != "background"])
    if not runs:
        return None

    try:
        current = find_latest_run(workspace, name)
        if _coverage_reports(current):
            return current
    except FuzzCtlError:
        current = None

    for run_dir in reversed(runs):
        if _coverage_reports(run_dir):
            return run_dir
    if current is not None and ((current / "aflpp").exists() or (current / "libfuzzer").exists() or (current / "fuzztest").exists()):
        return current
    for run_dir in reversed(runs):
        if (run_dir / "run.json").exists():
            return run_dir
        if (run_dir / "aflpp").exists() or (run_dir / "libfuzzer").exists() or (run_dir / "fuzztest").exists():
            return run_dir
    return None


def _coverage_reports(run_dir: Path | None) -> list[Path]:
    if run_dir is None:
        return []
    return sorted((run_dir / "coverage").glob("*.report.txt"))


def _parse_llvm_coverage_report(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total: dict[str, float] | None = None
    harness_name = path.name.removesuffix(".report.txt")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Filename", "---")):
            continue
        percents = [float(value) for value in re.findall(r"([0-9]+(?:\.[0-9]+)?)%", stripped)]
        if len(percents) < 3:
            continue
        file_name = stripped.split()[0]
        item = {
            "file": file_name,
            "region": percents[0],
            "function": percents[1],
            "line": percents[2],
            "report": str(path),
            "harness": harness_name,
        }
        if file_name == "TOTAL":
            total = {"region": percents[0], "function": percents[1], "line": percents[2]}
        else:
            rows.append(item)
    return {"report": str(path), "total": total, "files": rows}


def _coverage_row_score(row: dict[str, Any]) -> tuple[float, float, float]:
    return (float(row["line"]), float(row["function"]), float(row["region"]))


def _coverage_row_is_better(candidate: dict[str, Any], current: dict[str, Any] | None) -> bool:
    if current is None:
        return True
    return _coverage_row_score(candidate) > _coverage_row_score(current)


def _is_header_coverage_row(row: dict[str, Any]) -> bool:
    return Path(str(row["file"])).suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}


def _is_harness_coverage_row(row: dict[str, Any]) -> bool:
    file_name = str(row["file"]).replace("\\", "/")
    return file_name.startswith("fuzz_harnesses/") or "/fuzz_harnesses/" in file_name


def _is_harness_source_path(value: str) -> bool:
    file_name = str(value).replace("\\", "/")
    return file_name.startswith("fuzz_harnesses/") or "/fuzz_harnesses/" in file_name


def _best_file_rows(reports: list[dict[str, Any]], source_dir: Path) -> dict[str, dict[str, Any]]:
    file_rows: dict[str, dict[str, Any]] = {}
    for report in reports:
        for row in report["files"]:
            aliases = {str(row["file"]), Path(str(row["file"])).name}
            path = Path(str(row["file"]))
            if path.is_absolute():
                aliases.add(rel_to(path, source_dir))
            for alias in aliases:
                if _coverage_row_is_better(row, file_rows.get(alias)):
                    file_rows[alias] = row
    return file_rows


def _coverage_total(run_dir: Path | None) -> dict[str, float] | None:
    if run_dir is None:
        return None
    reports = _coverage_reports(run_dir)
    if not reports:
        return None
    totals = [
        parsed["total"]
        for parsed in (_parse_llvm_coverage_report(path) for path in reports)
        if parsed.get("total")
    ]
    if not totals:
        return None
    weakest = {
        "region": min(item["region"] for item in totals),
        "function": min(item["function"] for item in totals),
        "line": min(item["line"] for item in totals),
        "reports": len(totals),
    }
    return weakest


def _coverage_target_total(run_dir: Path | None) -> dict[str, Any] | None:
    if run_dir is None:
        return None
    reports = _coverage_reports(run_dir)
    if not reports:
        return None
    best_target_rows: list[dict[str, Any]] = []
    for parsed in (_parse_llvm_coverage_report(path) for path in reports):
        target_rows = [
            row
            for row in parsed["files"]
            if not _is_header_coverage_row(row) and not _is_harness_coverage_row(row)
        ]
        if not target_rows:
            continue
        best_target_rows.append(max(target_rows, key=_coverage_row_score))
    if not best_target_rows:
        return None
    return {
        "region": min(item["region"] for item in best_target_rows),
        "function": min(item["function"] for item in best_target_rows),
        "line": min(item["line"] for item in best_target_rows),
        "reports": len(best_target_rows),
        "mode": "best_target_file_per_report",
    }
