from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .builder import build_profile
from .harness_metrics import _build_artifacts, _coverage_target_total, _latest_fuzz_run, _review_data, _seed_count
from .manifest import TargetManifest
from .util import FuzzCtlError, ensure_dir, rel_to


def score_harnesses(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    as_json: bool = False,
) -> dict[str, Any]:
    review = _review_data(workspace, manifest)
    builds = _build_artifacts(workspace, manifest)
    seed_count = _seed_count(workspace, manifest)
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else _latest_fuzz_run(workspace, manifest.name)
    coverage = _coverage_target_total(run_dir)
    score = 0
    factors: list[dict[str, Any]] = []

    def award(points: int, ok: bool, name: str) -> None:
        nonlocal score
        if ok:
            score += points
        factors.append({"points": points if ok else 0, "max": points, "name": name, "ok": ok})

    source_backed = any(h.source and (manifest.source_dir(workspace) / h.source).exists() for h in manifest.harnesses)
    award(8, bool(manifest.harnesses), "manifest has at least one harness")
    award(10, not review["errors"], "harness review has no blocking errors")
    award(8, source_backed, "harness source exists")
    award(8, any(h.type == "libfuzzer" for h in manifest.harnesses), "libFuzzer harness available")
    award(8, any(h.type in {"file", "stdin"} for h in manifest.harnesses), "AFL++ file/stdin harness available")
    award(8, seed_count > 0, "seed corpus is non-empty")
    award(10, builds.get("afl_asan_ubsan", 0) > 0, "AFL++ ASan+UBSan build exists")
    award(10, builds.get("libfuzzer_asan_ubsan", 0) > 0, "libFuzzer ASan+UBSan build exists")
    award(5, bool(manifest.dictionary), "dictionary configured")
    award(5, run_dir is not None, "smoke or campaign run exists")
    if coverage:
        line_points = min(12, int((coverage["line"] / 70.0) * 12))
        func_points = min(8, int((coverage["function"] / 80.0) * 8))
        score += line_points + func_points
        factors.append({"points": line_points, "max": 12, "name": "line coverage depth", "ok": coverage["line"] >= 40})
        factors.append({"points": func_points, "max": 8, "name": "function coverage breadth", "ok": coverage["function"] >= 50})
    else:
        factors.append({"points": 0, "max": 12, "name": "line coverage depth", "ok": False})
        factors.append({"points": 0, "max": 8, "name": "function coverage breadth", "ok": False})

    recommendations: list[str] = []
    if review["errors"]:
        recommendations.append("Fix blocking harness review errors before fuzzing.")
    if seed_count == 0:
        recommendations.append("Add real seeds from tests, examples, or public sample files.")
    if not manifest.dictionary:
        recommendations.append("Create a dictionary from magic bytes, keywords, headers, and format markers.")
    if builds.get("afl_asan_ubsan", 0) == 0 and builds.get("libfuzzer_asan_ubsan", 0) == 0:
        recommendations.append("Run `harness validate <target> --build` to prove sanitizer builds work.")
    if not coverage:
        recommendations.append("Run coverage before deciding the harness is deep enough.")
    elif coverage["line"] < 40:
        recommendations.append("Coverage is shallow; improve seeds or split the harness around a deeper parser API.")

    result = {
        "target": manifest.name,
        "score": min(score, 100),
        "run": str(run_dir) if run_dir else None,
        "seed_count": seed_count,
        "build_artifacts": builds,
        "coverage": coverage,
        "review": review,
        "factors": factors,
        "recommendations": recommendations,
    }
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"harness score: {result['score']}/100 ({manifest.name})")
        for factor in factors:
            print(f"- {factor['points']}/{factor['max']}: {factor['name']}")
        if coverage:
            print(f"coverage: line={coverage['line']}% function={coverage['function']}% region={coverage['region']}%")
        for item in recommendations:
            print(f"recommendation: {item}")
    return result


def scaffold_harness(
    workspace: Path,
    manifest: TargetManifest,
    *,
    harness_type: str,
    name: str,
    function: str | None,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    out_dir = ensure_dir(source_dir / "fuzz_harnesses")
    suffix = "cc" if manifest.language == "c++" else "c"
    out = out_dir / f"{name}_{harness_type}.{suffix}"
    call = f"/* Wire the correct header and call {function or 'target_parse'}(data, size) before fuzzing. */"
    if harness_type == "libfuzzer":
        body = f"""#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (data == 0 || size == 0) {{
        return 0;
    }}
    {call}
    return 0;
}}
"""
    elif harness_type in {"file", "stdin"}:
        body = f"""#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int run_one(const uint8_t *data, size_t size) {{
    {call}
    return 0;
}}

int main(int argc, char **argv) {{
    FILE *f = stdin;
    if (argc > 1) {{
        f = fopen(argv[1], "rb");
        if (!f) return 2;
    }}
    size_t cap = 4096, len = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 1;
    for (;;) {{
        if (len == cap) {{
            cap *= 2;
            uint8_t *next = (uint8_t *)realloc(buf, cap);
            if (!next) {{ free(buf); return 1; }}
            buf = next;
        }}
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }}
    if (f != stdin) fclose(f);
    int rc = run_one(buf, len);
    free(buf);
    return rc;
}}
"""
    else:
        raise FuzzCtlError("harness type must be libfuzzer, file, or stdin")
    if out.exists():
        raise FuzzCtlError(f"harness already exists: {out}")
    out.write_text(body, encoding="utf-8")
    print(f"created harness template: {rel_to(out, workspace)}")
    print("review and wire the target API call before adding it to target.json")
    return out


def validate_harnesses(workspace: Path, manifest: TargetManifest, *, build: bool = False) -> int:
    source_dir = manifest.source_dir(workspace)
    errors = []
    if not manifest.harnesses:
        errors.append("manifest has no harnesses")
    for harness in manifest.harnesses:
        if harness.source and not (source_dir / harness.source).exists():
            errors.append(f"{harness.name}: source missing: {harness.source}")
        if harness.type not in {"file", "stdin", "libfuzzer", "fuzztest"}:
            errors.append(f"{harness.name}: unsupported harness type {harness.type}")
        if harness.type == "file" and "@@" not in " ".join(harness.argv):
            errors.append(f"{harness.name}: file harness argv should include @@")
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 2
    if build:
        if any(h.type == "file" for h in manifest.harnesses):
            build_profile(workspace, manifest, "afl_asan_ubsan")
        if any(h.type == "libfuzzer" for h in manifest.harnesses):
            build_profile(workspace, manifest, "libfuzzer_asan_ubsan")
        if any(h.type == "fuzztest" for h in manifest.harnesses):
            build_profile(workspace, manifest, "fuzztest_asan_ubsan")
    print("harness validation passed")
    return 0
