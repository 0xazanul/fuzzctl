from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .harness_candidates import _candidate_by_id, _candidate_context, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .manifest import TargetManifest
from .util import ensure_dir, now_id, rel_to, write_json


PARSER_TOKENS = ("parse", "decode", "deserialize", "load", "import", "read", "from_bytes", "unmarshal", "unpack")
SERIALIZER_TOKENS = ("serialize", "encode", "to_bytes", "marshal", "pack")


def _camel(value: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", value)
    return "".join(part[:1].upper() + part[1:] for part in parts if part) or "Candidate"


def _property_kind(function: str) -> str:
    lowered = function.lower()
    if any(token in lowered for token in SERIALIZER_TOKENS):
        return "roundtrip_source"
    if any(token in lowered for token in PARSER_TOKENS):
        return "never_crashes"
    return "api_invariant"


def _property_prompt(candidate: dict[str, Any]) -> str:
    kind = _property_kind(str(candidate.get("function", "")))
    if kind == "roundtrip_source":
        return (
            "Look for the matching parser/deserializer for this serializer and write a round-trip property. "
            "Do not assert equality until object comparison is well-defined and deterministic."
        )
    if kind == "never_crashes":
        return (
            "Start with a sanitizer-backed never-crashes property over arbitrary bytes, then add semantic assertions "
            "only after valid input construction is understood."
        )
    return "Inspect callers and tests, then define one deterministic invariant that must hold for generated inputs."


def _fuzztest_property_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for candidate in candidates:
        function = str(candidate.get("function", ""))
        kind = _property_kind(function)
        score = int(candidate.get("score", 0) or 0)
        if kind == "never_crashes":
            score += 2
        elif kind == "roundtrip_source":
            score += 1
        out.append(
            {
                "id": candidate.get("id"),
                "function": function,
                "params": candidate.get("params"),
                "relative_file": candidate.get("relative_file"),
                "line": candidate.get("line"),
                "score": score,
                "property": kind,
                "suggested_harness": f"{candidate.get('harness_name', function).lower()}_fuzztest",
                "domain": "std::string arbitrary bytes",
                "prompt_hint": _property_prompt(candidate),
                "candidate": candidate,
            }
        )
    out.sort(key=lambda item: (-int(item["score"]), str(item["relative_file"]), int(item.get("line") or 0)))
    return out


def _plan_markdown(workspace: Path, manifest: TargetManifest, plan: dict[str, Any]) -> str:
    lines = [
        f"# FuzzTest Property Plan: {manifest.name}",
        "",
        "FuzzTest is optional here. Use it for property/invariant harnesses, while AFL++ remains the long-running crash-discovery engine.",
        "",
        "## Build Contract",
        "",
        "- Add real FuzzTest harnesses as `type: fuzztest`.",
        "- Give them the `fuzztest_asan_ubsan` profile.",
        "- Prefer target-specific `build_commands.fuzztest_asan_ubsan` when the project already has CMake/Bazel FuzzTest integration.",
        "- Do not add generated templates to the manifest until the target API call, includes, and link flags are real.",
        "",
        "## Commands",
        "",
        "```bash",
        f"cd {workspace}",
        f"bin/fuzzctl --runtime native harness fuzztest-generate {manifest.name} --candidate <candidate-id>",
        f"bin/fuzzctl --runtime native build {manifest.name} --profile fuzztest_asan_ubsan",
        f"bin/fuzzctl --runtime native fuzztest {manifest.name} --seconds 300",
        "```",
        "",
        "## Property Candidates",
        "",
    ]
    for item in plan["properties"]:
        lines.extend(
            [
                f"### {item['id']}",
                "",
                f"- Function: `{item['function']}({item.get('params') or ''})`",
                f"- Location: `{item['relative_file']}:{item['line']}`",
                f"- Property: `{item['property']}`",
                f"- Suggested harness: `{item['suggested_harness']}`",
                f"- Prompt: `prompts/{item['id']}.md`",
                f"- Guidance: {item['prompt_hint']}",
                "",
            ]
        )
    if not plan["properties"]:
        lines.append("No obvious FuzzTest candidates were found. Inspect public APIs, tests, and serializers manually.")
    return "\n".join(lines).rstrip() + "\n"


def _candidate_prompt(workspace: Path, manifest: TargetManifest, item: dict[str, Any], build_context: dict[str, Any]) -> str:
    candidate = item["candidate"]
    context = _candidate_context(build_context, candidate)
    include_lines = "\n".join(f"- `{value}`" for value in context["include_dirs"][:20]) or "- none found"
    define_lines = "\n".join(f"- `{value}`" for value in context["defines"][:30]) or "- none found"
    return f"""# FuzzTest Harness Prompt: {manifest.name}/{item['id']}

Write one production-quality FuzzTest property harness. Do not replace existing AFL++ or libFuzzer harnesses.

## Target Candidate
- Function: `{item['function']}({item.get('params') or ''})`
- Location: `{item['relative_file']}:{item['line']}`
- Suggested property: `{item['property']}`
- Suggested harness name: `{item['suggested_harness']}`
- Domain: `{item['domain']}`
- Guidance: {item['prompt_hint']}

## Compile Context
- Matching compile unit: `{bool(context['compile_unit'])}`

Include dirs:
{include_lines}

Defines:
{define_lines}

## Required Shape
- Use `FUZZ_TEST(SuiteName, PropertyFunction)`.
- Use FuzzTest domains such as `fuzztest::Arbitrary<std::string>()` only when they match the target API.
- Keep setup deterministic and reset state between iterations.
- For parser properties, malformed input should return normally; sanitizers should catch memory bugs.
- For round-trip properties, only assert equality when object comparison is deterministic and semantically correct.
- Add the final harness to the manifest as `type: fuzztest` with profile `fuzztest_asan_ubsan`.

## Validation
```bash
cd {workspace}
bin/fuzzctl --runtime native harness review {manifest.name}
bin/fuzzctl --runtime native build {manifest.name} --profile fuzztest_asan_ubsan
bin/fuzzctl --runtime native fuzztest {manifest.name} --seconds 300
```
"""


def write_fuzztest_plan(workspace: Path, manifest: TargetManifest, *, as_json: bool = False) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    candidates = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    properties = _fuzztest_property_candidates(candidates)[:25]
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-fuzztest-plan")
    prompts_dir = ensure_dir(out_dir / "prompts")
    plan = {
        "target": manifest.name,
        "source_dir": str(source_dir),
        "created": out_dir.name,
        "build_context": {
            "available": bool(build_context),
            "compile_commands": build_context.get("compile_commands"),
            "unit_count": build_context.get("unit_count", 0),
        },
        "properties": properties,
    }
    write_json(out_dir / "fuzztest-plan.json", plan)
    (out_dir / "README.md").write_text(_plan_markdown(workspace, manifest, plan), encoding="utf-8")
    for item in properties:
        (prompts_dir / f"{item['id']}.md").write_text(_candidate_prompt(workspace, manifest, item, build_context), encoding="utf-8")
    if as_json:
        printable = dict(plan)
        printable["path"] = rel_to(out_dir, workspace)
        print(json.dumps(printable, indent=2, sort_keys=True))
    else:
        print(f"FuzzTest plan: {rel_to(out_dir, workspace)}")
        for item in properties[:12]:
            print(f"{item['score']} {item['property']} {item['id']} -> {item['suggested_harness']}")
    return out_dir


def write_fuzztest_template(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str,
    property_kind: str = "never_crashes",
    as_json: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    assert candidate is not None
    harness_name = f"{candidate['harness_name']}_fuzztest"
    func_name = _camel(harness_name)
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-fuzztest-template-{candidate['id']}")
    source = out_dir / f"{harness_name}.cc"
    template = f"""#include <string>

#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"

namespace {{

void {func_name}(const std::string& input) {{
  // Wire the target header and call before using this template:
  //   {candidate['function']}(... input.data() ..., input.size() ...);
  // Return normally for malformed inputs. Let ASan/UBSan expose memory bugs.
  (void)input;
}}

FUZZ_TEST(FuzzPipelineGenerated, {func_name})
    .WithDomains(fuzztest::Arbitrary<std::string>());

}}  // namespace
"""
    source.write_text(template, encoding="utf-8")
    manifest_entry = {
        "name": harness_name,
        "type": "fuzztest",
        "source": f"fuzz_harnesses/{harness_name}.cc",
        "profiles": ["fuzztest_asan_ubsan"],
        "compile_flags": [],
        "link_flags": [],
    }
    write_json(
        out_dir / "manifest-entry.json",
        {
            "candidate": candidate,
            "property": property_kind,
            "manifest_entry_after_template_is_wired": manifest_entry,
        },
    )
    (out_dir / "README.md").write_text(
        f"""# FuzzTest Template: {manifest.name}/{candidate['id']}

Template source: `{source.name}`

This is intentionally not added to `targets/{manifest.name}/target.json`.
Wire the target include, function call, compile flags, and link flags first.
Only then copy it into `{source_dir / 'fuzz_harnesses'}` and add `manifest-entry.json`.
""",
        encoding="utf-8",
    )
    if as_json:
        print(json.dumps({"path": rel_to(out_dir, workspace), "source": str(source), "manifest_entry": manifest_entry}, indent=2, sort_keys=True))
    else:
        print(f"FuzzTest template: {rel_to(out_dir, workspace)}")
        print(f"source: {rel_to(source, workspace)}")
        print(f"manifest entry draft: {rel_to(out_dir / 'manifest-entry.json', workspace)}")
    return out_dir
