from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .harness_candidates import _candidate_context
from .manifest import TargetManifest


def _candidate_prompt(
    workspace: Path,
    manifest: TargetManifest,
    data: dict[str, Any],
    candidate: dict[str, Any],
    build_context: dict[str, Any] | None = None,
) -> str:
    source_dir = manifest.source_dir(workspace)
    build_context = build_context or {}
    context = _candidate_context(build_context, candidate)
    harness_name = candidate["harness_name"]
    preferred_type = candidate["recommended_harness_type"]
    source_suffix = "cc" if manifest.language == "c++" else "c"
    proposed_source = f"fuzz_harnesses/{harness_name}_{preferred_type}.{source_suffix}"
    usage_lines = "\n".join(
        f"  - {ref['relative_file']}:{ref['line']}"
        for ref in candidate.get("usage_refs", [])[:8]
    ) or "  - none found; inspect call sites manually"
    header_lines = "\n".join(f"  - {item}" for item in candidate.get("header_refs", [])[:8]) or "  - none found"
    reasons = "\n".join(f"  - {item}" for item in candidate.get("reasons", []))
    risks = "\n".join(f"  - {item}" for item in candidate.get("risk_tags", []))
    samples = "\n".join(f"  - {item}" for item in data["sample_inputs"][:20]) or "  - none found"
    tokens = "\n".join(f"  - {item}" for item in data["dictionary_token_candidates"][:30]) or "  - none found"
    argv_note = "AFL++ file harness must include @@ in argv." if preferred_type == "file" else "libFuzzer harness should expose LLVMFuzzerTestOneInput."
    include_lines = "\n".join(f"  - {item}" for item in context["include_dirs"][:20]) or "  - none found"
    define_lines = "\n".join(f"  - {item}" for item in context["defines"][:30]) or "  - none found"
    link_lines = "\n".join(f"  - {item}" for item in context["link_artifacts"][:20]) or "  - none found"

    return f"""# AI Harness Work Order: {manifest.name}/{candidate['id']}

You are writing one fine-grained C/C++ fuzz harness. Do not make a broad catch-all harness.

## Target API
- Function: `{candidate['function']}({candidate['params']})`
- Location: `{candidate['relative_file']}:{candidate['line']}`
- Preferred harness type: `{preferred_type}`
- Proposed source: `{proposed_source}`
- Input strategy: {candidate['input_strategy']}
- Manifest target: `{manifest.name}`
- Source directory: `{source_dir}`

## Why This Candidate
{reasons}

## Security-Relevant Surface
{risks}

## Existing Call Sites
{usage_lines}

## Header Candidates
{header_lines}

## Compile Context
- Matching compile unit: `{bool(context['compile_unit'])}`
- Compile database: `{build_context.get('compile_commands', 'not found')}`

Include dirs:
{include_lines}

Defines:
{define_lines}

Link artifacts:
{link_lines}

## Seeds And Dictionary Hints
Sample inputs:
{samples}

Dictionary token candidates:
{tokens}

## Source Excerpt
```c
{candidate.get('source_excerpt') or 'excerpt unavailable'}
```

## Required Implementation
1. Inspect the target function, its callers, and any setup/cleanup APIs around it.
2. Write a narrow harness that feeds fuzz bytes into this API or the smallest wrapper needed to reach it.
3. Add or update `targets/{manifest.name}/target.json` so this harness is listed with sanitizer profiles.
4. Return normally on malformed inputs. Do not call `exit()`, `abort()`, sleep, spawn shell commands, use networking, or hide sanitizer crashes.
5. Keep all temporary files bounded and under a temp directory if the target has no in-memory API.
6. {argv_note}

## Validation Gate
Run these commands and fix failures before starting a long campaign:

```bash
cd {workspace}
bin/fuzzctl --runtime native harness review {manifest.name}
bin/fuzzctl --runtime native harness validate {manifest.name} --build
bin/fuzzctl --runtime native smoke {manifest.name} --seconds 300
bin/fuzzctl --runtime native coverage {manifest.name}
bin/fuzzctl --runtime native harness blockers {manifest.name}
bin/fuzzctl --runtime native guide coverage {manifest.name}
bin/fuzzctl --runtime native harness score {manifest.name}
```

The harness is not campaign-ready until review passes, ASan+UBSan builds, smoke runs, and coverage proves parser logic is reached.
"""


def _target_prompt(workspace: Path, manifest: TargetManifest, data: dict[str, Any]) -> str:
    source_dir = manifest.source_dir(workspace)
    candidate_lines = []
    for item in data["candidate_entrypoints"][:20]:
        candidate_lines.append(
            f"  - {item['id']}: {item['relative_file']}:{item['line']} "
            f"{item['function']}({item['params']}) score={item['score']} type={item['recommended_harness_type']}"
        )
    prompt = f"""You are writing production-quality, fine-grained C/C++ fuzz harnesses for the local fuzz-pipeline.

Target manifest:
```json
{json.dumps(manifest.to_dict(), indent=2, sort_keys=True)}
```

Repository facts:
- Source directory: {source_dir}
- Language: {data['detection']['language']}
- Build system: {data['detection']['build_system']}
- Candidate parser/API entrypoints:
{chr(10).join(candidate_lines) or "  - none found; inspect headers/tests manually"}
- Sample inputs:
{chr(10).join(f"  - {item}" for item in data['sample_inputs'][:20]) or "  - none found"}
- Public headers:
{chr(10).join(f"  - {item}" for item in data['public_headers'][:20]) or "  - none found"}
- Dictionary token candidates:
{chr(10).join(f"  - {item}" for item in data['dictionary_token_candidates'][:20]) or "  - none found"}

Write the harness in two steps:
1. First state the intended API, input format, initialization/reset needs, and why the target code is security-relevant.
2. Then edit or create one narrow harness source per parser/API surface.

Harness requirements:
- Feed opaque bytes and explicit size_t length into the narrowest parser/deserializer/file-format API.
- Return 0 for invalid input; never call exit() or abort() for ordinary malformed input.
- Do not use networking, sleeps, shell commands, nondeterminism, or uncontrolled filesystem writes.
- Do not convert fuzz bytes through C strings unless the real API is string-only.
- Keep the loop deterministic, fast, and stateless; use AFL++ persistent mode only when all state is reset.
- Build and validate with ASan+UBSan before claiming any crash.

Validation commands:
```bash
cd {workspace}
bin/fuzzctl --runtime native harness review {manifest.name}
bin/fuzzctl --runtime native harness validate {manifest.name} --build
bin/fuzzctl --runtime native smoke {manifest.name} --seconds 300
bin/fuzzctl --runtime native coverage {manifest.name}
bin/fuzzctl --runtime native harness blockers {manifest.name}
bin/fuzzctl --runtime native harness score {manifest.name}
```
"""
    return prompt


def _work_order_markdown(workspace: Path, manifest: TargetManifest, work_order: dict[str, Any]) -> str:
    lines = [
        f"# AI Harness Work Order: {manifest.name}",
        "",
        "This directory is the handoff packet for Codex/Claude harness authoring.",
        "Write one narrow harness at a time, validate it, then move to the next candidate.",
        "",
        "## Commands",
        "",
        "```bash",
        f"cd {workspace}",
        f"bin/fuzzctl --runtime native harness review {manifest.name}",
        f"bin/fuzzctl --runtime native harness validate {manifest.name} --build",
        f"bin/fuzzctl --runtime native smoke {manifest.name} --seconds 300",
        f"bin/fuzzctl --runtime native coverage {manifest.name}",
        f"bin/fuzzctl --runtime native harness blockers {manifest.name}",
        f"bin/fuzzctl --runtime native guide coverage {manifest.name}",
        f"bin/fuzzctl --runtime native harness score {manifest.name}",
        "```",
        "",
        "## Candidate Harnesses",
        "",
    ]
    for candidate in work_order["candidates"]:
        risks = ", ".join(candidate.get("risk_tags", []))
        lines.extend(
            [
                f"### {candidate['id']}",
                "",
                f"- Function: `{candidate['function']}({candidate['params']})`",
                f"- Location: `{candidate['relative_file']}:{candidate['line']}`",
                f"- Type: `{candidate['recommended_harness_type']}`",
                f"- Score: `{candidate['score']}`",
                f"- Risk tags: `{risks or 'manual-review'}`",
                f"- Prompt: `prompts/{candidate['id']}.md`",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
