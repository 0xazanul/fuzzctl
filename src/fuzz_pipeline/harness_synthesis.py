from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .harness_candidates import _candidate_by_id, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .harness_workorders import _candidate_prompt, write_candidate_knowledge
from .manifest import TargetManifest, save_manifest
from .util import ensure_dir, now_id, rel_to, run_cmd, short_hash, write_json


def _draft_harness(candidate: dict[str, Any], manifest: TargetManifest) -> str:
    ext = "cc" if manifest.language == "c++" else "c"
    comment = "/* Wire the correct public header and call the target API safely before fuzzing. */"
    if candidate.get("header_refs"):
        header = candidate["header_refs"][0]
        comment = f'/* Confirm this include and call {candidate["function"]}(data, size) before fuzzing. */\n#include "{header}"'
    return f"""#include <stddef.h>
#include <stdint.h>

{comment}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (data == 0) {{
        return 0;
    }}
    (void)data;
    (void)size;
    /* Candidate: {candidate['function']}({candidate['params']}) */
    /* Replace this placeholder with the narrowest valid call sequence. */
    return 0;
}}
/* Preferred extension: .{ext} */
"""


def _build_candidate_source(
    workspace: Path,
    manifest: TargetManifest,
    source: Path,
    out_dir: Path,
    *,
    print_cmd: bool = True,
) -> dict[str, Any]:
    from .build_context import context_flags_for_source

    suffix = source.suffix.lower()
    compiler = "clang++" if suffix in {".cc", ".cpp", ".cxx"} or (manifest.language == "c++" and suffix != ".c") else "clang"
    context_flags, link_args = context_flags_for_source(workspace, manifest, source)
    binary = out_dir / "candidate_fuzzer"
    cmd = [
        compiler,
        "-g",
        "-O1",
        "-fno-omit-frame-pointer",
        "-fno-sanitize-recover=all",
        "-DFUZZ_LIBFUZZER",
        "-fsanitize=fuzzer,address,undefined",
        *context_flags,
        str(source),
        *link_args,
        "-o",
        str(binary),
    ]
    result = run_cmd(cmd, cwd=manifest.source_dir(workspace), timeout=120, print_cmd=print_cmd)
    log = out_dir / "build.log"
    log.write_text(result.output, encoding="utf-8", errors="replace")
    return {
        "cmd": cmd,
        "returncode": result.returncode,
        "log": str(log),
        "binary": str(binary) if binary.exists() else None,
        "output_tail": result.output[-6000:],
    }


def synthesize_harness_attempt(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str,
    source: Path | None = None,
    attempts: int = 5,
    as_json: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    assert candidate is not None
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-synthesize-{candidate['id']}")
    prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
    (out_dir / "prompt.md").write_text(prompt, encoding="utf-8")
    knowledge_dir = write_candidate_knowledge(workspace, manifest, candidate_id=candidate["id"], quiet=as_json)
    draft = out_dir / f"{candidate['harness_name']}_draft.{'cc' if manifest.language == 'c++' else 'c'}"
    draft.write_text(_draft_harness(candidate, manifest), encoding="utf-8")

    selected_source = source.expanduser().resolve() if source else draft
    build = _build_candidate_source(workspace, manifest, selected_source, out_dir, print_cmd=not as_json)
    repair_prompt = f"""# Harness Repair Request

Candidate: `{candidate['id']}`
Source attempted: `{selected_source}`
Return code: `{build['returncode']}`
Attempts allowed: `{attempts}`

Use `prompt.md` and the knowledge packet at `{knowledge_dir}`. Fix only the harness source, manifest build args, or target-specific include/link flags. Do not remove ASan/UBSan/libFuzzer sanitizer flags.

## Build Command
```bash
{shlex.join(build['cmd'])}
```

## Build Log Tail
```text
{build['output_tail']}
```
"""
    (out_dir / "repair-prompt.md").write_text(repair_prompt, encoding="utf-8")
    attempt = {
        "id": short_hash(str(out_dir)),
        "candidate": candidate["id"],
        "source": str(selected_source),
        "workdir": rel_to(out_dir, workspace),
        "status": ("draft_ready_for_ai" if source is None else "build_ok") if build["returncode"] == 0 else "needs_repair",
        "build": build,
    }
    manifest.harness_attempts.append(attempt)
    save_manifest(workspace, manifest)
    write_json(out_dir / "attempt.json", attempt)
    if as_json:
        print(json.dumps(attempt, indent=2, sort_keys=True))
    else:
        print(f"synthesis attempt: {rel_to(out_dir, workspace)}")
        print(f"status: {attempt['status']}")
        print(f"draft: {rel_to(draft, workspace)}")
        print(f"repair prompt: {rel_to(out_dir / 'repair-prompt.md', workspace)}")
    return out_dir
