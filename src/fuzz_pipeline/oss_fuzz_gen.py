from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .advanced_tools import advanced_tool_status, oss_fuzz_gen_dir
from .build_context import load_build_context
from .harness_candidates import _candidate_by_id, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .harness_workorders import _candidate_prompt
from .manifest import TargetManifest
from .util import ensure_dir, rel_to, write_json


def write_llm_gen_workorder(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str,
    backend: str = "codex",
    as_json: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    build_context = load_build_context(workspace, manifest)
    data = _ai_plan_data(source_dir)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    assert candidate is not None
    status = advanced_tool_status(workspace)
    out = ensure_dir(workspace / "workorders" / manifest.name / f"{__import__('time').strftime('%Y%m%d-%H%M%S')}-llm-gen-{candidate['id']}")
    prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
    benchmark = {
        "project": manifest.name,
        "language": manifest.language,
        "target_path": str(source_dir),
        "function_signature": f"{candidate['function']}({candidate.get('params', '')})",
        "function_name": candidate["function"],
        "source_file": candidate["relative_file"],
        "line": candidate["line"],
        "build_system": manifest.build_system,
        "seed_corpus": manifest.seed_corpus,
        "dictionary": manifest.dictionary,
    }
    write_json(out / "candidate.json", candidate)
    write_json(out / "benchmark-skeleton.json", benchmark)
    (out / "prompt.md").write_text(prompt, encoding="utf-8")
    codex_task = f"""# Codex Harness Generation Task

Backend mode: `{backend}`
Target: `{manifest.name}`
Candidate: `{candidate['id']}`

Use this packet like an OSS-Fuzz-Gen style benchmark, but do not call an external LLM API from the pipeline.
Codex should write one narrow harness, then validate it locally.

Required validation:

```bash
bin/fuzzctl --runtime native harness review {manifest.name}
bin/fuzzctl --runtime native harness validate {manifest.name} --build
bin/fuzzctl --runtime native smoke {manifest.name} --seconds 300
bin/fuzzctl --runtime native coverage {manifest.name}
bin/fuzzctl --runtime native harness blockers {manifest.name}
bin/fuzzctl --runtime native harness qa {manifest.name}
```

OSS-Fuzz-Gen local repo detected: `{status['oss_fuzz_gen']['installed']}`
OSS-Fuzz-Gen path: `{oss_fuzz_gen_dir(workspace)}`
"""
    (out / "codex-task.md").write_text(codex_task, encoding="utf-8")
    ofg = f"""# OSS-Fuzz-Gen Adapter Notes

This project is not automatically uploaded to OSS-Fuzz. The packet provides:

- `benchmark-skeleton.json`: target function metadata.
- `candidate.json`: compile-aware candidate information.
- `prompt.md`: local Codex prompt using the same generate/compile/repair discipline.

If you intentionally want to run upstream OSS-Fuzz-Gen, install it at `{oss_fuzz_gen_dir(workspace)}` or set
`OSS_FUZZ_GEN_DIR`, then adapt this candidate into an OSS-Fuzz benchmark YAML and run their framework with your own
LLM credentials. Secrets must stay in the environment, not in this repository.
"""
    (out / "oss-fuzz-gen-notes.md").write_text(ofg, encoding="utf-8")
    payload: dict[str, Any] = {
        "target": manifest.name,
        "candidate": candidate["id"],
        "backend": backend,
        "workdir": str(out),
        "oss_fuzz_gen": status["oss_fuzz_gen"],
        "files": {
            "prompt": str(out / "prompt.md"),
            "codex_task": str(out / "codex-task.md"),
            "benchmark": str(out / "benchmark-skeleton.json"),
            "notes": str(out / "oss-fuzz-gen-notes.md"),
        },
    }
    write_json(out / "llm-gen.json", payload)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"llm-gen workorder: {rel_to(out, workspace)}")
        print(f"prompt: {rel_to(out / 'prompt.md', workspace)}")
    return out
