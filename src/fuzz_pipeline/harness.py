from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .builder import build_profile
from .detect import CPP_EXTS, C_EXTS
from .manifest import TargetManifest, save_manifest
from .util import FuzzCtlError, ensure_dir, now_id, read_json, rel_to, run_cmd, short_hash, write_json


ENTRY_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_\s\*]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*\{"
)
ENTRY_TOKENS = (
    "parse",
    "decode",
    "load",
    "read",
    "process",
    "handle",
    "deserialize",
    "unpack",
    "inflate",
    "decompress",
    "validate",
    "scan",
    "consume",
    "compile",
    "import",
)
STRING_RE = re.compile(r'"([^"\\\n\r]{2,40})"')
SAMPLE_DIR_TOKENS = {"corpus", "data", "example", "examples", "fixture", "fixtures", "sample", "samples", "test", "tests"}
SECURITY_FILE_TOKENS = {
    "archive",
    "bitmap",
    "codec",
    "compress",
    "decode",
    "decompress",
    "demux",
    "format",
    "image",
    "import",
    "inflate",
    "json",
    "media",
    "packet",
    "parse",
    "parser",
    "pdf",
    "read",
    "stream",
    "unpack",
    "xml",
}
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


def _slug(value: str) -> str:
    out = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return out[:80] or "candidate"


def _read_text(path: Path, limit: int = 500_000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) > limit:
        return text[:limit]
    return text


def _source_files(root: Path) -> list[Path]:
    exts = C_EXTS | CPP_EXTS
    ignored = {".git", "build", "runs", "target", "node_modules"}
    files = []
    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in exts:
            files.append(path)
    return sorted(files)


def _classify_candidate(root: Path, source: Path, function: str, params: str) -> dict[str, Any]:
    lowered = f"{function} {params} {source}".lower()
    reasons: list[str] = []
    risks: list[str] = []
    score = 1
    harness_type = "libfuzzer"
    input_strategy = "Feed arbitrary bytes plus explicit length directly into the API."

    if any(token in function.lower() for token in ENTRY_TOKENS):
        score += 2
        reasons.append("name looks like parser/decoder/importer logic")
    if any(token in lowered for token in ["uint8_t", "unsigned char", "void *", "char *"]):
        score += 2
        reasons.append("accepts byte or character buffer")
    if any(token in lowered for token in ["size_t", "len", "length", "size", "nbytes"]):
        score += 2
        reasons.append("has an explicit input length")
    if "file *" in lowered or "istream" in lowered:
        score += 1
        harness_type = "file"
        input_strategy = "Use a file/stdin harness or an in-memory stream wrapper if the API supports it."
        reasons.append("takes a stream-like input")
    if any(token in lowered for token in ["filename", "path", "filepath", "const char *file"]):
        score += 1
        harness_type = "file"
        input_strategy = "Write fuzz bytes to a bounded temporary file only if no in-memory API exists."
        reasons.append("takes a path-like input")
    if "fuzz" in source.name.lower() or "fuzz" in [part.lower() for part in source.parts]:
        score += 2
        reasons.append("near existing fuzz-related code")
    if any(part.lower() in {"test", "tests", "example", "examples"} for part in source.parts):
        score += 1
        reasons.append("near tests/examples, likely easy to call")
    if any(token in lowered for token in SECURITY_FILE_TOKENS):
        score += 1
        risks.append("input parsing or file-format surface")
    if any(token in lowered for token in ["alloc", "malloc", "copy", "memcpy", "strlen", "strcpy", "decompress", "inflate"]):
        risks.append("memory-size/copy/codec surface")

    if not reasons:
        reasons.append("function matched generic harness entrypoint scan")
    if not risks:
        risks.append("needs manual reachability review")

    return {
        "score": score,
        "recommended_harness_type": harness_type,
        "input_strategy": input_strategy,
        "reasons": reasons,
        "risk_tags": sorted(set(risks)),
        "relative_file": _relative(source, root),
    }


def _source_excerpt(source: Path, line: int, *, context: int = 18) -> str:
    text = _read_text(source)
    if not text:
        return ""
    lines = text.splitlines()
    start = max(1, line - context)
    end = min(len(lines), line + context)
    return "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))


def _usage_refs(root: Path, function: str, definition: Path) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for source in _source_files(root):
        text = _read_text(source, limit=250_000)
        if not text:
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            if source.resolve() == definition.resolve():
                # Keep non-definition intra-file callers, but avoid reporting the definition line as a usage.
                window = text[max(0, match.start() - 80):match.start()]
                if "static" in window or "extern" in window:
                    continue
            refs.append({"file": str(source), "relative_file": _relative(source, root), "line": line})
            if len(refs) >= 8:
                return refs
    return refs


def _header_refs(root: Path, function: str) -> list[str]:
    headers: list[str] = []
    pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for header in root.rglob("*"):
        if ".git" in header.parts:
            continue
        if not header.is_file() or header.suffix.lower() not in {".h", ".hh", ".hpp", ".hxx"}:
            continue
        if pattern.search(_read_text(header, limit=150_000)):
            headers.append(_relative(header, root))
        if len(headers) >= 8:
            break
    return headers


def _scan_candidates(root: Path) -> list[dict]:
    candidates = []
    for source in _source_files(root):
        text = _read_text(source)
        for match in ENTRY_RE.finditer(text):
            function = match.group(2)
            if not any(token in function.lower() for token in ENTRY_TOKENS):
                continue
            line = text.count("\n", 0, match.start()) + 1
            params = match.group(3).strip()
            classified = _classify_candidate(root, source, function, params)
            item = {
                "id": _slug(f"{source.stem}_{function}_{line}"),
                "file": str(source),
                "relative_file": classified["relative_file"],
                "line": line,
                "function": function,
                "params": params,
                "score": classified["score"],
                "recommended_harness_type": classified["recommended_harness_type"],
                "input_strategy": classified["input_strategy"],
                "reasons": classified["reasons"],
                "risk_tags": classified["risk_tags"],
                "header_refs": _header_refs(root, function),
                "usage_refs": _usage_refs(root, function, source),
                "source_excerpt": _source_excerpt(source, line),
            }
            item["harness_name"] = _slug(function)
            candidates.append(item)
    candidates.sort(key=lambda x: (-x["score"], x["file"], x["line"]))
    used: set[str] = set()
    for item in candidates:
        base = item["id"]
        candidate_id = base
        index = 2
        while candidate_id in used:
            candidate_id = f"{base}_{index}"
            index += 1
        used.add(candidate_id)
        item["id"] = candidate_id
    return candidates


def scan_harness_points(path: Path, *, as_json: bool = False) -> list[dict]:
    root = path.expanduser().resolve()
    candidates = _scan_candidates(root)
    if as_json:
        print(json.dumps(candidates, indent=2, sort_keys=True))
    else:
        if not candidates:
            print("no obvious parser/decoder harness points found")
        for item in candidates[:50]:
            print(f"{item['score']} {item['file']}:{item['line']} {item['function']}({item['params']})")
    return candidates


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _build_markers(root: Path) -> list[str]:
    names = [
        "CMakeLists.txt",
        "Makefile",
        "makefile",
        "configure",
        "meson.build",
        "build.ninja",
        "WORKSPACE",
        "BUILD",
    ]
    found: list[str] = []
    for name in names:
        for path in root.rglob(name):
            if ".git" not in path.parts:
                found.append(_relative(path, root))
    return sorted(found)[:40]


def _sample_files(root: Path) -> list[str]:
    samples: list[str] = []
    for path in root.rglob("*"):
        if len(samples) >= 60:
            break
        if not path.is_file() or ".git" in path.parts:
            continue
        parts = {part.lower() for part in path.parts}
        if not (parts & SAMPLE_DIR_TOKENS):
            continue
        if path.suffix.lower() in C_EXTS | CPP_EXTS | {".o", ".a", ".so", ".dylib"}:
            continue
        try:
            if path.stat().st_size > 1024 * 1024:
                continue
        except OSError:
            continue
        samples.append(_relative(path, root))
    return sorted(samples)


def _header_files(root: Path) -> list[str]:
    headers = []
    for path in root.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_file() and path.suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}:
            headers.append(_relative(path, root))
    return sorted(headers)[:60]


def _dictionary_tokens(root: Path) -> list[str]:
    tokens: set[str] = set()
    for source in _source_files(root)[:200]:
        text = source.read_text(encoding="utf-8", errors="replace")
        for match in STRING_RE.finditer(text[:200_000]):
            token = match.group(1).strip()
            if len(token) < 2 or len(token) > 40:
                continue
            if token.startswith("%") or "\\x" in token:
                continue
            if not any(ch.isalpha() for ch in token):
                continue
            if all(ch.isprintable() for ch in token):
                tokens.add(token)
            if len(tokens) >= 80:
                break
    return sorted(tokens)[:40]


def _ai_plan_data(path: Path) -> dict[str, Any]:
    from .detect import detect_target

    root = path.expanduser().resolve()
    detection = detect_target(root)
    return {
        "path": str(root),
        "detection": detection.to_dict(),
        "candidate_entrypoints": _scan_candidates(root)[:50],
        "build_markers": _build_markers(root),
        "public_headers": _header_files(root),
        "sample_inputs": _sample_files(root),
        "dictionary_token_candidates": _dictionary_tokens(root),
        "recommended_strategy": [
            "Prefer a libFuzzer harness around the narrowest parser/deserializer API that accepts bytes plus explicit length.",
            "Add a file-mode AFL++ harness for the same API when the project cannot reuse the libFuzzer entrypoint directly.",
            "Seed with existing tests/samples and extract magic bytes, keywords, headers, and format markers into a dictionary.",
            "Run ASan+UBSan smoke first, then coverage; iterate until parser code is reached before long campaigns.",
            "Use AFL++ persistent mode only after proving target state is reset between iterations.",
        ],
    }


def _print_ai_plan(data: dict[str, Any]) -> None:
    detection = data["detection"]
    print(f"# AI Harness Plan: {Path(data['path']).name}")
    print("")
    print(f"- Path: `{data['path']}`")
    print(f"- Supported: `{detection['supported']}`")
    print(f"- Language: `{detection['language']}`")
    print(f"- Build system: `{detection['build_system']}`")
    print(f"- C/C++ files: `{detection['c_files']}` / `{detection['cpp_files']}`")
    print("")
    print("## Candidate Entry Points")
    candidates = data["candidate_entrypoints"][:15]
    if not candidates:
        print("- No obvious parser/decoder function found; inspect public headers, examples, and tests manually.")
    for item in candidates:
        risks = ", ".join(item.get("risk_tags", []))
        print(
            f"- `{item['id']}` score {item['score']} {item['recommended_harness_type']}: "
            f"`{item['relative_file']}:{item['line']}` `{item['function']}({item['params']})`"
            f"{f' [{risks}]' if risks else ''}"
        )
    print("")
    print("## Inputs And Build Clues")
    for label, key in [
        ("Build markers", "build_markers"),
        ("Public headers", "public_headers"),
        ("Sample inputs", "sample_inputs"),
        ("Dictionary token candidates", "dictionary_token_candidates"),
    ]:
        values = data[key][:15]
        print(f"### {label}")
        if values:
            for value in values:
                print(f"- `{value}`")
        else:
            print("- none found")
        print("")
    print("## Required Harness Strategy")
    for item in data["recommended_strategy"]:
        print(f"- {item}")


def harness_ai_plan(path: Path, *, as_json: bool = False) -> dict[str, Any]:
    data = _ai_plan_data(path)
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        _print_ai_plan(data)
    return data


def _candidate_by_id(data: dict[str, Any], candidate_id: str | None) -> dict[str, Any] | None:
    if candidate_id is None:
        return None
    for item in data["candidate_entrypoints"]:
        if item["id"] == candidate_id or item["function"] == candidate_id:
            return item
    raise FuzzCtlError(f"candidate not found: {candidate_id}")


def _candidate_context(build_context: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    rel_file = candidate.get("relative_file")
    abs_file = Path(candidate.get("file", "")).resolve()
    for unit in build_context.get("units", []):
        unit_file = Path(unit.get("file", "")).resolve()
        if unit_file == abs_file or unit.get("relative_file") == rel_file:
            return {
                "compile_unit": unit,
                "include_dirs": unit.get("include_dirs", []),
                "defines": unit.get("defines", []),
                "compile_flags": unit.get("compile_flags", []),
                "link_artifacts": build_context.get("link_artifacts", []),
            }
    return {
        "compile_unit": None,
        "include_dirs": build_context.get("include_dirs", []),
        "defines": build_context.get("defines", []),
        "compile_flags": build_context.get("compile_flags", []),
        "link_artifacts": build_context.get("link_artifacts", []),
    }


def _enrich_candidates_with_context(candidates: list[dict[str, Any]], build_context: dict[str, Any]) -> list[dict[str, Any]]:
    if not build_context:
        return candidates
    out: list[dict[str, Any]] = []
    for candidate in candidates:
        item = dict(candidate)
        context = _candidate_context(build_context, item)
        item["build_context"] = {
            "has_compile_unit": bool(context["compile_unit"]),
            "include_dirs": context["include_dirs"][:20],
            "defines": context["defines"][:40],
            "compile_flags": context["compile_flags"][:40],
            "link_artifacts": context["link_artifacts"][:20],
        }
        if context["compile_unit"]:
            item["score"] += 2
            item.setdefault("reasons", []).append("has matching compile database unit")
        out.append(item)
    out.sort(key=lambda x: (-x["score"], x["relative_file"], x["line"]))
    return out


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


def harness_prompt(workspace: Path, manifest: TargetManifest, *, candidate_id: str | None = None) -> str:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context) if candidate else _target_prompt(workspace, manifest, data)
    print(prompt)
    return prompt


def index_harness_candidates(workspace: Path, manifest: TargetManifest, *, as_json: bool = False) -> list[dict[str, Any]]:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    candidates = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    index = {
        "target": manifest.name,
        "source_dir": str(source_dir),
        "build_context": {
            "available": bool(build_context),
            "compile_commands": build_context.get("compile_commands"),
            "unit_count": build_context.get("unit_count", 0),
        },
        "candidates": candidates,
    }
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / "indexes")
    write_json(out_dir / "latest-index.json", index)
    if as_json:
        print(json.dumps(index, indent=2, sort_keys=True))
    else:
        print(f"harness index: {rel_to(out_dir / 'latest-index.json', workspace)}")
        for item in candidates[:50]:
            ctx = "compile-db" if item.get("build_context", {}).get("has_compile_unit") else "heuristic"
            print(f"{item['score']} {ctx} {item['id']} {item['relative_file']}:{item['line']} {item['function']}({item['params']})")
    return candidates


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


def write_harness_work_order(
    workspace: Path,
    manifest: TargetManifest,
    *,
    limit: int = 8,
    as_json: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidates = data["candidate_entrypoints"][:limit]
    run_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-harness-work-order")
    prompts_dir = ensure_dir(run_dir / "prompts")

    work_order = {
        "target": manifest.name,
        "source_dir": str(source_dir),
        "created": run_dir.name,
        "manifest": manifest.to_dict(),
        "analysis": {
            "detection": data["detection"],
            "build_markers": data["build_markers"],
            "build_context": {
                "available": bool(build_context),
                "compile_commands": build_context.get("compile_commands"),
                "unit_count": build_context.get("unit_count", 0),
            },
            "public_headers": data["public_headers"],
            "sample_inputs": data["sample_inputs"],
            "dictionary_token_candidates": data["dictionary_token_candidates"],
        },
        "candidates": candidates,
        "validation_commands": [
            f"bin/fuzzctl --runtime native harness review {manifest.name}",
            f"bin/fuzzctl --runtime native harness validate {manifest.name} --build",
            f"bin/fuzzctl --runtime native smoke {manifest.name} --seconds 300",
            f"bin/fuzzctl --runtime native coverage {manifest.name}",
            f"bin/fuzzctl --runtime native harness blockers {manifest.name}",
            f"bin/fuzzctl --runtime native guide coverage {manifest.name}",
            f"bin/fuzzctl --runtime native harness score {manifest.name}",
        ],
        "rules": [
            "One narrow harness per parser/API surface.",
            "Do not hide crashes with signal handlers, catch-all handlers, or broad error swallowing.",
            "Do not use network, sleeps, shell commands, or nondeterminism inside the fuzz loop.",
            "Treat coverage as a harness-quality gate before long campaigns.",
            "Report only minimized reproducible sanitizer-backed crashes.",
        ],
    }

    for candidate in candidates:
        prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
        (prompts_dir / f"{candidate['id']}.md").write_text(prompt, encoding="utf-8")

    write_json(run_dir / "harness-work-order.json", work_order)
    (run_dir / "README.md").write_text(_work_order_markdown(workspace, manifest, work_order), encoding="utf-8")
    index = "\n".join(f"- [{c['id']}]({c['id']}.md)" for c in candidates)
    (prompts_dir / "INDEX.md").write_text(f"# Candidate Prompts\n\n{index}\n", encoding="utf-8")

    if as_json:
        print(json.dumps(work_order, indent=2, sort_keys=True))
    else:
        print(f"harness work order: {rel_to(run_dir, workspace)}")
        if candidates:
            print("candidate prompts:")
            for candidate in candidates:
                print(f"- {candidate['id']}: {rel_to(prompts_dir / (candidate['id'] + '.md'), workspace)}")
        else:
            print("no candidates found; inspect public headers, tests, and sample inputs manually")
    return run_dir


def write_candidate_knowledge(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str,
    as_json: bool = False,
    quiet: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    assert candidate is not None
    context = _candidate_context(build_context, candidate)
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-knowledge-{candidate['id']}")
    knowledge = {
        "target": manifest.name,
        "candidate": candidate,
        "manifest": manifest.to_dict(),
        "source_dir": str(source_dir),
        "build_context": {
            "compile_commands": build_context.get("compile_commands"),
            "unit_count": build_context.get("unit_count", 0),
            "candidate_context": context,
        },
        "samples": data["sample_inputs"],
        "dictionary_token_candidates": data["dictionary_token_candidates"],
        "instructions": [
            "Write one narrow harness for this candidate only.",
            "Use the matching compile unit flags/includes when adding headers or build args.",
            "If compile fails, fix the harness or manifest/build args; do not weaken sanitizer flags.",
            "Validate with review, ASan+UBSan build, smoke, coverage, and blocker analysis.",
        ],
    }
    prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
    write_json(out_dir / "knowledge.json", knowledge)
    (out_dir / "prompt.md").write_text(prompt, encoding="utf-8")
    if quiet:
        return out_dir
    if as_json:
        print(json.dumps(knowledge, indent=2, sort_keys=True))
    else:
        print(f"knowledge packet: {rel_to(out_dir, workspace)}")
        print(f"prompt: {rel_to(out_dir / 'prompt.md', workspace)}")
    return out_dir


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
    seed_dir = manifest.seed_dir(workspace)
    if not seed_dir.exists():
        return 0
    return sum(1 for path in seed_dir.iterdir() if path.is_file())


def _build_artifacts(workspace: Path, manifest: TargetManifest) -> dict[str, int]:
    out: dict[str, int] = {}
    for profile in ["afl_asan_ubsan", "afl_lto_cmplog", "libfuzzer_asan_ubsan", "coverage"]:
        build_json = workspace / "build" / manifest.name / profile / "build.json"
        if not build_json.exists():
            out[profile] = 0
            continue
        try:
            out[profile] = len(read_json(build_json).get("artifacts", []))
        except Exception:
            out[profile] = 0
    return out


def _latest_fuzz_run(workspace: Path, name: str) -> Path | None:
    run_root = workspace / "runs" / name
    if not run_root.exists():
        return None
    for run_dir in reversed(sorted([p for p in run_root.iterdir() if p.is_dir()])):
        if (run_dir / "run.json").exists():
            return run_dir
        if (run_dir / "coverage").exists() or (run_dir / "aflpp").exists() or (run_dir / "libfuzzer").exists():
            return run_dir
    return None


def _coverage_reports(run_dir: Path | None) -> list[Path]:
    if run_dir is None:
        return []
    return sorted((run_dir / "coverage").glob("*.report.txt"))


def _parse_llvm_coverage_report(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total: dict[str, float] | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Filename", "---")):
            continue
        percents = [float(value) for value in re.findall(r"([0-9]+(?:\.[0-9]+)?)%", stripped)]
        if len(percents) < 3:
            continue
        file_name = stripped.split()[0]
        item = {"file": file_name, "region": percents[0], "function": percents[1], "line": percents[2]}
        if file_name == "TOTAL":
            total = {k: float(v) for k, v in item.items() if k != "file"}
        else:
            rows.append(item)
    return {"report": str(path), "total": total, "files": rows}


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


def _draft_harness(candidate: dict[str, Any], manifest: TargetManifest) -> str:
    ext = "cc" if manifest.language == "c++" else "c"
    comment = "/* TODO: include the correct public header and call the target API safely. */"
    if candidate.get("header_refs"):
        header = candidate["header_refs"][0]
        comment = f'/* TODO: confirm this include and call {candidate["function"]}(data, size). */\n#include "{header}"'
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


def harness_blockers(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    as_json: bool = False,
) -> dict[str, Any]:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else _latest_fuzz_run(workspace, manifest.name)
    if run_dir is None:
        raise FuzzCtlError(f"no fuzz or coverage run found for {manifest.name}")
    reports = [_parse_llvm_coverage_report(path) for path in _coverage_reports(run_dir)]
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    candidates = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)

    file_rows: dict[str, dict[str, Any]] = {}
    for report in reports:
        for row in report["files"]:
            file_value = str(row["file"])
            file_rows[file_value] = row
            file_rows[Path(file_value).name] = row
            path = Path(file_value)
            if path.is_absolute():
                file_rows[rel_to(path, source_dir)] = row

    blockers: list[dict[str, Any]] = []
    if not file_rows:
        blockers.append(
            {
                "kind": "coverage_report_missing",
                "file": None,
                "reason": "no llvm-cov text reports found for this run; run `fuzzctl coverage <target>` before blocker analysis",
            }
        )
    seen_rows: set[str] = set()
    for row in file_rows.values():
        if row["file"] in seen_rows:
            continue
        seen_rows.add(row["file"])
        if row["line"] < 40 or row["function"] < 50:
            blockers.append({"kind": "low_coverage_file", **row})
    if file_rows:
        for candidate in candidates[:50]:
            row = file_rows.get(candidate["relative_file"]) or file_rows.get(Path(candidate["relative_file"]).name)
            if row is None:
                blockers.append(
                    {
                        "kind": "candidate_file_unreported",
                        "candidate": candidate["id"],
                        "file": candidate["relative_file"],
                        "function": candidate["function"],
                        "reason": "candidate file not present in llvm-cov report; harness may not link or execute it",
                    }
                )
            elif row["line"] < 40:
                blockers.append(
                    {
                        "kind": "candidate_shallow_coverage",
                        "candidate": candidate["id"],
                        "file": candidate["relative_file"],
                        "function": candidate["function"],
                        "line_coverage": row["line"],
                    }
                )

    result = {
        "target": manifest.name,
        "run": str(run_dir),
        "reports": reports,
        "blockers": blockers[:100],
        "recommendations": [
            "Prefer candidates whose compile database unit exists and whose file has low or absent coverage.",
            "Add valid seeds/dictionaries before increasing campaign duration.",
            "Split broad harnesses when one entrypoint reaches too many unrelated APIs with shallow coverage.",
        ],
    }
    out = ensure_dir(run_dir / "guidance")
    write_json(out / "harness-blockers.json", result)
    md = [f"# Harness Blockers: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace)}`", ""]
    for blocker in result["blockers"][:40]:
        subject = blocker.get("file") or "-"
        detail = blocker.get("function") or blocker.get("reason", "")
        md.append(f"- `{blocker['kind']}`: `{subject}` {detail}")
    if not result["blockers"]:
        md.append("- No blocker rows found. Run coverage first or inspect the HTML coverage report.")
    (out / "harness-blockers.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"harness blockers: {rel_to(out / 'harness-blockers.md', workspace)}")
        for blocker in result["blockers"][:20]:
            subject = blocker.get("file") or "-"
            detail = blocker.get("function") or blocker.get("reason", "")
            print(f"- {blocker['kind']}: {subject} {detail}")
    return result


def iterate_harness(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str | None = None,
    run_id: str | None = None,
) -> Path:
    blockers = harness_blockers(workspace, manifest, run_id=run_id, as_json=False)
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id) if candidate_id else (data["candidate_entrypoints"][0] if data["candidate_entrypoints"] else None)
    out = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-iteration")
    write_json(out / "blockers.json", blockers)
    if candidate:
        prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
        (out / f"{candidate['id']}-iteration-prompt.md").write_text(prompt, encoding="utf-8")
    (out / "README.md").write_text(
        f"# Harness Iteration: {manifest.name}\n\n"
        "Use `blockers.json` to decide whether to improve seeds/dictionary, split the harness, or target another API.\n",
        encoding="utf-8",
    )
    print(f"iteration packet: {rel_to(out, workspace)}")
    return out


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
    coverage = _coverage_total(run_dir)
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
    function: str | None
) -> Path:
    source_dir = manifest.source_dir(workspace)
    out_dir = ensure_dir(source_dir / "fuzz_harnesses")
    suffix = "cc" if manifest.language == "c++" else "c"
    out = out_dir / f"{name}_{harness_type}.{suffix}"
    call = f"/* TODO: include the correct header and call {function or 'target_parse'}(data, size). */"
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
    print("review and wire the TODO call before adding it to target.json")
    return out


def validate_harnesses(workspace: Path, manifest: TargetManifest, *, build: bool = False) -> int:
    source_dir = manifest.source_dir(workspace)
    errors = []
    if not manifest.harnesses:
        errors.append("manifest has no harnesses")
    for harness in manifest.harnesses:
        if harness.source and not (source_dir / harness.source).exists():
            errors.append(f"{harness.name}: source missing: {harness.source}")
        if harness.type not in {"file", "stdin", "libfuzzer"}:
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
    print("harness validation passed")
    return 0
