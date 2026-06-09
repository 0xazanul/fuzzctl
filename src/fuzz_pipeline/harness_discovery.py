from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .harness_source_context import (
    SourceText,
    _build_markers,
    _dictionary_tokens,
    _header_files,
    _header_refs,
    _header_texts,
    _relative,
    _sample_files,
    _slug,
    _source_excerpt,
    _source_texts,
    _usage_refs,
)


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
    "serialize",
    "encode",
    "marshal",
    "unmarshal",
    "unpack",
    "pack",
    "inflate",
    "decompress",
    "validate",
    "scan",
    "consume",
    "compile",
    "import",
)
SECURITY_FILE_TOKENS = {
    "archive",
    "bitmap",
    "codec",
    "compress",
    "decode",
    "decompress",
    "demux",
    "deserialize",
    "encode",
    "format",
    "image",
    "import",
    "inflate",
    "json",
    "media",
    "packet",
    "parse",
    "parser",
    "serialize",
    "pdf",
    "read",
    "stream",
    "unpack",
    "xml",
}


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


def _scan_candidates(
    root: Path,
    source_texts: list[SourceText] | None = None,
    header_texts: list[SourceText] | None = None,
) -> list[dict]:
    candidates = []
    source_texts = source_texts or _source_texts(root)
    header_texts = header_texts or _header_texts(root)
    for source, text in source_texts:
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
                "header_refs": _header_refs(root, header_texts, function),
                "usage_refs": _usage_refs(root, source_texts, function, source),
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


def _ai_plan_data(path: Path) -> dict[str, Any]:
    from .detect import detect_target

    root = path.expanduser().resolve()
    detection = detect_target(root)
    source_texts = _source_texts(root)
    header_texts = _header_texts(root)
    return {
        "path": str(root),
        "detection": detection.to_dict(),
        "candidate_entrypoints": _scan_candidates(root, source_texts, header_texts)[:50],
        "build_markers": _build_markers(root),
        "public_headers": _header_files(root),
        "sample_inputs": _sample_files(root),
        "dictionary_token_candidates": _dictionary_tokens(root, source_texts),
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
