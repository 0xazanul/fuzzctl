from __future__ import annotations

import re
from pathlib import Path
from typing import Any


STACK_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(?P<function>.+?)"
    r"(?:\s+(?P<file>/[^:\n]+):(?P<line>\d+)(?::(?P<column>\d+))?)?\s*$",
    re.MULTILINE,
)


def safe_read(path_value: object, limit: int = 20000) -> str:
    if not path_value:
        return ""
    path = Path(str(path_value))
    if not path.exists() or not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit]
    return text


def parse_frames(trace: str, source_dir: Path) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for match in STACK_FRAME_RE.finditer(trace):
        file_value = match.group("file") or ""
        rel_file = ""
        if file_value:
            try:
                rel_file = str(Path(file_value).resolve().relative_to(source_dir.resolve()))
            except ValueError:
                rel_file = file_value
        frames.append(
            {
                "index": int(match.group("index")),
                "function": match.group("function").strip(),
                "file": file_value,
                "rel_file": rel_file,
                "line": int(match.group("line")) if match.group("line") else None,
                "column": int(match.group("column")) if match.group("column") else None,
            }
        )
    return frames


def is_harness_frame(frame: dict[str, Any]) -> bool:
    rel_file = str(frame.get("rel_file") or frame.get("file") or "")
    function = str(frame.get("function") or "")
    return (
        "fuzz_harnesses/" in rel_file
        or "LLVMFuzzerTestOneInput" in function
        or function.startswith("fuzzer::")
        or function == "main" and "fuzz" in rel_file
    )


def is_runtime_frame(frame: dict[str, Any]) -> bool:
    function = str(frame.get("function") or "")
    rel_file = str(frame.get("rel_file") or frame.get("file") or "")
    runtime_markers = (
        "__libc_start",
        "_start",
        "FuzzerDriver",
        "RunOneTest",
        "ExecuteCallback",
        "malloc",
        "calloc",
        "operator new",
    )
    return any(marker in function for marker in runtime_markers) or "/lib/" in rel_file


def root_frame(frames: list[dict[str, Any]]) -> dict[str, Any] | None:
    for frame in frames:
        if is_runtime_frame(frame) or is_harness_frame(frame):
            continue
        if frame.get("rel_file") or frame.get("file"):
            return frame
    for frame in frames:
        if not is_runtime_frame(frame):
            return frame
    return frames[0] if frames else None
