from __future__ import annotations

import re
from pathlib import Path

from .detect import CPP_EXTS, C_EXTS


STRING_RE = re.compile(r'"([^"\\\n\r]{2,40})"')
SAMPLE_DIR_TOKENS = {"corpus", "data", "example", "examples", "fixture", "fixtures", "sample", "samples", "test", "tests"}

SourceText = tuple[Path, str]


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


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _source_excerpt(source: Path, line: int, *, context: int = 18) -> str:
    text = _read_text(source)
    if not text:
        return ""
    lines = text.splitlines()
    start = max(1, line - context)
    end = min(len(lines), line + context)
    return "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))


def _source_texts(root: Path, *, limit: int = 500_000) -> list[SourceText]:
    return [(source, _read_text(source, limit=limit)) for source in _source_files(root)]


def _usage_refs(root: Path, sources: list[SourceText], function: str, definition: Path) -> list[dict]:
    refs: list[dict] = []
    pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for source, text in sources:
        if not text:
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            if source.resolve() == definition.resolve():
                window = text[max(0, match.start() - 80):match.start()]
                if "static" in window or "extern" in window:
                    continue
            refs.append({"file": str(source), "relative_file": _relative(source, root), "line": line})
            if len(refs) >= 8:
                return refs
    return refs


def _header_texts(root: Path) -> list[SourceText]:
    headers: list[SourceText] = []
    for header in root.rglob("*"):
        if ".git" in header.parts:
            continue
        if not header.is_file() or header.suffix.lower() not in {".h", ".hh", ".hpp", ".hxx"}:
            continue
        headers.append((header, _read_text(header, limit=150_000)))
    return headers


def _header_refs(root: Path, headers: list[SourceText], function: str) -> list[str]:
    refs: list[str] = []
    pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for header, text in headers:
        if pattern.search(text):
            refs.append(_relative(header, root))
        if len(refs) >= 8:
            break
    return refs


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


def _dictionary_tokens(root: Path, sources: list[SourceText] | None = None) -> list[str]:
    tokens: set[str] = set()
    for _source, text in (sources or _source_texts(root))[:200]:
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
