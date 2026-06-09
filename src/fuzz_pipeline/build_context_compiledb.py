from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from .detect import CPP_EXTS, C_EXTS
from .util import FuzzCtlError, rel_to


IGNORED_DIRS = {".git", ".cache", "node_modules", "runs", "workorders"}
COMPILE_FLAG_PREFIXES = (
    "-I",
    "-D",
    "-U",
    "-isystem",
    "-iquote",
    "-include",
    "-std=",
    "-x",
    "-f",
    "-m",
    "-W",
)


def _is_ignored(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def _source_files(root: Path) -> list[Path]:
    exts = C_EXTS | CPP_EXTS
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts and not _is_ignored(p))


def _header_include_dirs(root: Path) -> list[Path]:
    header_exts = {".h", ".hh", ".hpp", ".hxx"}
    dirs = {root}
    for path in root.rglob("*"):
        if _is_ignored(path) or not path.is_file() or path.suffix.lower() not in header_exts:
            continue
        dirs.add(path.parent)
    return sorted(dirs, key=lambda p: (len(p.parts), str(p)))[:120]


def _argv(entry: dict[str, Any]) -> list[str]:
    if "arguments" in entry and isinstance(entry["arguments"], list):
        return [str(item) for item in entry["arguments"]]
    command = str(entry.get("command", ""))
    return shlex.split(command)


def _resolve_arg_path(value: str, directory: Path) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path.resolve())
    return str((directory / path).resolve())


def _extract_flags(argv: list[str], directory: Path, source_file: Path) -> dict[str, Any]:
    include_dirs: list[str] = []
    defines: list[str] = []
    other_flags: list[str] = []
    language: str | None = None
    standard: str | None = None
    skip_next = False

    for index, arg in enumerate(argv[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if arg in {"-c", "-o"}:
            skip_next = arg == "-o"
            continue
        if arg == str(source_file) or Path(arg).name == source_file.name:
            continue
        if arg in {"-I", "-isystem", "-iquote", "-include", "-D", "-U", "-x"}:
            if index + 1 < len(argv):
                value = argv[index + 1]
                if arg in {"-I", "-isystem", "-iquote"}:
                    include_dirs.append(_resolve_arg_path(value, directory))
                elif arg in {"-D", "-U"}:
                    defines.append(f"{arg}{value}")
                elif arg == "-x":
                    language = value
                    other_flags.extend([arg, value])
                else:
                    other_flags.extend([arg, _resolve_arg_path(value, directory)])
            skip_next = True
            continue
        if arg.startswith("-I") and len(arg) > 2:
            include_dirs.append(_resolve_arg_path(arg[2:], directory))
            continue
        if arg.startswith("-isystem") and len(arg) > len("-isystem"):
            include_dirs.append(_resolve_arg_path(arg[len("-isystem"):], directory))
            continue
        if arg.startswith("-D") or arg.startswith("-U"):
            defines.append(arg)
            continue
        if arg.startswith("-std="):
            standard = arg
            other_flags.append(arg)
            continue
        if arg.startswith(COMPILE_FLAG_PREFIXES):
            other_flags.append(arg)

    return {
        "include_dirs": sorted(set(include_dirs)),
        "defines": sorted(set(defines)),
        "language": language,
        "standard": standard,
        "compile_flags": other_flags,
    }


def find_compile_database(source_dir: Path, build_dir: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    roots = [p for p in [build_dir, source_dir] if p is not None and p.exists()]
    for root in roots:
        for path in root.rglob("compile_commands.json"):
            if not _is_ignored(path):
                candidates.append(path.resolve())
    if not candidates:
        return None

    def rank(path: Path) -> tuple[int, int, str]:
        in_pipeline_context = False
        if build_dir is not None:
            try:
                path.relative_to(build_dir.resolve())
                in_pipeline_context = True
            except ValueError:
                in_pipeline_context = False
        has_build_part = "build" in [part.lower() for part in path.parts]
        if in_pipeline_context:
            bucket = 2
        elif has_build_part:
            bucket = 0
        else:
            bucket = 1
        return bucket, len(path.parts), str(path)

    candidates.sort(key=rank)
    return candidates[0]


def _parse_compile_database(path: Path, source_dir: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        entries = json.load(file)
    if not isinstance(entries, list):
        raise FuzzCtlError(f"compile database is not a JSON array: {path}")

    units: list[dict[str, Any]] = []
    include_dirs: set[str] = set()
    defines: set[str] = set()
    standards: set[str] = set()
    compile_flags: list[str] = []

    for raw in entries:
        if not isinstance(raw, dict):
            continue
        directory = Path(str(raw.get("directory", path.parent))).expanduser().resolve()
        file_value = str(raw.get("file", ""))
        if not file_value:
            continue
        source_file = Path(file_value)
        if not source_file.is_absolute():
            source_file = (directory / source_file).resolve()
        argv = _argv(raw)
        flags = _extract_flags(argv, directory, source_file)
        include_dirs.update(flags["include_dirs"])
        defines.update(flags["defines"])
        if flags["standard"]:
            standards.add(flags["standard"])
        for flag in flags["compile_flags"]:
            if flag not in compile_flags:
                compile_flags.append(flag)
        units.append(
            {
                "file": str(source_file),
                "relative_file": rel_to(source_file, source_dir),
                "directory": str(directory),
                "compiler": argv[0] if argv else None,
                "arguments": argv[:120],
                **flags,
            }
        )

    return {
        "compile_commands": str(path),
        "units": units,
        "unit_count": len(units),
        "include_dirs": sorted(include_dirs),
        "defines": sorted(defines),
        "standards": sorted(standards),
        "compile_flags": compile_flags[:120],
    }
