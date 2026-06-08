from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

from .detect import CPP_EXTS, C_EXTS
from .manifest import TargetManifest, save_manifest
from .util import FuzzCtlError, ensure_dir, rel_to, run_cmd, which, write_json


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
    p = Path(value)
    if p.is_absolute():
        return str(p.resolve())
    return str((directory / p).resolve())


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
    with path.open("r", encoding="utf-8") as f:
        entries = json.load(f)
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


def _synthetic_compile_database(source_dir: Path, out_dir: Path) -> Path:
    entries: list[dict[str, Any]] = []
    include_args = [arg for inc in _header_include_dirs(source_dir) for arg in ("-I", str(inc))]
    for source in _source_files(source_dir):
        compiler = "clang++" if source.suffix.lower() in CPP_EXTS else "clang"
        entries.append(
            {
                "directory": str(source_dir),
                "arguments": [compiler, *include_args, "-c", str(source), "-o", str(out_dir / (source.name + ".o"))],
                "file": str(source),
            }
        )
    if not entries:
        raise FuzzCtlError(f"no C/C++ source files found for synthetic compile database: {source_dir}")
    path = out_dir / "compile_commands.json"
    write_json(path, entries)
    return path


def _generate_cmake_compile_database(source_dir: Path, out_dir: Path, *, print_cmd: bool = True) -> Path | None:
    if not (source_dir / "CMakeLists.txt").exists():
        return None
    generator = "Ninja" if which("ninja") else "Unix Makefiles"
    result = run_cmd(
        ["cmake", "-S", str(source_dir), "-B", str(out_dir), "-G", generator, "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
        timeout=120,
        print_cmd=print_cmd,
    )
    (out_dir / "configure.log").write_text(result.output, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        return None
    path = out_dir / "compile_commands.json"
    return path if path.exists() else None


def _generate_bear_compile_database(
    source_dir: Path,
    out_dir: Path,
    build_system: str,
    *,
    print_cmd: bool = True,
) -> Path | None:
    if not which("bear"):
        return None
    jobs = str(max(1, min(os.cpu_count() or 1, 8)))
    if build_system == "make":
        cmd = ["bear", "--output", str(out_dir / "compile_commands.json"), "--", "make", f"-j{jobs}"]
    elif build_system == "autotools" and (source_dir / "configure").exists():
        configure = run_cmd(["./configure"], cwd=source_dir, timeout=180, print_cmd=print_cmd)
        (out_dir / "configure.log").write_text(configure.output, encoding="utf-8", errors="replace")
        if configure.returncode != 0:
            return None
        cmd = ["bear", "--output", str(out_dir / "compile_commands.json"), "--", "make", f"-j{jobs}"]
    else:
        return None
    result = run_cmd(cmd, cwd=source_dir, timeout=180, print_cmd=print_cmd)
    (out_dir / "bear.log").write_text(result.output, encoding="utf-8", errors="replace")
    path = out_dir / "compile_commands.json"
    return path if path.exists() else None


def _find_link_artifacts(source_dir: Path, build_dir: Path) -> list[str]:
    roots = [source_dir, build_dir]
    artifacts: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if len(artifacts) >= 80:
                return artifacts
            if _is_ignored(path) or not path.is_file():
                continue
            if path.suffix in {".a", ".so", ".dylib"}:
                artifacts.append(str(path.resolve()))
    return sorted(set(artifacts))


def collect_build_context(
    workspace: Path,
    manifest: TargetManifest,
    *,
    generate: bool = False,
    method: str = "auto",
    update_manifest: bool = False,
    print_cmd: bool = True,
    refresh: bool = False,
) -> dict[str, Any]:
    source_dir = manifest.source_dir(workspace)
    out_dir = ensure_dir(workspace / "build" / manifest.name / "build-context")
    compile_db = None if refresh else find_compile_database(source_dir, out_dir)
    generated = False

    if compile_db is None and generate:
        if method in {"auto", "cmake"}:
            compile_db = _generate_cmake_compile_database(source_dir, out_dir, print_cmd=print_cmd)
            generated = compile_db is not None
        if compile_db is None and method in {"auto", "bear"}:
            compile_db = _generate_bear_compile_database(source_dir, out_dir, manifest.build_system, print_cmd=print_cmd)
            generated = compile_db is not None
        if compile_db is None and method in {"auto", "synthetic"}:
            compile_db = _synthetic_compile_database(source_dir, out_dir)
            generated = True

    if compile_db is None:
        raise FuzzCtlError(
            "no compile_commands.json found; pass --generate or build the project with CMAKE_EXPORT_COMPILE_COMMANDS=ON/Bear"
        )

    parsed = _parse_compile_database(compile_db, source_dir)
    context = {
        "schema": 1,
        "method": method,
        "generated": generated,
        "source_dir": str(source_dir),
        "build_dir": str(out_dir),
        "link_artifacts": _find_link_artifacts(source_dir, out_dir),
        **parsed,
    }
    write_json(out_dir / "build-context.json", context)
    if update_manifest:
        manifest.build_context = {
            "schema": 1,
            "path": rel_to(out_dir / "build-context.json", workspace),
            "compile_commands": rel_to(Path(context["compile_commands"]), workspace),
            "unit_count": context["unit_count"],
            "include_dirs": context["include_dirs"][:80],
            "defines": context["defines"][:120],
            "standards": context["standards"],
            "compile_flags": context["compile_flags"][:120],
            "link_artifacts": context["link_artifacts"][:40],
        }
        save_manifest(workspace, manifest)
    return context


def load_build_context(workspace: Path, manifest: TargetManifest) -> dict[str, Any]:
    path_value = manifest.build_context.get("path") if manifest.build_context else None
    if path_value:
        path = Path(path_value)
        if not path.is_absolute():
            path = workspace / path
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    try:
        return collect_build_context(workspace, manifest, generate=False, update_manifest=False)
    except FuzzCtlError:
        return {}


def context_flags_for_source(workspace: Path, manifest: TargetManifest, source: Path) -> tuple[list[str], list[str]]:
    context = load_build_context(workspace, manifest)
    if not context:
        return [], []
    source_resolved = source.resolve()
    units = context.get("units", [])
    selected = None
    for unit in units:
        if Path(unit.get("file", "")).resolve() == source_resolved:
            selected = unit
            break
    include_dirs = (selected or context).get("include_dirs", [])
    defines = (selected or context).get("defines", [])
    compile_flags = (selected or context).get("compile_flags", [])
    flags: list[str] = []
    for inc in include_dirs[:80]:
        flags.extend(["-I", str(inc)])
    flags.extend(str(item) for item in defines[:120])
    for flag in compile_flags[:120]:
        if flag.startswith(("-fsanitize", "-fprofile", "-fcoverage", "-O", "-g")):
            continue
        flags.append(str(flag))
    link_args = [str(path) for path in context.get("link_artifacts", [])[:40]]
    return flags, link_args


def print_build_context(context: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(context, indent=2, sort_keys=True))
        return
    print(f"compile_commands: {context.get('compile_commands')}")
    print(f"units: {context.get('unit_count', 0)}")
    print(f"generated: {context.get('generated')}")
    print("include dirs:")
    for item in context.get("include_dirs", [])[:20]:
        print(f"- {item}")
    print("defines:")
    for item in context.get("defines", [])[:20]:
        print(f"- {item}")
    print("link artifacts:")
    for item in context.get("link_artifacts", [])[:20]:
        print(f"- {item}")
