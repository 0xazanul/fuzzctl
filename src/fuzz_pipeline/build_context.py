from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .build_context_compiledb import (
    _header_include_dirs,
    _is_ignored,
    _parse_compile_database,
    _source_files,
    find_compile_database,
)
from .detect import CPP_EXTS
from .manifest import TargetManifest, save_manifest
from .util import FuzzCtlError, ensure_dir, rel_to, run_cmd, which, write_json


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
    skip_next = False
    skip_flags_with_value = {"-include", "-include-pch", "-Xclang", "-x"}
    skip_exact = {"-Winvalid-pch", "-fpch-instantiate-templates"}
    for raw in compile_flags[:120]:
        flag = str(raw)
        if skip_next:
            skip_next = False
            continue
        if flag in skip_flags_with_value:
            skip_next = True
            continue
        if flag in skip_exact:
            continue
        if not flag.startswith("-"):
            continue
        if flag.startswith(("-fsanitize", "-fprofile", "-fcoverage", "-O", "-g")):
            continue
        flags.append(flag)
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
