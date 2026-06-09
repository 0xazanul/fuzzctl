from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .util import FuzzCtlError, ensure_dir, rel_to, run_cmd, which_any, write_json


def external_tools_dir(workspace: Path) -> Path:
    return ensure_dir(workspace / "state" / "external-tools")


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    return Path(value).expanduser().resolve()


def oss_fuzz_gen_dir(workspace: Path) -> Path:
    return _env_path("OSS_FUZZ_GEN_DIR") or (external_tools_dir(workspace) / "oss-fuzz-gen")


def grammar_mutator_dir(workspace: Path) -> Path:
    return _env_path("AFL_GRAMMAR_MUTATOR_DIR") or (external_tools_dir(workspace) / "Grammar-Mutator")


def exploitable_dir(workspace: Path) -> Path:
    return _env_path("EXPLOITABLE_DIR") or (external_tools_dir(workspace) / "exploitable")


def exploitable_py_path(workspace: Path) -> Path | None:
    env_path = _env_path("EXPLOITABLE_PY")
    if env_path and env_path.exists():
        return env_path
    local_path = exploitable_dir(workspace) / "exploitable" / "exploitable.py"
    if local_path.exists():
        return local_path
    path_match = which_any(["exploitable.py"])
    return Path(path_match).resolve() if path_match else None


def _path_status(path: Path, marker: str) -> dict[str, Any]:
    marker_path = path / marker
    return {
        "path": str(path),
        "installed": path.exists() and marker_path.exists(),
        "marker": str(marker_path),
    }


def _glob_existing(root: Path, patterns: list[str]) -> list[str]:
    if not root.exists():
        return []
    matches: dict[Path, Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.exists():
                matches.setdefault(path.resolve(), path)
    return sorted(str(path) for path in matches.values())


def _command_first_line(argv: list[str]) -> str | None:
    if not argv or not argv[0]:
        return None
    result = run_cmd(argv, timeout=5)
    if result.returncode != 0:
        return None
    for line in result.output.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def advanced_tool_status(workspace: Path) -> dict[str, Any]:
    grammar_dir = grammar_mutator_dir(workspace)
    oss_dir = oss_fuzz_gen_dir(workspace)
    oss_venv_python = oss_dir / ".venv" / "bin" / "python"
    symcc = which_any(["symcc"])
    sympp = which_any(["sym++"])
    symcc_helper = which_any(["symcc_fuzzing_helper"])
    casr_commands = {
        name: which_any([name])
        for name in ["casr-san", "casr-ubsan", "casr-gdb", "casr-afl", "casr-libfuzzer", "casr-cluster", "casr-cli"]
    }
    exploitable = os.environ.get("EXPLOITABLE_PY") or which_any(["exploitable.py"])
    exploitable_py = exploitable_py_path(workspace)
    gdb = which_any(["gdb"])
    grammar_libs = _glob_existing(grammar_dir, ["libgrammarmutator-*.so", "src/libgrammarmutator-*.so"])
    grammar_generators = _glob_existing(grammar_dir, ["grammar_generator-*", "src/grammar_generator-*"])
    result = {
        "symcc": {
            "installed": bool(symcc and sympp and symcc_helper),
            "compiler_c": symcc,
            "compiler_cxx": sympp,
            "compiler_c_realpath": str(Path(symcc).resolve()) if symcc else None,
            "compiler_version": _command_first_line([symcc, "--version"]) if symcc else None,
            "helper": symcc_helper,
            "setup": [
                "Clone SymCC, initialize submodules, and build with `cmake -DSYMCC_RT_BACKEND=qsym -DZ3_TRUST_SYSTEM_VERSION=on`.",
                "Install the helper with `cargo install --path util/symcc_fuzzing_helper` from the SymCC repo.",
                "Ensure `symcc`, `sym++`, and `symcc_fuzzing_helper` are on PATH.",
            ],
        },
        "oss_fuzz_gen": {
            **_path_status(oss_dir, "run_all_experiments.py"),
            "env": "OSS_FUZZ_GEN_DIR",
            "venv_python": str(oss_venv_python) if oss_venv_python.exists() else None,
            "local_execution_ready": oss_venv_python.exists(),
            "setup": [
                f"git clone https://github.com/google/oss-fuzz-gen {oss_dir}",
                f"cd {oss_dir} && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt",
                "LLM API credentials are not stored by fuzz-pipeline; use Codex workorders by default.",
            ],
        },
        "grammar_mutator": {
            **_path_status(grammar_dir, "Makefile"),
            "env": "AFL_GRAMMAR_MUTATOR_DIR",
            "mutator_libs": grammar_libs,
            "generators": grammar_generators,
            "setup": [
                f"git clone https://github.com/AFLplusplus/Grammar-Mutator {grammar_dir}",
                f"cd {grammar_dir} && make GRAMMAR_FILE=grammars/json.json",
                "Use `fuzzctl corpus grammar-configure` to attach a built libgrammarmutator-*.so to a harness.",
            ],
        },
        "casr": {
            "installed": any(casr_commands.values()),
            "commands": casr_commands,
            "setup": [
                "Install the official CASR Linux release with `fuzzctl tools install-advanced --tool casr`.",
                "For sanitizer reports this pipeline uses `casr-san`; for gdb/exploitable evidence it uses `casr-gdb` when available.",
            ],
        },
        "exploitable": {
            "installed": bool(exploitable_py and gdb),
            "path": str(exploitable_py) if exploitable_py else exploitable,
            "gdb": gdb,
            "env_dir": "EXPLOITABLE_DIR",
            "env": "EXPLOITABLE_PY",
            "setup": [
                f"git clone https://github.com/jfoote/exploitable {exploitable_dir(workspace)}",
                "Install gdb and set EXPLOITABLE_PY to exploitable/exploitable.py if using a custom path.",
                "CASR can also provide exploitable-style severity when built with the relevant feature.",
            ],
        },
    }
    result["ready"] = {
        "hybrid_symcc": bool(result["symcc"]["installed"]),
        "oss_fuzz_gen_workorders": True,
        "oss_fuzz_gen_local_execution": bool(result["oss_fuzz_gen"]["installed"] and result["oss_fuzz_gen"]["local_execution_ready"]),
        "grammar_mutator_campaigns": bool(result["grammar_mutator"]["mutator_libs"]),
        "casr_triage": bool(casr_commands.get("casr-san") or casr_commands.get("casr-gdb")),
        "exploitable_gdb": bool(result["exploitable"]["installed"]),
    }
    return result


def print_advanced_tool_status(status: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(status, indent=2, sort_keys=True))
        return
    print("advanced fuzzing tools:")
    for name in ["symcc", "oss_fuzz_gen", "grammar_mutator", "casr", "exploitable"]:
        item = status[name]
        mark = "ready" if item.get("installed") else "missing"
        print(f"  {mark:7} {name}")
        if name == "symcc":
            print(f"          symcc={item.get('compiler_c') or '-'} sym++={item.get('compiler_cxx') or '-'} helper={item.get('helper') or '-'}")
            if item.get("compiler_version"):
                print(f"          version={item['compiler_version']}")
            if item.get("compiler_c_realpath"):
                print(f"          realpath={item['compiler_c_realpath']}")
        elif name == "casr":
            commands = item.get("commands", {})
            found = ", ".join(f"{k}={v}" for k, v in commands.items() if v) or "-"
            print(f"          {found}")
        elif name == "grammar_mutator":
            print(f"          libs={len(item.get('mutator_libs', []))} generators={len(item.get('generators', []))} path={item.get('path')}")
        elif name == "oss_fuzz_gen":
            local = "yes" if item.get("local_execution_ready") else "no"
            print(f"          path={item.get('path') or '-'} local_execution={local}")
        else:
            print(f"          path={item.get('path') or '-'}")
        if not item.get("installed"):
            for step in item.get("setup", [])[:2]:
                print(f"          setup: {step}")
    print("ready:")
    for name, value in status["ready"].items():
        print(f"  {'yes' if value else 'no ':3} {name}")


def clone_advanced_tool(workspace: Path, tool: str, *, dry_run: bool = False) -> Path:
    specs = {
        "oss-fuzz-gen": ("https://github.com/google/oss-fuzz-gen", oss_fuzz_gen_dir(workspace)),
        "grammar-mutator": ("https://github.com/AFLplusplus/Grammar-Mutator", grammar_mutator_dir(workspace)),
        "symcc": ("https://github.com/eurecom-s3/symcc", external_tools_dir(workspace) / "symcc"),
        "exploitable": ("https://github.com/jfoote/exploitable", exploitable_dir(workspace)),
    }
    if tool not in specs:
        raise FuzzCtlError(f"unsupported advanced tool clone target: {tool}")
    url, dest = specs[tool]
    if dest.exists():
        print(f"{tool} already exists: {rel_to(dest, workspace)}")
        return dest
    cmd = ["git", "clone", url, str(dest)]
    print("$ " + " ".join(cmd))
    if not dry_run:
        run_cmd(cmd, check=True)
    return dest


def write_advanced_install_plan(workspace: Path) -> Path:
    status = advanced_tool_status(workspace)
    out = ensure_dir(workspace / "workorders" / "_infrastructure" / "advanced-tools")
    write_json(out / "advanced-tools.json", status)
    lines = ["# Advanced Fuzzing Tool Setup", ""]
    for name in ["symcc", "oss_fuzz_gen", "grammar_mutator", "casr", "exploitable"]:
        item = status[name]
        lines.extend([f"## {name}", "", f"Installed: `{bool(item.get('installed'))}`", ""])
        for step in item.get("setup", []):
            lines.append(f"- `{step}`")
        lines.append("")
    (out / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"advanced install plan: {rel_to(out, workspace)}")
    return out
