from __future__ import annotations

import os
from pathlib import Path

from .build_context import context_flags_for_source
from .manifest import Harness, PROFILES, TargetManifest
from .util import FuzzCtlError, ensure_dir, rel_to, run_cmd, write_json


COMMON_FLAGS = ["-g", "-O1", "-fno-omit-frame-pointer", "-fno-sanitize-recover=all"]


def build_root(workspace: Path, manifest: TargetManifest, profile: str) -> Path:
    return workspace / "build" / manifest.name / profile


def harness_binary(workspace: Path, manifest: TargetManifest, profile: str, harness: Harness) -> Path:
    return build_root(workspace, manifest, profile) / harness.name


def _compiler_for(profile: str, language: str, source: Path) -> str:
    suffix = source.suffix.lower()
    is_cpp = suffix in {".cc", ".cpp", ".cxx"} or (language == "c++" and suffix != ".c")
    if profile == "symcc":
        return "sym++" if is_cpp else "symcc"
    if profile == "fuzztest_asan_ubsan":
        return "clang++"
    if profile == "afl_asan_ubsan":
        return "afl-clang-fast++" if is_cpp else "afl-clang-fast"
    if profile == "afl_lto_cmplog":
        return "afl-clang-lto++" if is_cpp else "afl-clang-lto"
    return "clang++" if is_cpp else "clang"


def _profile_flags(profile: str, harness: Harness) -> list[str]:
    if profile in {"afl_asan_ubsan", "afl_lto_cmplog"}:
        return [*COMMON_FLAGS, "-DFUZZ_STANDALONE", "-fsanitize=address,undefined"]
    if profile == "libfuzzer_asan_ubsan":
        return [*COMMON_FLAGS, "-DFUZZ_LIBFUZZER", "-fsanitize=fuzzer,address,undefined"]
    if profile == "fuzztest_asan_ubsan":
        return [
            *COMMON_FLAGS,
            "-DFUZZ_FUZZTEST",
            "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "-fsanitize=address,undefined",
            "-fsanitize-coverage=inline-8bit-counters",
            "-fsanitize-coverage=trace-cmp",
        ]
    if profile == "symcc":
        return [*COMMON_FLAGS, "-DFUZZ_STANDALONE"]
    if profile == "coverage":
        return [
            "-g",
            "-O1",
            "-DFUZZ_STANDALONE",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
        ]
    raise FuzzCtlError(f"unknown build profile: {profile}")


def _profile_env(profile: str) -> dict[str, str]:
    env = {
        "ASAN_OPTIONS": (
            "abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:"
            "strict_string_checks=1:symbolize=1"
        ),
        "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
    }
    if profile in {"afl_asan_ubsan", "afl_lto_cmplog"}:
        env.update({"AFL_USE_ASAN": "1", "AFL_USE_UBSAN": "1", "AFL_SKIP_CPUFREQ": "1"})
    if profile == "afl_lto_cmplog":
        env["AFL_LLVM_CMPLOG"] = "1"
    if profile == "symcc":
        env.pop("ASAN_OPTIONS", None)
        env.pop("UBSAN_OPTIONS", None)
        env["SYMCC_REGULAR_LIBCXX"] = "1"
    return env


def _run_custom_commands(
    workspace: Path,
    manifest: TargetManifest,
    profile: str,
    commands: list[list[str]],
) -> list[dict[str, str]]:
    source_dir = manifest.source_dir(workspace)
    out_dir = ensure_dir(build_root(workspace, manifest, profile))
    artifacts: list[dict[str, str]] = []
    replacements = {
        "{workspace}": str(workspace),
        "{source_dir}": str(source_dir),
        "{build_dir}": str(out_dir),
        "{profile}": profile,
    }
    for raw in commands:
        cmd = [replacements.get(token, token) for token in raw]
        result = run_cmd(cmd, cwd=source_dir, env=_profile_env(profile), print_cmd=True)
        (out_dir / "build.log").open("a", encoding="utf-8").write(result.output)
        if result.returncode != 0:
            raise FuzzCtlError(f"custom build command failed for {manifest.name}:{profile}")
    artifacts.append({"profile": profile, "kind": "custom", "path": str(out_dir)})
    return artifacts


def _build_raw_harnesses(workspace: Path, manifest: TargetManifest, profile: str) -> list[dict[str, str]]:
    source_dir = manifest.source_dir(workspace)
    out_dir = ensure_dir(build_root(workspace, manifest, profile))
    artifacts: list[dict[str, str]] = []
    for harness in manifest.harnesses:
        if harness.profiles and profile not in harness.profiles:
            if not (profile == "symcc" and harness.type in {"file", "stdin"} and "afl_asan_ubsan" in harness.profiles):
                continue
        if profile == "symcc" and harness.type not in {"file", "stdin"}:
            continue
        if profile == "libfuzzer_asan_ubsan" and harness.type != "libfuzzer":
            continue
        if profile == "fuzztest_asan_ubsan" and harness.type != "fuzztest":
            continue
        if profile not in {"libfuzzer_asan_ubsan", "fuzztest_asan_ubsan"} and harness.type in {"libfuzzer", "fuzztest"}:
            continue
        if not harness.source:
            continue
        source = (source_dir / harness.source).resolve()
        if not source.exists():
            raise FuzzCtlError(f"harness source not found: {source}")
        binary = harness_binary(workspace, manifest, profile, harness)
        compiler = _compiler_for(profile, manifest.language, source)
        context_flags, link_args = context_flags_for_source(workspace, manifest, source)
        cmd = [
            compiler,
            *_profile_flags(profile, harness),
            *context_flags,
            *harness.compile_flags,
            str(source),
            *link_args,
            *harness.link_flags,
            "-o",
            str(binary),
        ]
        result = run_cmd(cmd, cwd=source_dir, env=_profile_env(profile), print_cmd=True)
        (out_dir / f"{harness.name}.build.log").write_text(result.output, encoding="utf-8")
        if result.returncode != 0:
            raise FuzzCtlError(f"build failed for harness {harness.name} profile {profile}")
        artifacts.append(
            {
                "profile": profile,
                "harness": harness.name,
                "type": harness.type,
                "binary": str(binary),
                "source": str(source),
            }
        )
    return artifacts


def _build_project_system(workspace: Path, manifest: TargetManifest, profile: str) -> list[dict[str, str]]:
    source_dir = manifest.source_dir(workspace)
    out_dir = ensure_dir(build_root(workspace, manifest, profile))
    env = _profile_env(profile)
    if profile == "symcc":
        compiler_c = "symcc"
        compiler_cxx = "sym++"
    else:
        compiler_c = "afl-clang-fast" if profile.startswith("afl") else "clang"
        compiler_cxx = "afl-clang-fast++" if profile.startswith("afl") else "clang++"
    flags = " ".join(_profile_flags(profile, Harness(name="project", type="file")))
    env.update({"CC": compiler_c, "CXX": compiler_cxx, "CFLAGS": flags, "CXXFLAGS": flags, "LDFLAGS": flags})
    if manifest.build_system == "cmake":
        generator = "Ninja"
        run_cmd(["cmake", "-S", str(source_dir), "-B", str(out_dir), "-G", generator], env=env, check=True, print_cmd=True)
        run_cmd(["cmake", "--build", str(out_dir), "--parallel", str(os.cpu_count() or 1)], env=env, check=True, print_cmd=True)
    elif manifest.build_system == "make":
        run_cmd(["make", "-j", str(os.cpu_count() or 1)], cwd=source_dir, env=env, check=True, print_cmd=True)
    elif manifest.build_system == "autotools":
        run_cmd(["./configure", f"--prefix={out_dir / 'install'}"], cwd=source_dir, env=env, check=True, print_cmd=True)
        run_cmd(["make", "-j", str(os.cpu_count() or 1)], cwd=source_dir, env=env, check=True, print_cmd=True)
    else:
        raise FuzzCtlError(
            f"profile {profile} has no harness sources and build system {manifest.build_system!r} is not directly buildable"
        )
    return [{"profile": profile, "kind": manifest.build_system, "path": str(out_dir)}]


def build_profile(workspace: Path, manifest: TargetManifest, profile: str) -> Path:
    if profile not in PROFILES:
        raise FuzzCtlError(f"unknown profile {profile!r}; choose one of {', '.join(sorted(PROFILES))}")
    out_dir = ensure_dir(build_root(workspace, manifest, profile))
    artifacts: list[dict[str, str]]
    if profile in manifest.build_commands:
        artifacts = _run_custom_commands(workspace, manifest, profile, manifest.build_commands[profile])
    else:
        artifacts = _build_raw_harnesses(workspace, manifest, profile)
        if profile == "fuzztest_asan_ubsan" and not artifacts:
            raise FuzzCtlError(
                "no FuzzTest harness artifacts built; add a harness with type 'fuzztest' "
                "and profile 'fuzztest_asan_ubsan', or provide build_commands for this profile"
            )
        if not artifacts:
            artifacts = _build_project_system(workspace, manifest, profile)
    metadata = {
        "target": manifest.name,
        "profile": profile,
        "artifacts": artifacts,
    }
    write_json(out_dir / "build.json", metadata)
    print(f"built {manifest.name}:{profile} -> {rel_to(out_dir, workspace)}")
    return out_dir
