from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detect import Detection, detect_target
from .util import FuzzCtlError, ensure_dir, read_json, resolve_under_workspace, write_json


PROFILES = {
    "afl_asan_ubsan",
    "afl_lto_cmplog",
    "libfuzzer_asan_ubsan",
    "coverage",
}


@dataclass
class Harness:
    name: str
    type: str
    source: str | None = None
    argv: list[str] = field(default_factory=list)
    input_mode: str = "file"
    profiles: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Harness":
        return cls(
            name=str(data["name"]),
            type=str(data.get("type", "file")),
            source=data.get("source"),
            argv=list(data.get("argv", [])),
            input_mode=str(data.get("input_mode", data.get("type", "file"))),
            profiles=list(data.get("profiles", [])),
            env=dict(data.get("env", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "source": self.source,
            "argv": self.argv,
            "input_mode": self.input_mode,
            "profiles": self.profiles,
            "env": self.env,
        }


@dataclass
class TargetManifest:
    name: str
    language: str
    source_path: str
    build_system: str
    seed_corpus: str = "seeds"
    dictionary: str | None = None
    max_len: int = 4096
    timeout_ms: int = 1000
    memory_mb: int = 4096
    harnesses: list[Harness] = field(default_factory=list)
    build_commands: dict[str, list[list[str]]] = field(default_factory=dict)
    build_context: dict[str, Any] = field(default_factory=dict)
    harness_attempts: list[dict[str, Any]] = field(default_factory=list)
    coverage_goals: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetManifest":
        return cls(
            name=str(data["name"]),
            language=str(data.get("language", "c")),
            source_path=str(data["source_path"]),
            build_system=str(data.get("build_system", "raw")),
            seed_corpus=str(data.get("seed_corpus", "seeds")),
            dictionary=data.get("dictionary"),
            max_len=int(data.get("max_len", 4096)),
            timeout_ms=int(data.get("timeout_ms", 1000)),
            memory_mb=int(data.get("memory_mb", 4096)),
            harnesses=[Harness.from_dict(h) for h in data.get("harnesses", [])],
            build_commands={
                str(k): [list(cmd) for cmd in v]
                for k, v in dict(data.get("build_commands", {})).items()
            },
            build_context=dict(data.get("build_context", {})),
            harness_attempts=[dict(item) for item in data.get("harness_attempts", [])],
            coverage_goals=[dict(item) for item in data.get("coverage_goals", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "source_path": self.source_path,
            "build_system": self.build_system,
            "seed_corpus": self.seed_corpus,
            "dictionary": self.dictionary,
            "max_len": self.max_len,
            "timeout_ms": self.timeout_ms,
            "memory_mb": self.memory_mb,
            "harnesses": [h.to_dict() for h in self.harnesses],
            "build_commands": self.build_commands,
            "build_context": self.build_context,
            "harness_attempts": self.harness_attempts,
            "coverage_goals": self.coverage_goals,
        }

    def source_dir(self, workspace: Path) -> Path:
        p = resolve_under_workspace(workspace, self.source_path)
        assert p is not None
        return p

    def seed_dir(self, workspace: Path) -> Path:
        p = Path(self.seed_corpus)
        if p.is_absolute():
            return p.resolve()
        return (self.source_dir(workspace) / p).resolve()

    def dictionary_path(self, workspace: Path) -> Path | None:
        return resolve_under_workspace(workspace, self.dictionary)


def manifest_path(workspace: Path, name: str) -> Path:
    return workspace / "targets" / name / "target.json"


def load_manifest(workspace: Path, name: str) -> TargetManifest:
    path = manifest_path(workspace, name)
    if not path.exists():
        raise FuzzCtlError(f"target manifest not found: {path}")
    return TargetManifest.from_dict(read_json(path))


def save_manifest(workspace: Path, manifest: TargetManifest) -> Path:
    path = manifest_path(workspace, manifest.name)
    ensure_dir(path.parent)
    write_json(path, manifest.to_dict())
    return path


def create_manifest_from_path(workspace: Path, source: Path, name: str) -> tuple[TargetManifest, Detection]:
    detection = detect_target(source)
    if not detection.supported:
        raise FuzzCtlError(f"unsupported target: {detection.reason}")
    try:
        source_path = str(detection.path.relative_to(workspace.resolve()))
    except ValueError:
        source_path = str(detection.path)
    manifest = TargetManifest(
        name=name,
        language=detection.language,
        source_path=source_path,
        build_system=detection.build_system,
        seed_corpus="seeds",
        harnesses=[
            Harness(
                name="main_file",
                type="file",
                source=None,
                argv=["@@"],
                input_mode="file",
                profiles=["afl_asan_ubsan", "afl_lto_cmplog", "coverage"],
            )
        ],
    )
    return manifest, detection
