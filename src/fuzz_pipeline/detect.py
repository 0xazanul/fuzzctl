from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


C_EXTS = {".c", ".h"}
CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
IGNORED_DIRS = {".git", "build", "dist", "runs", "node_modules", "target"}


@dataclass
class Detection:
    path: Path
    supported: bool
    language: str
    build_system: str
    c_files: int
    cpp_files: int
    reason: str

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "supported": self.supported,
            "language": self.language,
            "build_system": self.build_system,
            "c_files": self.c_files,
            "cpp_files": self.cpp_files,
            "reason": self.reason,
        }


def detect_target(path: Path) -> Detection:
    root = path.expanduser().resolve()
    if not root.exists():
        return Detection(root, False, "unknown", "unknown", 0, 0, "path does not exist")
    if root.is_file():
        files = [root]
        marker_root = root.parent
    else:
        files = []
        marker_root = root
        for p in root.rglob("*"):
            if any(part in IGNORED_DIRS for part in p.parts):
                continue
            if p.is_file():
                files.append(p)

    c_files = sum(1 for p in files if p.suffix.lower() in C_EXTS)
    cpp_files = sum(1 for p in files if p.suffix.lower() in CPP_EXTS)
    if cpp_files:
        language = "c++"
    elif c_files:
        language = "c"
    else:
        return Detection(root, False, "unknown", "unknown", 0, 0, "no C/C++ source files found")

    if (marker_root / "CMakeLists.txt").exists():
        build_system = "cmake"
    elif (marker_root / "Makefile").exists() or (marker_root / "makefile").exists():
        build_system = "make"
    elif (marker_root / "configure").exists():
        build_system = "autotools"
    elif (marker_root / "meson.build").exists():
        build_system = "meson"
    else:
        build_system = "raw"

    return Detection(root, True, language, build_system, c_files, cpp_files, "supported C/C++ target")

