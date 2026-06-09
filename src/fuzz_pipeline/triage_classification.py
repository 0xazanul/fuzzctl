from __future__ import annotations

import re


ASAN_RE = re.compile(r"ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+)")
LSAN_RE = re.compile(r"ERROR: LeakSanitizer: detected memory leaks")
UBSAN_RE = re.compile(r"runtime error: ([^\n]+)")
STACK_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(.+)$", re.MULTILINE)


def crash_type(output: str, returncode: int) -> str:
    match = ASAN_RE.search(output)
    if match:
        return match.group(1).lower()
    if LSAN_RE.search(output):
        return "memory-leak"
    match = UBSAN_RE.search(output)
    if match:
        text = match.group(1).lower()
        if "null pointer" in text or "null" in text:
            return "null-pointer-undefined-behavior"
        if "signed integer overflow" in text:
            return "signed-integer-overflow"
        return "undefined-behavior"
    if "SEGV" in output or returncode in {-11, 139}:
        return "segv"
    if returncode == 124:
        return "timeout"
    return "unknown-crash"


def access_kind(output: str) -> str:
    if re.search(r"\bWRITE of size\b|\bWRITE memory access\b", output):
        return "write"
    if re.search(r"\bREAD of size\b|\bREAD memory access\b", output):
        return "read"
    return "unknown"


def severity(crash_kind: str, access: str, output: str) -> tuple[str, str]:
    crash_kind = crash_kind.lower()
    critical = {
        "heap-use-after-free",
        "double-free",
        "bad-free",
        "attempting-free-on-address-which-was-not-malloc()-ed",
        "alloc-dealloc-mismatch",
    }
    if crash_kind in critical:
        return "CRITICAL", "memory lifetime corruption with realistic exploitation potential"
    if "buffer-overflow" in crash_kind and access == "write":
        return "CRITICAL", "attacker-controlled out-of-bounds write"
    if crash_kind in {"heap-use-after-free", "stack-use-after-return"} and access == "write":
        return "CRITICAL", "attacker-controlled write through invalid lifetime"
    if "buffer-overflow" in crash_kind and access == "read":
        return "HIGH", "out-of-bounds read may disclose memory or drive later corruption"
    if "use-after" in crash_kind:
        return "HIGH", "use-after-free/read requires exploitability analysis"
    if crash_kind == "signed-integer-overflow" and re.search(r"alloc|malloc|calloc|realloc|new", output, re.I):
        return "HIGH", "integer overflow appears near allocation or sizing logic"
    if crash_kind == "memory-leak":
        return "LOW", "memory leak; security impact needs proof of attacker-amplified resource exhaustion"
    if "null" in crash_kind or crash_kind == "segv":
        return "MEDIUM", "crash/DoS by default; stronger impact needs boundary analysis"
    if crash_kind == "timeout":
        return "MEDIUM", "potential denial of service through excessive processing"
    return "LOW", "stability issue unless impact analysis proves memory safety risk"


def stack_state(output: str, crash_kind: str) -> str:
    frames = []
    for match in STACK_RE.finditer(output):
        frame = re.sub(r"\s+at\s+.*", "", match.group(1)).strip()
        frame = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", frame)
        frames.append(frame)
        if len(frames) == 3:
            break
    if not frames:
        token = re.search(r"dedup_token:\s*([0-9a-fA-F]+)", output)
        if token:
            return f"{crash_kind}:{token.group(1)}"
        return crash_kind
    return crash_kind + ":" + "|".join(frames)
