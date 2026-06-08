from __future__ import annotations

import json
from pathlib import Path

from .manifest import TargetManifest
from .triage import minimize_run, triage_run
from .util import ensure_dir, find_latest_run, rel_to


def _read_trace(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    return "\n".join(lines[:120])


def report_run(workspace: Path, manifest: TargetManifest, run_id: str | None = None) -> Path:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    triage_file = run_dir / "triage" / "unique_crashes.json"
    if not triage_file.exists():
        triage_run(workspace, manifest, run_id)
    data = json.loads(triage_file.read_text(encoding="utf-8"))
    if any("minimized_path" not in item for item in data.get("crashes", [])):
        minimize_run(workspace, manifest, run_id)
        data = json.loads(triage_file.read_text(encoding="utf-8"))

    out = ensure_dir(run_dir / "reports")
    index_lines = [f"# Fuzzing Report: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace)}`", ""]
    crashes = data.get("crashes", [])
    if not crashes:
        index_lines.append("No crashes were found.")
    for item in crashes:
        title = f"{item['severity']} {item['type']} in {item['harness']} ({item['id']})"
        report_path = out / f"{item['id']}.md"
        trace = _read_trace(item.get("trace_path", ""))
        cmd = " ".join(item.get("repro_cmd", []))
        body = [
            f"# {title}",
            "",
            f"Severity: **{item['severity']}**",
            f"Crash type: `{item['type']}`",
            f"Access: `{item.get('access', 'unknown')}`",
            f"Harness: `{item['harness']}`",
            f"Duplicates: `{item.get('duplicates', 0)}`",
            "",
            "## Impact",
            "",
            item.get("impact", "Impact not classified."),
            "",
            "Crash alone is not treated as sufficient. This report requires the minimized input, sanitizer trace, and a target-specific explanation of attacker reachability before submission.",
            "",
            "## Reproduction",
            "",
            "```bash",
            cmd,
            "```",
            "",
            f"Minimized input: `{rel_to(Path(item['minimized_path']), workspace)}`",
            f"Minimized size: `{item.get('minimized_size', '?')}` bytes",
            "",
            "Base64 reproducer:",
            "",
            "```text",
            item.get("reproducer_base64", ""),
            "```",
            "",
            "## Sanitizer Trace",
            "",
            "```text",
            trace,
            "```",
            "",
            "## Submission Checklist",
            "",
            "- [ ] Confirm untrusted input can reach this harness path.",
            "- [ ] Explain control over size, offset, contents, or lifetime.",
            "- [ ] Confirm whether the crash reproduces on the target product build.",
            "- [ ] For null deref/SEGV, prove more than DoS before claiming high impact.",
        ]
        report_path.write_text("\n".join(body) + "\n", encoding="utf-8")
        index_lines.append(f"- [{title}]({report_path.name})")
    index = out / "index.md"
    index.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    print(f"reports: {rel_to(out, workspace)}")
    return out

