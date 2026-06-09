from __future__ import annotations

import getpass
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from .crash_value import analyze_target_crash_value
from .findings import target_findings
from .manifest import TargetManifest
from .monitor_snapshot import _snapshot
from .supervisor import active_fuzz_processes
from .tools import collect_tool_status
from .util import find_latest_run, read_json, rel_to


_PUBLIC_IP_CACHE: tuple[float, str | None] | None = None


def lan_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def public_ip() -> str | None:
    global _PUBLIC_IP_CACHE
    now = time.monotonic()
    if _PUBLIC_IP_CACHE and now - _PUBLIC_IP_CACHE[0] < 600:
        return _PUBLIC_IP_CACHE[1]
    value: str | None = None
    try:
        with urllib.request.urlopen("https://ifconfig.me/ip", timeout=1.5) as response:
            text = response.read(128).decode("utf-8", errors="replace").strip()
            if text and len(text) <= 64:
                value = text
    except Exception:
        value = None
    _PUBLIC_IP_CACHE = (now, value)
    return value


def _local_listener_ok(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _ufw_hint() -> str:
    try:
        proc = subprocess.run(
            ["ufw", "status"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "ufw status unavailable; cloud firewall or VPS security-group rules may still block inbound access."
    text = " ".join(proc.stdout.split())
    if not text:
        return "ufw returned no status; cloud firewall or VPS security-group rules may still block inbound access."
    if "need to be root" in text.lower():
        return "ufw status requires root here; cloud firewall or VPS security-group rules may still block inbound access."
    return text[:240]


def connectivity_info(host: str, port: int, token_enabled: bool = False) -> dict:
    private = lan_ip()
    public = public_ip()
    ssh_host = public or "<vps-public-ip>"
    user = getpass.getuser()
    if host in {"127.0.0.1", "localhost"}:
        private_url = "not exposed; bound to localhost"
        public_url = "not exposed; bound to localhost"
    else:
        private_url = f"http://{private}:{port}/" if host in {"0.0.0.0", "::", private} else f"http://{host}:{port}/"
        public_url = f"http://{public}:{port}/" if public else "unknown"
    return {
        "bind_host": host,
        "bind_port": port,
        "local_url": f"http://127.0.0.1:{port}/",
        "private_ip": private,
        "private_url": private_url,
        "public_ip": public,
        "public_url": public_url,
        "listener_ok": _local_listener_ok(port),
        "ssh_tunnel": f"ssh -L {port}:127.0.0.1:{port} {user}@{ssh_host}",
        "recommended_url": f"http://127.0.0.1:{port}/",
        "recommended_access": "SSH tunnel",
        "token_auth": "enabled" if token_enabled else "disabled",
        "firewall_hint": _ufw_hint(),
        "note": (
            "10.x/172.16-31.x/192.168.x addresses are private. If your browser is not inside the same VNet/VPN, "
            "use the SSH tunnel even when the dashboard is listening correctly on the VPS."
        ),
    }


def _safe(path: Path, limit: int = 12000) -> str:
    if not path.exists() or not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > limit:
        return text[-limit:]
    return text


def _target_runs(workspace: Path, name: str) -> list[str]:
    runs_dir = workspace / "runs" / name
    if not runs_dir.exists():
        return []
    return sorted([p.name for p in runs_dir.iterdir() if p.is_dir() and p.name != "background"])


def _target_hidden(data: dict) -> tuple[bool, str]:
    if data.get("dashboard_hidden"):
        return True, str(data.get("dashboard_hidden_reason", "hidden by manifest"))
    source_path = str(data.get("source_path", ""))
    if source_path.startswith("fixtures/") or "/fixtures/" in source_path:
        return True, "lab fixture"
    return False, ""


def _target_findings(workspace: Path, target: str) -> dict:
    return target_findings(workspace, target)


def _target_crash_value(workspace: Path, manifest: TargetManifest) -> dict:
    return analyze_target_crash_value(workspace, manifest, write=False)


def _targets(workspace: Path) -> tuple[list[dict], list[dict]]:
    out = []
    hidden = []
    targets_dir = workspace / "targets"
    if not targets_dir.exists():
        return out, hidden
    for manifest_path in sorted(targets_dir.glob("*/target.json")):
        try:
            data = read_json(manifest_path)
            manifest = TargetManifest.from_dict(data)
            name = data["name"]
            runs = _target_runs(workspace, name)
            current_run = find_latest_run(workspace, name).name if runs else None
            target = {
                "name": name,
                "manifest": data,
                "runs": runs,
                "latest_run": current_run,
                "findings": _target_findings(workspace, name),
                "crash_value": _target_crash_value(workspace, manifest),
            }
            is_hidden, reason = _target_hidden(data)
            if is_hidden:
                target["hidden_reason"] = reason
                hidden.append(target)
            else:
                out.append(target)
        except Exception as exc:
            out.append({"name": manifest_path.parent.name, "error": str(exc), "runs": []})
    return out, hidden


def _systemd_user_status(targets: list[dict] | None = None) -> dict:
    services = [
        "fuzz-dashboard.service",
        "fuzz-dashboard-lan.service",
        "fuzz-dashboard-tunnel.service",
    ]
    for target in targets or []:
        name = str(target.get("name") or "").strip()
        if not name:
            continue
        services.extend([f"fuzz-monitor@{name}.service", f"fuzz-campaign@{name}.service"])
    out: dict[str, str] = {}
    for service in services:
        try:
            proc = subprocess.run(
                ["systemctl", "--user", "is-active", service],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=1.5,
                check=False,
            )
            out[service] = proc.stdout.strip() or f"exit {proc.returncode}"
        except (OSError, subprocess.TimeoutExpired):
            out[service] = "unavailable"
    return out


def _supervisor_state(workspace: Path, targets: list[dict]) -> dict:
    out: dict[str, dict] = {}
    for target in targets:
        name = target.get("name")
        if not name:
            continue
        state_file = workspace / "state" / "supervisor" / f"{name}.json"
        stored = read_json(state_file) if state_file.exists() else {}
        out[name] = {
            "state": stored,
            "active_processes": active_fuzz_processes(workspace, name),
        }
    return out


def _run_summary(workspace: Path, target: str, run_id: str | None = None) -> dict:
    run_dir = workspace / "runs" / target / run_id if run_id else find_latest_run(workspace, target)
    summary = {"target": target, "run_id": run_dir.name, "path": str(run_dir)}
    triage = run_dir / "triage" / "unique_crashes.json"
    if triage.exists():
        summary["triage"] = read_json(triage)
    guidance = run_dir / "guidance" / "coverage-guidance.md"
    if guidance.exists():
        summary["guidance"] = _safe(guidance)
    blockers = run_dir / "guidance" / "harness-blockers.md"
    if blockers.exists():
        summary["harness_blockers"] = _safe(blockers)
    suspicious = run_dir / "guidance" / "suspicious-points.md"
    if suspicious.exists():
        summary["suspicious_points"] = _safe(suspicious)
    post_cycle = run_dir / "post_cycle" / "post_cycle.json"
    if post_cycle.exists():
        summary["post_cycle"] = read_json(post_cycle)
    advanced_triage = run_dir / "advanced_triage" / "advanced-triage.json"
    if advanced_triage.exists():
        summary["advanced_triage"] = read_json(advanced_triage)
    hybrid_symcc = run_dir / "hybrid" / "symcc" / "symcc-hybrid.json"
    if hybrid_symcc.exists():
        summary["hybrid_symcc"] = read_json(hybrid_symcc)
    coverage = run_dir / "coverage"
    if coverage.exists():
        reports = list(coverage.glob("*.report.txt"))
        summary["coverage_report"] = _safe(reports[0]) if reports else ""
    monitor = run_dir / "monitor" / "state.json"
    if monitor.exists():
        summary["monitor"] = read_json(monitor)
        summary["snapshot"] = summary["monitor"].get("last_snapshot", {})
    else:
        try:
            summary["snapshot"] = _snapshot(workspace, run_dir)
        except Exception:
            summary["snapshot"] = {}
    coverage_inputs = run_dir / "coverage" / "inputs.json"
    if coverage_inputs.exists():
        summary["coverage_inputs"] = read_json(coverage_inputs)
    corpus_sync = run_dir / "corpus_sync" / "corpus_sync.json"
    if corpus_sync.exists():
        summary["corpus_sync"] = read_json(corpus_sync)
    summary["logs"] = [rel_to(p, workspace) for p in sorted(run_dir.rglob("*.log"))[:20]]
    summary["reports"] = [rel_to(p, workspace) for p in sorted((run_dir / "reports").glob("*.md"))] if (run_dir / "reports").exists() else []
    return summary


def collect_dashboard_state(workspace: Path, bind_host: str, bind_port: int, token_enabled: bool) -> dict:
    tools = collect_tool_status(workspace)
    targets, hidden_targets = _targets(workspace)
    runs = []
    for target in targets:
        for run_id in target.get("runs", [])[-10:]:
            runs.append({"target": target["name"], "run_id": run_id})
    return {
        "workspace": str(workspace),
        "lan_ip": lan_ip(),
        "connectivity": connectivity_info(bind_host, bind_port, token_enabled),
        "systemd": _systemd_user_status(targets),
        "supervisor": _supervisor_state(workspace, targets),
        "tools": tools,
        "targets": targets,
        "hidden_targets": hidden_targets,
        "runs": runs[-30:],
    }
