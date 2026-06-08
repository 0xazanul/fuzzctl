from __future__ import annotations

import html
import getpass
import hmac
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .detect import detect_target
from .launch import launch_repo
from .manifest import load_manifest
from .monitor import _snapshot, monitor_once
from .supervisor import active_fuzz_processes
from .tools import collect_tool_status
from .util import FuzzCtlError, default_workspace, find_latest_run, human_bytes, read_json, rel_to


CSS = """
:root{color-scheme:light;--bg:#f6f8fc;--surface:#fff;--surface2:#f7f9fc;--surface3:#eef4ff;--text:#1f1f1f;--muted:#667085;--line:#e4e7ec;--line2:#d0d5dd;--primary:#1a73e8;--primary2:#1557b0;--primaryText:#fff;--ok:#16833a;--okBg:#eaf6ee;--warn:#a75d00;--warnBg:#fff6dc;--bad:#c5221f;--badBg:#fdebea;--info:#185abc;--infoBg:#edf4ff;--shadow:0 1px 2px rgba(16,24,40,.05);--shadow2:0 16px 40px rgba(16,24,40,.10)}
:root[data-theme="dark"]{color-scheme:dark;--bg:#101318;--surface:#171b22;--surface2:#1d232d;--surface3:#172b46;--text:#f1f3f4;--muted:#a9b1bd;--line:#2b333f;--line2:#3b4554;--primary:#8ab4f8;--primary2:#aecbfa;--primaryText:#111418;--ok:#81c995;--okBg:#142f20;--warn:#fdd663;--warnBg:#352911;--bad:#f28b82;--badBg:#351d1c;--info:#8ab4f8;--infoBg:#172b46;--shadow:0 1px 2px rgba(0,0,0,.22);--shadow2:0 16px 44px rgba(0,0,0,.32)}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Google Sans","Inter",system-ui,-apple-system,Segoe UI,sans-serif;letter-spacing:0}a{color:var(--primary2);text-decoration:none}a:hover{text-decoration:underline}
.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:18px;min-height:60px;padding:0 28px;background:color-mix(in srgb,var(--surface) 88%,transparent);border-bottom:1px solid var(--line);backdrop-filter:saturate(180%) blur(16px)}.brand{display:flex;align-items:center;gap:11px;min-width:236px;color:var(--text)}.brand:hover{text-decoration:none}.brand-mark{display:grid;place-items:center;width:32px;height:32px;border-radius:8px;background:var(--text);color:var(--surface);font-weight:850;font-size:12px}.brand-name{display:block;font-size:15px;font-weight:760}.brand-sub{display:block;font-size:11px;color:var(--muted);margin-top:1px}.topnav{display:flex;gap:4px;flex:1}.topnav a{color:var(--muted);padding:7px 10px;border-radius:6px;font-weight:650;font-size:13px}.topnav a:hover{background:var(--surface2);color:var(--text);text-decoration:none}.theme-toggle{width:auto;flex:0 0 auto;display:inline-flex;align-items:center;border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:999px;padding:7px 11px;font-weight:750;font-size:12px}
.page{max-width:1440px;margin:0 auto;padding:26px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin:0 0 18px}.eyebrow{font-size:11px;color:var(--primary2);font-weight:850;text-transform:uppercase;letter-spacing:.08em}.page-heading h1{margin:3px 0 0;font-size:26px;line-height:1.15;font-weight:760}.sub{color:var(--muted);margin-top:4px}h1,h2,h3{letter-spacing:0}h2{margin:0;font-size:15px;line-height:1.25;font-weight:760}h3{margin:0 0 8px;font-size:12px;color:var(--muted);font-weight:800;text-transform:uppercase;letter-spacing:.04em}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px}.section-head p{margin:4px 0 0;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px}.card{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:16px;box-shadow:var(--shadow)}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span12{grid-column:span 12}
.metric{font-size:28px;line-height:1.05;font-weight:780;margin-top:8px}.metric.small{font-size:15px;overflow-wrap:anywhere}.metric-label{color:var(--muted);font-size:12px;margin-top:5px}.metric-card{min-height:116px}.muted{color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.info{color:var(--info)}.status{display:inline-flex;align-items:center;gap:6px;border:1px solid transparent;border-radius:999px;padding:3px 9px;font-size:11px;font-weight:850;white-space:nowrap}.status:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.status.ok{background:var(--okBg);color:var(--ok)}.status.warn{background:var(--warnBg);color:var(--warn)}.status.bad{background:var(--badBg);color:var(--bad)}.status.info{background:var(--infoBg);color:var(--info)}.status.neutral{background:var(--surface2);color:var(--muted);border-color:var(--line)}
.campaign-card{background:linear-gradient(180deg,color-mix(in srgb,var(--surface) 98%,var(--surface3)),var(--surface));border:1px solid var(--line);border-radius:8px;padding:20px;box-shadow:var(--shadow2)}.campaign-title{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:18px}.campaign-title h2{font-size:20px}.campaign-title p{margin:5px 0 0;color:var(--muted)}.campaign-metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--surface)}.campaign-metric{padding:16px;border-right:1px solid var(--line)}.campaign-metric:last-child{border-right:0}.campaign-metric .metric{font-size:26px}.campaign-metric h3{margin-bottom:10px}
.pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:4px 9px;margin:2px;background:var(--surface2);color:var(--muted);font-weight:750;font-size:12px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px;background:var(--surface)}table{width:100%;border-collapse:collapse;min-width:520px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);background:var(--surface2);font-size:11px;text-transform:uppercase;letter-spacing:.05em;font-weight:850}tr:last-child td{border-bottom:0}td{overflow-wrap:anywhere}code,pre{font-family:"Roboto Mono","SFMono-Regular",Consolas,monospace;background:var(--surface2);border:1px solid var(--line);border-radius:6px}code{padding:2px 6px;font-size:12px}pre{padding:14px;overflow:auto;max-height:520px;white-space:pre-wrap;overflow-wrap:anywhere}
label{display:block;margin:12px 0 6px;color:var(--muted);font-weight:800;font-size:11px;text-transform:uppercase;letter-spacing:.04em}input,select{width:100%;background:var(--surface);border:1px solid var(--line2);border-radius:6px;color:var(--text);padding:10px 11px;outline:none}input:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--primary) 16%,transparent)}button,.button{display:inline-flex;align-items:center;justify-content:center;background:var(--primary);border:0;color:var(--primaryText);border-radius:6px;padding:10px 14px;font-weight:800;cursor:pointer;min-height:38px;text-decoration:none}button:hover,.button:hover{text-decoration:none;filter:brightness(.98)}button.secondary,.button.secondary{background:var(--surface);border:1px solid var(--line2);color:var(--text)}
.row{display:flex;gap:12px;align-items:end}.row>*{flex:1}.small{font-size:12px}.list{display:grid;gap:9px}.item{display:block;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--surface)}.item:hover{border-color:var(--line2);box-shadow:var(--shadow)}.target-item{display:flex;align-items:center;justify-content:space-between;gap:12px}.target-name{font-weight:800}.target-meta{color:var(--muted);font-size:12px;margin-top:2px}.breadcrumb{margin:0 0 18px;color:var(--muted)}.breadcrumb a{font-weight:700}.empty{padding:18px;color:var(--muted);background:var(--surface2);border:1px dashed var(--line2);border-radius:8px}
details.card{padding:0;overflow:hidden}details.card summary{list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 16px;cursor:pointer}details.card summary::-webkit-details-marker{display:none}details.card summary:after{content:"Open";font-size:11px;color:var(--muted);font-weight:850;text-transform:uppercase;letter-spacing:.05em}details[open].card summary:after{content:"Close"}details.card .details-body{padding:0 16px 16px}
.nowrap{white-space:nowrap}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media(max-width:1000px){.span3,.span4,.span5,.span6,.span7,.span8{grid-column:span 12}.campaign-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.campaign-metric{border-bottom:1px solid var(--line)}.campaign-metric:nth-child(2n){border-right:0}.campaign-metric:last-child{border-bottom:0}.page-heading{display:block}.topbar{align-items:flex-start;flex-wrap:wrap;height:auto;padding:12px 16px}.brand{min-width:0;flex:1}.topnav{order:3;width:100%;overflow:auto}.page{padding:18px}.row{display:block}.row>*{margin-bottom:10px}.target-item{align-items:flex-start;display:block}.theme-toggle{margin-left:auto}}
@media(max-width:620px){.topnav{display:none}.topbar{align-items:center}.campaign-metrics{grid-template-columns:1fr}.campaign-metric{border-right:0;border-bottom:1px solid var(--line)}.campaign-metric:last-child{border-bottom:0}.metric{font-size:24px}.campaign-title{display:block}.campaign-title .status{margin-top:10px}}
"""

THEME_SCRIPT_HEAD = """
<script>
(function(){
  try {
    var saved = localStorage.getItem("fuzzTheme");
    var theme = saved || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
</script>
"""

THEME_SCRIPT_BODY = """
<script>
(function(){
  function label(theme){ return theme === "dark" ? "Light mode" : "Dark mode"; }
  var button = document.getElementById("themeToggle");
  if (!button) return;
  var current = document.documentElement.getAttribute("data-theme") || "light";
  button.textContent = label(current);
  button.addEventListener("click", function(){
    var next = (document.documentElement.getAttribute("data-theme") || "light") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("fuzzTheme", next); } catch (e) {}
    button.textContent = label(next);
  });
})();
</script>
"""

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
    target_runs = workspace / "runs" / target
    findings: list[dict] = []
    if not target_runs.exists():
        return {"total": 0, "reproducible": 0, "high_or_critical": 0, "findings": []}
    for triage_path in sorted(target_runs.glob("*/triage/unique_crashes.json")):
        try:
            data = read_json(triage_path)
        except Exception:
            continue
        run_dir = triage_path.parents[1]
        for crash in data.get("crashes", []):
            item = dict(crash)
            item["run_id"] = run_dir.name
            item["run_path"] = rel_to(run_dir, workspace)
            report_path = run_dir / "reports" / f"{item.get('id')}.md"
            if report_path.exists():
                item["report"] = rel_to(report_path, workspace)
            findings.append(item)
    triaged_count = len(findings)
    reproducible = [item for item in findings if item.get("reproducible")]
    high_or_critical = [
        item for item in reproducible
        if str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    reproducible.sort(
        key=lambda item: (
            severity_rank.get(str(item.get("severity", "")).upper(), -1),
            str(item.get("run_id", "")),
        ),
        reverse=True,
    )
    return {
        "total": len(reproducible),
        "triaged": triaged_count,
        "reproducible": len(reproducible),
        "high_or_critical": len(high_or_critical),
        "findings": reproducible,
    }


def _targets(workspace: Path) -> tuple[list[dict], list[dict]]:
    out = []
    hidden = []
    targets_dir = workspace / "targets"
    if not targets_dir.exists():
        return out, hidden
    for manifest_path in sorted(targets_dir.glob("*/target.json")):
        try:
            data = read_json(manifest_path)
            name = data["name"]
            runs = _target_runs(workspace, name)
            current_run = find_latest_run(workspace, name).name if runs else None
            target = {
                "name": name,
                "manifest": data,
                "runs": runs,
                "latest_run": current_run,
                "findings": _target_findings(workspace, name),
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


def _systemd_user_status() -> dict:
    services = [
        "fuzz-dashboard.service",
        "fuzz-dashboard-lan.service",
        "fuzz-monitor@mdnsresponder.service",
        "fuzz-campaign@mdnsresponder.service",
    ]
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


def state(workspace: Path) -> dict:
    tools = collect_tool_status(workspace)
    targets, hidden_targets = _targets(workspace)
    runs = []
    for target in targets:
        for run_id in target.get("runs", [])[-10:]:
            runs.append({"target": target["name"], "run_id": run_id})
    return {
        "workspace": str(workspace),
        "lan_ip": lan_ip(),
        "connectivity": connectivity_info(Handler.bind_host, Handler.bind_port, bool(Handler.auth_token)),
        "systemd": _systemd_user_status(),
        "supervisor": _supervisor_state(workspace, targets),
        "tools": tools,
        "targets": targets,
        "hidden_targets": hidden_targets,
        "runs": runs[-30:],
    }


def badge(label: object, tone: str = "neutral") -> str:
    safe_tone = tone if tone in {"ok", "warn", "bad", "info", "neutral"} else "neutral"
    return f"<span class='status {safe_tone}'>{html.escape(str(label))}</span>"


def service_tone(status: object) -> str:
    value = str(status)
    if value == "active":
        return "ok"
    if value in {"failed", "not-found"}:
        return "bad"
    if value in {"inactive", "deactivating", "activating"}:
        return "warn"
    return "neutral"


def crash_tone(severity: object) -> str:
    value = str(severity).upper()
    if value in {"CRITICAL", "HIGH"}:
        return "bad"
    if value == "MEDIUM":
        return "warn"
    if value in {"LOW", "INFO"}:
        return "info"
    return "neutral"


def metric_card(title: str, value: object, caption: str, tone: str = "") -> str:
    tone_class = f" {tone}" if tone else ""
    return (
        "<section class='card metric-card span3'>"
        f"<div class='section-head'><h2>{html.escape(title)}</h2></div>"
        f"<div class='metric{tone_class}'>{html.escape(str(value))}</div>"
        f"<div class='metric-label'>{html.escape(caption)}</div>"
        "</section>"
    )


def table_wrap(table: str) -> str:
    return f"<div class='table-wrap'>{table}</div>"


def page(title: str, body: str) -> bytes:
    safe_title = html.escape(title)
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{safe_title}</title>
  {THEME_SCRIPT_HEAD}
  <style>{CSS}</style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/" aria-label="Dashboard home">
      <span class="brand-mark">FP</span>
      <span><span class="brand-name">Fuzz Pipeline</span><span class="brand-sub">Memory-bug operations</span></span>
    </a>
    <nav class="topnav" aria-label="Primary navigation">
      <a href="/">Overview</a>
      <a href="/api/state">API State</a>
      <a href="/api/connectivity">Connectivity</a>
    </nav>
    <button id="themeToggle" class="theme-toggle" type="button" aria-label="Toggle color theme">Theme</button>
  </header>
  <main class="page">
    <div class="page-heading">
      <div>
        <div class="eyebrow">Fuzzing Control Plane</div>
        <h1>{safe_title}</h1>
      </div>
    </div>
    {body}
  </main>
  {THEME_SCRIPT_BODY}
</body>
</html>""".encode()


def render_home(workspace: Path) -> bytes:
    s = state(workspace)
    tools = s["tools"]
    conn = s["connectivity"]
    hidden_count = len(s.get("hidden_targets", []))
    installed = sum(1 for t in tools["tools"] if t["installed"])
    total = len(tools["tools"])
    docker = "ok" if tools["docker_access_ok"] else "blocked"
    core_pattern = tools.get("core_pattern") or "unknown"
    core_cls = "warn" if tools.get("core_pattern_warning") else "ok"
    target_cards = []
    for t in s["targets"]:
        latest = t.get("latest_run")
        target_name = html.escape(t["name"])
        link = f"<a href='/target/{target_name}' class='target-name'>{target_name}</a>"
        run = f"<a href='/run/{target_name}/{html.escape(latest)}'>{html.escape(latest)}</a>" if latest else "<span class='muted'>no runs</span>"
        harnesses = len(t.get("manifest", {}).get("harnesses", []))
        confirmed = int((t.get("findings") or {}).get("reproducible", 0) or 0)
        finding_label = "finding" if confirmed == 1 else "findings"
        target_cards.append(
            "<div class='item target-item'>"
            f"<div>{link}<div class='target-meta'>{harnesses} harnesses, latest {run}</div></div>"
            f"{badge(f'{confirmed} {finding_label}', 'bad' if confirmed else 'info')}"
            "</div>"
        )
    body = f"""
<div class="grid">
  {render_active_campaigns(workspace, s['targets'], s['supervisor'])}
  {render_findings_panel(s['targets'])}
  {metric_card('Toolchain', f'{installed}/{total}', 'curated tools available', 'ok' if installed == total else 'warn')}
  {metric_card('Docker', docker, tools.get('docker_access_error') or 'ready', 'ok' if docker == 'ok' else 'warn')}
  {metric_card('Production Targets', len(s['targets']), f'{hidden_count} lab fixtures hidden')}
  {metric_card('Core Dumps', 'piped' if tools.get('core_pattern_warning') else 'ok', core_pattern[:80], core_cls)}
  <section class="card span7">
    <div class="section-head"><div><h2>Production Targets</h2><p>Only real fuzzing targets are listed here. Lab fixtures are hidden from operations.</p></div>{badge(f'{hidden_count} hidden', 'neutral') if hidden_count else ''}</div>
    <div class="list">{''.join(target_cards) or '<div class="empty">No targets yet.</div>'}</div>
  </section>
  <section class="card span5">
    <div class="section-head"><div><h2>Launch Repository</h2><p>Onboard a new C/C++ target without claiming success before a harness exists.</p></div></div>
    <form method="post" action="/launch">
      <label>Git URL or local path</label><input name="source" placeholder="https://github.com/org/repo.git or /path/to/repo" required>
      <div class="row"><div><label>Name</label><input name="name" placeholder="optional"></div><div><label>Smoke seconds</label><input name="smoke" value="0"></div></div>
      <button type="submit">Start onboarding</button>
    </form>
  </section>
  <details class="card span12">
    <summary><div><h2>Connectivity</h2><p>Browser access, tunnel command, and LAN exposure state.</p></div>{badge(conn.get('token_auth', 'unknown'), 'ok' if conn.get('token_auth') == 'enabled' else 'warn')}</summary>
    <div class="details-body">{render_connectivity(conn)}</div>
  </details>
  <details class="card span12">
    <summary><div><h2>Recovery Services</h2><p>Systemd services and reboot-safe supervisor status.</p></div>{badge('healthy', 'ok') if all(v == 'active' for v in s['systemd'].values()) else badge('check', 'warn')}</summary>
    <div class="details-body">
      {render_supervisor_table(s['supervisor'])}
      <br>
      {render_systemd_table(s['systemd'])}
    </div>
  </details>
  <details class="card span12">
    <summary><div><h2>Tool Inventory</h2><p>Installed fuzzing, sanitizer, build, and analysis tools.</p></div>{badge(f'{installed}/{total}', 'ok' if installed == total else 'warn')}</summary>
    <div class="details-body">{render_tools_table(tools)}</div>
  </details>
</div>
"""
    return page("Fuzz Pipeline Dashboard", body)


def render_connectivity(conn: dict) -> str:
    rows = [
        ("Recommended access", conn["recommended_access"]),
        ("Browser URL after tunnel", conn["recommended_url"]),
        ("Bind", f"{conn['bind_host']}:{conn['bind_port']}"),
        ("Private URL", conn["private_url"]),
        ("Public URL", conn["public_url"]),
        ("Token auth", conn["token_auth"]),
        ("Local listener", "ok" if conn["listener_ok"] else "not reachable from localhost"),
        ("Firewall hint", conn["firewall_hint"]),
    ]
    body = "<table><tr><th>Check</th><th>Value</th></tr>"
    for label, value in rows:
        if label == "Local listener":
            value_html = badge(value, "ok" if conn["listener_ok"] else "bad")
        elif label == "Token auth":
            value_html = badge(value, "ok" if value == "enabled" else "warn")
        else:
            value_html = html.escape(str(value))
        body += f"<tr><td>{html.escape(label)}</td><td>{value_html}</td></tr>"
    body = table_wrap(body + "</table>")
    body += f"<p class='muted'>{html.escape(conn['note'])}</p>"
    body += f"<h3>SSH Tunnel</h3><pre>{html.escape(conn['ssh_tunnel'])}</pre>"
    return body


def render_tools_table(tools: dict) -> str:
    rows = []
    for t in tools["tools"]:
        cls = "ok" if t["installed"] else ("bad" if t["required"] else "warn")
        status = "ok" if t["installed"] else "missing"
        need = "required" if t["required"] else "optional"
        rows.append(
            f"<tr><td>{badge(status, cls)}</td><td>{html.escape(t['name'])}</td>"
            f"<td>{badge(need, 'bad' if t['required'] and not t['installed'] else 'neutral')}</td>"
            f"<td><code>{html.escape(t.get('path') or '-')}</code></td></tr>"
        )
    return table_wrap("<table><tr><th>Status</th><th>Tool</th><th>Need</th><th>Path</th></tr>" + "".join(rows) + "</table>")


def render_systemd_table(systemd: dict) -> str:
    rows = []
    for name, status in systemd.items():
        rows.append(f"<tr><td><code>{html.escape(name)}</code></td><td>{badge(status, service_tone(status))}</td></tr>")
    return table_wrap("<table><tr><th>Service</th><th>Status</th></tr>" + "".join(rows) + "</table>")


def render_supervisor_table(supervisor: dict) -> str:
    rows = []
    for target, data in sorted(supervisor.items()):
        state = data.get("state") or {}
        status = state.get("status", "unknown")
        active_count = len(data.get("active_processes") or [])
        cls = "ok" if status in {"running_campaign", "waiting_existing_campaign"} else ("warn" if status != "unknown" else "neutral")
        detail = ""
        if state.get("run_ids"):
            detail = ", ".join(str(item) for item in state.get("run_ids", []))
        elif state.get("next_check_seconds"):
            detail = f"next check {state.get('next_check_seconds')}s"
        rows.append(
            f"<tr><td>{html.escape(str(target))}</td><td>{badge(status, cls)}</td>"
            f"<td>{active_count}</td><td>{html.escape(detail)}</td></tr>"
        )
    return table_wrap("<table><tr><th>Target</th><th>Status</th><th>Active Processes</th><th>Detail</th></tr>" + "".join(rows) + "</table>")


def render_findings_panel(targets: list[dict]) -> str:
    all_findings = []
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for target in targets:
        target_name = str(target.get("name"))
        for finding in (target.get("findings") or {}).get("findings", []):
            all_findings.append((target_name, finding))
    all_findings.sort(
        key=lambda item: (
            severity_rank.get(str(item[1].get("severity", "")).upper(), -1),
            str(item[1].get("run_id", "")),
        ),
        reverse=True,
    )
    rows = []
    for target_name, finding in all_findings[:20]:
        severity = str(finding.get("severity", "INFO"))
        report = finding.get("report")
        finding_id = str(finding.get("id", "unknown"))
        report_link = (
            f"<a href='/file/{html.escape(str(report))}'><code>{html.escape(finding_id)}</code></a>"
            if report else f"<code>{html.escape(finding_id)}</code>"
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(target_name)}</td>"
            f"<td>{badge(severity, crash_tone(severity))}</td>"
            f"<td>{html.escape(str(finding.get('type', 'unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('harness', 'unknown')))}</td>"
            f"<td>{report_link}</td>"
            f"<td><a href='/run/{html.escape(target_name)}/{html.escape(str(finding.get('run_id', '')))}'>{html.escape(str(finding.get('run_id', '')))}</a></td>"
            "</tr>"
        )
    if not rows:
        return "<section class='card span12'><div class='section-head'><div><h2>Confirmed Findings</h2><p>No sanitizer-reproducible crashes have been triaged yet.</p></div>{}</div></section>".format(badge("0", "neutral"))
    count_note = "" if len(all_findings) <= len(rows) else f" Showing first {len(rows)}."
    return (
        "<section class='card span12'>"
        "<div class='section-head'><div><h2>Confirmed Findings</h2>"
        f"<p>Target-wide sanitizer-reproducible crashes, including smoke and libFuzzer runs.{html.escape(count_note)}</p></div>"
        f"{badge(str(len(all_findings)), 'bad')}"
        "</div>"
        + table_wrap("<table><tr><th>Target</th><th>Severity</th><th>Type</th><th>Harness</th><th>ID / Report</th><th>Run</th></tr>" + "".join(rows) + "</table>")
        + "</section>"
    )


def render_active_campaigns(workspace: Path, targets: list[dict], supervisor: dict) -> str:
    cards = []
    for target in targets:
        name = str(target.get("name"))
        run_id = target.get("latest_run")
        active = (supervisor.get(name) or {}).get("active_processes") or []
        afl_workers = [p for p in active if p.get("kind") == "afl-fuzz"]
        run_link = ""
        execs = paths = raw = "0"
        worker_text = f"{len(afl_workers)} AFL++"
        findings = target.get("findings") or {}
        confirmed = int(findings.get("reproducible", 0) or 0)
        high_or_critical = int(findings.get("high_or_critical", 0) or 0)
        if run_id:
            try:
                snap = _snapshot(workspace, workspace / "runs" / name / str(run_id))
                execs = f"{int(snap.get('execs', 0)):,}"
                paths = f"{int(snap.get('paths', 0)):,}"
                raw = str(snap.get("raw_crashes", 0))
                if snap.get("workers_expected"):
                    worker_text = f"{snap.get('workers_alive', 0)}/{snap.get('workers_expected', 0)} AFL++"
            except Exception:
                pass
            run_link = f"<a href='/run/{html.escape(name)}/{html.escape(str(run_id))}'>{html.escape(str(run_id))}</a>"
        else:
            run_link = "<span class='muted'>no runs</span>"
        status = (supervisor.get(name) or {}).get("state", {}).get("status", "unknown")
        cards.append(
            "<section class='campaign-card span12'>"
            "<div class='campaign-title'>"
            f"<div><h2>{html.escape(name)}</h2><p>Active run {run_link}</p></div>"
            f"{badge(status, 'ok' if status in {'running_campaign', 'waiting_existing_campaign'} else 'neutral')}"
            "</div>"
            "<div class='campaign-metrics'>"
            f"<div class='campaign-metric'><h3>Workers</h3><div class='metric'>{html.escape(worker_text)}</div><div class='metric-label'>long-running AFL++ capacity</div></div>"
            f"<div class='campaign-metric'><h3>Execs</h3><div class='metric'>{execs}</div><div class='metric-label'>total AFL++ executions</div></div>"
            f"<div class='campaign-metric'><h3>Paths</h3><div class='metric'>{paths}</div><div class='metric-label'>coverage-discovering queue paths</div></div>"
            f"<div class='campaign-metric'><h3>Confirmed Findings</h3><div class='metric {'bad' if confirmed else ''}'>{confirmed}</div><div class='metric-label'>{high_or_critical} high or critical</div></div>"
            f"<div class='campaign-metric'><h3>Active Raw</h3><div class='metric {'bad' if raw != '0' else ''}'>{html.escape(raw)}</div><div class='metric-label'>current-run crash artifacts</div></div>"
            "</div>"
            "</section>"
        )
    return "".join(cards) if cards else "<section class='card span12'><div class='empty'>No production fuzzing targets configured.</div></section>"


def render_target(workspace: Path, name: str) -> bytes:
    manifest = load_manifest(workspace, name)
    runs_dir = workspace / "runs" / name
    runs = sorted([p.name for p in runs_dir.iterdir() if p.is_dir() and p.name != "background"]) if runs_dir.exists() else []
    current_run = find_latest_run(workspace, name).name if runs else None
    findings = _target_findings(workspace, name)
    finding_rows = []
    for finding in findings.get("findings", [])[:10]:
        severity = str(finding.get("severity", "INFO"))
        report = finding.get("report")
        finding_id = str(finding.get("id", "unknown"))
        report_link = (
            f"<a href='/file/{html.escape(str(report))}'><code>{html.escape(finding_id)}</code></a>"
            if report else f"<code>{html.escape(finding_id)}</code>"
        )
        finding_rows.append(
            "<tr>"
            f"<td>{badge(severity, crash_tone(severity))}</td>"
            f"<td>{html.escape(str(finding.get('type', 'unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('harness', 'unknown')))}</td>"
            f"<td>{report_link}</td>"
            f"<td><a href='/run/{html.escape(name)}/{html.escape(str(finding.get('run_id', '')))}'>{html.escape(str(finding.get('run_id', '')))}</a></td>"
            "</tr>"
        )
    harness_rows = []
    for h in manifest.harnesses:
        harness_rows.append(
            f"<tr><td><b>{html.escape(h.name)}</b></td><td>{badge(h.type, 'info')}</td>"
            f"<td><code>{html.escape(str(h.source))}</code></td><td><code>{html.escape(' '.join(h.argv))}</code></td></tr>"
        )
    ordered_runs = []
    if current_run:
        ordered_runs.append(current_run)
    ordered_runs.extend([r for r in reversed(runs[-30:]) if r != current_run])
    run_items = ""
    for r in ordered_runs:
        is_current = r == current_run
        run_items += (
            "<div class='item target-item'>"
            f"<div><a class='target-name' href='/run/{html.escape(name)}/{html.escape(r)}'>{html.escape(r)}</a>"
            f"<div class='target-meta'>{'current active/latest run' if is_current else 'campaign artifacts, monitor state, coverage, and reports'}</div></div>"
            f"{badge('current' if is_current else 'open', 'ok' if is_current else 'info')}"
            "</div>"
        )
    body = f"""
<p class="breadcrumb"><a href="/">Dashboard</a> / {html.escape(name)}</p>
<div class="grid">
<section class="card metric-card span4"><div class="section-head"><h2>Harnesses</h2></div><div class="metric">{len(manifest.harnesses)}</div><div class="metric-label">configured fuzz entrypoints</div></section>
<section class="card metric-card span4"><div class="section-head"><h2>Runs</h2></div><div class="metric">{len(runs)}</div><div class="metric-label">stored run directories</div></section>
<section class="card metric-card span4"><div class="section-head"><h2>Findings</h2></div><div class="metric {'bad' if findings.get('reproducible') else ''}">{findings.get('reproducible', 0)}</div><div class="metric-label">{findings.get('high_or_critical', 0)} high or critical</div></section>
<section class="card span12"><div class="section-head"><div><h2>Confirmed Findings</h2><p>Sanitizer-reproducible crashes for this target across all runs.</p></div></div>{table_wrap('<table><tr><th>Severity</th><th>Type</th><th>Harness</th><th>ID / Report</th><th>Run</th></tr>' + (''.join(finding_rows) or '<tr><td colspan="5" class="muted">No confirmed findings.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Manifest</h2><p>Source of truth for build and harness orchestration.</p></div></div><pre>{html.escape(json.dumps(manifest.to_dict(), indent=2))}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Harnesses</h2><p>Each file harness can feed AFL++; libFuzzer harnesses run sanitizer smoke campaigns.</p></div></div>{table_wrap('<table><tr><th>Name</th><th>Type</th><th>Source</th><th>Argv</th></tr>' + ''.join(harness_rows) + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Runs</h2><p>Latest campaigns and smoke runs for this target.</p></div></div><div class="list">{run_items or '<div class="empty">No runs.</div>'}</div></section>
</div>
"""
    return page(f"Target: {name}", body)


def render_run(workspace: Path, target: str, run_id: str) -> bytes:
    summary = _run_summary(workspace, target, run_id)
    triage = summary.get("triage", {})
    crashes = triage.get("crashes", [])
    snap = summary.get("snapshot", {})
    coverage_inputs = summary.get("coverage_inputs", {})
    corpus_sync = summary.get("corpus_sync", {})
    crash_rows = []
    for c in crashes:
        sev = str(c.get("severity", "INFO"))
        crash_rows.append(f"<tr><td>{badge(sev, crash_tone(sev))}</td><td>{html.escape(str(c.get('type')))}</td><td><code>{html.escape(str(c.get('id')))}</code></td><td>{html.escape(str(c.get('impact')))}</td></tr>")
    logs = "".join(f"<div class='item'><a href='/file/{html.escape(p)}'>{html.escape(p)}</a></div>" for p in summary.get("logs", []))
    reports = "".join(f"<div class='item'><a href='/file/{html.escape(p)}'>{html.escape(p)}</a></div>" for p in summary.get("reports", []))
    queue_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{count}</td></tr>"
        for name, count in sorted((snap.get("queue_by_harness") or {}).items())
    )
    input_rows = ""
    for h in coverage_inputs.get("harnesses", []):
        input_rows += f"<tr><td>{html.escape(str(h.get('harness')))}</td><td>{html.escape(str(h.get('selected', 0)))}</td><td><code>{html.escape(str(h.get('sources', {}))[:240])}</code></td></tr>"
    corpus_rows = ""
    for h in corpus_sync.get("harnesses", []):
        status = str(h.get("status"))
        corpus_rows += f"<tr><td>{html.escape(str(h.get('harness')))}</td><td>{badge(status, 'ok' if status == 'ok' else 'warn')}</td><td>{html.escape(str(h.get('output_files', 0)))}</td><td><code>{html.escape(str(h.get('output', '-')))}</code></td></tr>"
    worker_tone = "ok" if snap.get("workers_expected") and snap.get("workers_alive") == snap.get("workers_expected") else "warn"
    raw_tone = "bad" if snap.get("raw_crashes") else ""
    body = f"""
<p class="breadcrumb"><a href="/">Dashboard</a> / <a href="/target/{html.escape(target)}">{html.escape(target)}</a> / {html.escape(run_id)}</p>
<div class="grid">
<section class="card span3"><h2>Run Findings</h2><div class="metric">{len(crashes)}</div><div class="muted">sanitizer-reproducible in this run</div></section>
<section class="card span3"><h2>Run Raw</h2><div class="metric {raw_tone}">{html.escape(str(snap.get('raw_crashes', 0)))}</div><div class="muted">untriaged artifacts in this run</div></section>
<section class="card span3"><h2>Execs</h2><div class="metric">{html.escape(str(snap.get('execs', 0)))}</div><div class="muted">paths {html.escape(str(snap.get('paths', 0)))}</div></section>
<section class="card span3"><h2>Workers</h2><div class="metric {worker_tone}">{html.escape(str(snap.get('workers_alive', 0)))}/{html.escape(str(snap.get('workers_expected', 0)))}</div><div class="muted">{'active' if snap.get('active') else 'complete'}</div></section>
<section class="card span6"><div class="section-head"><div><h2>Actions</h2><p>Common follow-up commands for this run.</p></div></div><pre>bin/fuzzctl --runtime native monitor {html.escape(target)} --run {html.escape(run_id)} --once
bin/fuzzctl --runtime native coverage {html.escape(target)} --run {html.escape(run_id)} --max-inputs 5000
bin/fuzzctl --runtime native corpus sync {html.escape(target)} --run {html.escape(run_id)}
bin/fuzzctl --runtime native report {html.escape(target)} --run {html.escape(run_id)}
bin/fuzzctl --runtime native guide coverage {html.escape(target)} --run {html.escape(run_id)}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Run</h2><p>Run directory and current lifecycle state.</p></div>{badge('active' if snap.get('active') else 'complete', 'ok' if snap.get('active') else 'neutral')}</div><div class="metric small">{html.escape(run_id)}</div><div class="muted">{html.escape(summary['path'])}</div></section>
<section class="card span12"><div class="section-head"><div><h2>Unique Crashes</h2><p>Only sanitizer-reproducible findings belong here.</p></div></div>{table_wrap('<table><tr><th>Severity</th><th>Type</th><th>ID</th><th>Impact</th></tr>' + (''.join(crash_rows) or '<tr><td colspan="4" class="muted">No triaged crashes.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>AFL Queue</h2><p>Coverage-discovering inputs by harness.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Inputs</th></tr>' + (queue_rows or '<tr><td colspan="2" class="muted">No AFL queue found.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Corpus Sync</h2><p>Minimized corpus promotion state.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Status</th><th>Files</th><th>Output</th></tr>' + (corpus_rows or '<tr><td colspan="4" class="muted">No corpus sync yet.</td></tr>') + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Coverage Inputs</h2><p>Input sources used for LLVM coverage generation.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Selected</th><th>Sources</th></tr>' + (input_rows or '<tr><td colspan="3" class="muted">No queue-based coverage run yet.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Coverage Guidance</h2><p>Coverage-driven next steps.</p></div></div><pre>{html.escape(summary.get('guidance') or 'No guidance yet.')}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Coverage Report</h2><p>LLVM source coverage summary.</p></div></div><pre>{html.escape(summary.get('coverage_report') or 'No coverage report yet.')}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Reports</h2><p>Generated Markdown findings and indexes.</p></div></div><div class="list">{reports or '<div class="empty">No reports.</div>'}</div></section>
<section class="card span6"><div class="section-head"><div><h2>Logs</h2><p>Campaign, harness, and build logs.</p></div></div><div class="list">{logs or '<div class="empty">No logs.</div>'}</div></section>
</div>
"""
    return page(f"Run: {target}/{run_id}", body)


def render_file(workspace: Path, rel: str) -> bytes:
    path = (workspace / unquote(rel)).resolve()
    if not str(path).startswith(str(workspace.resolve())):
        raise FuzzCtlError("file path escapes workspace")
    body = (
        f"<p class='breadcrumb'><a href='/'>Dashboard</a> / {html.escape(rel)}</p>"
        "<section class='card span12'>"
        f"<div class='section-head'><div><h2>{html.escape(rel)}</h2><p>Read-only file preview from the fuzzing workspace.</p></div></div>"
        f"<pre>{html.escape(_safe(path, 80000))}</pre></section>"
    )
    return page(rel, body)


class Handler(BaseHTTPRequestHandler):
    workspace: Path = default_workspace()
    bind_host: str = "127.0.0.1"
    bind_port: int = 8088
    auth_token: str | None = None

    def _send(self, data: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if getattr(self, "_set_auth_cookie", False) and self.auth_token:
            self.send_header("Set-Cookie", f"fuzz_dashboard_token={self.auth_token}; HttpOnly; SameSite=Lax; Path=/")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _request_token(self, parsed) -> str | None:
        query_token = parse_qs(parsed.query).get("token", [None])[0]
        if query_token:
            return query_token
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.removeprefix("Bearer ").strip()
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            key, value = part.strip().split("=", 1)
            if key == "fuzz_dashboard_token":
                return value
        return None

    def _authorized(self, parsed) -> bool:
        if not self.auth_token:
            return True
        supplied = self._request_token(parsed)
        return supplied is not None and hmac.compare_digest(supplied, self.auth_token)

    def _send_auth_required(self) -> None:
        body = """
<section class="card">
  <div class="section-head"><div><h2>Dashboard Token Required</h2><p>Authentication protects the LAN dashboard.</p></div></div>
  <p class="muted">Pass the token as an Authorization bearer token, a fuzz_dashboard_token cookie, or a temporary ?token= value.</p>
</section>
"""
        self._send(page("Unauthorized", body), status=401)

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            if parsed.path == "/healthz":
                data = {"ok": True, "workspace": str(self.workspace), "bind": f"{self.bind_host}:{self.bind_port}"}
                self._send(json.dumps(data, indent=2, sort_keys=True).encode(), content_type="application/json")
                return
            self._set_auth_cookie = False
            if self.auth_token:
                query_token = parse_qs(parsed.query).get("token", [None])[0]
                self._set_auth_cookie = query_token is not None and hmac.compare_digest(query_token, self.auth_token)
            if not self._authorized(parsed):
                self._send_auth_required()
                return
            if parsed.path == "/":
                self._send(render_home(self.workspace))
            elif parsed.path == "/api/state":
                self._send(json.dumps(state(self.workspace), indent=2, sort_keys=True).encode(), content_type="application/json")
            elif parsed.path == "/api/connectivity":
                info = connectivity_info(self.bind_host, self.bind_port, bool(self.auth_token))
                self._send(json.dumps(info, indent=2, sort_keys=True).encode(), content_type="application/json")
            elif len(parts) == 2 and parts[0] == "target":
                self._send(render_target(self.workspace, unquote(parts[1])))
            elif len(parts) == 3 and parts[0] == "run":
                self._send(render_run(self.workspace, unquote(parts[1]), unquote(parts[2])))
            elif len(parts) >= 2 and parts[0] == "file":
                self._send(render_file(self.workspace, "/".join(parts[1:])))
            else:
                self._send(page("Not Found", "<section class='card'>Not found</section>"), status=404)
        except Exception as exc:  # Keep dashboard debuggable.
            self._send(page("Dashboard Error", f"<section class='card'><pre>{html.escape(str(exc))}</pre></section>"), status=500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            if not self._authorized(parsed):
                self._send_auth_required()
                return
            length = int(self.headers.get("Content-Length", "0"))
            data = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
            if parsed.path == "/launch":
                source = data.get("source", [""])[0].strip()
                name = data.get("name", [""])[0].strip() or None
                smoke_seconds = int(data.get("smoke", ["0"])[0] or 0)
                run_dir = launch_repo(self.workspace, source, name=name, smoke_seconds=smoke_seconds)
                target_name = name or read_json(run_dir / "launch.json")["name"]
                self.send_response(303)
                self.send_header("Location", f"/run/{target_name}/{run_dir.name}")
                self.end_headers()
            else:
                self._send(page("Not Found", "<section class='card'>Not found</section>"), status=404)
        except Exception as exc:
            self._send(page("Launch Error", f"<section class='card'><pre>{html.escape(str(exc))}</pre></section>"), status=500)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"dashboard {self.address_string()} - {fmt % args}")


def serve_dashboard(workspace: Path, host: str, port: int, *, token: str | None = None, token_env: str = "FUZZ_DASHBOARD_TOKEN") -> None:
    auth_token = token or os.environ.get(token_env)
    Handler.workspace = workspace
    Handler.bind_host = host
    Handler.bind_port = port
    Handler.auth_token = auth_token
    server = ThreadingHTTPServer((host, port), Handler)
    info = connectivity_info(host, port, bool(auth_token))
    print(f"dashboard listening on {host}:{port}")
    print(f"health: {info['local_url']}healthz")
    print(f"recommended access: {info['recommended_access']}")
    print(f"ssh tunnel: {info['ssh_tunnel']}")
    print(f"open in browser after tunnel: {info['recommended_url']}")
    print(f"private URL if same VNet/VPN: {info['private_url']}")
    print(f"public URL if firewall allows it: {info['public_url']}")
    if auth_token:
        print("token auth: enabled")
    elif host in {"0.0.0.0", "::"}:
        print("warning: token auth disabled; prefer SSH tunnel or set FUZZ_DASHBOARD_TOKEN before exposing this port")
    server.serve_forever()
