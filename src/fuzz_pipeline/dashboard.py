from __future__ import annotations

import html
import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .dashboard_state import (
    _safe,
    _target_crash_value,
    _target_findings,
    _targets,
    collect_dashboard_state,
    connectivity_info,
)
from .dashboard_crash import render_crash_value_detail_body
from .dashboard_home import render_home_body
from .dashboard_target import render_target_body
from .dashboard_run import render_run_body
from .launch import launch_repo
from .manifest import load_manifest
from .util import FuzzCtlError, default_workspace, read_json


CSS = """
:root{color-scheme:light;--bg:#f3f0e8;--bg2:#e8edf0;--surface:#fffdf8;--surface2:#f6f3ec;--surface3:#eef6f2;--text:#1d211f;--muted:#66736c;--line:#ded8cc;--line2:#c7bdae;--primary:#0c6b58;--primary2:#084f42;--primaryText:#fffdf8;--accent:#c56a2c;--accent2:#175c9a;--ok:#147a4c;--okBg:#e6f4ec;--warn:#a35b00;--warnBg:#fff2d2;--bad:#b3261e;--badBg:#fce8e6;--info:#175c9a;--infoBg:#e8f1fb;--shadow:0 1px 1px rgba(34,28,16,.05),0 10px 28px rgba(34,28,16,.08);--shadow2:0 1px 0 rgba(255,255,255,.75) inset,0 24px 70px rgba(34,28,16,.14)}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0d1110;--bg2:#11191a;--surface:#151a18;--surface2:#1d2421;--surface3:#14261f;--text:#f3efe5;--muted:#a7b4ad;--line:#2b342f;--line2:#435047;--primary:#63d3b1;--primary2:#9ce6cf;--primaryText:#08100d;--accent:#f3a45d;--accent2:#8dc7ff;--ok:#69d391;--okBg:#143120;--warn:#f2c45c;--warnBg:#32270f;--bad:#ff8c82;--badBg:#351a18;--info:#8dc7ff;--infoBg:#13283a;--shadow:0 1px 2px rgba(0,0,0,.32);--shadow2:0 1px 0 rgba(255,255,255,.04) inset,0 26px 80px rgba(0,0,0,.38)}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at top left,color-mix(in srgb,var(--surface3) 58%,transparent),transparent 36rem),linear-gradient(135deg,var(--bg),var(--bg2));color:var(--text);font:14px/1.48 Aptos,"IBM Plex Sans","Segoe UI",sans-serif;letter-spacing:0}body:before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background-image:linear-gradient(color-mix(in srgb,var(--line) 48%,transparent) 1px,transparent 1px),linear-gradient(90deg,color-mix(in srgb,var(--line) 42%,transparent) 1px,transparent 1px);background-size:48px 48px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.55),transparent 78%)}a{color:var(--primary2);text-decoration:none}a:hover{text-decoration:underline;text-underline-offset:3px}
.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:18px;min-height:64px;padding:0 28px;background:color-mix(in srgb,var(--surface) 86%,transparent);border-bottom:1px solid var(--line);backdrop-filter:saturate(140%) blur(18px);box-shadow:0 1px 0 color-mix(in srgb,var(--text) 5%,transparent)}.brand{display:flex;align-items:center;gap:12px;min-width:250px;color:var(--text)}.brand:hover{text-decoration:none}.brand-mark{display:grid;place-items:center;width:36px;height:36px;border-radius:7px;background:linear-gradient(135deg,var(--primary),var(--accent2));color:var(--primaryText);font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-weight:900;font-size:12px;box-shadow:0 10px 24px color-mix(in srgb,var(--primary) 26%,transparent)}.brand-name{display:block;font-size:15px;font-weight:820}.brand-sub{display:block;font-size:11px;color:var(--muted);margin-top:1px}.topnav{display:flex;gap:4px;flex:1}.topnav a{color:var(--muted);padding:8px 11px;border-radius:7px;font-weight:760;font-size:13px}.topnav a:hover{background:var(--surface2);color:var(--text);text-decoration:none}.theme-toggle{width:auto;flex:0 0 auto;display:inline-flex;align-items:center;border:1px solid var(--line2);background:var(--surface);color:var(--text);border-radius:999px;padding:8px 12px;font-weight:820;font-size:12px;box-shadow:var(--shadow)}
.page{max-width:1480px;margin:0 auto;padding:28px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin:0 0 20px}.eyebrow{font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-size:11px;color:var(--primary);font-weight:900;text-transform:uppercase;letter-spacing:.12em}.page-heading h1{margin:4px 0 0;font-family:Aptos,"IBM Plex Sans","Segoe UI",sans-serif;font-size:30px;line-height:1.08;font-weight:850}.sub{color:var(--muted);margin-top:4px}h1,h2,h3{letter-spacing:0}h2{margin:0;font-size:15px;line-height:1.25;font-weight:850}h3{margin:0 0 8px;font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-size:11px;color:var(--muted);font-weight:900;text-transform:uppercase;letter-spacing:.08em}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px}.section-head p{margin:4px 0 0;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px}.card{position:relative;background:color-mix(in srgb,var(--surface) 96%,transparent);border:1px solid var(--line);border-radius:9px;padding:16px;box-shadow:var(--shadow);overflow:hidden}.card:after{content:"";position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,var(--primary),transparent 45%,var(--accent) 100%);opacity:.45}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span12{grid-column:span 12}
.metric{font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-size:30px;line-height:1.02;font-weight:900;margin-top:8px;letter-spacing:-.02em}.metric.small{font-size:15px;overflow-wrap:anywhere;letter-spacing:0}.metric-label{color:var(--muted);font-size:12px;margin-top:6px}.metric-card{min-height:118px}.muted{color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.info{color:var(--info)}.status{display:inline-flex;align-items:center;gap:6px;border:1px solid transparent;border-radius:999px;padding:4px 9px;font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-size:11px;font-weight:900;white-space:nowrap}.status:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 0 3px color-mix(in srgb,currentColor 12%,transparent)}.status.ok{background:var(--okBg);color:var(--ok)}.status.warn{background:var(--warnBg);color:var(--warn)}.status.bad{background:var(--badBg);color:var(--bad)}.status.info{background:var(--infoBg);color:var(--info)}.status.neutral{background:var(--surface2);color:var(--muted);border-color:var(--line)}
.campaign-card{position:relative;background:linear-gradient(135deg,color-mix(in srgb,var(--surface) 94%,transparent),color-mix(in srgb,var(--surface3) 86%,transparent));border:1px solid var(--line);border-radius:10px;padding:20px;box-shadow:var(--shadow2);overflow:hidden}.campaign-card:before{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 0 58%,color-mix(in srgb,var(--primary) 10%,transparent) 58% 66%,transparent 66%);pointer-events:none}.campaign-title{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:18px}.campaign-title h2{font-size:22px}.campaign-title p{margin:5px 0 0;color:var(--muted)}.campaign-metrics{position:relative;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);border-radius:9px;overflow:hidden;background:color-mix(in srgb,var(--surface) 88%,transparent)}.campaign-metric{padding:16px;border-right:1px solid var(--line);min-height:108px}.campaign-metric:last-child{border-right:0}.campaign-metric .metric{font-size:27px}.campaign-metric h3{margin-bottom:10px}
.pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:4px 9px;margin:2px;background:var(--surface2);color:var(--muted);font-weight:820;font-size:12px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px;background:var(--surface);box-shadow:0 1px 0 color-mix(in srgb,var(--text) 4%,transparent) inset}table{width:100%;border-collapse:collapse;min-width:560px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);background:linear-gradient(180deg,var(--surface2),color-mix(in srgb,var(--surface2) 72%,var(--surface)));font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;font-weight:900}tr:last-child td{border-bottom:0}tbody tr:hover,table tr:hover td{background:color-mix(in srgb,var(--surface3) 45%,transparent)}td{overflow-wrap:anywhere}code,pre{font-family:"JetBrains Mono","Berkeley Mono","SFMono-Regular",ui-monospace,monospace;background:var(--surface2);border:1px solid var(--line);border-radius:6px}code{padding:2px 6px;font-size:12px}pre{padding:14px;overflow:auto;max-height:520px;white-space:pre-wrap;overflow-wrap:anywhere}
label{display:block;margin:12px 0 6px;color:var(--muted);font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-weight:900;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em}input,select{width:100%;background:var(--surface);border:1px solid var(--line2);border-radius:7px;color:var(--text);padding:10px 11px;outline:none}input:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--primary) 16%,transparent)}button,.button{display:inline-flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--primary),var(--primary2));border:0;color:var(--primaryText);border-radius:7px;padding:10px 14px;font-weight:860;cursor:pointer;min-height:38px;text-decoration:none;box-shadow:0 10px 22px color-mix(in srgb,var(--primary) 18%,transparent)}button:hover,.button:hover{text-decoration:none;filter:brightness(1.03)}button.secondary,.button.secondary{background:var(--surface);border:1px solid var(--line2);color:var(--text);box-shadow:var(--shadow)}
.row{display:flex;gap:12px;align-items:end}.row>*{flex:1}.small{font-size:12px}.list{display:grid;gap:9px}.item{display:block;padding:12px;border:1px solid var(--line);border-radius:9px;background:color-mix(in srgb,var(--surface) 88%,transparent)}.item:hover{border-color:var(--line2);box-shadow:var(--shadow);text-decoration:none}.target-item{display:flex;align-items:center;justify-content:space-between;gap:12px}.target-name{font-weight:880}.target-meta{color:var(--muted);font-size:12px;margin-top:3px}.breadcrumb{margin:0 0 18px;color:var(--muted)}.breadcrumb a{font-weight:780}.empty{padding:18px;color:var(--muted);background:color-mix(in srgb,var(--surface2) 82%,transparent);border:1px dashed var(--line2);border-radius:9px}
details.card{padding:0;overflow:hidden}details.card summary{list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 16px;cursor:pointer}details.card summary::-webkit-details-marker{display:none}details.card summary:after{content:"Open";font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace;font-size:10px;color:var(--muted);font-weight:900;text-transform:uppercase;letter-spacing:.08em}details[open].card summary:after{content:"Close"}details.card .details-body{padding:0 16px 16px}
.nowrap{white-space:nowrap}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.worker-table td:nth-child(2),.worker-table td:nth-child(3),.worker-table td:nth-child(4),.worker-table td:nth-child(5){font-family:"JetBrains Mono","Berkeley Mono",ui-monospace,monospace}.profile-list{display:flex;flex-wrap:wrap;gap:4px}
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

def state(workspace: Path) -> dict:
    return collect_dashboard_state(workspace, Handler.bind_host, Handler.bind_port, bool(Handler.auth_token))


def _redact_log_text(text: str) -> str:
    text = re.sub(r"([?&]token=)[^&\s]+", r"\1<redacted>", text)
    text = re.sub(r"(Authorization:\s*Bearer\s+)\S+", r"\1<redacted>", text, flags=re.I)
    return text


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
        <div class="eyebrow">Sanitizer Operations</div>
        <h1>{safe_title}</h1>
      </div>
    </div>
    {body}
  </main>
  {THEME_SCRIPT_BODY}
</body>
</html>""".encode()


def render_home(workspace: Path) -> bytes:
    return page("Fuzz Pipeline Dashboard", render_home_body(workspace, state(workspace)))


def render_target(workspace: Path, name: str) -> bytes:
    return page(f"Target: {name}", render_target_body(workspace, name))


def render_run(workspace: Path, target: str, run_id: str) -> bytes:
    return page(f"Run: {target}/{run_id}", render_run_body(workspace, target, run_id))


def render_crash_value_detail(workspace: Path, target: str, crash_id: str) -> bytes:
    return page(f"Crash Value: {target}/{crash_id}", render_crash_value_detail_body(workspace, target, crash_id))


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
            elif len(parts) == 2 and parts[0] == "api" and parts[1] == "crash-value":
                targets, _ = _targets(self.workspace)
                data = {
                    "targets": [
                        {"name": target.get("name"), "crash_value": target.get("crash_value", {})}
                        for target in targets
                    ]
                }
                self._send(json.dumps(data, indent=2, sort_keys=True).encode(), content_type="application/json")
            elif len(parts) == 3 and parts[0] == "api" and parts[1] == "crash-value":
                manifest = load_manifest(self.workspace, unquote(parts[2]))
                data = _target_crash_value(self.workspace, manifest)
                self._send(json.dumps(data, indent=2, sort_keys=True).encode(), content_type="application/json")
            elif len(parts) == 2 and parts[0] == "target":
                self._send(render_target(self.workspace, unquote(parts[1])))
            elif len(parts) == 3 and parts[0] == "run":
                self._send(render_run(self.workspace, unquote(parts[1]), unquote(parts[2])))
            elif len(parts) == 3 and parts[0] == "crash":
                self._send(render_crash_value_detail(self.workspace, unquote(parts[1]), unquote(parts[2])))
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
        print(f"dashboard {self.address_string()} - {_redact_log_text(fmt % args)}")


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
