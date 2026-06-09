from __future__ import annotations

import html
from pathlib import Path

from .dashboard_panels import (
    render_active_campaigns,
    render_connectivity,
    render_crash_value_panel,
    render_findings_panel,
    render_supervisor_table,
    render_systemd_table,
    render_tools_table,
)
from .dashboard_ui import badge, metric_card


def render_home_body(workspace: Path, dashboard_state: dict) -> str:
    tools = dashboard_state["tools"]
    conn = dashboard_state["connectivity"]
    hidden_count = len(dashboard_state.get("hidden_targets", []))
    installed = sum(1 for t in tools["tools"] if t["installed"])
    total = len(tools["tools"])
    docker = "ok" if tools["docker_access_ok"] else "blocked"
    core_pattern = tools.get("core_pattern") or "unknown"
    core_cls = "warn" if tools.get("core_pattern_warning") else "ok"

    target_cards = []
    for target in dashboard_state["targets"]:
        latest = target.get("latest_run")
        target_name = html.escape(target["name"])
        link = f"<a href='/target/{target_name}' class='target-name'>{target_name}</a>"
        run = f"<a href='/run/{target_name}/{html.escape(latest)}'>{html.escape(latest)}</a>" if latest else "<span class='muted'>no runs</span>"
        harnesses = len(target.get("manifest", {}).get("harnesses", []))
        target_findings_data = target.get("findings") or {}
        confirmed = int(target_findings_data.get("reproducible", 0) or 0)
        collapsed = int(target_findings_data.get("duplicate_artifacts", 0) or 0)
        finding_label = "finding" if confirmed == 1 else "findings"
        duplicate_note = f", {collapsed} duplicate artifacts collapsed" if collapsed else ""
        target_cards.append(
            "<div class='item target-item'>"
            f"<div>{link}<div class='target-meta'>{harnesses} harnesses, latest {run}{html.escape(duplicate_note)}</div></div>"
            f"{badge(f'{confirmed} unique {finding_label}', 'bad' if confirmed else 'info')}"
            "</div>"
        )

    return f"""
<div class="grid">
  {render_active_campaigns(workspace, dashboard_state['targets'], dashboard_state['supervisor'])}
  {render_crash_value_panel(dashboard_state['targets'])}
  {render_findings_panel(dashboard_state['targets'])}
  {metric_card('Toolchain', f'{installed}/{total}', 'curated tools available', 'ok' if installed == total else 'warn')}
  {metric_card('Docker', docker, tools.get('docker_access_error') or 'ready', 'ok' if docker == 'ok' else 'warn')}
  {metric_card('Production Targets', len(dashboard_state['targets']), f'{hidden_count} lab fixtures hidden')}
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
    <summary><div><h2>Recovery Services</h2><p>Systemd services and reboot-safe supervisor status.</p></div>{badge('healthy', 'ok') if all(v == 'active' for v in dashboard_state['systemd'].values()) else badge('check', 'warn')}</summary>
    <div class="details-body">
      {render_supervisor_table(dashboard_state['supervisor'])}
      <br>
      {render_systemd_table(dashboard_state['systemd'])}
    </div>
  </details>
  <details class="card span12">
    <summary><div><h2>Tool Inventory</h2><p>Installed fuzzing, sanitizer, build, and analysis tools.</p></div>{badge(f'{installed}/{total}', 'ok' if installed == total else 'warn')}</summary>
    <div class="details-body">{render_tools_table(tools)}</div>
  </details>
</div>
"""
