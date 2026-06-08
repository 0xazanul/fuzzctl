# Fuzz Pipeline systemd user services

These units are templates for recovery after SSH disconnects or VPS reboots. They do not store secrets; Discord webhook
configuration is loaded from `/home/azanul/.config/fuzz-pipeline/env`.
Use `KEY=value` lines in that file; systemd does not accept shell `export KEY=value` syntax.

Install:

```bash
mkdir -p ~/.config/systemd/user
cp /home/azanul/fuzz-pipeline/systemd/fuzz-*.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now fuzz-dashboard.service
systemctl --user enable --now fuzz-dashboard-lan.service
systemctl --user enable --now fuzz-monitor@mdnsresponder.service
systemctl --user enable --now fuzz-campaign@mdnsresponder.service
loginctl enable-linger "$USER"
```

`fuzz-dashboard.service` binds to `127.0.0.1:8088` for SSH tunnels. `fuzz-dashboard-lan.service`
binds to `0.0.0.0:8089` and requires `FUZZ_DASHBOARD_TOKEN` from
`/home/azanul/.config/fuzz-pipeline/env`.

`fuzz-campaign@.service` runs the supervisor loop, not a blind campaign command. If an AFL++ campaign is already
running for the target, it waits and adopts the slot instead of starting a duplicate. When the active campaign exits,
the supervisor starts the next 24-hour AFL++ cycle with 8 workers and runs post-cycle triage, reporting, corpus sync, and coverage.

Status:

```bash
systemctl --user status fuzz-dashboard.service fuzz-dashboard-lan.service fuzz-monitor@mdnsresponder.service fuzz-campaign@mdnsresponder.service
/home/azanul/fuzz-pipeline/bin/fuzzctl --runtime native supervisor status mdnsresponder
```

Host core dump tuning for AFL++ crash handling:

```bash
sudo sysctl -w kernel.core_pattern=core
sudo sysctl -w kernel.core_uses_pid=0
printf 'kernel.core_pattern=core\nkernel.core_uses_pid=0\n' | sudo tee /etc/sysctl.d/zz-fuzz-pipeline-core.conf
sudo sysctl --system
```
