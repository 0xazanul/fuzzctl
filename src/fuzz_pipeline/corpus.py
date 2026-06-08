from __future__ import annotations

import subprocess
import shutil
from pathlib import Path
from typing import Any

from .builder import build_profile, harness_binary
from .campaign import _asan_env, _file_target_argv
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, ensure_dir, find_latest_run, iter_files, rel_to, run_cmd, sha256_file, which, write_json


def _dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _dns_query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    return header + _dns_name(name) + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")


def _dns_response_a(name: str, ip: bytes = b"\x7f\x00\x00\x01") -> bytes:
    question = _dns_name(name) + b"\x00\x01\x00\x01"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip
    return b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer


def _thread_tlv(t: int, value: bytes) -> bytes:
    return bytes([t & 0xff, len(value) & 0xff]) + value[:255]


def _thread_netdata_seed_cases() -> dict[str, bytes]:
    prefix_payload = b"\x40\xfd\x00\xde\xad\xbe\xef"
    border_router = _thread_tlv(3, b"\x12\x34\x00\x01")
    route = _thread_tlv(5, b"\x20\x01\xaa\xbb")
    service = _thread_tlv(1, b"\x01\x02\x03\x04" + _thread_tlv(6, b"\x00\x10payload"))
    prefix = _thread_tlv(0, prefix_payload + border_router + route)
    return {
        "thread-empty.tlv": b"\x00",
        "thread-prefix-route.tlv": b"\x01" + prefix,
        "thread-service.tlv": b"\x02" + service,
        "thread-nested-mixed.tlv": b"\x02" + prefix + service + _thread_tlv(2, b"\x01\x02"),
        "thread-extended-len-edge.tlv": b"\x01" + bytes([0, 250]) + b"\xaa" * 250,
    }


def _dns_rdata_seed_cases() -> dict[str, bytes]:
    return {
        "rdata-a.bin": bytes([0]) + b"\x7f\x00\x00\x01",
        "rdata-ns.bin": bytes([1]) + _dns_name("ns.example.local"),
        "rdata-cname.bin": bytes([2]) + _dns_name("alias.example.local"),
        "rdata-soa.bin": bytes([3]) + _dns_name("ns.example.local") + _dns_name("hostmaster.example.local") + b"\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x00\x3c",
        "rdata-ptr.bin": bytes([4]) + _dns_name("service.example.local"),
        "rdata-txt.bin": bytes([5]) + b"\x0bpath=/index\x07id=demo",
        "rdata-aaaa.bin": bytes([6]) + bytes.fromhex("20010db8000000000000000000000001"),
        "rdata-srv.bin": bytes([7]) + b"\x00\x00\x00\x05\x1f\x90" + _dns_name("host.example.local"),
        "rr-full-message.bin": bytes([1]) + _dns_query("example.local", 16, 1),
    }


def _dnssec_rdata_seed_cases() -> dict[str, bytes]:
    return {
        "dnssec-ds-sha256.bin": (
            bytes([0])
            + b"\x12\x34"  # key tag
            + b"\x08"  # algorithm
            + b"\x02"  # digest type
            + bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        ),
        "dnssec-dnskey-rsa.bin": (
            bytes([1])
            + b"\x01\x00"  # flags
            + b"\x03"  # protocol
            + b"\x08"  # algorithm
            + b"\x03\x01\x00\x01" + b"public-key-material"
        ),
        "dnssec-nsec-bitmap.bin": (
            bytes([2])
            + _dns_name("next.example.local")
            + b"\x00\x06\x40\x00\x00\x00\x00\x03"  # A, RRSIG, NSEC
        ),
        "dnssec-rrsig.bin": (
            bytes([3])
            + b"\x00\x01"  # covered type A
            + b"\x08"  # algorithm
            + b"\x03"  # labels
            + b"\x00\x00\x0e\x10"  # original TTL
            + b"\x7f\xff\xff\xff"  # expiration
            + b"\x00\x00\x00\x01"  # inception
            + b"\x12\x34"  # key tag
            + _dns_name("signer.example.local")
            + b"signature-material"
        ),
    }


def _config_seed_cases() -> dict[str, bytes]:
    return {
        "config-minimal.conf": b"interface eth0\nport 5353\nlisten 127.0.0.1\n",
        "config-proxy.conf": b"interface eth0 wlan0\nport 5353 udp\nlisten 127.0.0.1 ::1\ntls-key /tmp/key.pem\ntls-cert /tmp/cert.pem\nallow example.local\n",
        "config-comments.conf": b"# fuzz config\n\nlisten 0.0.0.0\nallow *.local service instance\n",
    }


def _ddns_settings_seed_cases() -> dict[str, bytes]:
    return {
        "ddns-settings-valid.conf": (
            b"DomainDiscoveryDisabled true\n"
            b"hostname host.example.com.\n"
            b"zone example.com.\n"
            b"secret-64 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        ),
        "ddns-settings-invalid-domain.conf": b"hostname " + b"a" * 80 + b".example.\nzone bad..zone\n",
        "ddns-settings-secret-only.conf": b"secret-64 !!!!\nzone example.com.\n",
        "ddns-settings-prefix-edge.conf": b"hostname\nhostname \nDomainDiscoveryDisabled false\n",
    }


def _responder_readline_seed_cases() -> dict[str, bytes]:
    return {
        "readline-service.conf": b"My Service\n_http._tcp.\nlocal.\n8080\npath=/index\n",
        "readline-comments.conf": b"# comment\n\n\t\nVisible Line\r\nSecond Line\n",
        "readline-nul-prefix.conf": b"\x00hidden\nnext\n",
        "readline-long-line.conf": b"A" * 300 + b"\n",
    }


def _dnssd_proxy_config_seed_cases() -> dict[str, bytes]:
    return {
        "dnssd-proxy-all-verbs.conf": (
            b"interface eth0 default.service.arpa.\n"
            b"nopush wlan0 local.\n"
            b"udp-port 5353\n"
            b"tcp-port 5354\n"
            b"tls-port 853\n"
            b"my-name discoveryproxy\n"
            b"tls-key /tmp/proxy.key\n"
            b"tls-cert /tmp/proxy.crt\n"
            b"tls-cacert /tmp/ca.crt\n"
            b"listen-addr 127.0.0.1\n"
            b"publish-addr 192.0.2.10\n"
        ),
        "dnssd-proxy-boundary-ports.conf": b"udp-port 0\ntcp-port 65535\ntls-port 65536\n",
        "dnssd-proxy-long-name.conf": b"my-name " + b"a" * 260 + b"\nlisten-addr ::1\n",
        "dnssd-proxy-mixed-invalid.conf": b"interface eth0\nunknown value\npublish-addr\nnopush if0 home.arpa.\n",
    }


def _dnssd_relay_config_seed_cases() -> dict[str, bytes]:
    return {
        "dnssd-relay-all-verbs.conf": (
            b"interface eth0 default.service.arpa.\n"
            b"nopush wlan0 local.\n"
            b"udp-port 53\n"
            b"tcp-port 5353\n"
            b"tls-port 853\n"
            b"tls-key /tmp/relay.key\n"
            b"tls-cert /tmp/relay.crt\n"
            b"tls-cacert /tmp/ca.crt\n"
            b"listen-addr 127.0.0.1\n"
        ),
        "dnssd-relay-boundary-ports.conf": b"udp-port -1\ntcp-port 0\ntls-port 65535\n",
        "dnssd-relay-addresses.conf": b"listen-addr ::1\nlisten-addr 0.0.0.0\nlisten-addr 192.0.2.20\n",
        "dnssd-relay-mixed-invalid.conf": b"interface\nunknown value\nnopush if0 home.arpa.\n",
    }


def _srp_filedata_seed_cases() -> dict[str, bytes]:
    return {
        "srp-filedata-empty.bin": b"",
        "srp-filedata-short.bin": b"\x00\x01\x00\x04\x7f\x00\x00\x01\x13\x88",
        "srp-filedata-ipv6.bin": b"\x00\x1c\x00\x10" + bytes.fromhex("20010db8000000000000000000000001") + b"\x13\x88",
        "srp-filedata-oversize.bin": b"A" * 4096,
    }


def _srp_replication_tlv(selector: int, payload: bytes) -> bytes:
    return bytes([selector & 0xff, min(len(payload), 255)]) + payload[:255]


def _srp_replication_seed_cases() -> dict[str, bytes]:
    dns_header = b"\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return {
        "srpl-session.dso": (
            b"\x00"
            + _srp_replication_tlv(0, b"")
            + _srp_replication_tlv(1, _dns_name("default.service.arpa"))
            + _srp_replication_tlv(2, b"\x00\x02")
        ),
        "srpl-candidate.dso": (
            b"\x01"
            + _srp_replication_tlv(3, _dns_name("host.default.service.arpa"))
            + _srp_replication_tlv(4, b"\x00\x00\x00\x2a")
            + _srp_replication_tlv(5, b"\x00\x00\x12\x34")
        ),
        "srpl-candidate-response.dso": b"\x02" + _srp_replication_tlv(6, b""),
        "srpl-host.dso": (
            b"\x03"
            + _srp_replication_tlv(3, _dns_name("host.default.service.arpa"))
            + _srp_replication_tlv(9, dns_header + _dns_name("host.default.service.arpa"))
            + _srp_replication_tlv(10, b"\x01\x23\x45\x67\x89\xab\xcd\xef")
            + _srp_replication_tlv(4, b"\x00\x00\x00\x01")
        ),
    }


def _srp_key_config_seed_cases() -> dict[str, bytes]:
    key_32 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    key_short = b"AQIDBAUGBwg="
    return {
        "srp-key-valid.conf": b"example.key. IN KEY 512 3 163 " + key_32 + b"\n",
        "srp-key-short.conf": b"short.key. IN KEY 0 3 163 " + key_short + b"\n",
        "srp-key-invalid-base64.conf": b"bad.key. IN KEY 0 3 163 !!!!\n",
        "srp-key-invalid-fields.conf": b"bad.key. CH TXT flags protocol algorithm secret\n",
    }


def _dns_wire_seed_cases() -> dict[str, bytes]:
    return {
        "dns-query-a.local.bin": _dns_query("example.local", 1, 1),
        "dns-query-aaaa.local.bin": _dns_query("example.local", 28, 1),
        "dns-query-srv.local.bin": _dns_query("_http._tcp.local", 33, 1),
        "dns-response-a.local.bin": _dns_response_a("example.local"),
        "dns-compressed-edge.bin": b"\x12\x34\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00" + _dns_name("example.local") + b"\x00\x01\x00\x01\xc0\x0c\x00\x1c\x00\x01",
    }


def _generic_seed_cases() -> dict[str, bytes]:
    return {
        "generic-empty.bin": b"",
        "generic-zero.bin": b"\x00",
        "generic-ascii.bin": b"fuzz\n",
        "generic-ff.bin": b"\xff" * 16,
    }


def _builtin_seed_cases(harness: Harness) -> dict[str, bytes]:
    name = harness.name.lower()
    source = str(harness.source or "").lower()
    cases = _generic_seed_cases()
    if "dns_wire" in name or "dns_wire" in source:
        cases.update(_dns_wire_seed_cases())
    if "dnssec" in name or "dnssec" in source:
        cases.update(_dnssec_rdata_seed_cases())
    if "dns_rdata" in name or "rdata" in source:
        cases.update(_dns_rdata_seed_cases())
    if "thread_netdata" in name or "thread-network-data" in source:
        cases.update(_thread_netdata_seed_cases())
    if "config" in name or "config_parse" in source:
        cases.update(_config_seed_cases())
    if "ddns_settings" in name or "ddns_settings" in source:
        cases.update(_ddns_settings_seed_cases())
    if "responder_readline" in name or "responder_readline" in source:
        cases.update(_responder_readline_seed_cases())
    if "dnssd_proxy_config" in name or "dnssd_proxy_config" in source:
        cases.update(_dnssd_proxy_config_seed_cases())
    if "dnssd_relay_config" in name or "dnssd_relay_config" in source:
        cases.update(_dnssd_relay_config_seed_cases())
    if "srp_filedata" in name or "srp-filedata" in source:
        cases.update(_srp_filedata_seed_cases())
    if "srp_replication" in name or "srp-replication" in source:
        cases.update(_srp_replication_seed_cases())
    if "srp_key" in name or "srp-dns-proxy" in source or "hmac" in source:
        cases.update(_srp_key_config_seed_cases())
    return cases


def _write_seed(path: Path, data: bytes) -> bool:
    if path.exists() and path.read_bytes() == data:
        return False
    ensure_dir(path.parent)
    path.write_bytes(data)
    return True


def _run_radamsa(inputs: list[Path], out_dir: Path, *, mutations_per_input: int) -> dict[str, Any]:
    radamsa = which("radamsa")
    if not radamsa:
        return {"used": False, "reason": "radamsa not installed", "generated": 0}
    generated = 0
    for source in inputs:
        for index in range(mutations_per_input):
            out = out_dir / f"radamsa-{source.stem}-{index:03d}.bin"
            with source.open("rb") as src, out.open("wb") as dst:
                result = subprocess.run([radamsa], stdin=src, stdout=dst, stderr=subprocess.PIPE, timeout=10)
            if result.returncode == 0 and out.exists():
                generated += 1
            elif out.exists():
                out.unlink()
    return {"used": True, "generated": generated}


def corpus_enrich(
    workspace: Path,
    manifest: TargetManifest,
    *,
    mutations_per_input: int = 0,
    overwrite: bool = False,
) -> Path:
    out = ensure_dir(workspace / "corpora" / manifest.name)
    report: dict[str, Any] = {"target": manifest.name, "harnesses": [], "mutations_per_input": mutations_per_input}
    base_seed_dir = manifest.seed_dir(workspace)
    base_inputs = iter_files([base_seed_dir]) if base_seed_dir.exists() else []

    for harness in manifest.harnesses:
        current = ensure_dir(out / harness.name / "current")
        if overwrite:
            shutil.rmtree(current)
            ensure_dir(current)
        written = 0
        for name, data in _builtin_seed_cases(harness).items():
            if _write_seed(current / name, data):
                written += 1
        for source in base_inputs:
            target = current / f"base-{source.name}"
            if not target.exists():
                shutil.copy2(source, target)
                written += 1
        inputs = iter_files([current])
        radamsa = _run_radamsa(inputs, current, mutations_per_input=mutations_per_input) if mutations_per_input > 0 else {"used": False, "reason": "disabled", "generated": 0}
        files = iter_files([current])
        report["harnesses"].append(
            {
                "harness": harness.name,
                "output": rel_to(current, workspace),
                "files": len(files),
                "written": written,
                "radamsa": radamsa,
            }
        )

    write_json(out / "enrichment.json", report)
    print(f"corpus enrichment output: {rel_to(out, workspace)}")
    return out


def _quarantine_input(path: Path, quarantine_dir: Path) -> Path:
    digest = sha256_file(path)[:16]
    suffix = path.suffix if len(path.suffix) <= 16 else ""
    name = f"{path.stem}-{digest}{suffix}"
    destination = quarantine_dir / name
    index = 1
    while destination.exists():
        destination = quarantine_dir / f"{path.stem}-{digest}-{index}{suffix}"
        index += 1
    ensure_dir(quarantine_dir)
    shutil.move(str(path), str(destination))
    return destination


def corpus_prune_crashers(
    workspace: Path,
    manifest: TargetManifest,
    *,
    harness_names: list[str] | None = None,
    timeout_seconds: float = 2.0,
) -> Path:
    root = ensure_dir(workspace / "corpora" / manifest.name)
    selected = set(harness_names or [])
    report: dict[str, Any] = {
        "target": manifest.name,
        "timeout_seconds": timeout_seconds,
        "harnesses": [],
    }

    for harness in manifest.harnesses:
        if harness.type != "file":
            continue
        if selected and harness.name not in selected:
            continue
        current = root / harness.name / "current"
        binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
        summary: dict[str, Any] = {
            "harness": harness.name,
            "input": rel_to(current, workspace),
            "checked": 0,
            "quarantined": 0,
            "skipped": None,
            "crashers": [],
        }
        if not current.exists():
            summary["skipped"] = "corpus directory missing"
            report["harnesses"].append(summary)
            continue
        if not binary.exists():
            summary["skipped"] = f"missing binary {rel_to(binary, workspace)}"
            report["harnesses"].append(summary)
            continue

        env = _asan_env()
        env.update(harness.env)
        quarantine = root / harness.name / "quarantine"
        for path in iter_files([current]):
            summary["checked"] += 1
            result = run_cmd(
                _file_target_argv(binary, harness, str(path)),
                cwd=manifest.source_dir(workspace),
                env=env,
                timeout=timeout_seconds,
            )
            if result.returncode == 0:
                continue
            moved = _quarantine_input(path, quarantine)
            summary["quarantined"] += 1
            summary["crashers"].append(
                {
                    "from": rel_to(path, workspace),
                    "to": rel_to(moved, workspace),
                    "returncode": result.returncode,
                    "output_tail": result.output[-1200:],
                }
            )
        report["harnesses"].append(summary)

    write_json(root / "prune-crashers.json", report)
    print(f"corpus prune output: {rel_to(root, workspace)}")
    return root


def _sample_paths(paths: list[Path], limit: int) -> list[Path]:
    if limit <= 0:
        return []
    if len(paths) <= limit:
        return paths
    head = max(1, limit // 2)
    tail = max(0, limit - head)
    out: list[Path] = []
    seen: set[Path] = set()
    for path in [*paths[:head], *paths[-tail:]]:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out[:limit]


def _harness_inputs(workspace: Path, manifest: TargetManifest, run_dir: Path, harness: Harness, max_inputs: int) -> tuple[list[Path], dict[str, Any]]:
    sources: list[tuple[str, list[Path], bool]] = []
    seed_dir = manifest.seed_dir(workspace)
    if seed_dir.exists():
        sources.append(("seed", iter_files([seed_dir]), True))
    curated = workspace / "corpora" / manifest.name / harness.name / "current"
    if curated.exists():
        sources.append(("curated", iter_files([curated]), True))
    if harness.type == "file":
        afl_root = run_dir / "aflpp" / harness.name / "findings"
        if afl_root.exists():
            sources.append(("afl_queue", sorted(afl_root.glob("*/queue/id:*")), False))
    if harness.type == "libfuzzer":
        lf_root = run_dir / "libfuzzer" / harness.name / "corpus"
        if lf_root.exists():
            sources.append(("libfuzzer_corpus", iter_files([lf_root]), False))

    selected: list[Path] = []
    seen_hashes: set[str] = set()
    summary: dict[str, Any] = {"harness": harness.name, "sources": {}, "selected": 0, "deduped": 0}

    for label, paths, force in sources:
        source = {"discovered": len(paths), "selected": 0, "deduped": 0}
        remaining = max_inputs - len(selected)
        candidates = paths if force else _sample_paths(paths, remaining)
        for path in candidates:
            if len(selected) >= max_inputs and not force:
                break
            if not path.is_file():
                continue
            digest = sha256_file(path)
            if digest in seen_hashes:
                source["deduped"] += 1
                summary["deduped"] += 1
                continue
            seen_hashes.add(digest)
            selected.append(path)
            source["selected"] += 1
        summary["sources"][label] = source
    summary["selected"] = len(selected)
    return selected, summary


def _copy_inputs(inputs: list[Path], out_dir: Path) -> None:
    ensure_dir(out_dir)
    for index, path in enumerate(inputs):
        digest = sha256_file(path)
        suffix = path.suffix if len(path.suffix) <= 16 else ""
        shutil.copy2(path, out_dir / f"{index:06d}-{digest[:16]}{suffix}")


def _replace_dir(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    ensure_dir(dst.parent)
    shutil.copytree(src, dst)


def _run_afl_cmin(workspace: Path, manifest: TargetManifest, harness: Harness, in_dir: Path, out_dir: Path) -> dict[str, Any]:
    binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
    if not binary.exists():
        return {"tool": "afl-cmin", "used": False, "reason": f"missing binary {binary}"}
    if not which("afl-cmin"):
        return {"tool": "afl-cmin", "used": False, "reason": "afl-cmin not installed"}
    env = _asan_env()
    env.update(harness.env)
    cmd = [
        "afl-cmin",
        "-i",
        str(in_dir),
        "-o",
        str(out_dir),
        "-m",
        "none",
        "-t",
        f"{manifest.timeout_ms}+",
        "--",
        *_file_target_argv(binary, harness),
    ]
    result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=env, timeout=900, print_cmd=True)
    return {"tool": "afl-cmin", "used": result.returncode == 0, "returncode": result.returncode, "output_tail": result.output[-4000:]}


def _run_libfuzzer_merge(workspace: Path, manifest: TargetManifest, harness: Harness, in_dir: Path, out_dir: Path) -> dict[str, Any]:
    binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", harness)
    if not binary.exists():
        return {"tool": "libfuzzer-merge", "used": False, "reason": f"missing binary {binary}"}
    env = _asan_env()
    env.update(harness.env)
    cmd = [str(binary), "-merge=1", str(out_dir), str(in_dir), f"-max_len={manifest.max_len}"]
    result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=env, timeout=900, print_cmd=True)
    return {"tool": "libfuzzer-merge", "used": result.returncode == 0, "returncode": result.returncode, "output_tail": result.output[-4000:]}


def corpus_sync(workspace: Path, manifest: TargetManifest, run_id: str | None = None, *, max_inputs: int = 20000) -> Path:
    if max_inputs <= 0:
        raise FuzzCtlError("--max-inputs must be greater than zero")
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    out = ensure_dir(run_dir / "corpus_sync")
    report: dict[str, Any] = {"target": manifest.name, "run": str(run_dir), "max_inputs": max_inputs, "harnesses": []}

    if any(h.type == "file" for h in manifest.harnesses):
        build_profile(workspace, manifest, "afl_asan_ubsan")
    if any(h.type == "libfuzzer" for h in manifest.harnesses):
        try:
            build_profile(workspace, manifest, "libfuzzer_asan_ubsan")
        except FuzzCtlError as exc:
            print(f"warning: libFuzzer profile unavailable for corpus merge: {exc}")

    for harness in manifest.harnesses:
        inputs, summary = _harness_inputs(workspace, manifest, run_dir, harness, max_inputs)
        if not inputs:
            summary["status"] = "skipped"
            summary["reason"] = "no corpus inputs found"
            report["harnesses"].append(summary)
            continue

        harness_dir = ensure_dir(out / harness.name)
        all_dir = harness_dir / "all"
        minimized_dir = harness_dir / "minimized"
        if all_dir.exists():
            shutil.rmtree(all_dir)
        if minimized_dir.exists():
            shutil.rmtree(minimized_dir)
        _copy_inputs(inputs, all_dir)

        tool_result: dict[str, Any]
        if harness.type == "file":
            tool_result = _run_afl_cmin(workspace, manifest, harness, all_dir, minimized_dir)
        elif harness.type == "libfuzzer":
            ensure_dir(minimized_dir)
            tool_result = _run_libfuzzer_merge(workspace, manifest, harness, all_dir, minimized_dir)
        else:
            tool_result = {"tool": "copy", "used": False, "reason": f"unsupported harness type {harness.type}"}

        if not minimized_dir.exists() or not any(minimized_dir.iterdir()):
            if minimized_dir.exists():
                shutil.rmtree(minimized_dir)
            shutil.copytree(all_dir, minimized_dir)
            tool_result["fallback"] = "deduped-copy"

        current = workspace / "corpora" / manifest.name / harness.name / "current"
        _replace_dir(minimized_dir, current)
        summary["status"] = "synced"
        summary["tool"] = tool_result
        summary["output"] = rel_to(current, workspace)
        summary["output_files"] = len([p for p in current.iterdir() if p.is_file()])
        report["harnesses"].append(summary)

    write_json(out / "corpus_sync.json", report)
    print(f"corpus sync output: {rel_to(out, workspace)}")
    return out
