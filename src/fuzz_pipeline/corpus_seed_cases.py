from __future__ import annotations

from .manifest import Harness


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
            + b"\x12\x34"
            + b"\x08"
            + b"\x02"
            + bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        ),
        "dnssec-dnskey-rsa.bin": (
            bytes([1])
            + b"\x01\x00"
            + b"\x03"
            + b"\x08"
            + b"\x03\x01\x00\x01" + b"public-key-material"
        ),
        "dnssec-nsec-bitmap.bin": bytes([2]) + _dns_name("next.example.local") + b"\x00\x06\x40\x00\x00\x00\x00\x03",
        "dnssec-rrsig.bin": (
            bytes([3])
            + b"\x00\x01"
            + b"\x08"
            + b"\x03"
            + b"\x00\x00\x0e\x10"
            + b"\x7f\xff\xff\xff"
            + b"\x00\x00\x00\x01"
            + b"\x12\x34"
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
