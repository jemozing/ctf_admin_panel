#!/usr/bin/env python3
"""Local process checks; fixture ingest is NOT proof of live AF_PACKET capture.

Builds fresh capture/archive binaries in a private temporary directory unless
explicit binaries are supplied. Uses neither Docker nor the competition VM.
"""

import argparse
import base64
import datetime as dt
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse


ROOT = Path(__file__).resolve().parents[2]


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def request(endpoint, path, token=None, data=None, method="GET", origin=None):
    connection = (UnixHTTP(endpoint) if isinstance(endpoint, Path)
                  else http.client.HTTPConnection("127.0.0.1", endpoint, timeout=3))
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if origin:
        headers["Origin"] = origin
    if data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        body = response.read()
        try:
            decoded = json.loads(body)
        except (ValueError, UnicodeError):
            decoded = body.decode(errors="replace")
        return response.status, decoded
    finally:
        connection.close()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def frame(protocol, source, destination, sport, dport, payload):
    ipv6 = ":" in source
    transport = (struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 1024, 0, 0)
                 if protocol == "tcp" else struct.pack("!HHHH", sport, dport, 8 + len(payload), 0))
    body = transport + payload
    if ipv6:
        network = struct.pack("!IHBB", 6 << 28, len(body), 6 if protocol == "tcp" else 17, 64)
    else:
        network = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(body), 1, 0x4000, 64,
                              6 if protocol == "tcp" else 17, 0)
    network += ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02" + struct.pack("!H", 0x86DD if ipv6 else 0x0800) + network + body


def decode_pcap(data):
    if len(data) < 24 or struct.unpack("<IHHIIII", data[:24]) != (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1):
        raise AssertionError("invalid classic Ethernet PCAP header")
    records, offset = [], 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise AssertionError("partial PCAP record header")
        seconds, micros, included, original = struct.unpack("<IIII", data[offset:offset + 16])
        offset += 16
        if seconds == 0 or micros >= 1000000 or included > original or offset + included > len(data):
            raise AssertionError("invalid PCAP timestamp or record bounds")
        records.append((data[offset:offset + included], original))
        offset += included
    return records


def run(args):
    report_path = Path(args.report).resolve()
    if report_path.exists():
        raise SystemExit("Report already exists; use a new --report path.")
    report = {"schema_version": 1, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": {"platform": sys.platform, "live_af_packet": False,
                        "capture_policy_enabled": False, "synthetic_archive_ingest": True,
                        "vm_touched": False, "docker_used": False}, "checks": []}
    processes, logs = [], []

    def check(name, condition, **details):
        report["checks"].append({"name": name, "passed": bool(condition), **details})
        if not condition:
            raise AssertionError(name)

    def terminate(process, kill=False):
        if process.poll() is None:
            (process.kill if kill else process.terminate)()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    try:
        with tempfile.TemporaryDirectory(prefix="ctfm-packet-", dir="/tmp") as temporary:
            temp = Path(temporary)
            os.chmod(temp, 0o700)
            capture_bin, archive_bin = Path(args.capture_binary or temp / "capture"), Path(args.archive_binary or temp / "archive")
            env = dict(os.environ, GOCACHE=str(ROOT / ".cache/go-build"), GOMODCACHE=str(ROOT / ".cache/go-mod"))
            for supplied, binary, package in [(args.capture_binary, capture_bin, "./cmd/ctfm-capture"),
                                               (args.archive_binary, archive_bin, "./cmd/ctfm-packets")]:
                if not supplied:
                    subprocess.run(["go", "build", "-o", str(binary), package], cwd=ROOT, env=env,
                                   check=True, stdout=subprocess.DEVNULL, timeout=120)
            check("fresh_compiled_process_binaries", capture_bin.is_file() and archive_bin.is_file())
            token_values = {name: secrets.token_hex(32) for name in ("capture-control", "ingest", "read")}
            for name, value in token_values.items():
                token_file = temp / name
                token_file.write_text(value + "\n")
                token_file.chmod(0o600)
            policy = {"schema_version": 1, "revision": 1, "enabled": False, "snaplen": 0,
                      "max_packets_per_second": 1000, "interfaces": []}
            policy_file = temp / "policy.json"
            policy_file.write_text(json.dumps(policy))
            policy_file.chmod(0o600)
            capture_port, archive_port = free_port(), free_port()
            while archive_port == capture_port:
                archive_port = free_port()
            capture_socket, archive_socket = temp / "capture.sock", temp / "archive.sock"
            archive_cmd = [str(archive_bin), "--listen", f"127.0.0.1:{archive_port}", "--control-unix", str(archive_socket),
                           "--state", str(temp / "archive-state"), "--ingest-token-file", str(temp / "ingest"),
                           "--read-token-file", str(temp / "read"), "--quota-bytes", str(4 << 20),
                           "--per-service-bytes", str(1 << 20), "--minimum-free-bytes", "1", "--max-records", "100"]
            capture_cmd = [str(capture_bin), "--policy-file", str(policy_file), "--control-listen", f"127.0.0.1:{capture_port}",
                           "--control-unix", str(capture_socket), "--control-token-file", str(temp / "capture-control"),
                           "--ingest-url", f"http://127.0.0.1:{archive_port}", "--ingest-token-file", str(temp / "ingest")]

            def launch(command):
                log = open(temp / f"process-{len(logs)}.log", "xb")
                logs.append(log)
                process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log)
                processes.append(process)
                return process

            def ready(process, port, endpoint):
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise AssertionError("process exited before readiness")
                    try:
                        if request(port, "/healthz")[0] == 200 and endpoint.exists():
                            return
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(0.05)
                raise AssertionError("local process readiness timeout")

            archive = launch(archive_cmd)
            capture = launch(capture_cmd)
            ready(archive, archive_port, archive_socket)
            ready(capture, capture_port, capture_socket)
            for binary, port in [(capture_bin, capture_port), (archive_bin, archive_port)]:
                subprocess.run([str(binary), "health", "--url", f"http://127.0.0.1:{port}/healthz"], check=True, timeout=4,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            check("both_process_health_commands", True)
            control, ingest, read = (token_values[k] for k in ("capture-control", "ingest", "read"))
            check("capture_control_auth", request(capture_socket, "/v1/status")[0] == 401)
            check("capture_control_origin_denied", request(capture_socket, "/v1/status", control, origin="https://foreign.invalid")[0] == 401)
            status, capture_status = request(capture_socket, "/v1/status", control)
            check("capture_disabled_without_raw_access", status == 200 and not capture_status["enabled"] and capture_status["revision"] == 1)
            check("capture_preflight_does_not_enable", request(capture_socket, "/v1/preflight", control, policy, "POST")[0] == 200)
            check("capture_pause_control", request(capture_socket, "/v1/pause", control, method="POST")[0] == 200)
            check("archive_read_auth", request(archive_socket, "/v1/status")[0] == 401 and request(archive_socket, "/v1/status", ingest)[0] == 401)
            check("archive_network_listener_has_no_read_api", request(archive_port, "/v1/status", read)[0] == 404)
            check("archive_read_socket_cannot_ingest", request(archive_socket, "/v1/packets", read, {}, "POST")[0] == 404)
            check("archive_read_token_cannot_ingest", request(archive_port, "/v1/packets", read, {}, "POST")[0] == 401)
            now = dt.datetime.now(dt.timezone.utc)
            timestamp = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
            fixtures = [
                ("alpha", "app", "tcp", "172.20.0.9", "172.20.0.5", 50000, 7000, "ingress", b"\0\0\0\0\4test"),
                ("beta", "edge", "udp", "172.20.0.6", "172.20.0.9", 7001, 50001, "egress", b"\x00\xffudp-fixture"),
                ("alpha", "app", "tcp", "fd00::9", "fd00::5", 50002, 7443, "ingress", b"\x16\x03\x03opaque-tls"),
            ]
            expected, metadata = [], []
            for index, (service, component, protocol, source, destination, sport, dport, direction, payload) in enumerate(fixtures, 1):
                data = frame(protocol, source, destination, sport, dport, payload)
                record = {"packet_id": f"fixture-{index}", "collector_epoch": "fixture-epoch", "policy_revision": 1, "at": timestamp,
                          "service_id": service, "component": component, "interface": "fixture0", "if_index": 7,
                          "direction": direction, "protocol": protocol, "source_ip": source, "destination_ip": destination,
                          "source_port": sport, "destination_port": dport, "tcp_flags": 24 if protocol == "tcp" else 0,
                          "wire_length": len(data), "captured_length": len(data), "truncated": False, "link_type": 1,
                          "attribution": "unique", "data": base64.b64encode(data).decode()}
                result, _ = request(archive_port, "/v1/packets", ingest, record, "POST")
                check(f"fixture_ingest_{protocol}_{index}", result == 202)
                expected.append((data, len(data)))
                metadata.append(record)
            only_metadata = dict(metadata[1], packet_id="fixture-4", service_id="alpha", component="app", captured_length=0,
                                 truncated=True, not_captured_reason="metadata_only")
            only_metadata.pop("data")
            check("metadata_only_ingest", request(archive_port, "/v1/packets", ingest, only_metadata, "POST")[0] == 202)
            expected.append((b"", only_metadata["wire_length"]))
            ambiguous = dict(metadata[0], packet_id="fixture-5", attribution="ambiguous",
                             candidates=[{"service_id": "alpha", "component": "app"}, {"service_id": "beta", "component": "edge"}])
            ambiguous.pop("service_id")
            ambiguous.pop("component")
            check("ambiguous_fixture_ingest", request(archive_port, "/v1/packets", ingest, ambiguous, "POST")[0] == 202)
            expected.append(expected[0])
            status, page = request(archive_socket, "/v1/packets?limit=200", read)
            check("metadata_list_contains_no_payload", status == 200 and len(page["records"]) == 5 and all("data" not in r for r in page["records"]))
            old_cursor, old_epoch = page["live_cursor"], page["epoch"]
            filters = [("service_id=alpha", 4), ("service_id=beta", 2), ("component=edge", 2), ("protocol=udp", 2),
                       ("ip=fd00::5", 1), ("source_port=50000", 2), ("destination_port=7443", 1), ("direction=egress", 2),
                       ("service_id=alpha&protocol=tcp&destination_port=7443", 1)]
            before = (now - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
            after = (now + dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
            filters.append((urllib.parse.urlencode({"from": before, "until": after}), 5))
            for query, count in filters:
                code, filtered = request(archive_socket, "/v1/packets?" + query, read)
                check("filter_" + query.split("=")[0], code == 200 and len(filtered["records"]) == count, query=query)
            for query in ("protocol=icmp", "limit=201", "limit=1&limit=2", "unknown=1"):
                check("invalid_filter_denied", request(archive_socket, "/v1/packets?" + query, read)[0] == 400, query=query)
            code, raw = request(archive_socket, "/v1/packets/fixture-1/raw", read)
            check("separate_raw_preserves_exact_frame", code == 200 and base64.b64decode(raw["data"]) == expected[0][0])
            code, detail = request(archive_socket, "/v1/packets/fixture-1", read)
            check("detail_omits_payload", code == 200 and "data" not in detail)
            code, exported = request(archive_socket, "/v1/export", read, {"query": {}, "max_packets": 10, "max_bytes": 1 << 20}, "POST")
            check("pcap_exact_tcp_udp_ipv6_metadata_and_repeated_frames", code == 200 and exported["packets"] == 5 and
                  decode_pcap(base64.b64decode(exported["data"])) == expected)
            for limit, packets_count in [({"max_packets": 1}, 1), ({"max_bytes": 24}, 0)]:
                code, limited = request(archive_socket, "/v1/export", read, {"query": {}, **limit}, "POST")
                check("pcap_export_bounds", code == 200 and limited["packets"] == packets_count and limited["truncated"], **limit)
            check("pcap_invalid_bound_denied", request(archive_socket, "/v1/export", read, {"query": {}, "max_bytes": 23}, "POST")[0] == 400)
            terminate(archive, kill=True)
            check("archive_crash_does_not_stop_capture_health", request(capture_port, "/healthz")[0] == 200 and capture.poll() is None)
            archive = launch(archive_cmd)
            ready(archive, archive_port, archive_socket)
            code, restarted = request(archive_socket, "/v1/packets?" + urllib.parse.urlencode({"cursor": old_cursor}), read)
            check("archive_restart_preserves_records_and_signals_epoch_gap", code == 200 and restarted["epoch"] != old_epoch and
                  restarted["gap"] and len(restarted["records"]) == 5)
            code, raw = request(archive_socket, "/v1/packets/fixture-1/raw", read)
            check("archive_restart_preserves_exact_frame", code == 200 and base64.b64decode(raw["data"]) == expected[0][0])
            code, status = request(capture_socket, "/v1/status", control)
            check("no_synthetic_frame_claimed_as_live_capture", code == 200 and status["counters"]["observed"] == 0 and not status["enabled"])
            # Terminate while temporary private files still exist; then delete
            # sockets, SQLite, journal, binaries, fixture bytes and credentials.
            for process in reversed(processes):
                terminate(process)
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        for process in reversed(processes):
            terminate(process)
        for log in logs:
            log.close()
        report["all_child_processes_stopped"] = all(p.poll() is not None for p in processes)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]), "report": str(report_path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="new report path; existing reports are never overwritten")
    parser.add_argument("--capture-binary")
    parser.add_argument("--archive-binary")
    sys.exit(run(parser.parse_args()))
