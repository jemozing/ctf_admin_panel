#!/usr/bin/env python3
"""Real dashboard/executor/capture/archive process smoke, without Docker or VM.

The capture policy stays disabled. TCP/UDP frames enter the archive through its
private authenticated fixture-ingest API; this does NOT test Linux AF_PACKET,
bridge observation, a browser renderer, or competition service acceptance.
"""

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse

from packet_capture_process_smoke import decode_pcap, frame, free_port, request as archive_request

ROOT = Path(__file__).resolve().parents[2]


def run(args):
    report_path = Path(args.report).resolve()
    if report_path.exists():
        raise SystemExit("Report already exists; use a new --report path.")
    report = {"schema_version": 1, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": {"platform": sys.platform, "architecture": platform.machine(), "actual_process_gateway": True,
                        "live_af_packet": False, "capture_policy_enabled": False,
                        "synthetic_archive_ingest": True, "empty_service_registry": True,
                        "docker_used": False, "docker_endpoint_scope": "nonexistent_temporary_unix_socket",
                        "vm_touched": False, "browser_rendering": False},
              "checks": []}
    processes, logs = [], []

    def check(name, condition, **details):
        report["checks"].append({"name": name, "passed": bool(condition), **details})
        if not condition:
            raise AssertionError(name)

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    try:
        with tempfile.TemporaryDirectory(prefix="ctfm-panel-packet-", dir="/tmp") as temporary:
            temp = Path(temporary).resolve()
            temp.chmod(0o700)
            paths = {name: temp / name for name in ("policy", "games", "workspaces", "executor-state", "dashboard-state")}
            for path in paths.values():
                path.mkdir(mode=0o700)
            binaries = {"manager": Path(args.manager_binary).resolve(), "capture": Path(args.capture_binary).resolve(),
                        "archive": Path(args.archive_binary).resolve()}
            check("compiled_binaries_available", all(path.is_file() for path in binaries.values()))
            report["binaries"] = {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
                                  for name, path in binaries.items()}
            tokens = {name: secrets.token_hex(32) for name in ("capture-control", "ingest", "read")}
            for name, token in tokens.items():
                (temp / name).write_text(token + "\n")
                (temp / name).chmod(0o600)
            password = "Smoke-" + secrets.token_hex(24)
            policy = {"schema_version": 1, "revision": 1, "enabled": False, "snaplen": 0,
                      "max_packets_per_second": 1000, "interfaces": []}
            policy_file = paths["policy"] / "policy.json"
            policy_file.write_text(json.dumps(policy))
            policy_file.chmod(0o600)
            archive_port, panel_port = free_port(), free_port()
            while panel_port == archive_port:
                panel_port = free_port()
            capture_socket, archive_socket, executor_socket = (temp / name for name in ("capture.sock", "archive.sock", "executor.sock"))
            config = {"state_directory": str(paths["executor-state"]), "socket": str(executor_socket),
                      "docker_host": "unix://" + str(temp / "nonexistent-docker.sock"), "docker_binary": "/usr/bin/false",
                      "discovery_roots": [str(paths["games"])], "workspace_roots": [str(paths["workspaces"])],
                      "web_uid": os.geteuid(), "development": True,
                      "capture": {"enabled": True, "policy_directory": str(paths["policy"]),
                                  "control_url": "unix://" + str(capture_socket), "control_token_file": str(temp / "capture-control"),
                                  "packets_url": "unix://" + str(archive_socket), "packets_token_file": str(temp / "read"),
                                  "allowed_interfaces": ["br-smokefixture"]}}
            config_file = temp / "executor.json"
            config_file.write_text(json.dumps(config))
            config_file.chmod(0o600)

            def launch(command):
                log = open(temp / ("process-%d.log" % len(logs)), "x+b")
                logs.append(log)
                process = subprocess.Popen([str(value) for value in command], cwd=ROOT, stdout=log, stderr=log)
                processes.append(process)
                return process

            def wait_for(predicate, name, seconds=15):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if any(process.poll() is not None for process in processes):
                        raise AssertionError("child exited before " + name)
                    try:
                        if predicate():
                            return
                    except (OSError, http.client.HTTPException, ValueError):
                        pass
                    time.sleep(0.05)
                raise AssertionError("timeout: " + name)

            launch([binaries["archive"], "--listen", f"127.0.0.1:{archive_port}", "--control-unix", archive_socket,
                    "--state", temp / "archive-state", "--ingest-token-file", temp / "ingest", "--read-token-file", temp / "read",
                    "--quota-bytes", str(4 << 20), "--per-service-bytes", str(1 << 20), "--minimum-free-bytes", "1", "--max-records", "100"])
            launch([binaries["capture"], "--policy-file", policy_file, "--control-listen", "", "--control-unix", capture_socket,
                    "--control-token-file", temp / "capture-control", "--ingest-url", f"http://127.0.0.1:{archive_port}",
                    "--ingest-token-file", temp / "ingest"])
            wait_for(lambda: archive_socket.exists() and capture_socket.exists(), "private archive/capture sockets")
            initialized = subprocess.run([str(binaries["manager"]), "init-admin", "--state", str(paths["dashboard-state"]),
                                          "--username", "smokeadmin"], input=(password + "\n").encode(),
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            check("actual_cli_init_admin", initialized.returncode == 0)
            launch([binaries["manager"], "--config", config_file, "executor"])
            wait_for(executor_socket.exists, "executor Unix socket")
            launch([binaries["manager"], "dashboard", "--state", paths["dashboard-state"], "--socket", executor_socket,
                    "--listen", f"127.0.0.1:{panel_port}", "--allowed-hosts", f"127.0.0.1:{panel_port}"])
            origin = f"http://127.0.0.1:{panel_port}"

            def panel(path, method="GET", data=None, session=None, csrf=True, request_origin=None):
                headers = {"Origin": origin if request_origin is None else request_origin}
                if session:
                    headers["Cookie"] = session["cookie"]
                    if csrf:
                        headers["X-CSRF-Token"] = session["csrf"]
                body = None
                if data is not None:
                    body = json.dumps(data).encode()
                    headers["Content-Type"] = "application/json"
                connection = http.client.HTTPConnection("127.0.0.1", panel_port, timeout=6)
                try:
                    connection.request(method, path, body, headers)
                    response = connection.getresponse()
                    raw, response_headers = response.read(12 << 20), dict(response.getheaders())
                    decoded = json.loads(raw) if "application/json" in response.getheader("Content-Type", "") else raw
                    return response.status, decoded, response_headers
                finally:
                    connection.close()

            wait_for(lambda: panel("/healthz")[0] == 200, "dashboard HTTP")
            code, html, _ = panel("/")
            assets = re.findall(rb'(?:src|href)="(/assets/[^" ]+)"', html) if isinstance(html, bytes) else []
            check("embedded_dashboard_and_assets", code == 200 and bool(assets) and all(panel(asset.decode())[0] == 200 for asset in assets))

            def login(username, value):
                code, body, headers = panel("/api/auth/login", "POST", {"username": username, "password": value})
                if code != 200:
                    raise AssertionError("panel login failed")
                return {"cookie": headers["Set-Cookie"].split(";", 1)[0], "csrf": body["csrf_token"]}

            admin = login("smokeadmin", password)
            check("actual_dashboard_session_login", bool(admin["cookie"]) and bool(admin["csrf"]))
            code, services, _ = panel("/api/services", session=admin)
            check("empty_registry_without_docker_connection", code == 200 and services == [])
            code, targets, _ = panel("/api/capture/targets", session=admin)
            check("only_configured_interface_no_fabricated_targets", code == 200 and targets["targets"] == [] and targets["allowed_interfaces"] == ["br-smokefixture"])
            code, current, _ = panel("/api/capture/policy", session=admin)
            check("admin_reads_disabled_capture_policy", code == 200 and not current["policy"]["enabled"])
            disabled = {"expected_revision": current["desired_revision"], "enabled": False, "target_ids": [], "snaplen": 0, "max_packets_per_second": 1000}
            code, preview, _ = panel("/api/capture/preview", "POST", disabled, admin)
            check("admin_previews_disabled_policy_over_real_ipc", code == 200 and bool(preview.get("digest")) and not preview["policy"]["enabled"])
            code, confirmed, _ = panel("/api/capture/confirm", "POST", {"proposal_id": preview["proposal_id"], "digest": preview["digest"]}, admin)
            check("admin_confirms_disabled_policy_over_real_ipc", code == 200 and confirmed["desired_revision"] > current["desired_revision"])
            desired_revision = confirmed["desired_revision"]
            wait_for(lambda: panel("/api/capture/policy", session=admin)[1]["applied_revision"] == desired_revision, "capture applies confirmed disabled revision")
            check("desired_revision_observed_applied", True, desired_revision=desired_revision)
            now = dt.datetime.now(dt.timezone.utc)
            expected_frames = []
            for index, protocol in enumerate(("tcp", "udp"), 1):
                payload = b"\x00\xffCTFM-PANEL-FIXTURE-" + protocol.encode()
                data = frame(protocol, "172.20.0.9", "172.20.0.5", 40000 + index, 7000 + index, payload)
                record = {"packet_id": f"panel-fixture-{index}", "collector_epoch": "synthetic-panel-fixtures", "policy_revision": 1,
                          "at": now.isoformat().replace("+00:00", "Z"), "service_id": "fixture-game", "component": "fixture-app",
                          "interface": "br-smokefixture", "if_index": 7, "direction": "ingress", "protocol": protocol,
                          "source_ip": "172.20.0.9", "destination_ip": "172.20.0.5", "source_port": 40000 + index,
                          "destination_port": 7000 + index, "tcp_flags": 24 if protocol == "tcp" else 0, "wire_length": len(data),
                          "captured_length": len(data), "truncated": False, "link_type": 1, "attribution": "unique", "data": base64.b64encode(data).decode()}
                code, _ = archive_request(archive_port, "/v1/packets", tokens["ingest"], record, "POST")
                check("private_synthetic_" + protocol + "_archive_ingest", code == 202)
                expected_frames.append((data, len(data)))
            code, metadata, _ = panel("/api/packets?service_id=fixture-game&limit=50", session=admin)
            check("panel_metadata_via_executor_archive_contains_no_bytes", code == 200 and len(metadata["records"]) == 2 and all("data" not in item for item in metadata["records"]))
            code, raw, _ = panel("/api/packets/panel-fixture-1", session=admin)
            check("admin_raw_frame_preserved_end_to_end", code == 200 and base64.b64decode(raw["data"]) == expected_frames[0][0])
            export = {"query": {"service_ids": ["fixture-game"], "from": (now - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
                                "until": (now + dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")}, "max_packets": 10, "max_bytes": 1 << 20}
            check("export_without_csrf_denied", panel("/api/packets/export", "POST", export, admin, csrf=False)[0] == 403)
            check("export_with_foreign_origin_denied", panel("/api/packets/export", "POST", export, admin, request_origin="https://foreign.invalid")[0] == 403)
            code, pcap, headers = panel("/api/packets/export", "POST", export, admin)
            check("panel_binary_pcap_exact_tcp_udp_frames", code == 200 and decode_pcap(pcap) == expected_frames)
            normalized_headers = {key.lower(): value for key, value in headers.items()}
            check("panel_binary_pcap_bounds_headers", normalized_headers.get("content-type") == "application/vnd.tcpdump.pcap" and
                  normalized_headers.get("x-packet-count") == "2" and normalized_headers.get("x-packets-truncated") == "false")
            viewer_password = "Viewer-" + secrets.token_hex(24)
            code, _, _ = panel("/api/users", "POST", {"username": "packetviewer", "password": viewer_password, "role": "viewer", "sensitive_access": False}, admin)
            check("admin_creates_ordinary_viewer", code == 201)
            viewer = login("packetviewer", viewer_password)
            code, viewer_page, _ = panel("/api/packets?limit=50", session=viewer)
            check("viewer_metadata_allowed_without_payload", code == 200 and len(viewer_page["records"]) == 2 and
                  all("data" not in item for item in viewer_page["records"]))
            for path, method, body in (("/api/packets/panel-fixture-1", "GET", None), ("/api/packets/export", "POST", export), ("/api/capture/targets", "GET", None)):
                check("viewer_denied_" + path.rsplit("/", 1)[-1], panel(path, method, body, viewer)[0] == 403)
            code, audit, _ = panel("/api/audit", session=admin)
            check("raw_export_capture_confirm_audited", code == 200 and all(any(row["action"] == action and row["result"] == "succeeded" for row in audit)
                  for action in ("packets.raw.read", "packets.export", "capture.policy.confirm")))
            audit_text = json.dumps(audit)
            check("fixture_payload_and_credentials_absent_from_audit", "CTFM-PANEL-FIXTURE" not in audit_text and
                  all(base64.b64encode(data).decode() not in audit_text for data, _ in expected_frames) and
                  all(value not in audit_text for value in (*tokens.values(), password, viewer_password)))
            code, status, _ = panel("/api/packets/status", session=viewer)
            check("capture_remains_disabled_zero_live_observations", code == 200 and not status["capture"]["enabled"] and
                  not status["capture"].get("running", False) and status["capture"]["counters"]["observed"] == 0 and status["store"]["stored_records"] == 2)
            for process in reversed(processes):
                stop(process)
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        for process in reversed(processes):
            stop(process)
        if not report.get("passed"):
            report["process_exit_codes"] = [process.poll() for process in processes]
            report["process_error_tails"] = []
            for log in logs:
                log.seek(0)
                tail = log.read()[-2048:].decode(errors="replace")
                for secret in list(locals().get("tokens", {}).values()) + [locals().get("password", ""), locals().get("viewer_password", "")]:
                    if secret:
                        tail = tail.replace(secret, "[redacted]")
                report["process_error_tails"].append(tail)
        for log in logs:
            log.close()
        report["all_child_processes_stopped"] = all(process.poll() is not None for process in processes)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]), "report": str(report_path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--manager-binary", default=str(ROOT / "bin/ctf-manager"))
    parser.add_argument("--capture-binary", default=str(ROOT / "bin/ctfm-capture"))
    parser.add_argument("--archive-binary", default=str(ROOT / "bin/ctfm-packets"))
    sys.exit(run(parser.parse_args()))
