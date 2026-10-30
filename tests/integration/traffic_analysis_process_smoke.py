#!/usr/bin/env python3
"""Real panel/Unix IPC/archive traffic analysis with private synthetic fixtures.

Four production processes run locally. Capture stays disabled: a trusted helper
seeds a private fixture registry and synthetic Ethernet/TCP/HTTP2/gRPC records
enter the authenticated archive fixture-ingest API. This does not cover live
AF_PACKET, Docker, service registration, a browser renderer, or VM acceptance.
No installed configuration, real service data, or system CA store is changed.
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
import signal
import subprocess
import sys
import tempfile
import time

from packet_capture_process_smoke import free_port, request as archive_request

ROOT = Path(__file__).resolve().parents[2]


def run(args):
    report_path = Path(args.report).resolve()
    if report_path.exists():
        raise SystemExit("Report already exists; use a new --report path.")
    report = {"schema_version": 1, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "fixture_sha256": hashlib.sha256((ROOT / "tests/integration/analysis_fixture/main.go").read_bytes()).hexdigest(),
              "scope": {"platform": sys.platform, "architecture": platform.machine(),
                        "actual_process_gateway": True, "production_process_count": 4,
                        "live_af_packet": False, "capture_policy_enabled": False,
                        "synthetic_archive_ingest": True, "seeded_fixture_registry": True,
                        "service_registration_tested": False, "docker_used": False,
                        "docker_endpoint_scope": "nonexistent_temporary_unix_socket",
                        "vm_touched": False, "browser_rendering": False}, "checks": []}
    processes, logs, secret_values = [], [], []
    temp = None

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
        with tempfile.TemporaryDirectory(prefix="ctfm-analysis-panel-", dir="/tmp") as temporary:
            temp = Path(temporary).resolve()
            temp.chmod(0o700)
            try:
                paths = {name: temp / name for name in ("policy", "games", "workspaces", "executor-state", "dashboard-state")}
                for path in paths.values():
                    path.mkdir(mode=0o700)
                environment = {**os.environ, "GOCACHE": str(ROOT / ".cache/go-build"),
                               "GOMODCACHE": str(ROOT / ".cache/go-mod"), "GOPROXY": "off"}
                binaries = {}
                specs = (("manager", args.manager_binary, "./cmd/ctf-manager"),
                         ("capture", args.capture_binary, "./cmd/ctfm-capture"),
                         ("archive", args.archive_binary, "./cmd/ctfm-packets"),
                         ("fixture", args.fixture_binary, "./tests/integration/analysis_fixture"))
                report["binaries"] = {}
                for name, supplied, package in specs:
                    path = Path(supplied).resolve() if supplied else temp / ("ctfm-" + name)
                    if not supplied:
                        built = subprocess.run(["go", "build", "-trimpath", "-o", str(path), package], cwd=ROOT,
                                               env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
                        if built.returncode:
                            raise AssertionError(name + " build failed: " + built.stderr[-2048:].decode(errors="replace"))
                    if not path.is_file():
                        raise AssertionError(name + " binary missing")
                    binaries[name] = path
                    report["binaries"][name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                                "bytes": path.stat().st_size, "supplied": bool(supplied)}
                check("production_binaries_and_fixture_available", True)
                seeded = subprocess.run([str(binaries["fixture"]), "--root", str(temp)], cwd=ROOT,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                if seeded.returncode:
                    raise AssertionError("private offline seed failed: " + seeded.stderr[-2048:].decode(errors="replace"))
                fixture = json.loads(seeded.stdout)
                check("trusted_offline_private_fixture_registry_seeded", fixture["seeded_fixture_registry"] and
                      fixture["service_id"] == "fixture-game" and len(fixture["records"]) == 24)
                tokens = {name: secrets.token_hex(32) for name in ("capture-control", "ingest", "read")}
                password, viewer_password = "Admin-" + secrets.token_hex(24), "Viewer-" + secrets.token_hex(24)
                secret_values.extend([*tokens.values(), password, viewer_password])
                for name, token in tokens.items():
                    (temp / name).write_text(token + "\n")
                    (temp / name).chmod(0o600)
                policy_file = paths["policy"] / "policy.json"
                policy_file.write_text(json.dumps({"schema_version": 1, "revision": 1, "enabled": False,
                                                   "snaplen": 0, "max_packets_per_second": 1000, "interfaces": []}))
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

                def wait_for(predicate, name, seconds=20):
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
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
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
                    connection = http.client.HTTPConnection("127.0.0.1", panel_port, timeout=8)
                    try:
                        connection.request(method, path, body, headers)
                        response = connection.getresponse()
                        raw, response_headers = response.read(12 << 20), dict(response.getheaders())
                        decoded = json.loads(raw) if "application/json" in response.getheader("Content-Type", "") else raw
                        return response.status, decoded, response_headers
                    finally:
                        connection.close()

                def login(username, value):
                    code, body, headers = panel("/api/auth/login", "POST", {"username": username, "password": value})
                    if code != 200:
                        raise AssertionError("panel login failed")
                    return {"cookie": headers["Set-Cookie"].split(";", 1)[0], "csrf": body["csrf_token"]}

                wait_for(lambda: panel("/healthz")[0] == 200, "dashboard HTTP")
                code, html, _ = panel("/")
                assets = re.findall(rb'(?:src|href)="(/assets/[^" ]+)"', html) if isinstance(html, bytes) else []
                check("embedded_dashboard_and_assets_respond", code == 200 and bool(assets) and all(panel(a.decode())[0] == 200 for a in assets))
                admin = login("smokeadmin", password)
                code, services, _ = panel("/api/services", session=admin)
                check("seeded_service_available_without_real_docker_endpoint", code == 200 and len(services) == 1 and services[0]["id"] == fixture["service_id"])
                for record in fixture["records"]:
                    code, _ = archive_request(archive_port, "/v1/packets", tokens["ingest"], record, "POST")
                    if code != 202:
                        raise AssertionError("private synthetic ingest rejected " + record["packet_id"])
                check("all_24_synthetic_ethernet_tcp_records_ingested_privately", True)
                code, page, _ = panel("/api/flows?service_id=fixture-game&protocol=tcp&limit=50", session=admin)
                check("four_flow_metadata_list_through_real_panel_executor_archive", code == 200 and len(page["flows"]) == 4 and
                      page["scanned_packets"] == 24 and bool(page["query"].get("cursor")) and bool(page["query"].get("until")))
                check("flow_metadata_excludes_sensitive_chunks", all("directions" not in flow and "data" not in flow for flow in page["flows"]))
                groups = {}
                for name, port in fixture["ports"].items():
                    groups[name] = next(flow for flow in page["flows"] if port in (flow["a"]["port"], flow["b"]["port"]))
                requests = {name: {"query": page["query"], "flow_id": flow["id"]} for name, flow in groups.items()}
                code, detail, _ = panel("/api/flows/detail", "POST", requests["known"], admin)
                by_endpoint = {direction["from"]: b"".join(base64.b64decode(chunk["data"]) for chunk in direction["chunks"])
                               for direction in detail.get("directions", [])}
                client_side = "a" if groups["known"]["a"]["port"] == fixture["ports"]["known"] else "b"
                server_side = "b" if client_side == "a" else "a"
                check("sensitive_tcp_reassembly_preserves_both_exact_h2_byte_streams", code == 200 and
                      by_endpoint[client_side] == base64.b64decode(fixture["request_bytes"]) and
                      by_endpoint[server_side] == base64.b64decode(fixture["response_bytes"]))
                code, opaque, _ = panel("/api/flows/decode", "POST", requests["known"], admin)
                rpc = opaque["rpcs"][0] if code == 200 and len(opaque.get("rpcs", [])) == 1 else {}
                check("grpc_envelope_status_trailers_decode_without_descriptor", code == 200 and opaque["protocol"] == "grpc" and
                      rpc.get("path") == "/demo.Echo/Chat" and rpc.get("grpc_status") == 0 and
                      rpc.get("grpc_message") == "fixture complete" and rpc.get("request_ended") and rpc.get("response_ended"))
                check("descriptor_free_messages_remain_opaque_exact_bytes", rpc["request_messages"][0].get("type") is None and
                      "json" not in rpc["request_messages"][0] and base64.b64decode(rpc["request_messages"][0]["data"]) == b"\x0a\x05alice" and
                      base64.b64decode(rpc["response_messages"][0]["data"]) == b"\x08\x01")
                check("analysis_without_csrf_denied", panel("/api/flows/decode", "POST", requests["known"], admin, csrf=False)[0] == 403)
                check("analysis_foreign_origin_denied", panel("/api/flows/decode", "POST", requests["known"], admin, request_origin="https://foreign.invalid")[0] == 403)
                preview_request = {"service_id": fixture["service_id"], "data": fixture["descriptor"]}
                check("browser_cannot_forge_descriptor_initiator", panel("/api/descriptors/preview", "POST", {**preview_request, "initiator": "forged-user"}, admin)[0] == 400)
                code, preview, _ = panel("/api/descriptors/preview", "POST", preview_request, admin)
                check("admin_descriptor_preview_pins_trusted_current_release_and_source", code == 200 and
                      preview["info"]["binding"] == {"service_id": fixture["service_id"], "release_id": fixture["release_id"], "source_digest": fixture["source_digest"]} and
                      bool(preview.get("proposal_id")) and not preview["confirmed"])
                descriptor_id = preview["id"]
                bound = {**requests["known"], "descriptor_id": descriptor_id}
                check("unconfirmed_descriptor_cannot_name_messages", panel("/api/flows/decode", "POST", bound, admin)[0] in (400, 404))
                bad = {"proposal_id": preview["proposal_id"], "digest": "sha256:" + "0" * 64}
                check("wrong_confirmation_digest_rejected", panel("/api/descriptors/confirm", "POST", bad, admin)[0] == 409)
                code, confirmed, _ = panel("/api/descriptors/confirm", "POST", {"proposal_id": preview["proposal_id"], "digest": preview["digest"]}, admin)
                check("admin_confirms_descriptor_via_panel_only", code == 200 and confirmed["confirmed"] and confirmed["id"] == descriptor_id)
                code, named, _ = panel("/api/flows/decode", "POST", bound, admin)
                rpc = named["rpcs"][0] if code == 200 and len(named.get("rpcs", [])) == 1 else {}
                check("trusted_version_descriptor_decodes_exact_named_protobuf_json", code == 200 and
                      rpc["request_messages"][0].get("type") == "demo.Request" and rpc["request_messages"][0].get("json") == {"name": "alice"} and
                      rpc["response_messages"][0].get("type") == "demo.Response" and rpc["response_messages"][0].get("json") == {"ok": True} and
                      rpc.get("client_streaming") is True and rpc.get("server_streaming") is True)
                if args.browser_script:
                    browser_script = Path(args.browser_script).resolve()
                    if not browser_script.is_file():
                        raise AssertionError("optional browser helper missing")
                    browser_context = {"origin": origin, "username": "smokeadmin", "password": password,
                                       "descriptorBase64": fixture["descriptor"], "descriptorID": descriptor_id,
                                       "serviceID": fixture["service_id"], "releaseID": fixture["release_id"],
                                       "knownPort": fixture["ports"]["known"]}
                    # Put Chromium's disposable profile/cache under this private
                    # fixture and reap its process group if the helper hangs.
                    browser = subprocess.Popen(["node", str(browser_script)], cwd=ROOT,
                                               env={**os.environ, "TMPDIR": str(temp)}, stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                    try:
                        browser_stdout, _ = browser.communicate(json.dumps(browser_context).encode(), timeout=90)
                    except subprocess.TimeoutExpired:
                        os.killpg(browser.pid, signal.SIGTERM)
                        try:
                            browser.communicate(timeout=3)
                        except subprocess.TimeoutExpired:
                            os.killpg(browser.pid, signal.SIGKILL)
                            browser.communicate(timeout=3)
                        raise AssertionError("optional browser helper exceeded its deadline") from None
                    try:
                        browser_result = json.loads(browser_stdout)
                    except (ValueError, UnicodeError):
                        raise AssertionError("optional browser helper did not return bounded JSON") from None
                    report["browser"] = browser_result
                    report["scope"]["browser_rendering"] = bool(browser_result.get("launched"))
                    check("optional_headless_browser_checks", browser.returncode == 0 and
                          (browser_result.get("passed") or browser_result.get("unavailable")))
                for name in ("legacy", "wrong-version", "mixed-version"):
                    code, refused, _ = panel("/api/flows/decode", "POST", {**requests[name], "descriptor_id": descriptor_id}, admin)
                    check(name.replace("-", "_") + "_captured_version_refuses_descriptor_names", code == 400 and "rpcs" not in refused)
                code, user, _ = panel("/api/users", "POST", {"username": "analysisviewer", "password": viewer_password,
                                                           "role": "viewer", "sensitive_access": False}, admin)
                check("admin_creates_ordinary_viewer", code == 201)
                viewer = login("analysisviewer", viewer_password)
                code, viewer_page, _ = panel("/api/flows?limit=50", session=viewer)
                check("ordinary_viewer_reads_only_flow_metadata", code == 200 and len(viewer_page["flows"]) == 4 and
                      all("directions" not in flow for flow in viewer_page["flows"]))
                check("ordinary_viewer_denied_raw_decode_and_descriptor_metadata", all(
                    panel(path, method, body, viewer)[0] == 403 for path, method, body in
                    (("/api/flows/detail", "POST", requests["known"]), ("/api/flows/decode", "POST", bound), ("/api/descriptors", "GET", None))))
                code, _, _ = panel("/api/users/" + user["id"], "PATCH", {"sensitive_access": True}, admin)
                check("admin_grants_sensitive_access", code == 200)
                sensitive_viewer = login("analysisviewer", viewer_password)
                code, visible, _ = panel("/api/descriptors", session=sensitive_viewer)
                check("sensitive_viewer_gets_descriptor_metadata_without_schema_methods", code == 200 and len(visible) == 1 and
                      visible[0]["method_count"] == 1 and not visible[0]["info"].get("methods"))
                check("sensitive_viewer_can_decode_bound_grpc", panel("/api/flows/decode", "POST", bound, sensitive_viewer)[0] == 200)
                check("sensitive_viewer_cannot_mutate_descriptor_schema", all(
                    panel(path, method, body, sensitive_viewer)[0] == 403 for path, method, body in
                    (("/api/descriptors/preview", "POST", preview_request),
                     ("/api/descriptors/confirm", "POST", {"proposal_id": preview["proposal_id"], "digest": preview["digest"]}),
                     ("/api/descriptors/" + descriptor_id, "DELETE", None))))
                code, _, _ = panel("/api/users/" + user["id"] + "/revoke-sessions", "POST", {}, admin)
                check("revoked_sensitive_session_cannot_read_retained_analysis", code == 200 and
                      panel("/api/flows/detail", "POST", requests["known"], sensitive_viewer)[0] == 401)
                code, _, _ = panel("/api/descriptors/" + descriptor_id, "DELETE", session=admin)
                check("admin_deletes_descriptor_through_panel", code == 200)
                code, deleted, _ = panel("/api/descriptors", session=admin)
                check("deleted_descriptor_absent_from_metadata", code == 200 and deleted == [])
                check("deleted_descriptor_cannot_continue_naming_payloads", panel("/api/flows/decode", "POST", bound, admin)[0] in (400, 404))
                code, after, _ = panel("/api/flows/decode", "POST", requests["known"], admin)
                check("descriptor_deletion_preserves_opaque_grpc_bytes", code == 200 and
                      after["rpcs"][0]["request_messages"][0]["data"] == opaque["rpcs"][0]["request_messages"][0]["data"] and
                      "json" not in after["rpcs"][0]["request_messages"][0] and "type" not in after["rpcs"][0]["request_messages"][0])
                code, audit, _ = panel("/api/audit", session=admin)
                check("raw_decode_preview_confirm_delete_revoke_success_audited", code == 200 and all(
                    any(row["action"] == action and row["result"] == "succeeded" for row in audit)
                    for action in ("flows.raw.read", "flows.grpc.decode", "descriptors.preview", "descriptors.confirm", "descriptors.delete", "session.revoke")))
                audit_text = json.dumps(audit)
                check("audit_excludes_payload_descriptor_and_credentials", all(value not in audit_text for value in
                      [*secret_values, fixture["descriptor"], fixture["request_bytes"], fixture["response_bytes"], "alice"]))
                code, status, _ = panel("/api/packets/status", session=admin)
                check("capture_stays_disabled_zero_live_packets_all_synthetic_frames_retained", code == 200 and
                      not status["capture"]["enabled"] and not status["capture"].get("running", False) and
                      status["capture"]["counters"]["observed"] == 0 and status["store"]["stored_records"] == 24)
                check("all_four_production_processes_remain_alive", len(processes) == 4 and all(p.poll() is None for p in processes))
                report["passed"] = True
            finally:
                for process in reversed(processes):
                    stop(process)
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
                for value in secret_values:
                    tail = tail.replace(value, "[redacted]")
                report["process_error_tails"].append(tail)
        for log in logs:
            log.close()
        report["all_child_processes_stopped"] = all(process.poll() is not None for process in processes)
        report["private_fixture_removed_on_exit"] = temp is None or not temp.exists()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]), "report": str(report_path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--manager-binary", help="Existing binary; otherwise compile into private fixture directory")
    parser.add_argument("--capture-binary", help="Existing binary; otherwise compile into private fixture directory")
    parser.add_argument("--archive-binary", help="Existing binary; otherwise compile into private fixture directory")
    parser.add_argument("--fixture-binary", help="Existing trusted fixture helper; otherwise compile privately")
    parser.add_argument("--browser-script", help="Optional trusted local browser helper; fixture credentials are passed only through stdin")
    sys.exit(run(parser.parse_args()))
