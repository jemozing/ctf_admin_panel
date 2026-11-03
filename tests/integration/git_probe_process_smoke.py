#!/usr/bin/env python3
"""Browser contract smoke with a real dashboard and a fake Unix executor.

The fixture advertises bounded synthetic Git refs. It does not contact GitHub,
run Git, access Docker, register a service or save credentials. Real HTTPS Git
transport is covered separately by sourcegit tests. Secrets enter only stdin
and memory; reports exclude paths, credentials, process logs and screenshots.
"""

import argparse
import datetime as dt
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = "/srv/ctfm-ui-services"
FIXTURE_SERVICE = FIXTURE_ROOT + "/game"


def run(args):
    report_path = Path(args.report).resolve()
    if report_path.exists():
        raise SystemExit("Report already exists; choose a new report path.")
    report = {"schema_version": 1, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": {"actual_dashboard": True, "actual_init_admin": True, "actual_browser": True,
                        "executor_protocol_fixture": True, "real_git_transport": False,
                        "external_network": False, "docker_used": False, "vm_touched": False,
                        "service_registered": False, "screenshots_or_credentials_retained": False},
              "checks": [], "passed": False}
    processes, logs = [], []
    server = server_thread = None
    tracking = {"probe_requests": 0, "directory_requests": 0, "delayed_directories": 0,
                "registration_inspects": 0, "write_requests": 0,
                "default_ref_seen": False, "full_branch_seen": False, "valid_token_seen": False,
                "invalid_token_rejected": False, "delayed_probes": 0, "registration_scope_only": True}
    lock = threading.Lock()
    token, invalid_token = secrets.token_hex(24), secrets.token_hex(24)

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def stop(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)

    class ExecutorServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = False

        def handle_error(self, request, client_address):
            # Do not print request bodies, credentials or connection diagnostics.
            pass

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *values):
            pass

        def reply(self, status, value):
            data = json.dumps(value).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            if self.path == "/v1/fixture/status":
                with lock:
                    self.reply(200, {key: tracking[key] for key in ("delayed_probes", "delayed_directories")})
            elif self.path == "/v1/health":
                self.reply(200, {"status": "ok", "schema_version": 1})
            elif self.path in ("/v1/services", "/v1/operations"):
                self.reply(200, [])
            elif self.path == "/v1/registration/options":
                self.reply(200, {"discovery_roots": [FIXTURE_ROOT], "workspace_roots": ["/srv/ctfm-ui-workspaces"]})
            else:
                self.reply(404, {"code": "not_found", "message": "Fixture endpoint unavailable"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 16384:
                self.reply(413, {"code": "body_too_large", "message": "Fixture request exceeds limit"})
                return
            try:
                data = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeError):
                self.reply(400, {"code": "invalid_request", "message": "Invalid fixture request"})
                return
            if self.path == "/v1/registration/inspect":
                with lock:
                    tracking["registration_inspects"] += 1
                if data.get("project_directory") != FIXTURE_SERVICE:
                    self.reply(400, {"code": "invalid_registration", "message": "Unexpected fixture directory"})
                    return
                self.reply(200, {"service": {"schema_version": 1, "id": "draft-git-probe", "name": "Git probe fixture",
                                           "description": "Synthetic browser contract fixture", "compose_project": "fixture-game",
                                           "project_directory": FIXTURE_SERVICE, "source_directory": "/srv/ctfm-ui-workspaces/game",
                                           "compose_files": ["compose.yaml"], "profiles": [], "policy_revision": 1,
                                           "file_map_revision": 1, "managed_paths": [{"path": "app", "kind": "code"}],
                                           "data_paths": [], "targets": ["app"],
                                           "containers": [{"component": "app", "role": "application", "id": "a" * 64,
                                                           "image_id": "sha256:" + "b" * 64}]}, "warnings": []})
                return
            if self.path == "/v1/git/directories":
                source = data.get("source", {})
                directory = data.get("directory")
                alternate = source.get("ref") == "refs/heads/feature/next"
                paths = {"": ["alternate"] if alternate else ["vuln-service"],
                         "vuln-service": ["web"], "vuln-service/web": []}
                with lock:
                    tracking["directory_requests"] += 1
                    tracking["registration_scope_only"] &= not bool(data.get("service_id"))
                    if directory == "vuln-service/web":
                        tracking["delayed_directories"] += 1
                if directory == "vuln-service/web":
                    time.sleep(1)
                if directory not in paths or "subdirectory" in source:
                    self.reply(400, {"code": "invalid_request", "message": "Invalid fixture path"})
                    return
                listing = {"directory": directory, "truncated": False, "directories": [
                    {"name": name, "path": f"{directory}/{name}" if directory else name}
                    for name in paths[directory]]}
                if directory:
                    listing["parent"] = directory.rpartition("/")[0]
                self.reply(200, listing)
                return
            if self.path != "/v1/git/probe":
                with lock:
                    tracking["write_requests"] += 1
                self.reply(409, {"code": "fixture_write_forbidden", "message": "Fixture does not permit writes"})
                return
            source = data.get("source", {})
            ref = source.get("ref") or "HEAD"
            with lock:
                tracking["probe_requests"] += 1
                tracking["default_ref_seen"] |= ref == "HEAD"
                tracking["full_branch_seen"] |= ref == "refs/heads/feature/next"
                tracking["registration_scope_only"] &= not bool(data.get("service_id"))
                tracking["valid_token_seen"] |= source.get("token") == token
            if source.get("url", "").endswith("/slow.git"):
                with lock:
                    tracking["delayed_probes"] += 1
                time.sleep(2.4)
            if source.get("token", "") not in ("", token):
                with lock:
                    tracking["invalid_token_rejected"] = True
                self.reply(502, {"code": "git_access_failed", "message": "Repository access failed; verify URL and credentials"})
                return
            branches = [{"name": "main", "ref": "refs/heads/main", "commit": "a" * 40},
                        {"name": "feature/next", "ref": "refs/heads/feature/next", "commit": "b" * 40}]
            status = "available" if ref in ("HEAD", "main", "refs/heads/main", "feature/next", "refs/heads/feature/next") else "missing"
            if ref == "release":
                status = "ambiguous"
            if ref == "c" * 40:
                status = "unverified"
            empty = source.get("url", "").endswith("/empty.git")
            result = {"branches": [] if empty else branches, "selected_ref": ref,
                      "ref_status": "missing" if empty else status,
                      "truncated": source.get("url", "").endswith("/many.git"),
                      "checked_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            if not empty:
                result["default_branch"] = "main"
            if status == "available" and not empty:
                result["resolved_commit"] = "b" * 40 if "feature/next" in ref else "a" * 40
            self.reply(200, result)

    try:
        with tempfile.TemporaryDirectory(prefix="ctfm-git-ui-", dir="/tmp") as temporary:
            temp = Path(temporary).resolve()
            temp.chmod(0o700)
            try:
                manager = Path(args.manager_binary).resolve()
                check("compiled_manager_available", manager.is_file() and os.access(manager, os.X_OK))
                report["manager_binary"] = {"sha256": hashlib.sha256(manager.read_bytes()).hexdigest(), "bytes": manager.stat().st_size}
                state = temp / "dashboard-state"
                state.mkdir(mode=0o700)
                password = "Git-UI-Smoke-" + secrets.token_hex(24)
                initialized = subprocess.run([str(manager), "init-admin", "--state", str(state), "--username", "gitprobeadmin"],
                                             input=(password + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
                check("real_cli_init_admin", initialized.returncode == 0)
                executor_socket = temp / "executor.sock"
                server = ExecutorServer(str(executor_socket), Handler)
                executor_socket.chmod(0o600)
                server_thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
                server_thread.start()
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    port = listener.getsockname()[1]
                origin = "http://127.0.0.1:" + str(port)
                log = (temp / "dashboard.log").open("x+b")
                logs.append(log)
                dashboard = subprocess.Popen([str(manager), "dashboard", "--state", str(state), "--socket", str(executor_socket),
                                              "--listen", "127.0.0.1:" + str(port), "--allowed-hosts", "127.0.0.1:" + str(port)],
                                             cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                processes.append(dashboard)
                deadline = time.monotonic() + 20
                ready = False
                while time.monotonic() < deadline and dashboard.poll() is None:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                    try:
                        connection.request("GET", "/healthz")
                        response = connection.getresponse()
                        response.read()
                        ready = response.status == 200
                    except (OSError, http.client.HTTPException):
                        pass
                    finally:
                        connection.close()
                    if ready:
                        break
                    time.sleep(0.05)
                check("actual_dashboard_ready", ready)
                companion = subprocess.Popen([args.node_binary, str(Path(__file__).with_name("git_probe_browser_smoke.cjs"))],
                                             cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             text=True, start_new_session=True)
                processes.append(companion)
                browser_input = {"origin": origin, "username": "gitprobeadmin", "password": password,
                                 "service": FIXTURE_SERVICE, "token": token, "invalid_token": invalid_token,
                                 "executor_socket": str(executor_socket)}
                output, _ = companion.communicate(json.dumps(browser_input), timeout=150)
                check("browser_report_bounded", len(output) <= 65536)
                report["browser"] = json.loads(output)
                check("actual_browser_git_controls", companion.returncode == 0 and report["browser"].get("passed", False))
                check("browser_closed", report["browser"].get("browser_closed", False))
                with lock:
                    report["fixture"] = dict(tracking)
                check("read_only_registration_context", tracking["registration_inspects"] == 1 and tracking["write_requests"] == 0 and tracking["registration_scope_only"])
                check("drafts_and_credentials_reached_protocol_fixture", tracking["probe_requests"] >= 10 and tracking["default_ref_seen"] and tracking["full_branch_seen"] and tracking["valid_token_seen"] and tracking["invalid_token_rejected"] and tracking["delayed_probes"] >= 2)
                report["passed"] = True
            finally:
                for process in reversed(processes):
                    stop(process)
                if server is not None:
                    server.shutdown()
                    server.server_close()
                if server_thread is not None:
                    server_thread.join(timeout=3)
                for log in logs:
                    log.close()
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["passed"] = False
    finally:
        for process in reversed(processes):
            stop(process)
        report["all_child_processes_stopped"] = all(process.poll() is not None for process in processes)
        report["executor_fixture_stopped"] = server_thread is None or not server_thread.is_alive()
        report["passed"] &= report["all_child_processes_stopped"] and report["executor_fixture_stopped"]
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]),
                      "browser_checks": len(report.get("browser", {}).get("checks", [])),
                      "all_child_processes_stopped": report["all_child_processes_stopped"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manager-binary", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--node-binary", default="node")
    sys.exit(run(parser.parse_args()))
