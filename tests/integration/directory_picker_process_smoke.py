#!/usr/bin/env python3
"""Real dashboard/executor/browser smoke for directory selection, without Docker.

Uses fresh temporary state, an administrator created through the real CLI and a
nonexistent temporary Docker socket. No containers are created or registered.
The report excludes credentials, local paths, process logs and screenshots.
"""

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(args):
    report_path = Path(args.report).resolve()
    if report_path.exists():
        raise SystemExit("Report already exists; use a new --report path.")
    report = {
        "schema_version": 1,
        "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": {
            "platform": sys.platform,
            "architecture": platform.machine(),
            "actual_dashboard_executor_processes": True,
            "actual_browser": True,
            "api_mocking": False,
            "docker_used": False,
            "docker_endpoint_scope": "nonexistent_temporary_unix_socket",
            "vm_touched": False,
            "containers_registered": False,
            "screenshots_or_credentials_retained": False,
        },
        "checks": [],
        "passed": False,
    }
    processes, logs = [], []

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def stop(process):
        if process.poll() is None:
            # These groups belong only to this fixture. Include Chromium if a
            # timed-out Node companion cannot close it through Playwright.
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

    try:
        with tempfile.TemporaryDirectory(prefix="ctfm-dir-picker-", dir="/tmp") as temporary:
            temp = Path(temporary).resolve()
            temp.chmod(0o700)
            try:
                manager = Path(args.manager_binary).resolve()
                check("compiled_manager_available", manager.is_file() and os.access(manager, os.X_OK))
                report["manager_binary"] = {
                    "sha256": hashlib.sha256(manager.read_bytes()).hexdigest(),
                    "bytes": manager.stat().st_size,
                }
                games, workspaces, executor_state, dashboard_state, outside = (
                    temp / name for name in ("games", "workspaces", "executor-state", "dashboard-state", "outside")
                )
                for path in (games, workspaces, executor_state, dashboard_state, outside):
                    path.mkdir(mode=0o700)
                service, empty = games / "service", games / "empty"
                service.mkdir(mode=0o700)
                empty.mkdir(mode=0o700)
                (service / "components").mkdir(mode=0o700)
                (service / "compose.yaml").write_text("services:\n  app:\n    image: busybox:1.37\n")
                (games / "ordinary-file.txt").write_text("Not a directory.\n")
                (outside / "external-only").mkdir(mode=0o700)
                (games / "linked-service").symlink_to(outside, target_is_directory=True)
                password = "Directory-Smoke-" + secrets.token_hex(24)
                executor_socket = temp / "executor.sock"
                config = {
                    "state_directory": str(executor_state),
                    "socket": str(executor_socket),
                    "docker_host": "unix://" + str(temp / "nonexistent-docker.sock"),
                    "docker_binary": "/usr/bin/false",
                    "discovery_roots": [str(games)],
                    "workspace_roots": [str(workspaces)],
                    "web_uid": os.geteuid(),
                    "development": True,
                }
                config_file = temp / "executor.json"
                config_file.write_text(json.dumps(config))
                config_file.chmod(0o600)

                def launch(command):
                    log = (temp / ("process-%d.log" % len(logs))).open("x+b")
                    logs.append(log)
                    process = subprocess.Popen([str(value) for value in command], cwd=ROOT,
                                               stdout=log, stderr=log, start_new_session=True)
                    processes.append(process)
                    return process

                def wait_for(predicate, name):
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if any(process.poll() is not None for process in processes):
                            raise AssertionError("fixture_child_exited")
                        try:
                            if predicate():
                                return
                        except (OSError, http.client.HTTPException):
                            pass
                        time.sleep(0.05)
                    raise AssertionError(name)

                initialized = subprocess.run(
                    [str(manager), "init-admin", "--state", str(dashboard_state), "--username", "directoryadmin"],
                    input=(password + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
                )
                check("actual_cli_init_admin", initialized.returncode == 0)
                launch([manager, "--config", config_file, "executor"])
                wait_for(executor_socket.exists, "executor_socket_timeout")
                panel_port = free_port()
                origin = "http://127.0.0.1:" + str(panel_port)
                launch([manager, "dashboard", "--state", dashboard_state, "--socket", executor_socket,
                        "--listen", "127.0.0.1:" + str(panel_port), "--allowed-hosts", "127.0.0.1:" + str(panel_port)])

                def health():
                    connection = http.client.HTTPConnection("127.0.0.1", panel_port, timeout=2)
                    try:
                        connection.request("GET", "/healthz")
                        response = connection.getresponse()
                        response.read()
                        return response.status == 200
                    finally:
                        connection.close()

                wait_for(health, "dashboard_http_timeout")
                check("real_dashboard_http_ready", True)
                browser_input = {"origin": origin, "username": "directoryadmin", "password": password,
                                 "root": str(games), "service": str(service), "empty": str(empty)}
                companion = subprocess.Popen(
                    [args.node_binary, str(Path(__file__).with_name("directory_picker_browser_smoke.cjs"))],
                    cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, start_new_session=True,
                )
                processes.append(companion)
                output, _ = companion.communicate(json.dumps(browser_input), timeout=150)
                if len(output) > 65536:
                    raise AssertionError("browser_report_exceeds_limit")
                report["browser"] = json.loads(output)
                check("real_browser_directory_navigation", companion.returncode == 0 and report["browser"].get("passed", False))
                check("browser_closed_before_fixture_shutdown", report["browser"].get("browser_closed", False))
                report["passed"] = True
            finally:
                for process in reversed(processes):
                    stop(process)
                for log in logs:
                    log.close()
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["passed"] = False
    finally:
        for process in reversed(processes):
            stop(process)
        report["all_child_processes_stopped"] = all(process.poll() is not None for process in processes)
        report["passed"] = report["passed"] and report["all_child_processes_stopped"]
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
