#!/usr/bin/env python3
"""Exercise an isolated dashboard/executor Compose stack, without game projects.

Build the two images first with `docker compose build`. Only a uniquely named
panel project and a new temporary native Docker volume are created. Existing game
containers are never registered, stopped, or recreated.

Native Linux storage preserves UID/GID even when the client runs on macOS. The
volume is bind-mounted at its exact daemon-side mountpoint; no game data is used.
"""

import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


REPOSITORY = Path(__file__).resolve().parents[2]
PASSWORD = "compose-smoke-admin-password"


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed: {args[0]} {' '.join(args[1:4])}\n{result.stderr[-4000:]}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPOSITORY / "tests/integration/reports/compose-smoke-2026-10-19.json")
    args = parser.parse_args()
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker CLI is required")
    context = json.loads(command([docker, "context", "inspect"]))[0]
    endpoint = os.environ.get("DOCKER_HOST", context["Endpoints"]["docker"]["Host"])
    if not endpoint.startswith("unix:///"):
        parser.error("only an explicitly local Unix Docker socket is supported")
    socket_path = endpoint.removeprefix("unix://")
    identifier = uuid.uuid4().hex[:12]
    project = "ctfm-panel-smoke-" + identifier
    volume_name = project + "-state"
    command([docker, "volume", "create", volume_name])
    state = Path(json.loads(command([docker, "volume", "inspect", volume_name]))[0]["Mountpoint"])
    launch = Path(tempfile.mkdtemp(prefix=project + "-launch-")).resolve()
    report = {"test": "compose-panel", "status": "failed", "project": project, "game_projects_registered": 0, "storage": "isolated native Docker volume; exact daemon mountpoint bind; no game data"}
    server = json.loads(command([docker, "version", "--format", "{{json .Server}} "]))
    report["runtime"] = {"os": server["Os"], "architecture": server["Arch"], "engine_version": server["Version"], "host_compose": command([docker, "compose", "version"]).strip()}
    # Only this dedicated temporary root and read-only source checkout are exposed
    # to the one-shot Linux bootstrap helper. The daemon socket is stat'ed only.
    helper = [docker, "run", "--rm", "--mount", f"type=bind,source={state},target={state}", "--mount", f"type=bind,source={REPOSITORY},target={REPOSITORY},readonly", "--mount", f"type=bind,source={socket_path},target=/var/run/docker.sock", "python:3.11-slim", "python3", "-c"]
    compose = None
    try:
        prepare = """
import json, os, subprocess, sys
from pathlib import Path
root, repository = map(Path, sys.argv[1:])
os.chown(root, 0, 0); os.chmod(root, 0o755)
result = subprocess.run(['python3', str(repository/'scripts/compose-bootstrap.py'), '--root', str(root)], capture_output=True, text=True)
if result.returncode: raise RuntimeError(result.stderr)
print(json.dumps({'environment': (root/'config/compose.env').read_text(), 'mounts': (root/'config/compose.mounts.yaml').read_text()}))
"""
        prepared = json.loads(command(helper + [prepare, str(state), str(REPOSITORY)]))
        mounts = launch / "compose.mounts.yaml"
        mounts.write_text(prepared["mounts"])
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = prepared["environment"].replace(str(state / "config/compose.mounts.yaml"), str(mounts))
        environment = environment.replace("CTFM_DOCKER_SOCKET=/var/run/docker.sock", f"CTFM_DOCKER_SOCKET={socket_path}")
        environment = environment.replace("CTFM_PORT=8765", f"CTFM_PORT={port}")
        environment = environment.replace("CTFM_ALLOWED_HOSTS=localhost:8765,127.0.0.1:8765", f"CTFM_ALLOWED_HOSTS=localhost:{port},127.0.0.1:{port},127.0.0.1:8765")
        env_file = launch / "compose.env"
        env_file.write_text(environment)
        compose = [docker, "compose", "--project-name", project, "--env-file", str(env_file)]
        command(compose + ["config", "--quiet"])
        command(compose + ["run", "--rm", "--no-deps", "-T", "dashboard", "init-admin", "--state", "/var/lib/ctf-manager", "--username", "admin"], input=PASSWORD + "\n")
        command(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
        base = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def request(path, payload=None, csrf=None):
            headers = {}
            data = None
            if payload is not None:
                data = json.dumps(payload).encode()
                headers.update({"Content-Type": "application/json", "Origin": base})
                if csrf:
                    headers["X-CSRF-Token"] = csrf
            req = urllib.request.Request(base + path, data=data, headers=headers)
            try:
                with opener.open(req, timeout=10) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as error:
                return error.code, error.read()

        assert request("/healthz")[0] == 200
        assert request("/api/services")[0] == 401
        assert request("/api/metrics/host")[0] == 401
        assert b'id="root"' in request("/")[1]

        def login():
            status, body = request("/api/auth/login", {"username": "admin", "password": PASSWORD})
            assert status == 200, (status, body)
            status, body = request("/api/auth/session")
            assert status == 200
            return json.loads(body)["csrf_token"]

        login()
        assert json.loads(request("/api/status")[1])["executor"] == "ok"
        assert json.loads(request("/api/services")[1]) == []
        host_metrics = json.loads(request("/api/metrics/host")[1])
        assert host_metrics["retention_seconds"] == 3600
        assert host_metrics["history_storage"] == "memory"
        assert host_metrics["latest"]["cpu_percent"] is None
        assert host_metrics["latest"]["memory_total_bytes"] is None
        assert host_metrics["latest"]["source"] == "unconfigured"
        assert request("/api/metrics/host?path=/proc/stat")[0] == 400
        report["unconfigured_host_metrics_are_nullable"] = True
        report["host_metrics_require_login_and_reject_query_paths"] = True
        assert request("/api/operations", {"command": "not-a-valid-action"})[0] == 403
        report.update(authenticated_ipc=True, unauthorized_api_rejected=True, csrf_rejected=True, embedded_frontend=True)

        ids = {name: command(compose + ["ps", "--quiet", name]).strip() for name in ("dashboard", "executor")}
        report["images"] = {}
        for name, container_id in ids.items():
            info = json.loads(command([docker, "inspect", container_id]))[0]
            report["images"][name] = info["Image"]
            assert not info["HostConfig"]["Privileged"]
            assert info["HostConfig"]["ReadonlyRootfs"]
            assert info["HostConfig"]["CapDrop"] == ["ALL"]
            for setting in ("PidMode", "IpcMode", "UTSMode", "NetworkMode"):
                assert info["HostConfig"].get(setting) != "host"
            if name == "dashboard":
                assert info["Config"]["User"] == "10001:10001"
                assert {item["Destination"] for item in info["Mounts"] if item["Type"] == "bind"} == {"/var/lib/ctf-manager", "/run/ctf-manager"}
                assert {item["Destination"] for item in info["Mounts"]} <= {"/tmp", "/var/lib/ctf-manager", "/run/ctf-manager"}
                assert "/tmp" in info["HostConfig"]["Tmpfs"]
                assert not next(item for item in info["Mounts"] if item["Destination"] == "/run/ctf-manager")["RW"]
        report["mount_uid_isolation"] = True
        report["runtime"]["executor_compose"] = command(compose + ["exec", "-T", "executor", "docker", "compose", "version"]).strip()

        command([docker, "kill", "--signal", "KILL", ids["executor"]])
        # Docker treats an API-requested kill as a manual stop for restart policy.
        # Start the same container, preserving the abrupt-death socket and state.
        command([docker, "start", ids["executor"]])
        for _ in range(60):
            time.sleep(0.5)
            if json.loads(request("/api/status")[1]).get("executor") == "ok":
                break
        else:
            raise AssertionError("executor did not recover its IPC socket after SIGKILL")
        report["executor_sigkill_recovery"] = True

        command(compose + ["restart", "dashboard"])
        for _ in range(40):
            time.sleep(0.25)
            try:
                if request("/healthz")[0] == 200:
                    break
            except OSError:
                pass
        assert request("/api/auth/session")[0] == 401
        login()
        report.update(account_persistence=True, restart_revokes_sessions=True)

        command(compose + ["stop", "executor"])
        assert json.loads(request("/api/status")[1])["executor"] == "unavailable"
        assert request("/healthz")[0] == 200
        report["dashboard_survives_executor_stop"] = True
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        if compose:
            try:
                report["panel_logs"] = command(compose + ["logs", "--no-color", "--tail", "30"])[-8000:]
                for name in ("dashboard", "executor"):
                    container_id = command(compose + ["ps", "--all", "--quiet", name]).strip()
                    if container_id:
                        report[name + "_health"] = json.loads(command([docker, "inspect", container_id]))[0]["State"]
            except Exception as diagnostic_error:
                report["diagnostic_error"] = str(diagnostic_error)
        raise
    finally:
        if compose:
            try:
                command(compose + ["down", "--timeout", "10"])
            except Exception as error:
                report["cleanup_error"] = str(error)
        try:
            command([docker, "volume", "rm", volume_name])
            shutil.rmtree(launch)
            report["isolated_stack_cleaned_up"] = True
        except Exception as error:
            report["cleanup_error"] = str(error)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
