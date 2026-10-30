#!/usr/bin/env python3
"""A missing dedicated installation root must fail without creating host paths."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import uuid

from runtime_qualification import runtime_qualification

ROOT = Path(__file__).resolve().parents[2]


def run(arguments, **kwargs):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
    environment.update(kwargs.pop("env", {}))
    return subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=90, **kwargs)


def checked(arguments, **kwargs):
    result = run(arguments, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr + result.stdout)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/unprepared-host-2026-10-20.json")
    args = parser.parse_args()
    project = "ctfm-unprepared-" + uuid.uuid4().hex[:12]
    directory = "/srv/" + project
    report = {"test": "unprepared-host-negative", "status": "failed", "project": project,
              "started_at": datetime.now(timezone.utc).isoformat(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "scope": "new missing installation root; no existing game paths mounted or modified",
              "limitations": ["Negative installation-path acceptance only; successful installation and executor binary execution are not exercised by this suite"]}
    compose = None
    environment = {}
    try:
        endpoint = os.environ.get("DOCKER_HOST") or json.loads(checked(["docker", "context", "inspect"]))[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix:///"):
            raise RuntimeError("only a local Unix daemon is supported")
        server = json.loads(checked(["docker", "version", "--format", "{{json .Server}} "]))
        image = json.loads(checked(["docker", "image", "inspect", "ctf-manager-executor:local"]))[0]
        report["runtime"] = {"os": server["Os"], "architecture": server["Arch"], "engine_version": server["Version"]}
        report["executor_image_id"] = image["Id"]
        report["runtime_qualification"] = runtime_qualification(server, image)
        report["acceptance_scope"] = {"negative_installation": True, "successful_installation": False,
                                      "executor_binary_executed": False}
        report["limitations"].append(report["runtime_qualification"]["scope_note"])
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = {"CTFM_ROOT": directory, "CTFM_DOCKER_SOCKET": endpoint.removeprefix("unix://"), "CTFM_PORT": str(port)}
        compose = ["docker", "compose", "--project-name", project, "--file", str(ROOT / "compose.yaml")]
        configuration = json.loads(checked(compose + ["config", "--format", "json"], env=environment))
        mounts = [item for service in configuration["services"].values() for item in service.get("volumes", [])]
        if any(item.get("bind", {}).get("create_host_path", True) for item in mounts if item["type"] == "bind"):
            raise RuntimeError("an installation bind allows silent host-path creation")
        result = run(compose + ["up", "--detach", "--no-build"], env=environment)
        report["compose_result"] = {"exit_code": result.returncode, "output": result.stderr + result.stdout}
        if not result.returncode or "bind source path does not exist" not in result.stderr + result.stdout or directory not in result.stderr + result.stdout:
            raise RuntimeError("unprepared installation did not fail explicitly on its missing bind source")
        running = checked(["docker", "ps", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).splitlines()
        if running:
            raise RuntimeError("unprepared installation started a container")
        # A second exact bind resolution must still fail. Unlike --volume,
        # --mount never creates a missing source; no parent host root is mounted.
        probe = run(["docker", "create", "--name", project + "-probe", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--mount", "type=bind,source=" + directory + "/config,target=/missing,readonly",
                     "--entrypoint", "/bin/true", "ctf-manager-executor:local"])
        if not probe.returncode:
            checked(["docker", "rm", project + "-probe"])
            raise RuntimeError("failed Compose unexpectedly created the installation source")
        if "bind source path does not exist" not in probe.stderr:
            raise RuntimeError("cannot verify absent installation source: " + probe.stderr)
        report["checks"] = {"all_binds_create_host_path_false": True, "explicit_missing_source_error": True,
                            "no_running_panel_container": True, "host_config_source_still_missing": True}
        if sys.platform != "linux":
            result = run([sys.executable, str(ROOT / "scripts/compose-bootstrap.py"), "--root", directory])
            if not result.returncode or "production bootstrap must run locally as root on the Linux Docker host" not in result.stderr:
                raise RuntimeError("unsupported host bootstrap was not rejected")
            report["checks"]["non_linux_production_bootstrap_rejected"] = True
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if compose:
            cleanup = run(compose + ["down", "--timeout", "5"], env=environment)
            report["cleanup_exit_code"] = cleanup.returncode
            leftovers = checked(["docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).splitlines()
            networks = checked(["docker", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).splitlines()
            report["cleanup"] = {"containers": leftovers, "networks": networks}
            if cleanup.returncode or leftovers or networks:
                report["status"] = "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": report["checks"], "report": str(args.report)}))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
