#!/usr/bin/env python3
"""Exercise local proposal/approval against one new synthetic named-volume project.

Host writes stay under this checkout's var/. Existing Compose projects are never
restarted. No deploy, baseline, snapshot, rollback or migration APIs are invoked.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
VAR = (ROOT / "var").resolve()
sys.path.insert(0, str(ROOT / "tests/fixtures"))
from prepare import prepare_fixture  # noqa: E402


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(arguments, *, environment=None, timeout=90, success=True):
    result = subprocess.run(arguments, env=environment, text=True, capture_output=True, timeout=timeout)
    if success and result.returncode:
        # These commands handle only the synthetic fixture; never dump Docker inspect/env.
        raise RuntimeError(f"{Path(arguments[0]).name} {arguments[1:3]} failed: {result.stderr.strip()} {result.stdout.strip()}")
    return result


def json_command(arguments, **kwargs):
    return json.loads(run(arguments, **kwargs).stdout)


def private_json(path, value):
    require(path.resolve().is_relative_to(VAR), "host output must remain under var/")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, indent=2)
        output.write("\n")


def api(url, method, path, value=None):
    body = None if value is None else json.dumps({"value": value}).encode()
    request = Request(url + path, data=body, method=method, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=3)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def wait_ready(compose, environment):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            binding = run(compose + ["port", "app", "8080"], environment=environment, timeout=10).stdout.strip()
            require(binding.startswith("127.0.0.1:") and "\n" not in binding, "unexpected published port")
            url = "http://" + binding
            if api(url, "GET", "/health")[0] == 200:
                return url
        except (OSError, ValueError, RuntimeError, URLError):
            pass
        time.sleep(0.25)
    raise RuntimeError("new fixture did not become healthy")


def inspect_starts(docker, environment, ids=None):
    if ids is None:
        ids = run(docker + ["ps", "--all", "--quiet", "--no-trunc"], environment=environment).stdout.split()
    if not ids:
        return {}
    output = run(docker + ["inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *ids], environment=environment).stdout
    return dict(line.split(maxsplit=1) for line in output.splitlines())


def verify_config(model, project, work):
    require(model.get("name") == project, "unexpected Compose project")
    require(set(model["services"]) == {"app", "database"}, "only bundled app/database components are allowed")
    for name, service in model["services"].items():
        require(not service.get("privileged") and not service.get("devices") and not service.get("cap_add"), "unsafe fixture privileges")
        require(service.get("network_mode") not in ("host",) and service.get("pid") != "host" and service.get("ipc") != "host", "unsafe host namespace")
        require(Path(service["build"]["context"]).resolve().is_relative_to(work.resolve()), "external build context")
        for port in service.get("ports", []):
            require(port.get("host_ip") == "127.0.0.1", "wildcard fixture port")
        for mount in service.get("volumes", []):
            require(name == "database" and mount["type"] == "volume" and mount["target"] == "/data", "unexpected fixture mount")
    require(not model.get("networks", {}).get("default", {}).get("external"), "external fixture network")
    require(not model.get("volumes", {}).get("database-data", {}).get("external"), "external fixture volume")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=VAR / "executor.dev.json")
    parser.add_argument("--keep", action="store_true", help="keep only this smoke's containers running")
    parser.add_argument("--report", type=Path, help="new output file under var/; never overwritten")
    args = parser.parse_args()
    run_id = uuid.uuid4().hex[:10]
    project = "ctfm-reg-smoke-" + run_id
    service_id = "reg-smoke-" + run_id
    work = VAR / "fixtures" / ("registration-" + run_id)
    source = VAR / "workspaces" / ("registration-" + run_id)
    result_dir = VAR / "registration-runs" / run_id
    report_path = args.report.resolve() if args.report else result_dir / "report.json"
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "run_id": run_id, "project": project, "service_id": service_id, "status": "failed", "scope": "registration proposal/approval only; no baseline or deploy", "checks": {}}
    compose = None
    docker = None
    other_starts = None
    started = False
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith("COMPOSE_"):
            environment.pop(key)
    try:
        require(args.config.resolve().is_relative_to(VAR), "smoke bootstrap must be under var/")
        require(report_path.resolve().is_relative_to(VAR) and not report_path.exists(), "report must be a new file under var/")
        bootstrap = json.loads(args.config.read_text())
        require(bootstrap.get("development") is True, "smoke requires an explicit development bootstrap")
        state = Path(bootstrap["state_directory"])
        require(state.resolve() == VAR / "executor" and not state.is_symlink(), "only this checkout's var/executor state may be used")
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(state.stat().st_uid == os.getuid(), "executor state must belong to the current user")
        state.chmod(0o700)
        binary = ROOT / "bin/ctf-manager"
        require(binary.is_file(), "build bin/ctf-manager before running the smoke")
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        docker = [bootstrap["docker_binary"], "--host", bootstrap["docker_host"]]
        cli = [str(binary), "--config", str(args.config.resolve())]
        report["compose"] = run(docker + ["compose", "version"], environment=environment).stdout.strip()
        report["engine"] = json_command(docker + ["version", "--format", "{{json .Server}}"], environment=environment)
        other_starts = inspect_starts(docker, environment)
        report["other_containers_before"] = len(other_starts)
        prepare_fixture("named-volume", work)
        source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(work, source)
        compose = docker + ["compose", "--project-name", project, "--file", str(work / "compose.yaml")]
        normalized = json_command(compose + ["config", "--format", "json"], environment=environment)
        verify_config(normalized, project, work)
        report["checks"]["loopback_and_profile_preflight"] = True
        started = True
        run(compose + ["up", "--detach", "--build"], environment=environment, timeout=300)
        url = wait_ready(compose, environment)
        key = "registration_" + run_id
        value = "CTFM_TEST_FLAG_REG_" + run_id
        require(api(url, "PUT", "/flags/" + key, value)[0] == 200, "synthetic flag write failed")
        before = json_command(cli + ["inventory", "--project", project])
        target_starts = inspect_starts(docker, environment, [x["id"] for x in before])
        require(len(before) == 2 and {x["component"] for x in before} == {"app", "database"}, "fixture runtime component mismatch")
        database = next(x for x in before if x["component"] == "database")
        require(len(database["mounts"]) == 1 and database["mounts"][0]["type"] == "volume" and database["mounts"][0]["target"] == "/data", "unexpected data mount")
        volume = database["mounts"][0]["source"]
        require(volume == project + "_database-data", "unexpected actual volume identity")
        service = {
            "schema_version": 1, "id": service_id, "name": "Registration smoke " + run_id,
            "description": "Synthetic registration-only smoke; containers are stopped after the test unless --keep is passed.",
            "project_directory": str(work), "source_directory": str(source), "compose_project": project,
            "compose_files": ["compose.yaml"],
            "managed_paths": [{"path": "code", "kind": "code"}, {"path": "compose.yaml", "kind": "configuration"}],
            "data_paths": [
                {"name": "database-data", "kind": "named_volume", "source": volume, "target": "/data", "component": "database", "significant": True, "loss_accepted": False},
                {"name": "app-layer", "kind": "writable_layer", "target": "/tmp", "component": "app", "significant": False, "loss_accepted": True},
                {"name": "database-layer", "kind": "writable_layer", "target": "/tmp", "component": "database", "significant": False, "loss_accepted": True},
            ],
            "targets": ["app"],
            "containers": [{"component": x["component"], "id": x["id"], "image_id": x["image_id"], "role": "database" if x["component"] == "database" else "application"} for x in before],
            "policy_revision": 1, "file_map_revision": 1,
        }
        private_json(result_dir / "service.json", service)
        proposal = json_command(cli + ["propose", "--service", str(result_dir / "service.json"), "--actor", "registration-smoke"])
        private_json(result_dir / "proposal.json", proposal)
        report["proposal_id"], report["proposal_digest"] = proposal["id"], proposal["digest"]
        report["checks"]["proposal_created"] = True
        wrong = run(cli + ["approve", "--proposal", proposal["id"], "--digest", "sha256:" + "0" * 64, "--actor", "registration-smoke"], success=False)
        require(wrong.returncode != 0 and "digest does not match" in wrong.stderr, "wrong digest was not rejected for the expected reason")
        require(all(x["id"] != service_id for x in json_command(cli + ["services"])), "wrong digest unexpectedly approved registration")
        report["checks"]["wrong_digest_rejected_without_registration"] = True
        approved = json_command(cli + ["approve", "--proposal", proposal["id"], "--digest", proposal["digest"], "--actor", "registration-smoke"])
        require(approved["id"] == service_id, "approved service identity mismatch")
        registered = next(x for x in json_command(cli + ["services"]) if x["id"] == service_id)
        require(registered["containers"] == approved["containers"] and registered["data_paths"] == service["data_paths"], "persisted registration differs from approval")
        after = json_command(cli + ["inventory", "--project", project])
        signatures = lambda items: sorted((x["component"], x["id"], x["image_id"], x["mounts"]) for x in items)
        require(signatures(before) == signatures(after), "proposal/approval changed containers, images or mounts")
        require(api(url, "GET", "/flags/" + key)[1]["value"] == value, "registration changed synthetic game data")
        require(inspect_starts(docker, environment, [x["id"] for x in after]) == target_starts, "proposal/approval restarted a target container")
        report["checks"].update({"valid_digest_approved": True, "service_persisted": True, "container_ids_images_mounts_unchanged": True, "target_container_started_at_unchanged": True, "synthetic_game_data_unchanged": True})
        report["target_container_started_at"] = target_starts
        report["inventory"] = [{k: x[k] for k in ("component", "id", "image_id", "mounts")} for x in after]
        report["volume_retained"] = volume
        report["project_directory"], report["source_directory"] = str(work), str(source)
        report["status"] = "passed"
    except (RuntimeError, OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    finally:
        if started and compose is not None and not args.keep:
            try:
                run(compose + ["down", "--remove-orphans"], environment=environment, timeout=60)
                report["checks"]["own_containers_stopped_without_volume_removal"] = True
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                report["cleanup_error"] = str(error)
                report["status"] = "failed"
        if docker is not None and other_starts is not None:
            try:
                current = inspect_starts(docker, environment)
                report["external_observation"] = {
                    "preexisting_container_count": len(other_starts),
                    "preexisting_ids_absent_after": len(set(other_starts) - set(current)),
                    "preexisting_start_times_changed": sum(current.get(key) != value for key, value in other_starts.items() if key in current),
                    "scope": "observed only; unrelated projects are not frozen or controlled by this smoke",
                }
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                report["external_observation"] = {"error": str(error), "scope": "read-only observation of unrelated projects"}
        report["containers_kept"] = args.keep
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        if report_path.resolve().is_relative_to(VAR) and not report_path.exists():
            private_json(report_path, report)
        print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
