#!/usr/bin/env python3
"""Exercise releases with a production Linux executor and native bind storage.

Creates one uniquely named synthetic game project, one executor container and a
new native Linux daemon directory. The root is mounted at its exact path, so
executor and daemon see identical service/workspace paths even on a macOS client.
No pre-existing game project is registered or modified. No global prune is used.
The executor has no network; the daemon's registry network is not blocked.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from runtime_qualification import runtime_qualification

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]


def command(args, *, input=None, timeout=180, success=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
    result = subprocess.run(args, input=input, capture_output=True, text=True,
                            timeout=timeout, env=env)
    if success and result.returncode:
        raise RuntimeError(f"command {Path(args[0]).name} {args[1:3]} failed: "
                           + (result.stderr + result.stdout)[-6000:])
    return result


def parsed(args, **kwargs):
    return json.loads(command(args, **kwargs).stdout)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def api(base, method, path, value=None):
    body = None if value is None else json.dumps({"value": value}).encode()
    request = urllib.request.Request(base + path, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=3) as response:
        require(response.status == 200, "fixture HTTP request failed")
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executor-image", default="ctf-manager-executor:local")
    parser.add_argument("--report", type=Path,
                        default=ROOT / "tests/integration/reports/container-release-smoke-2026-10-19.json")
    args = parser.parse_args()
    docker = shutil.which("docker")
    require(docker is not None, "Docker CLI is required")
    context = parsed([docker, "context", "inspect"])[0]
    endpoint = os.environ.get("DOCKER_HOST", context["Endpoints"]["docker"]["Host"])
    require(endpoint.startswith("unix:///"), "only local Unix Docker socket is supported")
    socket_path = endpoint.removeprefix("unix://")
    identifier = uuid.uuid4().hex[:10]
    project = "ctfm-container-release-" + identifier
    service_id = "container-release-" + identifier
    executor_name = project + "-executor"
    launch = Path(tempfile.mkdtemp(prefix=project + "-")).resolve()
    report = {"test": "production-container-bind-release", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "project": project, "service_id": service_id, "checks": {},
              "scope": "new synthetic bind-code/bind-data project only; no existing game project registered",
              "offline_limit": "executor --network none; daemon registry connectivity is not blocked"}
    root = None
    own_image_tags = set()
    game_started = False
    executor_started = False
    before_other = {}

    def docker_json(*parts):
        return parsed([docker, *parts])

    def starts():
        ids = command([docker, "ps", "--all", "--quiet", "--no-trunc"]).stdout.split()
        if not ids:
            return {}
        lines = command([docker, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *ids]).stdout.splitlines()
        return dict(line.split(maxsplit=1) for line in lines)

    def helper(code, *arguments, input=None):
        return command([docker, "run", "--rm", "--network", "none",
                        "--mount", f"type=bind,source={root},target={root}",
                        "--mount", f"type=bind,source={ROOT},target={ROOT},readonly",
                        "python:3.11-slim", "python3", "-c", code,
                        str(root), *map(str, arguments)], input=input)

    def cli(*parts, success=True):
        return command([docker, "exec", executor_name, "/usr/local/bin/ctf-manager",
                        "--config", str(root / "config/executor.json"), *parts], success=success)

    def cli_json(*parts):
        return json.loads(cli(*parts).stdout)

    def write_json(name, value):
        target = root / "requests" / name
        local = launch / name
        local.write_text(json.dumps(value) + "\n")
        command([docker, "cp", str(local), executor_name + ":" + str(target)])
        return str(target)

    def wait_ready():
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                return api(base, "GET", "/health")
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(.25)
        raise RuntimeError("synthetic bind application did not become healthy")

    def operation(action, *, expected="succeeded", **fields):
        request = {"service_id": service_id, "action": action,
                   "initiator": "container-smoke", "idempotency_key": uuid.uuid4().hex, **fields}
        request_path = write_json("request.json", request)
        preview = cli_json("preview", "--request", request_path)
        request["plan_digest"] = preview["plan_digest"]
        write_json("request.json", request)
        result = cli_json("submit", "--request", request_path)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            observed = cli_json("operation", "--operation", result["spec"]["id"])
            if observed["state"] in ("succeeded", "failed", "requires_recovery", "interrupted"):
                if observed["state"] != expected:
                    report.setdefault("operation_diagnostics", {})[action] = cli_json("events", "--operation", observed["spec"]["id"])
                    raise RuntimeError(f"{action}: unexpected operation result {observed}")
                retry = cli_json("submit", "--request", request_path)
                require(retry["spec"]["id"] == observed["spec"]["id"], "retry changed operation identity")
                return observed
            time.sleep(.2)
        raise RuntimeError("operation did not complete: " + action)

    try:
        before_other = starts()
        server = docker_json("version", "--format", "{{json .Server}}")
        report["runtime"] = {"os": server["Os"], "architecture": server["Arch"],
                             "engine_version": server["Version"]}
        image = docker_json("image", "inspect", args.executor_image)[0]
        report["executor_image_id"] = image["Id"]
        report["runtime_qualification"] = runtime_qualification(server, image)
        report.setdefault("limitations", []).append(report["runtime_qualification"]["scope_note"])
        # Compile only the fixture-scoped revocation helper, using local Go
        # module/build caches. It cannot address arbitrary executor vaults.
        helper_binary = launch / "secret-revocation"
        build_env = os.environ.copy()
        build_env.update(GOOS="linux", GOARCH=server["Arch"], CGO_ENABLED="0",
                         GOCACHE=str(ROOT / ".cache/go-build"),
                         GOMODCACHE=str(ROOT / ".cache/go-mod"), GOPROXY="off")
        compiled = subprocess.run(["go", "build", "-o", str(helper_binary),
                                   "./tests/integration/secret_revocation"], cwd=ROOT,
                                  env=build_env, text=True, capture_output=True, timeout=90)
        require(compiled.returncode == 0, "fixture revocation helper build failed: " + compiled.stderr)
        root = Path("/srv") / project
        # Docker creates only this unique bind source in the Linux daemon. The
        # parent /srv and host root are never exposed inside a helper.
        command([docker, "run", "--rm", "--network", "none", "--volume", f"{root}:{root}",
                 "python:3.11-slim", "python3", "-c", "import pathlib,sys; p=pathlib.Path(sys.argv[1]); assert not any(p.iterdir())", str(root)])
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        base = "http://127.0.0.1:" + str(port)
        setup = '''
import json, os, shutil, sys
from pathlib import Path
root, repository, port = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
os.chmod(root, 0o755)
for name in ('services', 'workspaces', 'config', 'requests'):
    (root/name).mkdir(mode=0o755)
(root/'executor').mkdir(mode=0o700)
(root/'runtime').mkdir(mode=0o750); os.chown(root/'runtime', 0, 10001)
sys.path.insert(0, str(repository/'tests/fixtures'))
from prepare import prepare_fixture
active = prepare_fixture('bind-mount', root/'services/game')
(active/'.env').write_text('CTFM_FIXTURE_UID=10001\\nCTFM_FIXTURE_GID=10001\\n')
os.chown(active/'data', 10001, 10001)
text = (active/'compose.yaml').read_text().replace('    shm_size: 64m', '    environment:\\n      CTFM_SYNTHETIC_SECRET: fixture-revocation-only\\n    shm_size: 64m').replace('      - target: 8080', '      - target: 8080\\n        published: "'+port+'"')
(active/'compose.yaml').write_text(text)
shutil.copytree(active, root/'workspaces/game', ignore=shutil.ignore_patterns('data'))
configuration = {'state_directory': str(root/'executor'), 'socket': str(root/'runtime/executor.sock'),
'docker_host': 'unix:///var/run/docker.sock', 'docker_binary': '/usr/local/bin/docker',
'compose_binary': '/usr/local/libexec/docker/cli-plugins/docker-compose',
'discovery_roots': [str(root/'services')], 'workspace_roots': [str(root/'workspaces')],
'web_uid': 10001, 'development': False}
(root/'config/executor.json').write_text(json.dumps(configuration)); os.chmod(root/'config/executor.json', 0o600)
'''
        helper(setup, ROOT, port)
        # A synthetic administrator-owned wrapper records only fixed Compose
        # arguments and can reject explicit build/pull commands during rollback.
        wrapper = "#!/bin/sh\nfor argument in \"$@\"; do\nif [ \"$argument\" = build ] || [ \"$argument\" = pull ]; then\nif [ -f '" + str(root / "executor/rollback-guard") + "' ]; then echo 'build/pull forbidden by acceptance guard' >&2; exit 97; fi\nfi\ndone\nprintf '%s\\0' \"$@\" >> '" + str(root / "executor/compose-argv") + "'\n/usr/local/libexec/docker/cli-plugins/docker-compose \"$@\" 2> '" + str(root / "executor/compose-stderr") + "'\nresult=$?\ncat '" + str(root / "executor/compose-stderr") + "' >&2\nexit \"$result\"\n"
        helper("import json,os,sys; from pathlib import Path; p=Path(sys.argv[1]); w=p/'config/compose-wrapper'; w.write_text(sys.argv[2]); os.chmod(w,0o700); c=p/'config/executor.json'; value=json.loads(c.read_text()); value['compose_binary']=str(w); c.write_text(json.dumps(value))", wrapper)
        mounts = ["--mount", f"type=bind,source={root},target={root}",
                  "--mount", f"type=bind,source={socket_path},target=/var/run/docker.sock"]
        compose = [docker, "run", "--rm", "--network", "none", *mounts,
                   "--entrypoint", "/usr/local/bin/docker", args.executor_image,
                   "compose", "--project-name", project, "--file", str(root / "services/game/compose.yaml")]
        game_started = True
        command(compose + ["up", "--detach", "--build"], timeout=300)
        own_image_tags.add(project + "-app:latest")
        wait_ready()
        key = "container_" + identifier
        flag = "CTFM_TEST_FLAG_CONTAINER_" + identifier
        state_value = "state_" + identifier
        api(base, "PUT", "/flags/" + key, flag)
        api(base, "PUT", "/state/" + key, state_value)
        initial_version = api(base, "GET", "/version")
        command([docker, "run", "--detach", "--name", executor_name,
                 "--user", "0:10001", "--network", "none", "--read-only",
                 "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
                 "--cap-add", "FOWNER", "--security-opt", "no-new-privileges:true",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777", *mounts,
                 args.executor_image, "--config", str(root / "config/executor.json"), "executor"])
        executor_started = True
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if cli("status", success=False).returncode == 0:
                break
            time.sleep(.2)
        else:
            raise RuntimeError("production executor did not start")
        report["executor_platform_checks"] = cli_json("doctor")
        binary_platform = next(x["detail"] for x in report["executor_platform_checks"] if x["name"] == "platform")
        report["runtime_qualification"] = runtime_qualification(server, image, binary_platform=binary_platform)
        report["executor_execution"] = {"binary_platform": binary_platform,
                                        "daemon_architecture": server["Arch"],
                                        "emulated": None if report["runtime_qualification"]["executor_matches_daemon"] is None else not report["runtime_qualification"]["executor_matches_daemon"]}
        initial = cli_json("inventory", "--project", project)
        require(len(initial) == 1 and initial[0]["component"] == "app", "unexpected fixture inventory")
        policy = {"schema_version": 1, "id": service_id, "name": "Container bind smoke " + identifier,
                  "project_directory": str(root / "services/game"), "source_directory": str(root / "workspaces/game"),
                  "compose_project": project, "compose_files": ["compose.yaml"],
                  "managed_paths": [{"path": "code", "kind": "code"}, {"path": "compose.yaml", "kind": "configuration"},
                                    {"path": ".env", "kind": "configuration"}],
                  "data_paths": [{"name": "game-data", "kind": "bind", "source": str(root / "services/game/data"),
                                  "target": "/data", "component": "app", "significant": True, "loss_accepted": False},
                                 {"name": "app-layer", "kind": "writable_layer", "target": "/tmp", "component": "app",
                                  "significant": False, "loss_accepted": True}],
                  "targets": ["app"], "containers": [{"component": "app", "id": initial[0]["id"],
                                                        "image_id": initial[0]["image_id"], "role": "application"}],
                  "policy_revision": 1, "file_map_revision": 1}
        policy_path = write_json("service.json", policy)
        proposal = cli_json("propose", "--service", policy_path)
        cli_json("approve", "--proposal", proposal["id"], "--digest", proposal["digest"])
        report["checks"]["production_registration_with_exact_native_paths"] = True
        report["diagnostic_device_ids"] = command([docker, "exec", executor_name, "/bin/busybox", "stat", "-c", "%d %i %n", str(root / "services/game"), str(root / "services/game/code"), str(root / "services/game/code/app.py"), str(root / "services/game/.env"), str(root / "services/game/compose.yaml")]).stdout.splitlines()
        operation("snapshot")
        details = cli_json("service", "--service", service_id)
        baseline = details["current_release_id"]
        require(baseline, "baseline/imported release missing")
        baseline_snapshot = next(x["id"] for x in details["snapshots"] if x["purpose"] == "baseline")
        initial_start = starts()[initial[0]["id"]]
        for _ in range(4):
            operation("snapshot")
        rotation = cli_json("rotate")
        retained = cli_json("service", "--service", service_id)
        require(sum(x["purpose"] == "manual" for x in retained["snapshots"]) == 3, "manual snapshot rotation did not retain newest three")
        require(baseline_snapshot in rotation["protected_snapshots"] and baseline in rotation["protected_releases"], "rotation did not protect baseline/imported release")
        require(starts()[initial[0]["id"]] == initial_start, "rotation restarted game")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "rotation changed game data")
        report["checks"]["rotation_cli_preserves_baseline_and_game_before_switch"] = True
        storage_status = cli_json("storage")
        require(storage_status["snapshots"]["bytes"] > 0 and storage_status["docker_usage_bytes"] > 0, "storage CLI did not return measured usage")
        require(storage_status["state_capacity"]["available_bytes"] > 0, "state physical capacity missing")
        require("docker_capacity" not in storage_status, "unmounted Docker root has invented physical free-space data")
        report["checks"]["storage_cli_reports_usage_and_unknown_unmounted_docker_capacity"] = True
        helper("from pathlib import Path; import sys; p=Path(sys.argv[1]); (p/'workspaces/game/code/VERSION').write_text(sys.argv[2]+'\\n')", "container-" + identifier)
        operation("prepare")
        require(api(base, "GET", "/version") == initial_version, "Prepare changed live bind-mounted code")
        details = cli_json("service", "--service", service_id)
        operation("build", candidate_id=details["candidate_id"])
        require(api(base, "GET", "/version") == initial_version, "Build changed live bind-mounted code")
        details = cli_json("service", "--service", service_id)
        target = next(x for x in details["releases"] if x["id"] != baseline)
        report["checks"]["prepare_build_keep_live_bind_code_unchanged"] = True
        for release in details["releases"]:
            own_image_tags.update(image["retention_tag"] for image in release["images"])
        data_mount = next(x for x in initial[0]["mounts"] if x["target"] == "/data")
        operation("deploy", release_id=target["id"], confirm_data_compatibility=True)
        wait_ready()
        require(api(base, "GET", "/version")["version"] == "container-" + identifier, "Deploy did not switch bind code")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "Deploy lost bind-data flag")
        require(api(base, "GET", "/state/" + key)["value"] == state_value, "Deploy lost bind-data state")
        current = cli_json("inventory", "--project", project)[0]
        require(next(x for x in current["mounts"] if x["target"] == "/data") == data_mount, "Deploy changed data bind identity")
        report["checks"]["deploy_bind_code_and_data_preserved"] = True
        helper("import pathlib,sys; p=pathlib.Path(sys.argv[1]); (p/'executor/rollback-guard').touch(); (p/'executor/compose-argv').write_bytes(b'')")
        operation("rollback", release_id=baseline, confirm_data_compatibility=True)
        rollback_argv = helper("import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); print(json.dumps((p/'executor/compose-argv').read_bytes().decode().split('\\0')[:-1]))").stdout
        report["rollback_compose_arguments"] = json.loads(rollback_argv)
        require("build" not in report["rollback_compose_arguments"] and "pull" not in report["rollback_compose_arguments"], "rollback invoked an explicit build/pull command")
        require("--no-build" in report["rollback_compose_arguments"] and "--pull" in report["rollback_compose_arguments"] and "never" in report["rollback_compose_arguments"], "rollback did not enforce no-build and pull-never")
        report["checks"]["rollback_rejects_build_pull_commands_and_uses_pull_never"] = True
        wait_ready()
        require(api(base, "GET", "/version") == initial_version, "Rollback did not restore baseline bind code")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "Rollback lost flag")
        require(api(base, "GET", "/state/" + key)["value"] == state_value, "Rollback lost state")
        report["checks"]["rollback_exact_baseline_with_executor_network_none"] = True
        current = cli_json("inventory", "--project", project)[0]
        start_before = starts()[current["id"]]
        command([docker, "stop", "--time", "20", executor_name])
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "Stopping executor affected game")
        require(starts()[current["id"]] == start_before, "Stopping executor restarted game")
        command([docker, "start", executor_name])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if cli("status", success=False).returncode == 0:
                break
            time.sleep(.2)
        require(cli_json("service", "--service", service_id)["current_release_id"] == baseline, "executor restart lost current release")
        require(starts()[current["id"]] == start_before, "Restarting executor restarted game")
        require(api(base, "GET", "/state/" + key)["value"] == state_value, "executor restart changed state")
        report["checks"]["executor_stop_restart_does_not_restart_game_or_change_data"] = True
        # Delete only this unreferenced candidate's private retention tag/image.
        # The baseline image remains referenced by the running game container.
        missing_image = next(x for x in target["images"] if x["component"] == "app")
        command([docker, "image", "rm", missing_image["retention_tag"]])
        require(command([docker, "image", "inspect", missing_image["image_id"]], success=False).returncode != 0,
                "candidate image still has another tag; cannot honestly test missing image")
        op = operation("deploy", release_id=target["id"], confirm_data_compatibility=True, expected="failed")
        require(not op.get("mutation_started", False), "missing image reached mutation stage")
        require(starts()[current["id"]] == start_before, "missing exact image stopped/restarted application")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "missing exact image changed game data")
        report["checks"]["missing_exact_image_fails_before_application_stop"] = True
        refs = cli_json("service", "--service", service_id)["service"]["secret_versions"]
        require(refs, "synthetic environment did not create a versioned secret")
        revoke_path = str(root / "requests/secret-revocation")
        command([docker, "cp", str(helper_binary), executor_name + ":" + revoke_path])
        command([docker, "exec", executor_name, revoke_path, str(root), refs[0]["secret_id"], refs[0]["version"]])
        op = operation("rollback", release_id=baseline, confirm_data_compatibility=True, expected="failed")
        require(not op.get("mutation_started", False), "revoked secret reached mutation stage")
        require(starts()[current["id"]] == start_before, "revoked secret stopped/restarted application")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "secret revocation changed game data")
        report["checks"]["revoked_release_secret_fails_before_application_stop"] = True
        report["executor_settings"] = {"development": False, "user": "0:10001", "network_mode": "none", "read_only_root": True,
                                       "capabilities": ["CHOWN", "DAC_OVERRIDE", "FOWNER"], "native_storage": True}
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        if executor_started:
            try:
                report["private_synthetic_compose_stderr"] = helper("from pathlib import Path; import sys; p=Path(sys.argv[1])/'executor/compose-stderr'; print(p.read_text() if p.exists() else '')").stdout[-6000:]
            except Exception:
                pass
            report["executor_logs"] = command([docker, "logs", "--tail", "30", executor_name], success=False).stdout[-4000:]
            if game_started:
                own_ids = command([docker, "ps", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
                if own_ids:
                    observed = parsed([docker, "inspect", *own_ids])
                    report["diagnostic_mount_options"] = [{"mounts": x["Mounts"], "host_mounts": x["HostConfig"].get("Mounts", []), "host_binds": x["HostConfig"].get("Binds", [])} for x in observed]
    finally:
        if executor_started:
            command([docker, "rm", "--force", executor_name], success=False)
        if game_started:
            cleanup = command(compose + ["down", "--remove-orphans"], success=False)
            if cleanup.returncode:
                report["cleanup_error"] = cleanup.stderr[-2000:]
                report["status"] = "failed"
        # All names are recorded from resources created by this run only.
        for tag in sorted(own_image_tags):
            command([docker, "image", "rm", tag], success=False)
        if root is not None:
            # Remove only this known directory's contents through its own bind.
            # The empty root directory remains, because its parent is not mounted.
            try:
                helper("import pathlib,shutil,sys; p=pathlib.Path(sys.argv[1]); [(shutil.rmtree(x) if x.is_dir() and not x.is_symlink() else x.unlink()) for x in p.iterdir()]")
                report["isolated_native_directory_contents_removed"] = True
                report["empty_daemon_directory_retained"] = str(root)
            except Exception as cleanup_error:
                report["cleanup_error"] = str(cleanup_error)
                report["status"] = "failed"
        after_other = starts()
        report["external_observation"] = {
            "preexisting_count": len(before_other),
            "preexisting_ids_absent_after": len(set(before_other) - set(after_other)),
            "preexisting_started_at_changed": sum(after_other[key] != value for key, value in before_other.items() if key in after_other),
            "scope": "read-only observation; unrelated projects are not frozen by this test"}
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        shutil.rmtree(launch)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
