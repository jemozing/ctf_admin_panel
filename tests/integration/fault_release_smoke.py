#!/usr/bin/env python3
"""Deterministic production-executor crash and real Docker response-loss suite.

Only this unique synthetic project's Docker resources and native daemon directory
are mutable. External Unix API/Compose gates stop at observable durable pipeline
boundaries; product code contains no test hook. The daemon is never restarted and
registry connectivity is unchanged. Report limitations remain explicit.
"""

import argparse
from datetime import datetime, timezone
import hashlib
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
BOUNDARIES = (
    ("before_durable_mutation", "before_budget", ""),
    ("after_intent_before_stop", "before_stop", ""),
    ("stop_applied_response_not_received", "after_stop", ""),
    ("files_applied_before_compose_up", "", "before_up"),
    ("compose_up_applied_before_observation", "", "after_up"),
    ("active_release_recorded_before_warmup", "before_warmup", ""))


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
    parser.add_argument("--boundary", action="append", choices=[value[0] for value in BOUNDARIES],
                        help="run only these crash boundaries; default runs all six")
    parser.add_argument("--report", type=Path,
                        default=ROOT / "tests/integration/reports/fault-release-smoke-2026-10-19.json")
    args = parser.parse_args()
    docker = shutil.which("docker")
    require(docker is not None, "Docker CLI is required")
    context = parsed([docker, "context", "inspect"])[0]
    endpoint = os.environ.get("DOCKER_HOST", context["Endpoints"]["docker"]["Host"])
    require(endpoint.startswith("unix:///"), "only local Unix Docker socket is supported")
    socket_path = endpoint.removeprefix("unix://")
    identifier = uuid.uuid4().hex[:10]
    project = "ctfm-fault-release-" + identifier
    service_id = "fault-release-" + identifier
    executor_name = project + "-executor"
    proxy_name = project + "-proxy"
    proxy_started = False
    launch = Path(tempfile.mkdtemp(prefix=project + "-")).resolve()
    report = {"test": "production-container-fault-release", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "project": project, "service_id": service_id, "checks": {},
              "scope": "new synthetic bind-code/bind-data project only; no existing game project registered",
              "offline_limit": "executor --network none; daemon registry connectivity is not blocked"}
    report["harness_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["proxy_sha256"] = hashlib.sha256((ROOT / "tests/integration/fault_docker_proxy.py").read_bytes()).hexdigest()
    root = None
    own_image_tags = set()
    game_started = False
    executor_started = False
    before_other = {}
    before_labels = {}

    def docker_json(*parts):
        return parsed([docker, *parts])

    def starts():
        ids = command([docker, "ps", "--all", "--quiet", "--no-trunc"]).stdout.split()
        if not ids:
            return {}
        # Concurrent acceptance helpers may exit between ps and inspect. Keep
        # the valid observations; protected/owned IDs are asserted separately.
        lines = command([docker, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *ids], success=False).stdout.splitlines()
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
        label_template = '{"id":{{json .Id}},"name":{{json .Name}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}'
        label_lines = command([docker, "inspect", "--format", label_template, *before_other], success=False).stdout.splitlines() if before_other else []
        before_labels = {item["id"]: item for item in map(json.loads, label_lines)}
        report["preexisting_labels"] = list(before_labels.values())
        server = docker_json("version", "--format", "{{json .Server}}")
        report["runtime"] = {"os": server["Os"], "architecture": server["Arch"],
                             "engine_version": server["Version"]}
        image = docker_json("image", "inspect", args.executor_image)[0]
        report["requested_executor_image"] = args.executor_image
        report["executor_image_id"] = image["Id"]
        report["runtime_qualification"] = runtime_qualification(server, image)
        # Tags may be rebuilt by another acceptance task during this long run.
        # Pin the inspected immutable image for every container in this suite.
        args.executor_image = image["Id"]
        report["limitations"] = [report["runtime_qualification"]["scope_note"], "No real daemon restart or registry-network blocking", "No SQLite/fsync/power-loss fault injection", "Single application target; multi-component partial switching remains separate"]
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
        # An administrator-owned fixture wrapper gates only real Compose up.
        wrapper = "#!/bin/sh\nexport DOCKER_HOST=unix:///var/run/docker.sock\naction=\nfor argument in \"$@\"; do [ \"$argument\" = up ] && action=up; done\ngate=$(cat '" + str(root / "config/compose-gate") + "' 2>/dev/null || true)\nif [ \"$action:$gate\" = up:before_up ]; then touch '" + str(root / "config/compose-reached") + "'; while [ -f '" + str(root / "config/compose-gate") + "' ]; do sleep 0.05; done; fi\n/usr/local/libexec/docker/cli-plugins/docker-compose \"$@\"\nresult=$?\nif [ \"$result:$action:$gate\" = 0:up:after_up ]; then touch '" + str(root / "config/compose-reached") + "'; while [ -f '" + str(root / "config/compose-gate") + "' ]; do sleep 0.05; done; fi\nexit \"$result\"\n"
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
        # A separate fixture proxy forwards real SDK requests through a Unix
        # socket. The Compose wrapper explicitly keeps using the real socket.
        command([docker, "run", "--detach", "--name", proxy_name, "--network", "none",
                 "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                 *mounts, "--mount", f"type=bind,source={ROOT},target={ROOT},readonly",
                 "python:3.11-slim", "python3", str(ROOT / "tests/integration/fault_docker_proxy.py"),
                 str(root), "/var/run/docker.sock"])
        proxy_started = True
        helper("import json,sys; from pathlib import Path; p=Path(sys.argv[1]); c=p/'config/executor.json'; v=json.loads(c.read_text()); v['docker_host']='unix://'+str(p/'config/docker-proxy.sock'); c.write_text(json.dumps(v))")
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
        report["executor_binary_sha256"] = command([docker, "exec", executor_name, "/bin/busybox", "sha256sum", "/usr/local/bin/ctf-manager"]).stdout.split()[0]
        operation("snapshot")
        details = cli_json("service", "--service", service_id)
        baseline = details["current_release_id"]
        require(baseline, "imported baseline is missing")
        helper("from pathlib import Path; import sys; p=Path(sys.argv[1]); (p/'workspaces/game/code/VERSION').write_text(sys.argv[2]+'\\n')", "fault-" + identifier)
        operation("prepare")
        details = cli_json("service", "--service", service_id)
        operation("build", candidate_id=details["candidate_id"])
        details = cli_json("service", "--service", service_id)
        target = next(x for x in details["releases"] if x["id"] != baseline)
        for release in details["releases"]:
            own_image_tags.update(item["retention_tag"] for item in release["images"])

        def control(proxy="", compose_gate=""):
            helper("from pathlib import Path; import sys; p=Path(sys.argv[1])/'config'; [(p/n).unlink(missing_ok=True) for n in ('proxy-mode','proxy-reached','compose-gate','compose-reached')]; [(p/n).write_text(v) for n,v in (('proxy-mode',sys.argv[2]),('compose-gate',sys.argv[3])) if v]", proxy, compose_gate)

        def read_file(relative):
            return command([docker, "exec", proxy_name, "python3", "-c",
                            "from pathlib import Path; import sys; p=Path(sys.argv[1]); print(p.read_text() if p.exists() else '')",
                            str(root / relative)]).stdout.strip()

        def wait_gate(name):
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                present = command([docker, "exec", proxy_name, "python3", "-c",
                                   "from pathlib import Path; import sys; print(Path(sys.argv[1]).exists())",
                                   str(root / "config" / name)]).stdout.strip()
                if present == "True":
                    return
                time.sleep(.1)
            raise RuntimeError("fault gate was not reached: " + name)

        def wait_operation(operation_id, expected, after_updated_at=None):
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                result = cli_json("operation", "--operation", operation_id)
                if result["updated_at"] == after_updated_at:
                    time.sleep(.1)
                    continue
                if result["state"] in expected:
                    return result
                if result["state"] in ("succeeded", "failed", "requires_recovery", "interrupted"):
                    raise RuntimeError("unexpected fault operation outcome: " + json.dumps(result))
                time.sleep(.15)
            raise RuntimeError("operation deadline exceeded: " + operation_id)

        def state_and_locks(operation_id):
            return json.loads(helper("import json,sqlite3,sys; from pathlib import Path; p=Path(sys.argv[1]); db=sqlite3.connect('file:'+str(p/'executor/executor.db')+'?mode=ro',uri=True); states=[json.loads(r[0]) for r in db.execute(\"SELECT payload FROM records WHERE kind='runtime_state'\")]; latest=max(states,key=lambda x:x['sequence']); print(json.dumps({'state':latest,'locks':[list(r) for r in db.execute('SELECT resource,operation_id FROM locks WHERE operation_id=?',(sys.argv[2],))]}))", operation_id).stdout)

        def submit_deploy(proxy_mode="", compose_mode=""):
            request = {"service_id": service_id, "action": "deploy", "release_id": target["id"],
                       "confirm_data_compatibility": True, "initiator": "fault-smoke", "idempotency_key": uuid.uuid4().hex}
            path = write_json("fault-request.json", request)
            request["plan_digest"] = cli_json("preview", "--request", path)["plan_digest"]
            write_json("fault-request.json", request)
            control(proxy_mode, compose_mode)
            submitted = cli_json("submit", "--request", path)
            helper("from pathlib import Path; import sys; (Path(sys.argv[1])/'config/operation-id').write_text(sys.argv[2])", submitted["spec"]["id"])
            return submitted["spec"]["id"], path

        def recover(operation_id):
            request = {"service_id": service_id, "action": "recover", "recovery_operation_id": operation_id,
                       "confirm_data_compatibility": True, "initiator": "fault-smoke", "idempotency_key": uuid.uuid4().hex}
            path = write_json("recover-request.json", request)
            request["plan_digest"] = cli_json("preview", "--request", path)["plan_digest"]
            write_json("recover-request.json", request)
            submitted = cli_json("submit", "--request", path)
            require(submitted["spec"]["id"] == operation_id, "recovery lost original operation identity")
            result = wait_operation(operation_id, ("failed",), submitted["updated_at"])
            require(result["outcome"]["returned_to_previous"], "recovery did not record confirmed compensation")
            require(not state_and_locks(operation_id)["locks"], "confirmed recovery did not release locks")
            wait_ready()
            require(api(base, "GET", "/version") == initial_version, "recovery failed to restore baseline files/runtime")
            require(api(base, "GET", "/flags/" + key)["value"] == flag, "recovery lost flag")
            require(api(base, "GET", "/state/" + key)["value"] == state_value, "recovery lost persistent state")
            require(cli_json("service", "--service", service_id)["current_release_id"] == baseline, "recovery reports wrong active release")
            return result

        def restart_executor():
            command([docker, "start", executor_name])
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if cli("status", success=False).returncode == 0:
                    return
                time.sleep(.1)
            raise RuntimeError("executor did not restart")

        # Simulate a caller losing the Submit response body after the executor
        # has durably accepted the real HTTP request. The intermediary verifies
        # only the 202 status and deliberately discards the entire JSON body, so
        # it has no operation ID to retry. It does not manufacture a stored job.
        lost_request = {"service_id": service_id, "action": "deploy", "release_id": target["id"],
                        "confirm_data_compatibility": True, "initiator": "fault-smoke", "idempotency_key": uuid.uuid4().hex}
        path = write_json("lost-submit.json", lost_request)
        lost_request["plan_digest"] = cli_json("preview", "--request", path)["plan_digest"]
        write_json("lost-submit.json", lost_request)
        helper("import http.client,json,socket,sys; from pathlib import Path; p=Path(sys.argv[1]); c=http.client.HTTPConnection('executor'); c.sock=socket.socket(socket.AF_UNIX); c.sock.connect(str(p/'runtime/executor.sock')); c.request('POST','/v1/operations',body=sys.argv[2],headers={'Content-Type':'application/json'}); response=c.getresponse(); assert response.status==202; c.close()", json.dumps(lost_request))
        retried = cli_json("submit", "--request", path)
        retry_operation_id = retried["spec"]["id"]
        wait_operation(retry_operation_id, ("succeeded",))
        require(cli_json("submit", "--request", path)["spec"]["id"] == retry_operation_id, "lost Submit response retry duplicated operation")
        duplicates = int(helper("import sqlite3,sys; from pathlib import Path; db=sqlite3.connect('file:'+str(Path(sys.argv[1])/'executor/executor.db')+'?mode=ro',uri=True); print(db.execute('SELECT count(*) FROM operations WHERE initiator=? AND idempotency_key=?',('fault-smoke',sys.argv[2])).fetchone()[0])", lost_request["idempotency_key"]).stdout)
        require(duplicates == 1, "lost Submit response created multiple durable operations")
        wait_ready()
        require(api(base, "GET", "/version")["version"] == "fault-" + identifier, "accepted Deploy after lost response did not execute")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "lost response retry lost persistent flag")
        operation("rollback", release_id=baseline, confirm_data_compatibility=True)
        wait_ready()
        require(api(base, "GET", "/version") == initial_version, "baseline reset after lost-response case failed")
        report["checks"]["real_submit_response_body_discarded_retry_exactly_one_durable_deploy"] = True

        report["crash_cases"] = []
        requested_boundaries = [value for value in BOUNDARIES if args.boundary is None or value[0] in args.boundary]
        report["requested_crash_boundaries"] = [value[0] for value in requested_boundaries]
        for boundary, proxy_mode, compose_mode in requested_boundaries:
            operation_id, path = submit_deploy(proxy_mode, compose_mode)
            wait_gate("proxy-reached" if proxy_mode else "compose-reached")
            before = cli_json("operation", "--operation", operation_id)
            require(before["state"] == "running", "crash gate did not stop a running operation")
            expected_mutation = boundary != "before_durable_mutation"
            require(before["mutation_started"] == expected_mutation, "wrong durable mutation side of gate")
            before_evidence = state_and_locks(operation_id)
            require(before_evidence["locks"], "running operation does not own durable locks")
            inspected = docker_json("inspect", *command([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split())
            runtime = [{"id": item["Id"], "image_id": item["Image"], "state": item["State"]["Status"],
                        "started_at": item["State"]["StartedAt"], "mounts": item["Mounts"]} for item in inspected]
            require(len(runtime) == 1, "crash boundary has wrong real component count")
            expected_runtime = "exited" if boundary in ("stop_applied_response_not_received", "files_applied_before_compose_up") else "running"
            require(runtime[0]["state"] == expected_runtime, "wrong real Docker state at crash boundary")
            files = read_file("services/game/code/VERSION")
            expected_files = "fault-" + identifier if boundary in ("files_applied_before_compose_up", "compose_up_applied_before_observation", "active_release_recorded_before_warmup") else initial_version["version"]
            require(files == expected_files, "wrong real active file state at crash boundary")
            # Kill PID 1 in the real executor container. No product test hook,
            # graceful shutdown, fake store or synthetic terminal state is used.
            command([docker, "kill", "--signal", "KILL", executor_name])
            starts_after_kill = starts()
            game_ids_after_kill = command([docker, "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
            control()
            restart_executor()
            interrupted = wait_operation(operation_id, ("interrupted",))
            require(interrupted["mutation_started"] == expected_mutation, "restart lost mutation intent")
            require(state_and_locks(operation_id)["locks"] == before_evidence["locks"], "restart lost unresolved resource locks")
            time.sleep(.8)
            require(read_file("services/game/code/VERSION") == files, "restart blindly replayed active file mutation")
            current_starts = starts()
            game_ids_after_restart = command([docker, "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
            require(game_ids_after_kill == game_ids_after_restart, "restart blindly replaced application container")
            require(all(starts_after_kill[key] == current_starts[key] for key in game_ids_after_kill), "restart blindly replayed Docker action")
            retry = cli_json("submit", "--request", path)
            require(retry["spec"]["id"] == operation_id and retry["state"] == "interrupted", "retry replayed interrupted operation")
            if boundary == "active_release_recorded_before_warmup":
                require(before_evidence["state"]["current_release_id"] == target["id"], "warmup crash hid actually launched release")
                require(before["stage"] == "warmup", "warmup gate did not observe persisted warmup stage")
            restored = recover(operation_id)
            report["crash_cases"].append({"boundary": boundary, "operation_id": operation_id,
                "at_kill": {"stage": before["stage"], "mutation_started": before["mutation_started"],
                            "active_release_id": before_evidence["state"]["current_release_id"], "active_version_file": files,
                            "runtime": runtime, "lock_count": len(before_evidence["locks"])},
                "after_restart": {"state": interrupted["state"], "locks_preserved": True, "no_blind_replay": True, "idempotent_retry": True},
                "recovery": {"state": restored["state"], "returned_to_previous": True, "locks_released": True, "flag_and_state_preserved": True}})
            print(json.dumps({"boundary": boundary, "status": "passed"}), flush=True)
        report["checks"]["all_requested_external_gate_sigkill_boundaries_explicit_recovery"] = True

        operation_id, _ = submit_deploy("lose_stop_response")
        wait_gate("proxy-reached")
        unknown = wait_operation(operation_id, ("requires_recovery",))
        require(unknown["mutation_started"] and not unknown["outcome"]["actual_state_known"], "lost actual Stop response was misreported as known success")
        require(state_and_locks(operation_id)["locks"], "unknown Stop response released locks")
        control()
        recover(operation_id)
        report["checks"]["real_stop_response_loss_requires_recovery_preserves_locks_data"] = True

        # Simulate temporary API unavailability for only this executor. The game
        # container and shared Docker daemon continue running throughout.
        fixture_ids = command([docker, "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        started_before = {key: value for key, value in starts().items() if key in fixture_ids}
        request = {"service_id": service_id, "action": "deploy", "release_id": target["id"], "confirm_data_compatibility": True,
                   "initiator": "fault-smoke", "idempotency_key": uuid.uuid4().hex}
        path = write_json("unavailable-request.json", request)
        request["plan_digest"] = cli_json("preview", "--request", path)["plan_digest"]
        write_json("unavailable-request.json", request)
        control("unavailable")
        unavailable = cli_json("submit", "--request", path)
        refused = wait_operation(unavailable["spec"]["id"], ("failed",))
        require(not refused["mutation_started"], "unavailable Docker API reached active mutation")
        require(api(base, "GET", "/flags/" + key)["value"] == flag, "API unavailability affected running game's data")
        starts_after_unavailable = starts()
        require(all(starts_after_unavailable.get(key) == value for key, value in started_before.items()), "API unavailability restarted fixture container")
        control()
        require(cli_json("service", "--service", service_id)["current_release_id"] == baseline, "API restoration lost active release")
        report["checks"]["executor_only_docker_api_503_fails_closed_running_game_unchanged"] = True

        # A truly missing runtime component must not be silently recreated during
        # recovery. The unresolved lock/evidence are preserved for administrator
        # reconciliation; teardown affects only this disposable fixture project.
        operation_id, _ = submit_deploy("after_stop")
        wait_gate("proxy-reached")
        game_ids = command([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        require(len(game_ids) == 1, "unexpected component set for disappearance scenario")
        command([docker, "rm", game_ids[0]])
        control()
        wait_operation(operation_id, ("requires_recovery",))
        request = {"service_id": service_id, "action": "recover", "recovery_operation_id": operation_id,
                   "confirm_data_compatibility": True, "initiator": "fault-smoke", "idempotency_key": uuid.uuid4().hex}
        path = write_json("missing-recover.json", request)
        request["plan_digest"] = cli_json("preview", "--request", path)["plan_digest"]
        write_json("missing-recover.json", request)
        cli_json("submit", "--request", path)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            observed = cli_json("operation", "--operation", operation_id)
            if observed["state"] == "requires_recovery" and "runtime component count changed" in observed["outcome"].get("reason", ""):
                break
            time.sleep(.1)
        else:
            raise RuntimeError("missing component recovery did not fail closed: " + json.dumps(observed))
        require(state_and_locks(operation_id)["locks"], "missing runtime component released unresolved locks")
        require(not command([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.strip(), "recovery silently recreated externally removed component")
        persisted = json.loads(helper("import json,sqlite3,sys; from pathlib import Path; db=sqlite3.connect('file:'+str(Path(sys.argv[1])/'services/game/data/state.sqlite3')+'?mode=ro',uri=True); print(json.dumps(dict(db.execute('SELECT namespace,value FROM entries WHERE key=?',(sys.argv[2],)))))", key).stdout)
        require(persisted == {"flags": flag, "state": state_value}, "missing-container handling changed persistent game data")
        report["checks"]["externally_removed_component_recovery_refused_without_blind_recreate_locks_retained"] = True
        report["proxy_events"] = [json.loads(line) for line in read_file("config/proxy-events.jsonl").splitlines()]
        report["executor_settings"] = {"development": False, "user": "0:10001", "network_mode": "none", "read_only_root": True,
                                       "capabilities": ["CHOWN", "DAC_OVERRIDE", "FOWNER"], "native_storage": True}
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        if executor_started:
            report["executor_logs"] = command([docker, "logs", "--tail", "40", executor_name], success=False).stdout[-6000:]
        if proxy_started:
            report["proxy_logs"] = command([docker, "logs", "--tail", "40", proxy_name], success=False).stderr[-6000:]
            try:
                report["proxy_events"] = read_file("config/proxy-events.jsonl").splitlines()[-100:]
            except Exception:
                pass
    finally:
        if executor_started:
            command([docker, "rm", "--force", executor_name], success=False)
        if proxy_started:
            command([docker, "rm", "--force", proxy_name], success=False)
        if game_started:
            cleanup = command(compose + ["down", "--remove-orphans"], success=False)
            if cleanup.returncode:
                report["cleanup_error"] = cleanup.stderr[-2000:]
                report["status"] = "failed"
        for pattern in (project + "-*", "ctf-manager/" + service_id + ":*"):
            own_image_tags.update(command([docker, "image", "ls", "--filter", "reference=" + pattern,
                                           "--format", "{{.Repository}}:{{.Tag}}"], success=False).stdout.split())
        for tag in sorted(own_image_tags):
            command([docker, "image", "rm", tag], success=False)
        if root is not None:
            try:
                helper("import pathlib,shutil,sys; p=pathlib.Path(sys.argv[1]); [(shutil.rmtree(x) if x.is_dir() and not x.is_symlink() else x.unlink()) for x in p.iterdir()]")
                report["isolated_native_directory_contents_removed"] = True
                report["empty_daemon_directory_retained"] = str(root)
            except Exception as cleanup_error:
                report["cleanup_error"] = str(cleanup_error)
                report["status"] = "failed"
        after_other = starts()
        concurrent = {key for key, item in before_labels.items()
                      if (item.get("project") or "").startswith(("ctfm-workflows-", "ctfm-load-"))}
        protected = {key for key, item in before_labels.items() if item.get("project") and key not in concurrent}
        report["external_observation"] = {"preexisting_count": len(before_other),
            "preexisting_ids_absent_after": len(set(before_other) - set(after_other)),
            "preexisting_started_at_changed": sum(after_other[key] != value for key, value in before_other.items() if key in after_other),
            "raw_missing_ids": sorted(set(before_other) - set(after_other)),
            "raw_started_at_changed_ids": sorted(key for key in before_other if key in after_other and before_other[key] != after_other[key]),
            "protected_compose_count": len(protected),
            "protected_compose_missing_ids": sorted(protected - set(after_other)),
            "protected_compose_started_at_changed_ids": sorted(key for key in protected if key in after_other and before_other[key] != after_other[key]),
            "concurrent_acceptance_ids": sorted(concurrent),
            "scope": "preexisting Compose projects asserted except concurrent ctfm-workflows-/ctfm-load- acceptance projects; all raw deltas retained"}
        if report["external_observation"]["protected_compose_missing_ids"] or report["external_observation"]["protected_compose_started_at_changed_ids"]:
            report["status"] = "failed"
            report["external_concurrent_change_detected"] = True
        remaining_tags = command([docker, "image", "ls", "--filter", "reference=ctf-manager/" + service_id + ":*", "--format", "{{.Repository}}:{{.Tag}}"], success=False).stdout.split()
        remaining_build_tags = command([docker, "image", "ls", "--filter", "reference=" + project + "-*", "--format", "{{.Repository}}:{{.Tag}}"], success=False).stdout.split()
        remaining_game = command([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        remaining_named = command([docker, "ps", "--all", "--quiet", "--filter", "name=^/" + project + "-(executor|proxy)$"]).stdout.split()
        remaining_networks = command([docker, "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        remaining_volumes = command([docker, "volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        report["cleanup_postflight"] = {"game_containers": remaining_game, "executor_proxy_containers": remaining_named,
            "networks": remaining_networks, "volumes": remaining_volumes,
            "retention_tags": remaining_tags, "build_tags": remaining_build_tags}
        if any(report["cleanup_postflight"].values()):
            report["status"] = "failed"
            report["cleanup_error"] = "owned Docker resources remain after cleanup"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        shutil.rmtree(launch)
    print(json.dumps({key: value for key, value in report.items() if key not in ("proxy_events", "crash_cases")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
