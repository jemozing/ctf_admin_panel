#!/usr/bin/env python3
"""Real Apply-EROFS and partial multi-component switching in an owned fixture.

The shared Docker daemon and existing game/panel projects are never changed.
No product fault hook or database outcome fabrication is used. Only this unique
executor's mount profile and its administrator-controlled Compose wrapper vary.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
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


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(args, *, input=None, timeout=180, success=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
    result = subprocess.run(args, input=input, capture_output=True, text=True,
                            timeout=timeout, env=env)
    if success and result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} {args[1:3]} failed: " +
                           (result.stderr + result.stdout)[-5000:])
    return result


def parsed(args, **kwargs):
    return json.loads(run(args, **kwargs).stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executor-image", default="ctf-manager-executor:local")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/fault-multi-component-2026-10-20.json")
    args = parser.parse_args()
    docker = shutil.which("docker")
    require(docker, "Docker CLI required")
    context = parsed([docker, "context", "inspect"])[0]
    endpoint = os.environ.get("DOCKER_HOST", context["Endpoints"]["docker"]["Host"])
    require(endpoint.startswith("unix:///"), "only local Docker Unix endpoint supported")
    socket_path = endpoint.removeprefix("unix://")
    identity = uuid.uuid4().hex[:12]
    project, service_id = "ctfm-fault-multi-" + identity, "fault-multi-" + identity
    root = Path("/srv") / project
    active = root / "services/game"
    executor_name = project + "-executor"
    launch = Path(tempfile.mkdtemp(prefix=project + "-")).resolve()
    owned_tags = set()
    started = game_started = directory_created = False
    report = {"test": "multi-component-partial-switch-and-apply-erofs", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(), "project": project,
              "service_id": service_id, "checks": {}, "cases": [],
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "limitations": ["Real EROFS is an executor-only read-only bind, not ENOSPC/fsync/power loss",
                              "Compose failure is fixture-scoped after real recreation of one target",
                              "No shared daemon restart, registry disconnection or live-project mutation"]}

    def starts():
        ids = run([docker, "ps", "--all", "--quiet", "--no-trunc"]).stdout.split()
        if not ids:
            return {}
        # A concurrent acceptance helper can exit between ps and inspect.
        # Protected and fixture-owned container identities are checked below.
        lines = run([docker, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *ids], success=False).stdout.splitlines()
        return dict(line.split(maxsplit=1) for line in lines)

    before = starts()
    label_template = '{"id":{{json .Id}},"name":{{json .Name}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}'
    observed_labels = run([docker, "inspect", "--format", label_template, *before], success=False).stdout.splitlines() if before else []
    labels_before = {item["id"]: item for item in map(json.loads, observed_labels)}
    concurrent_before = {key for key, item in labels_before.items() if (item.get("project") or "").startswith(("ctfm-workflows-", "ctfm-load-"))}
    protected_before = {key for key, item in labels_before.items() if item.get("project") and key not in concurrent_before}
    report["preexisting_labels"] = list(labels_before.values())
    image = parsed([docker, "image", "inspect", args.executor_image])[0]
    executor_image = image["Id"]
    helper_image = parsed([docker, "image", "inspect", "python:3.11-slim"])[0]["Id"]
    report["executor_image_id"] = executor_image
    report["executor_image_platform"] = image["Os"] + "/" + image["Architecture"]
    report["docker"] = parsed([docker, "version", "--format", "{{json .Server}}"])
    report["runtime_qualification"] = runtime_qualification(report["docker"], image)
    report["limitations"].append(report["runtime_qualification"]["scope_note"])

    def helper(code, *values):
        return run([docker, "run", "--rm", "--network", "none", "--mount", f"type=bind,src={root},dst={root}",
                    "--mount", f"type=bind,src={ROOT},dst={ROOT},readonly", helper_image,
                    "python3", "-c", code, str(root), *map(str, values)])

    def cli(*parts, success=True):
        return run([docker, "exec", executor_name, "/usr/local/bin/ctf-manager", "--config",
                    str(root / "config/executor.json"), *parts], success=success)

    def cj(*parts):
        return json.loads(cli(*parts).stdout)

    def request_file(value):
        name = "request-" + uuid.uuid4().hex + ".json"
        local = launch / name
        local.write_text(json.dumps(value) + "\n")
        target = str(root / "requests" / name)
        run([docker, "cp", str(local), executor_name + ":" + target])
        return target

    def submit(action, **fields):
        request = {"service_id": service_id, "action": action, "initiator": "fault-multi-acceptance",
                   "idempotency_key": uuid.uuid4().hex, **fields}
        preview = cj("preview", "--request", request_file(request))
        request["plan_digest"] = preview["plan_digest"]
        path = request_file(request)
        return cj("submit", "--request", path), path

    def wait(operation, expected, *, changed_from=None):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            value = cj("operation", "--operation", operation)
            if changed_from and value["updated_at"] == changed_from:
                time.sleep(.15)
                continue
            if value["state"] in expected:
                return value
            if value["state"] in ("succeeded", "failed", "requires_recovery", "interrupted", "cancelled"):
                raise RuntimeError("unexpected operation result: " + json.dumps(value))
            time.sleep(.2)
        raise RuntimeError("operation timeout: " + operation)

    def operation(action, **fields):
        accepted, path = submit(action, **fields)
        result = wait(accepted["spec"]["id"], ("succeeded",))
        require(cj("submit", "--request", path)["spec"]["id"] == accepted["spec"]["id"], "idempotent request changed identity")
        return result

    def inspect():
        ids = run([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        require(len(ids) == 4, "synthetic project must retain four components")
        result = {}
        for item in parsed([docker, "inspect", *ids]):
            component = item["Config"]["Labels"]["com.docker.compose.service"]
            result[component] = {"id": item["Id"], "image_id": item["Image"], "state": item["State"]["Status"],
                                 "started_at": item["State"]["StartedAt"], "mounts": item["Mounts"],
                                 "ports": item["NetworkSettings"]["Ports"]}
        return result

    def url(component):
        return "http://127.0.0.1:" + inspect()[component]["ports"]["8080/tcp"][0]["HostPort"]

    def api(component, method, path, value=None):
        request = urllib.request.Request(url(component) + path, method=method,
                  data=None if value is None else json.dumps({"value": value}).encode(),
                  headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.load(response)

    def ready():
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                for component in ("app_a", "app_b", "db_a", "db_b"):
                    api(component, "GET", "/health")
                return
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(.3)
        raise RuntimeError("fixture health timeout")

    def evidence(operation):
        value = json.loads(helper("""import json,sqlite3,sys
from pathlib import Path
p=Path(sys.argv[1]); db=sqlite3.connect('file:'+str(p/'executor/executor.db')+'?mode=ro',uri=True)
states=[json.loads(row[0]) for row in db.execute("SELECT payload FROM records WHERE kind='runtime_state'")]
print(json.dumps({'locks':[list(row) for row in db.execute('SELECT resource,operation_id FROM locks WHERE operation_id=?',(sys.argv[2],))], 'state':max(states,key=lambda x:x['sequence']), 'recovery_approvals':db.execute("SELECT count(*) FROM records WHERE kind='recovery_consumed'").fetchone()[0], 'active_version':(p/'services/game/code/VERSION').read_text().strip()}))
""", operation).stdout)
        value["runtime"] = inspect()
        value["operation"] = cj("operation", "--operation", operation)
        value["details"] = cj("service", "--service", service_id)
        value["events"] = cj("events", "--operation", operation)
        value["diagnostics"] = cj("diagnostics", "--operation", operation)
        return value

    def control(mode):
        helper("from pathlib import Path;import sys;p=Path(sys.argv[1])/'config/compose-mode';p.write_text(sys.argv[2])", mode)

    def start_executor(read_only_project):
        nonlocal started
        mounts = ["--mount", f"type=bind,src={root},dst={root}",
                  "--mount", f"type=bind,src={socket_path},dst=/var/run/docker.sock"]
        if read_only_project:
            mounts += ["--mount", f"type=bind,src={active},dst={active},readonly"]
        command = [docker, "run", "--detach", "--name", executor_name, "--user", "0:10001", "--network", "bridge", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777"]
        for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "KILL"):
            command += ["--cap-add", capability]
        run(command + mounts + [executor_image, "--config", str(root / "config/executor.json"), "executor"])
        started = True
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if cli("status", success=False).returncode == 0:
                return
            time.sleep(.2)
        raise RuntimeError("owned executor did not start")

    def recover(operation, expected):
        accepted, path = submit("recover", recovery_operation_id=operation, confirm_data_compatibility=True)
        require(accepted["spec"]["id"] == operation, "Recover lost original identity")
        result = wait(operation, (expected,), changed_from=accepted["updated_at"])
        require(cj("submit", "--request", path)["spec"]["id"] == operation, "Recover retry changed identity")
        return result

    key = "multi_" + identity
    values = {"app_a": "CTFM_SYNTHETIC_FLAG_A_" + identity, "app_b": "CTFM_SYNTHETIC_FLAG_B_" + identity}

    def preserved(initial, use_apps=True):
        current = inspect()
        for component in ("db_a", "db_b"):
            require(all(current[component][name] == initial[component][name] for name in ("id", "started_at", "image_id", "mounts")), "database dependency was changed: " + component)
        for app, value in values.items():
            component = app if use_apps else "db_" + app[-1]
            require(api(component, "GET", "/flags/" + key)["value"] == value, "persistent flag lost: " + app)
        return True

    try:
        run([docker, "run", "--rm", "--network", "none", "--volume", f"{root}:{root}", helper_image,
             "python3", "-c", "from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not any(p.iterdir())", str(root)])
        directory_created = True
        setup = """import json,os,shutil,sys
from pathlib import Path
r,repository=Path(sys.argv[1]),Path(sys.argv[2]);os.chmod(r,0o755)
for name in ('services','workspaces','config','requests'): (r/name).mkdir(mode=0o755)
(r/'executor').mkdir(mode=0o700);(r/'runtime').mkdir(mode=0o750);os.chown(r/'runtime',0,10001)
active=r/'services/game';active.mkdir();shutil.copytree(repository/'tests/fixtures/app',active/'code',ignore=shutil.ignore_patterns('__pycache__','test_app.py','*.pyc'))
services={}
for name in ('app_a','app_b','db_a','db_b'):
 service={'build':'./code','shm_size':'64m','read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'logging':{'driver':'json-file','options':{'max-size':'2m','max-file':'2'}},'ports':[{'target':8080,'host_ip':'127.0.0.1','protocol':'tcp'}]}
 if name.startswith('app_'):
  database='db_'+name[-1];service['environment']={'FIXTURE_STORAGE':'remote','FIXTURE_BACKEND_URL':'http://'+database+':8080'};service['depends_on']={database:{'condition':'service_healthy'}}
 else:
  service['environment']={'FIXTURE_ROLE':'database'};service['volumes']=[name+'-data:/data']
 services[name]=service
(active/'compose.yaml').write_text(json.dumps({'services':services,'volumes':{'db_a-data':{},'db_b-data':{}}}))
shutil.copytree(active,r/'workspaces/game')
c={'state_directory':str(r/'executor'),'socket':str(r/'runtime/executor.sock'),'docker_host':'unix:///var/run/docker.sock','docker_binary':'/usr/local/bin/docker','compose_binary':str(r/'config/compose-wrapper'),'discovery_roots':[str(r/'services')],'workspace_roots':[str(r/'workspaces')],'web_uid':10001,'development':False}
(r/'config/executor.json').write_text(json.dumps(c));os.chmod(r/'config/executor.json',0o600)
"""
        helper(setup, ROOT)
        wrapper = """#!/bin/sh
export DOCKER_HOST=unix:///var/run/docker.sock
action=
project= directory= file= envfile=
previous=
for argument in "$@"; do
 case "$previous" in --project-name) project=$argument;; --project-directory) directory=$argument;; --file) file=$argument;; --env-file) envfile=$argument;; esac
 [ "$argument" = up ] && action=up
 previous=$argument
done
mode=$(cat 'MODE' 2>/dev/null || true)
if [ "$action:$mode" = up:block_up ]; then echo 'fixture: Compose up refused before recreation' >&2; exit 72; fi
if [ "$action:$mode" = up:partial_a ]; then
 /usr/local/libexec/docker/cli-plugins/docker-compose --progress plain --project-name "$project" --project-directory "$directory" --file "$file" --env-file "$envfile" up --detach --no-build --pull never --no-deps --force-recreate app_a
 result=$?
 [ "$result" = 0 ] || exit "$result"
 echo 'fixture: app_a really recreated; injected failure before app_b recreation' >&2
 exit 71
fi
exec /usr/local/libexec/docker/cli-plugins/docker-compose "$@"
""".replace("MODE", str(root / "config/compose-mode"))
        helper("from pathlib import Path;import os,sys;p=Path(sys.argv[1])/'config/compose-wrapper';p.write_text(sys.argv[2]);os.chmod(p,0o700)", wrapper)
        mounts = ["--mount", f"type=bind,src={root},dst={root}", "--mount", f"type=bind,src={socket_path},dst=/var/run/docker.sock"]
        compose = [docker, "run", "--rm", "--network", "bridge", *mounts, "--entrypoint", "/usr/local/bin/docker", executor_image,
                   "compose", "--project-name", project, "--file", str(active / "compose.yaml")]
        game_started = True
        run(compose + ["up", "--detach", "--build"], timeout=300)
        owned_tags.update(project + "-" + name + ":latest" for name in ("app_a", "app_b", "db_a", "db_b"))
        ready()
        initial = inspect()
        for app, value in values.items():
            api(app, "PUT", "/flags/" + key, value)
        initial_version = {app: api(app, "GET", "/version") for app in values}
        start_executor(True)
        executor_mounts = parsed([docker, "inspect", executor_name])[0]["Mounts"]
        readonly_mount = next(item for item in executor_mounts if item["Destination"] == str(active))
        require(not readonly_mount["RW"], "Apply fault requires a real read-only executor project bind")
        report["apply_fault_executor_mount"] = readonly_mount
        inventory = cj("inventory", "--project", project)
        policy = {"schema_version": 1, "id": service_id, "name": "Isolated multi fault " + identity,
                  "project_directory": str(active), "source_directory": str(root / "workspaces/game"),
                  "compose_project": project, "compose_files": ["compose.yaml"], "managed_paths": [{"path": "code", "kind": "code"}],
                  "data_paths": [{"name": name + "-data", "kind": "named_volume", "source": project + "_" + name + "-data", "target": "/data", "component": name, "significant": True, "loss_accepted": False} for name in ("db_a", "db_b")] +
                                [{"name": name + "-layer", "kind": "writable_layer", "target": "/tmp", "component": name, "significant": False, "loss_accepted": True} for name in initial],
                  "targets": ["app_a", "app_b"], "containers": [{"component": item["component"], "id": item["id"], "image_id": item["image_id"], "role": "database" if item["component"].startswith("db_") else "application"} for item in inventory],
                  "policy_revision": 1, "file_map_revision": 1}
        proposal = cj("propose", "--service", request_file(policy))
        cj("approve", "--proposal", proposal["id"], "--digest", proposal["digest"])
        operation("snapshot")
        baseline_details = cj("service", "--service", service_id)
        baseline = baseline_details["current_release_id"]
        helper("from pathlib import Path;import sys;(Path(sys.argv[1])/'workspaces/game/code/VERSION').write_text(sys.argv[2]+chr(10))", "multi-" + identity)
        operation("prepare")
        operation("build", candidate_id=cj("service", "--service", service_id)["candidate_id"])
        details = cj("service", "--service", service_id)
        target = next(release for release in details["releases"] if release["id"] != baseline)
        for release in details["releases"]:
            owned_tags.update(image["retention_tag"] for image in release["images"])
        report["releases"] = {"baseline": baseline, "target": target["id"], "baseline_images": {item["component"]: item["image_id"] for item in baseline_details["releases"][0]["images"]}, "target_images": {item["component"]: item["image_id"] for item in target["images"]}}
        require(all(api(app, "GET", "/version") == initial_version[app] for app in values), "Build changed running versions")
        preserved(initial)
        report["checks"]["baseline_and_real_two_target_build_preserve_runtime_data"] = True

        # Real kernel EROFS, including a failed explicit recovery attempt.
        accepted, _ = submit("deploy", release_id=target["id"], confirm_data_compatibility=True)
        op_id = accepted["spec"]["id"]
        failed = wait(op_id, ("requires_recovery",))
        require(failed["mutation_started"] and "read-only file system" in failed["outcome"]["reason"].lower(), "Apply did not expose actual EROFS after mutation")
        first = evidence(op_id)
        require(first["locks"] and all(first["runtime"][app]["id"] == initial[app]["id"] and first["runtime"][app]["state"] == "exited" for app in values), "EROFS incorrectly recreated app or released locks")
        preserved(initial, False)
        recover(op_id, "requires_recovery")
        second = evidence(op_id)
        require("read-only file system" in second["operation"]["outcome"]["reason"].lower(), "Recovery did not surface actual EROFS")
        require(second["locks"] == first["locks"] and second["recovery_approvals"] > first["recovery_approvals"], "failed recovery lost locks or approval consumption")
        run([docker, "stop", executor_name]);run([docker, "rm", executor_name]);started = False
        before_repair = inspect()
        start_executor(False)
        unchanged = inspect()
        require(all(unchanged[name]["id"] == before_repair[name]["id"] and unchanged[name]["started_at"] == before_repair[name]["started_at"] for name in unchanged), "executor mount repair blindly changed game")
        recovered = recover(op_id, "failed")
        require(recovered["outcome"]["returned_to_previous"], "recovery after writable mount repair did not confirm compensation")
        ready();preserved(initial)
        final = evidence(op_id)
        require(not final["locks"] and final["details"]["current_release_id"] == baseline, "repaired recovery did not release locks/restore baseline")
        require(all(api(app, "GET", "/version") == initial_version[app] for app in values), "EROFS recovery did not restore baseline responses")
        report["cases"].append({"case": "apply_erofs_then_recovery_erofs_then_explicit_repair", "operation_id": op_id, "apply_failure": first, "recovery_failure": second, "after_repair": final})
        report["checks"]["real_apply_and_recovery_erofs_preserve_data_locks_then_recover"] = True
        print(json.dumps({"case": "apply_erofs", "status": "passed"}), flush=True)

        # A real Compose up is limited to app_a, then reports an injected error.
        before_partial = inspect()
        control("partial_a")
        accepted, _ = submit("deploy", release_id=target["id"], confirm_data_compatibility=True)
        op_id = accepted["spec"]["id"]
        wait(op_id, ("requires_recovery",))
        partial = evidence(op_id)
        runtime = partial["runtime"]
        require(runtime["app_a"]["id"] != before_partial["app_a"]["id"] and runtime["app_a"]["image_id"] == report["releases"]["target_images"]["app_a"] and runtime["app_a"]["state"] == "running", "partial switch did not really replace app_a")
        require(runtime["app_b"]["id"] == before_partial["app_b"]["id"] and runtime["app_b"]["image_id"] == report["releases"]["baseline_images"]["app_b"] and runtime["app_b"]["state"] == "exited", "partial switch unexpectedly replaced app_b")
        require(partial["locks"] and partial["details"].get("current_release_id") != target["id"], "partial switch falsely reported completed release or released locks")
        require(partial["operation"]["state"] == "requires_recovery" and not partial["operation"]["outcome"]["actual_state_known"], "partial effect incorrectly reported success/known final outcome")
        preserved(initial, False)
        control("block_up")
        recover(op_id, "requires_recovery")
        blocked = evidence(op_id)
        require(blocked["locks"] == partial["locks"] and blocked["recovery_approvals"] > partial["recovery_approvals"], "failed partial recovery lost protected evidence")
        preserved(initial, False)
        control("")
        recovered = recover(op_id, "failed")
        require(recovered["outcome"]["returned_to_previous"], "fresh partial recovery failed to restore previous release")
        ready();preserved(initial)
        final = evidence(op_id)
        require(not final["locks"] and final["details"]["current_release_id"] == baseline, "partial recovery did not restore baseline/locks")
        require(all(final["runtime"][app]["image_id"] == report["releases"]["baseline_images"][app] and api(app, "GET", "/version") == initial_version[app] for app in values), "partial recovery did not restore exact images/responses")
        report["cases"].append({"case": "two_target_partial_compose_switch_and_failed_recovery_retry", "operation_id": op_id, "partial_switch": partial, "recovery_failure": blocked, "recovered": final})
        report["checks"]["partial_two_component_switch_no_false_success_failed_recovery_safe_fresh_retry_exact"] = True
        report["checks"]["both_database_ids_started_at_mounts_and_two_flags_preserved"] = True
        report["flag_sha256"] = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in values.items()}
        report["status"] = "passed"
        print(json.dumps({"case": "partial_switch", "status": "passed"}), flush=True)
    except Exception as error:
        report["error"] = str(error)
        if started:
            report["executor_logs"] = run([docker, "logs", "--tail", "40", executor_name], success=False).stdout[-6000:]
    finally:
        if started:
            run([docker, "rm", "--force", executor_name], success=False)
        if game_started:
            result = run(compose + ["down", "--volumes", "--remove-orphans"], success=False)
            report["cleanup_compose_returncode"] = result.returncode
            if result.returncode:
                report["cleanup_error"] = result.stderr[-2500:];report["status"] = "failed"
        for pattern in (project + "-*", "ctf-manager/" + service_id + ":*"):
            owned_tags.update(run([docker, "image", "ls", "--filter", "reference=" + pattern, "--format", "{{.Repository}}:{{.Tag}}"], success=False).stdout.split())
        for tag in sorted(owned_tags):
            run([docker, "image", "rm", tag], success=False)
        if directory_created:
            try:
                helper("from pathlib import Path;import shutil,sys;p=Path(sys.argv[1]);[(shutil.rmtree(x) if x.is_dir() and not x.is_symlink() else x.unlink()) for x in p.iterdir()]")
                report["cleanup_native_contents_removed"] = True
                report["empty_daemon_directory_retained"] = str(root)
            except Exception as error:
                report["cleanup_error"] = str(error);report["status"] = "failed"
        remaining = run([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).stdout.split()
        report["remaining_owned_game_containers"] = len(remaining)
        if remaining:
            report["cleanup_error"] = "owned game containers remain after cleanup"
            report["status"] = "failed"
        report["cleanup_postflight"] = {
            "game_containers": remaining,
            "executor_containers": run([docker, "ps", "--all", "--quiet", "--filter", "name=^/" + executor_name + "$"], success=False).stdout.split(),
            "networks": run([docker, "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project], success=False).stdout.split(),
            "volumes": run([docker, "volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project], success=False).stdout.split(),
            "retention_tags": run([docker, "image", "ls", "--filter", "reference=ctf-manager/" + service_id + ":*", "--format", "{{.Repository}}:{{.Tag}}"], success=False).stdout.split(),
            "build_tags": run([docker, "image", "ls", "--filter", "reference=" + project + "-*", "--format", "{{.Repository}}:{{.Tag}}"], success=False).stdout.split(),
        }
        if any(report["cleanup_postflight"].values()):
            report["cleanup_error"] = "owned Docker resources remain after cleanup"
            report["status"] = "failed"
        after = starts()
        report["preexisting_observation"] = {"count": len(before), "missing_ids": list(set(before) - set(after)),
                  "started_at_changed_ids": [key for key in before if key in after and before[key] != after[key]],
                  "protected_compose_count": len(protected_before), "protected_compose_missing_ids": list(protected_before - set(after)),
                  "protected_compose_started_at_changed_ids": [key for key in protected_before if key in after and before[key] != after[key]],
                  "concurrent_acceptance_ids": sorted(concurrent_before), "concurrent_acceptance_missing_ids": list(concurrent_before - set(after)),
                  "scope": "preexisting Compose projects asserted except explicitly concurrent ctfm-workflows-/ctfm-load- acceptance projects; raw deltas retained"}
        if report["preexisting_observation"]["protected_compose_missing_ids"] or report["preexisting_observation"]["protected_compose_started_at_changed_ids"]:
            report["status"] = "failed";report["external_concurrent_change_detected"] = True
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        shutil.rmtree(launch)
    print(json.dumps({key: value for key, value in report.items() if key not in ("cases", "docker")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
