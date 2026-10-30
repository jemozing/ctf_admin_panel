#!/usr/bin/env python3
"""Isolated production-executor acceptance of health/snapshots/cancel/scheduler.

Uses only two new synthetic Compose projects and one unique native daemon root.
The immutable image under test is never rebuilt or retagged. Unix HTTP requests
exercise production typed APIs as a local administrator, not browser/RBAC flows.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
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
TERMINAL = {"succeeded", "failed", "cancelled", "interrupted", "requires_recovery"}


def should_preserve_fixture(requested, status):
    return requested is True and status != "passed"


def exception_metadata(error):
    result = {"type": type(error).__name__}
    if isinstance(error, subprocess.TimeoutExpired):
        executable = error.cmd[0] if isinstance(error.cmd, (list, tuple)) and error.cmd else "subprocess"
        result.update(timeout_seconds=error.timeout, executable=Path(str(executable)).name,
                      argv_and_captured_output="omitted")
    return result


def safe_rpc_path(path):
    # Keep route names only: never copy IDs, query strings, or unknown suffixes.
    parts = str(path).split("?", 1)[0].split("#", 1)[0].split("/")
    if parts == ["", "v1", "preview"] or parts == ["", "v1", "operations"]:
        return "/".join(parts)
    if parts[:3] == ["", "v1", "services"] and len(parts) >= 4:
        suffix = parts[4:]
        if suffix in ([], ["checks"], ["checks", "manual"]):
            return "/v1/services/:service_id" + ("/" + "/".join(suffix) if suffix else "")
    if parts[:3] == ["", "v1", "operations"] and len(parts) >= 4:
        suffix = parts[4:]
        if suffix in ([], ["events"], ["cancel"]):
            return "/v1/operations/:operation_id" + ("/" + "/".join(suffix) if suffix else "")
    return "unrecognized_route"


@contextmanager
def trace_rpc(report, method, path, clock=time.monotonic):
    started = clock()
    entry = {"method": method if method in ("GET", "POST") else "unknown",
             "path": safe_rpc_path(path), "elapsed_seconds": 0.0,
             "phase": "running", "completed": False, "error_type": None}
    report["last_rpc"] = entry
    try:
        yield
    except Exception as error:
        entry.update(phase="error", error_type=type(error).__name__)
        raise
    else:
        entry.update(phase="completed", completed=True)
    finally:
        entry["elapsed_seconds"] = round(max(0.0, clock() - started), 6)
        history = report.setdefault("rpc_durations", [])
        history.append(dict(entry))
        del history[:-16]


def native_local_helper_evidence(endpoint, docker_info, *, local_platform, local_kernel, effective_uid, socket_mode):
    require(local_platform == "linux", "native local helpers require local Linux")
    require(effective_uid == 0, "native local helpers require local root")
    require(endpoint.startswith("unix:///") and "?" not in endpoint and "#" not in endpoint,
            "native local helpers require an absolute local Unix Docker endpoint")
    require(stat.S_ISSOCK(socket_mode), "native local helpers require an actual Unix socket")
    require(docker_info.get("OSType") == "linux", "native local helpers require a Linux Docker daemon")
    require(bool(local_kernel) and docker_info.get("KernelVersion") == local_kernel,
            "native local helpers require the same local and Docker daemon kernel")
    return {"local_platform": local_platform, "effective_uid": effective_uid,
            "local_kernel": local_kernel, "daemon_kernel": docker_info["KernelVersion"],
            "daemon_os": docker_info["OSType"], "unix_socket_verified": True,
            "same_kernel_verified": True}


def command(args, *, timeout=180, success=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True,
                            timeout=timeout, env=env)
    if success and result.returncode:
        raise RuntimeError(f"command {args[:3]} failed: " + (result.stderr + result.stdout)[-5000:])
    return result


def parsed(args, **kwargs):
    return json.loads(command(args, **kwargs).stdout)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def app(base, method, path, value=None, status=200):
    body = None if value is None else json.dumps({"value": value}).encode()
    request = urllib.request.Request(base + path, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        require(response.status == status, "fixture HTTP status mismatch: " + path)
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executor-image", default="ctf-manager-executor:local")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/mvp-workflows-smoke-2026-10-20.json")
    parser.add_argument("--pipeline-negatives-only", action="store_true", help="run VOLUME refusal, stale plan and managed-delete pipeline checks")
    parser.add_argument("--capture-live-sqlite", action="store_true", help="compare external live SQLite reads with offline reads after graceful shutdown; require linked writer sidecars and matching terminal operations, locks and switch observations")
    parser.add_argument("--preserve-on-failure", action="store_true", help="debug only: retain this UUID fixture and launch directory after a failed scenario; successful runs always clean up")
    parser.add_argument("--native-local-helpers", action="store_true", help="run Python fixture helpers locally using this interpreter; requires local Linux root, an actual Unix Docker socket, and the same host/daemon kernel")
    args = parser.parse_args()
    docker = shutil.which("docker")
    require(docker, "Docker CLI required")
    context = parsed([docker, "context", "inspect"])[0]
    endpoint = os.environ.get("DOCKER_HOST", context["Endpoints"]["docker"]["Host"])
    require(endpoint.startswith("unix:///"), "local Unix Docker daemon required")
    daemon_socket = endpoint.removeprefix("unix://")
    token = uuid.uuid4().hex[:10]
    prefix = "ctfm-workflows-" + token
    root = Path("/srv") / prefix
    launch = Path(tempfile.mkdtemp(prefix=prefix + "-"))
    projects = {key: prefix + "-" + key for key in ("a", "b")}
    service_ids = {key: "workflows-" + token + "-" + key for key in projects}
    executor_name = prefix + "-executor"
    report = {"test": "mvp-new-workflows-production-executor", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "projects": projects, "service_ids": service_ids, "checks": {}, "operations": [],
              "helper_execution": {"requested": "native_local" if args.native_local_helpers else "docker_container",
                                   "effective": "not_started" if args.native_local_helpers else "docker_container"},
              "scope": "two new synthetic bind-code/bind-data projects; typed Unix API as local administrator",
              "limitations": ["No browser/RBAC claim; isolated production executor API and CLI",
                              "No daemon restart or registry-offline claim",
                              "Scheduler gates are administrator-owned fixture Compose wrappers; product has no test hooks"]}
    class ScenarioComplete(Exception):
        pass

    root_created = False
    executor_started = False
    executor_stopped = False
    started_projects = []
    own_tags = set()
    composes = {}
    before_other = {}
    image_id = None
    bases = {}
    flags = {key: "CTFM_TEST_FLAG_" + token + "_" + key for key in projects}
    game_key = "game_" + token
    private_probe = "PRIVATE_SYNTHETIC_PROBE_" + uuid.uuid4().hex
    helper_label = "ctfm.acceptance.run=" + prefix
    native_helpers = False

    def starts(timeout=180):
        ids = command([docker, "ps", "--all", "--quiet", "--no-trunc"], timeout=timeout).stdout.split()
        if not ids:
            return {}
        return dict(line.split(maxsplit=1) for line in command(
            [docker, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *ids], timeout=timeout).stdout.splitlines())

    def helper(code, *values, timeout=60):
        if native_helpers:
            return command([sys.executable, "-c", code, root, *values], timeout=timeout)
        return command([docker, "run", "--rm", "--label", helper_label, "--network", "none", "--mount",
                        f"type=bind,source={root},target={root}", "--mount",
                        f"type=bind,source={ROOT},target={ROOT},readonly", "python:3.11-slim",
                        "python3", "-c", code, root, *values], timeout=timeout)

    def rpc(method, path, payload=None, expected=200):
        code = '''import http.client,json,socket,sys
from pathlib import Path
root=Path(sys.argv[1]); method,path,payload=sys.argv[2:5]
assert path.startswith('/v1/services/workflows-') or path.startswith('/v1/operations') or path=='/v1/preview'
class UnixHTTP(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect(str(root/'runtime/executor.sock'))
client=UnixHTTP('executor',timeout=20)
body=None if payload=='null' else payload
client.request(method,path,body,{'Content-Type':'application/json','Host':'executor'})
response=client.getresponse();data=response.read(4*1024*1024+1)
assert len(data)<=4*1024*1024
print(json.dumps({'status':response.status,'body':json.loads(data)}))
'''
        with trace_rpc(report, method, path):
            result = json.loads(helper(code, method, path, json.dumps(payload)).stdout)
            require(result["status"] == expected, "typed API status mismatch: " + path + " " + str(result))
            return result["body"]

    def db_file_observation(timeout=180):
        return command([docker, 'exec', executor_name, '/bin/busybox', 'sh', '-c',
                        'for f in "$1"/executor/executor.db*; do /bin/busybox stat -c "%n bytes=%s inode=%i" "$f"; done; '
                        'for f in /proc/1/fd/*; do t=$(readlink "$f"); case "$t" in *executor.db*) echo "$f $t"; cat /proc/1/fdinfo/${f##*/};; esac; done',
                        'sh', str(root)], success=False, timeout=timeout).stdout[-7000:]

    def failure_container_observation():
        result = {"scope": "only this UUID fixture, executor name, and labelled helpers", "containers": [], "errors": []}
        names = [executor_name] if executor_started else []
        filters = ["label=com.docker.compose.project=" + project for project in projects.values()]
        filters.append("label=" + helper_label)
        for selected in filters:
            try:
                observed = command([docker, "ps", "--all", "--quiet", "--no-trunc", "--filter", selected], timeout=3, success=False)
                names.extend(observed.stdout.split())
            except Exception as error:
                result["errors"].append(exception_metadata(error))
        names = list(dict.fromkeys(names))
        result["truncated"] = len(names) > 16
        if names:
            fields = '{"id":{{json .Id}},"name":{{json .Name}},"image_id":{{json .Image}},"status":{{json .State.Status}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"oom_killed":{{json .State.OOMKilled}},"exit_code":{{json .State.ExitCode}},"restart_count":{{json .RestartCount}},"pids_limit":{{json .HostConfig.PidsLimit}}}'
            try:
                observed = command([docker, "inspect", "--format", fields, *names[:16]], timeout=4, success=False)
                result["inspect_exit_code"] = observed.returncode
                result["containers"] = [json.loads(line) for line in observed.stdout[:32768].splitlines() if line.strip()]
            except Exception as error:
                result["errors"].append(exception_metadata(error))
        return result

    def cli(*values, success=True):
        before = db_file_observation()
        result = command([docker, "exec", executor_name, "/usr/local/bin/ctf-manager", "--config",
                          root / "config/executor.json", *values], success=success)
        after = db_file_observation()
        report.setdefault('cli_database_fd_observations', []).append({'command': list(map(str, values)), 'before': before, 'after': after})
        require('(deleted)' not in before and '(deleted)' not in after,
                'SQLite writer sidecar inode was unlinked during CLI access: ' + str(values))
        return result

    def cli_json(*values):
        return json.loads(cli(*values).stdout)

    def details(key):
        return rpc("GET", "/v1/services/" + service_ids[key])

    def health(key):
        return rpc("GET", "/v1/services/" + service_ids[key] + "/checks")

    def request_operation(key, action, **fields):
        request = {"service_id": service_ids[key], "action": action, "initiator": "workflow-smoke",
                   "idempotency_key": uuid.uuid4().hex, **fields}
        plan = rpc("POST", "/v1/preview", request)
        request["plan_digest"] = plan["plan_digest"]
        op = rpc("POST", "/v1/operations", request, expected=202)
        return op, request

    def wait_operation(op_id, expected="succeeded", after=None):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            op = rpc("GET", "/v1/operations/" + op_id)
            if after and op["updated_at"] == after:
                time.sleep(.1)
                continue
            if op["state"] in TERMINAL:
                if op["state"] != expected:
                    report.setdefault("unexpected_operations", []).append(op)
                    report.setdefault("unexpected_events", {})[op_id] = rpc("GET", "/v1/operations/" + op_id + "/events")
                    raise RuntimeError("unexpected operation outcome: " + str(op))
                report["operations"].append(op)
                print(json.dumps({"operation":op["spec"]["kind"],"state":op["state"],"id":op_id}),flush=True)
                return op
            time.sleep(.12)
        raise RuntimeError("operation timed out: " + op_id)

    def operation(key, action, expected="succeeded", **fields):
        op, request = request_operation(key, action, **fields)
        result = wait_operation(op["spec"]["id"], expected)
        retry = rpc("POST", "/v1/operations", request, expected=202)
        require(retry["spec"]["id"] == result["spec"]["id"], "idempotent request duplicated operation")
        return result

    def wait_ready(key):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                return app(bases[key], "GET", "/health")
            except (OSError, ValueError, RuntimeError):
                time.sleep(.2)
        raise RuntimeError("fixture did not become ready: " + key)

    def version(key):
        return app(bases[key], "GET", "/version")["version"]

    def preserve(key):
        require(app(bases[key], "GET", "/flags/" + game_key)["value"] == flags[key], "game flag lost: " + key)
        require(app(bases[key], "GET", "/state/" + game_key)["value"] == "state_" + key, "game state lost: " + key)

    def gate(action):
        helper("from pathlib import Path;import sys;p=Path(sys.argv[1])/'config';(p/'gate-reached').unlink(missing_ok=True);(p/'gate').write_text(sys.argv[2])", action)

    def wait_gate():
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if command([docker, "exec", executor_name, "/bin/busybox", "test", "-f", root / "config/gate-reached"], success=False).returncode == 0:
                return
            time.sleep(.12)
        raise RuntimeError("Compose gate not reached")

    def release_gate():
        helper("from pathlib import Path;import sys;(Path(sys.argv[1])/'config/gate').unlink(missing_ok=True)")

    def sql_evidence():
        return json.loads(helper('''import json,sqlite3,sys
from pathlib import Path
p=Path(sys.argv[1]);db=sqlite3.connect('file:'+str(p/'executor/executor.db')+'?mode=ro',uri=True)
kinds=('check_observation','runtime_switch_observation','docker_build_reservation','manual_health')
print(json.dumps({'records':{kind:[json.loads(row[0]) for row in db.execute('SELECT payload FROM records WHERE kind=? ORDER BY created_at',(kind,))] for kind in kinds},'locks':[list(row) for row in db.execute('SELECT resource,operation_id FROM locks')],'operation_states':[(json.loads(row[0])['spec']['id'],json.loads(row[0])['state']) for row in db.execute('SELECT payload FROM operations')],'python_sqlite_version':sqlite3.sqlite_version,'files':{name:{'bytes':(p/'executor'/name).stat().st_size,'inode':(p/'executor'/name).stat().st_ino} for name in ('executor.db','executor.db-wal','executor.db-shm') if (p/'executor'/name).exists()}}))''').stdout)

    def disk_read_after_shutdown():
        nonlocal executor_stopped
        report['executor_db_fdinfo_before_shutdown'] = db_file_observation()
        require('(deleted)' not in report['executor_db_fdinfo_before_shutdown'],
                'SQLite writer sidecar inode was unlinked before shutdown')
        live = sql_evidence() if args.capture_live_sqlite else None
        if live is not None:
            report['live_external_sqlite_evidence'] = live
            report['executor_db_fdinfo_after_external_reader'] = db_file_observation()
            require('(deleted)' not in report['executor_db_fdinfo_after_external_reader'],
                    'external SQLite reader unlinked writer sidecars')
        command([docker,'stop','--time','20',executor_name]);executor_stopped=True
        for key in projects:preserve(key)
        offline = sql_evidence();report['evidence'] = offline
        report['checks']['game_traffic_and_data_remain_after_executor_shutdown'] = True
        if live is not None:
            live_keys=[(x['operation_id'],x['at']) for x in live['records']['runtime_switch_observation']]
            disk_keys=[(x['operation_id'],x['at']) for x in offline['records']['runtime_switch_observation']]
            if live['locks']!=offline['locks'] or live_keys!=disk_keys or live['operation_states']!=offline['operation_states']:
                report['live_reader_classification']='external_sqlite_reader_inconsistent_while_writer_active'
            else:report['live_reader_classification']='live_and_offline_sqlite_observations_agree'
            require(report['live_reader_classification']=='live_and_offline_sqlite_observations_agree',
                    'live SQLite reader disagreed with offline terminal operations, locks or switch observations')
            report['checks']['live_and_offline_sqlite_match_with_linked_writer_sidecars'] = True
        else:
            report['live_reader_classification']='no_external_sqlite_reader_while_writer_active; offline_after_graceful_shutdown'
        require(not offline['locks'],'resolved operations retained locks in offline database')
        return offline

    def negative_pipeline():
        before=cli_json('inventory','--project',projects['a'])[0]
        before_started=starts()[before['id']]
        before_releases={item['id'] for item in details('a')['releases']}
        helper("from pathlib import Path;import sys;p=Path(sys.argv[1]);d=p/'workspaces/a/code/Dockerfile';(p/'config/original-Dockerfile').write_bytes(d.read_bytes());d.write_text(d.read_text()+'\\nVOLUME /unregistered-game-volume\\n');(p/'services/a/operator-note').write_text('unmanaged-operator-note')")
        operation('a','prepare');bad=operation('a','build',expected='failed',candidate_id=details('a')['candidate_id'])
        require(not bad['mutation_started'],'unregistered VOLUME build reached runtime mutation')
        after=cli_json('inventory','--project',projects['a'])[0]
        require(after['id']==before['id'] and starts()[after['id']]==before_started and after['mounts']==before['mounts'],'VOLUME rejection changed running container or mounts')
        require({item['id'] for item in details('a')['releases']}==before_releases,'failed VOLUME build published a ready release')
        require('undeclared VOLUME' in bad['outcome']['reason'],'Build failed for a reason unrelated to unregistered VOLUME');preserve('a')
        report['checks']['A30_undeclared_volume_refused_before_game_stop_or_volume_creation']=True
        helper("from pathlib import Path;import sys;p=Path(sys.argv[1]);w=p/'workspaces/a/code';(w/'Dockerfile').write_bytes((p/'config/original-Dockerfile').read_bytes());(w/'VERSION').write_text('valid-added-file\\n');(w/'obsolete.txt').write_text('managed obsolete file')")
        operation('a','prepare');candidate=details('a')['candidate_id'];candidate_tree=next(x['tree_digest'] for x in details('a')['snapshots'] if x['id']==candidate)
        helper("from pathlib import Path;import sys;(Path(sys.argv[1])/'workspaces/a/code/VERSION').write_text('later-unprepared-workspace\\n')")
        operation('a','build',candidate_id=candidate)
        target=next(x for x in details('a')['releases'] if x['id'] not in before_releases)
        require(target['tree_digest']==candidate_tree,'later workspace edit replaced fixed candidate')
        request={'service_id':service_ids['a'],'action':'deploy','release_id':target['id'],'confirm_data_compatibility':True,'initiator':'workflow-smoke','idempotency_key':uuid.uuid4().hex}
        preview=rpc('POST','/v1/preview',request);request['plan_digest']=preview['plan_digest'];count_before=len(rpc('GET','/v1/operations'))
        helper("from pathlib import Path;import sys;p=Path(sys.argv[1]);a=p/'services/a/code/VERSION';(p/'config/active-version-before-drift').write_bytes(a.read_bytes());a.write_text('external-active-drift\\n')")
        rpc('POST','/v1/operations',request,expected=409)
        require(len(rpc('GET','/v1/operations'))==count_before,'stale plan created an operation')
        fresh=rpc('POST','/v1/preview',request)
        require(fresh['active_file_drift'] and not fresh['accepted_file_drift'],'active drift silently accepted')
        require(starts()[before['id']]==before_started,'stale plan rejection restarted application')
        helper("from pathlib import Path;import sys;p=Path(sys.argv[1]);(p/'services/a/code/VERSION').write_bytes((p/'config/active-version-before-drift').read_bytes())")
        report['checks']['A09_stale_plan_rejected_without_queue_or_implicit_drift_accept']=True
        operation('a','deploy',release_id=target['id'],confirm_data_compatibility=True);wait_ready('a');require(version('a')=='valid-added-file','frozen candidate changed after workspace edit')
        require(helper("from pathlib import Path;import sys;print((Path(sys.argv[1])/'services/a/code/obsolete.txt').read_text())").stdout.strip()=='managed obsolete file','managed added file not deployed')
        helper("from pathlib import Path;import sys;w=Path(sys.argv[1])/'workspaces/a/code';(w/'obsolete.txt').unlink();(w/'VERSION').write_text('valid-deleted-file\\n')")
        known={item['id'] for item in details('a')['releases']};operation('a','prepare');operation('a','build',candidate_id=details('a')['candidate_id'])
        deleted_release=next(x for x in details('a')['releases'] if x['id'] not in known)
        operation('a','deploy',release_id=deleted_release['id'],confirm_data_compatibility=True);wait_ready('a');preserve('a')
        verify=helper("from pathlib import Path;import json,sys;p=Path(sys.argv[1])/'services/a';print(json.dumps({'deleted':not(p/'code/obsolete.txt').exists(),'excluded':(p/'code/cache/preserve.txt').read_text(),'unmanaged':(p/'operator-note').read_text()}))").stdout
        values=json.loads(verify);require(values=={'deleted':True,'excluded':'excluded-runtime-cache','unmanaged':'unmanaged-operator-note'},'managed deletion touched excluded/unmanaged files')
        require(version('a')=='valid-deleted-file','delete candidate did not deploy')
        report['checks']['A10_managed_delete_preserves_excluded_unmanaged_and_game_data']=True
        report['pipeline_negative_results']={'VOLUME_build_operation':bad['spec']['id'],'fixed_candidate_tree':candidate_tree,'added_release':target['id'],'deleted_release':deleted_release['id'],'file_evidence':values}

    try:
        before_other = starts()
        server = parsed([docker, "version", "--format", "{{json .Server}}"])
        image = parsed([docker, "image", "inspect", args.executor_image])[0]
        image_id = image["Id"]
        report["runtime"] = {"os": server["Os"], "architecture": server["Arch"], "engine_version": server["Version"]}
        report["executor_image_id"] = image_id
        report["runtime_qualification"] = runtime_qualification(server, image)
        report["limitations"].append(report["runtime_qualification"]["scope_note"])
        if args.native_local_helpers:
            docker_info = parsed([docker, "info", "--format", "{{json .}}"])
            report["helper_execution"]["guard_evidence"] = native_local_helper_evidence(
                endpoint, docker_info, local_platform=sys.platform, local_kernel=os.uname().release,
                effective_uid=os.geteuid(), socket_mode=Path(daemon_socket).stat().st_mode)
        command([docker, "run", "--rm", "--network", "none", "--volume", f"{root}:{root}",
                 "python:3.11-slim", "python3", "-c", "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert not any(p.iterdir())", root])
        root_created = True
        if args.native_local_helpers:
            require(root.is_dir() and not root.is_symlink() and not any(root.iterdir()),
                    "new daemon fixture directory is not visible and empty on the local host")
            native_helpers = True
            report["helper_execution"].update(effective="native_local", daemon_root_locally_visible=True,
                scope="Python fixture helpers and Unix API probes use the local interpreter; executor, Compose and CLI still use Docker")
        ports = {}
        for key in projects:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0));ports[key] = reservation.getsockname()[1]
            bases[key] = "http://127.0.0.1:" + str(ports[key])
        setup = '''import json,os,shutil,sys
from pathlib import Path
root,repo,ports=Path(sys.argv[1]),Path(sys.argv[2]),json.loads(sys.argv[3]);os.chmod(root,0o755)
for name in ('services','workspaces','config','requests'):(root/name).mkdir(mode=0o755)
(root/'executor').mkdir(mode=0o700);(root/'runtime').mkdir(mode=0o750);os.chown(root/'runtime',0,10001)
sys.path.insert(0,str(repo/'tests/fixtures'));from prepare import prepare_fixture
for key,port in ports.items():
 active=prepare_fixture('bind-mount',root/'services'/key)
 (active/'code/cache').mkdir();(active/'code/cache/preserve.txt').write_text('excluded-runtime-cache')
 (active/'.env').write_text('CTFM_FIXTURE_UID=10001\\nCTFM_FIXTURE_GID=10001\\n');os.chown(active/'data',10001,10001)
 text=(active/'compose.yaml').read_text().replace('  app:','  app_'+key+':').replace('      - target: 8080','      - target: 8080\\n        published: "'+str(port)+'"')
 (active/'compose.yaml').write_text(text);shutil.copytree(active,root/'workspaces'/key,ignore=shutil.ignore_patterns('data'))
configuration={'state_directory':str(root/'executor'),'socket':str(root/'runtime/executor.sock'),'docker_host':'unix:///var/run/docker.sock','docker_binary':'/usr/local/bin/docker','compose_binary':str(root/'config/compose-wrapper'),'discovery_roots':[str(root/'services')],'workspace_roots':[str(root/'workspaces')],'web_uid':10001,'development':False,'scheduler':{'builds':1,'copies':1,'switches':1}}
(root/'config/executor.json').write_text(json.dumps(configuration));os.chmod(root/'config/executor.json',0o600)
'''
        helper(setup, ROOT, json.dumps(ports))
        wrapper = "#!/bin/sh\naction=\nfor argument in \"$@\"; do case \"$argument\" in build|up) action=$argument;; esac; done\ngate=$(cat '" + str(root / "config/gate") + "' 2>/dev/null || true)\nif [ \"$action\" = \"$gate\" ] && [ -n \"$gate\" ]; then touch '" + str(root / "config/gate-reached") + "'; while [ -f '" + str(root / "config/gate") + "' ]; do sleep 0.05; done; fi\nexec /usr/local/libexec/docker/cli-plugins/docker-compose \"$@\"\n"
        helper("from pathlib import Path;import os,sys;p=Path(sys.argv[1])/'config/compose-wrapper';p.write_text(sys.argv[2]);os.chmod(p,0o700)", wrapper)
        mounts = ["--mount", f"type=bind,source={root},target={root}", "--mount", f"type=bind,source={daemon_socket},target=/var/run/docker.sock"]
        for key, project in projects.items():
            composes[key] = [docker, "run", "--rm", "--network", "bridge", *mounts, "--entrypoint", "/usr/local/bin/docker", image_id,
                             "compose", "--project-name", project, "--file", str(root / "services" / key / "compose.yaml")]
            started_projects.append(key)
            own_tags.add(project + "-app_" + key + ":latest")
            command(composes[key] + ["up", "--detach", "--build"], timeout=300)
            wait_ready(key)
            app(bases[key], "PUT", "/flags/" + game_key, flags[key]);app(bases[key], "PUT", "/state/" + game_key, "state_" + key)
        command([docker, "run", "--detach", "--name", executor_name, "--user", "0:10001", "--network", projects['a'] + "_default", "--read-only", "--cap-drop", "ALL",
                 "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL", "--security-opt", "no-new-privileges:true",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777", *mounts, image_id, "--config", root / "config/executor.json", "executor"])
        executor_started = True
        command([docker, "network", "connect", projects['b'] + "_default", executor_name])
        deadline = time.monotonic() + 30
        while cli("status", success=False).returncode:
            require(time.monotonic() < deadline, "executor startup timeout");time.sleep(.15)
        report["executor_binary_sha256"] = command([docker, "exec", executor_name, "/bin/busybox", "sha256sum", "/usr/local/bin/ctf-manager"]).stdout.split()[0]
        report["doctor"] = cli_json("doctor")
        binary_platform = next((item["detail"] for item in report["doctor"] if item["name"] == "platform"), None)
        report["runtime_qualification"] = runtime_qualification(server, image, binary_platform=binary_platform)
        baselines = {};snapshots = {};original_versions = {};data_mounts = {}
        for key, project in projects.items():
            inventory = cli_json("inventory", "--project", project)
            require(len(inventory) == 1, "unexpected fixture container count")
            current = inventory[0];data_mounts[key] = next(item for item in current['mounts'] if item['target'] == '/data')
            policy = {"schema_version":1,"id":service_ids[key],"name":"MVP workflow " + key,"project_directory":str(root/'services'/key),"source_directory":str(root/'workspaces'/key),"compose_project":project,"compose_files":["compose.yaml"],"managed_paths":[{"path":"code","kind":"code","exclusions":["cache"]},{"path":"compose.yaml","kind":"configuration"},{"path":".env","kind":"configuration"}],"data_paths":[{"name":"game-data","kind":"bind","source":str(root/'services'/key/'data'),"target":"/data","component":"app_"+key,"significant":True,"loss_accepted":False},{"name":"layer","kind":"writable_layer","target":"/tmp","component":"app_"+key,"significant":False,"loss_accepted":True}],"targets":["app_"+key],"containers":[{"component":"app_"+key,"id":current['id'],"image_id":current['image_id'],"role":"application"}],"policy_revision":1,"file_map_revision":1}
            local = launch / ('service-' + key + '.json');local.write_text(json.dumps(policy));local.chmod(0o600)
            destination = root/'requests'/local.name;command([docker,'cp',local,executor_name+':'+str(destination)])
            proposal = cli_json('propose','--service',destination);cli_json('approve','--proposal',proposal['id'],'--digest',proposal['digest'])
            operation(key,'snapshot');view = details(key);baselines[key] = view['current_release_id'];original_versions[key] = version(key)
            operation(key,'snapshot');snapshots[key] = next(item['id'] for item in details(key)['snapshots'] if item['purpose']=='manual')
            preserve(key)
        report['checks']['isolated_two_production_registrations_and_baselines'] = True
        report['baseline_releases']=baselines;report['manual_snapshot_ids']=snapshots
        if args.pipeline_negatives_only:
            negative_pipeline()
            for key in projects:
                for release in details(key)['releases']:own_tags.update(item['retention_tag'] for item in release['images'])
            disk_read_after_shutdown();report['status']='passed';raise ScenarioComplete
        checks_path = '/v1/services/' + service_ids['a'] + '/checks'
        probe_key = 'synthetic_probe_' + token
        checks = [{'id':'tcp-ready','source':'readiness','kind':'tcp','address':'app_a:8080','timeout_seconds':2},
                  {'id':'http-ready','source':'readiness','kind':'http','url':'http://app_a:8080/health','expected_status':200,'body_contains':'ok','timeout_seconds':2},
                  {'id':'synthetic-sequence','source':'local_functional','kind':'http_sequence','timeout_seconds':2,'side_effects_reviewed':True,'cleanup_description':'Delete only our synthetic probe row after successful or failed health check','steps':[{'method':'PUT','url':'http://app_a:8080/state/'+probe_key,'headers':{'Content-Type':'application/json'},'body':json.dumps({'value':private_probe}),'expected_status':200},{'method':'GET','url':'http://app_a:8080/state/'+probe_key,'expected_status':200,'body_contains':private_probe}],'cleanup_steps':[{'method':'DELETE','url':'http://app_a:8080/state/'+probe_key,'expected_status':200}]}]
        view = rpc('POST',checks_path,{'expected_revision':0,'confirmed':True,'actor':'workflow-admin','policy':{'checks':checks,'warmup_seconds':20,'overall_timeout_seconds':20,'attempts':2,'retry_interval_seconds':1,'validity_seconds':60}})
        require(private_probe not in json.dumps(view),'private health input leaked to GET/POST response')
        view = health('a')
        stale_manual = {'expected_release_id':view['current_release_id'],'expected_state_sequence':view['state_sequence']+1,'expected_runtime_digest':view['runtime_digest'],'ttl_seconds':2,'healthy':True,'comment':'Reject stale synthetic runtime observation','actor':'workflow-defender'}
        rpc('POST',checks_path+'/manual',stale_manual,expected=409)
        require(not health('a')['manual_confirmations'],'stale manual provenance created evidence')
        manual = rpc('POST',checks_path+'/manual',{'expected_release_id':view['current_release_id'],'expected_state_sequence':view['state_sequence'],'expected_runtime_digest':view['runtime_digest'],'ttl_seconds':2,'healthy':True,'comment':'Synthetic flag read by workflow acceptance','actor':'workflow-defender'})
        require(manual['state']=='healthy' and health('a')['manual_confirmations'][0]['state']=='healthy','fresh manual confirmation missing')
        time.sleep(2.2)
        require(health('a')['manual_confirmations'][0]['state']=='stale','manual confirmation TTL did not expire')
        operation('a','restart')
        signals = {item['source']:item['state'] for item in details('a')['health']}
        require(signals['readiness']=='healthy' and signals['local_functional']=='healthy','typed health checks failed through executor bridge')
        app(bases['a'],'GET','/state/'+probe_key,status=404);preserve('a')
        report['checks']['tcp_http_and_mutating_http_sequence_with_cleanup'] = True
        report['checks']['manual_provenance_and_ttl'] = True
        for key in projects:
            helper("from pathlib import Path;import sys;(Path(sys.argv[1])/'workspaces'/sys.argv[2]/'code/VERSION').write_text(sys.argv[3]+'\\n')",key,'new-'+token+'-'+key)
            operation(key,'prepare')
        gate('build')
        blocked, _ = request_operation('a','build',candidate_id=details('a')['candidate_id']);wait_gate()
        queued, _ = request_operation('b','build',candidate_id=details('b')['candidate_id'])
        require(rpc('GET','/v1/operations/'+queued['spec']['id'])['state']=='queued','build concurrency limit not enforced')
        cancelled = rpc('POST','/v1/operations/'+queued['spec']['id']+'/cancel',{'actor':'workflow-defender'})
        require(cancelled['state']=='cancelled' and not cancelled['mutation_started'],'queued cancel had mutation or wrong state')
        report['operations'].append(cancelled)
        snapshot_b = operation('b','snapshot')
        require(rpc('GET','/v1/operations/'+blocked['spec']['id'])['state']=='running','copy did not overlap the held build lane')
        require(version('a')==original_versions['a'] and version('b')==original_versions['b'],'preparation/build modified active code')
        release_gate();wait_operation(blocked['spec']['id'])
        operation('b','build',candidate_id=details('b')['candidate_id'])
        release_a = next(item for item in details('a')['releases'] if item['id']!=baselines['a'])
        report['checks']['independent_copy_lane_during_build_and_queued_build_cancel'] = True
        pending = {'service_id':service_ids['a'],'action':'deploy','release_id':release_a['id'],'confirm_data_compatibility':True,'initiator':'workflow-smoke','idempotency_key':uuid.uuid4().hex}
        preview=rpc('POST','/v1/preview',pending);pending['plan_digest']=preview['plan_digest']
        count_before=len(rpc('GET','/v1/operations'))
        current_policy=health('a')
        rpc('POST',checks_path,{'expected_revision':current_policy['revision'],'confirmed':True,'actor':'workflow-admin','policy':{'checks':checks,'warmup_seconds':20,'overall_timeout_seconds':20,'attempts':2,'retry_interval_seconds':1,'validity_seconds':61}})
        rpc('POST','/v1/operations',pending,expected=409)
        require(len(rpc('GET','/v1/operations'))==count_before,'health replacement queued a stale preview')
        report['checks']['health_policy_replacement_invalidates_preview_without_queue'] = True
        operation('a','deploy',release_id=release_a['id'],confirm_data_compatibility=True);wait_ready('a')
        require(version('a')=='new-'+token+'-a','Deploy did not apply prepared candidate');preserve('a')
        app(bases['a'],'PUT','/state/post_deploy','survives-all-rollbacks')
        operation('a','rollback',release_id=baselines['a'],confirm_data_compatibility=True);wait_ready('a');preserve('a')
        require(version('a')==original_versions['a'],'Rollback did not restore original code')
        report['checks']['typed_health_deploy_rollback_preserves_game_and_new_data'] = True
        restored = operation('a','restore_snapshot',snapshot_id=snapshots['a'])
        candidate = details('a')['candidate_id']
        helper("from pathlib import Path;import sys;(Path(sys.argv[1])/'workspaces/a/code/VERSION').write_text('unprepared-workspace-must-not-be-used\\n')")
        before_ids = {item['id'] for item in details('a')['releases']}
        operation('a','build',candidate_id=candidate)
        restored_release = next(item for item in details('a')['releases'] if item['id'] not in before_ids)
        operation('a','deploy',release_id=restored_release['id'],confirm_data_compatibility=True);wait_ready('a')
        require(version('a')==original_versions['a'],'snapshot candidate was replaced by later workspace edits');preserve('a')
        require(app(bases['a'],'GET','/state/post_deploy')['value']=='survives-all-rollbacks','snapshot restore rolled data back')
        report['checks']['manual_snapshot_to_immutable_candidate_build_deploy'] = True
        report['snapshot_restore_pipeline']={'candidate_id':candidate,'snapshot_id':snapshots['a'],'release_id':restored_release['id']}
        gate('up')
        switching, _ = request_operation('a','deploy',release_id=release_a['id'],confirm_data_compatibility=True);wait_gate()
        active = rpc('GET','/v1/operations/'+switching['spec']['id']);require(active['mutation_started'],'cancellation gate was before mutation')
        cancelled = rpc('POST','/v1/operations/'+switching['spec']['id']+'/cancel',{'actor':'workflow-defender'})
        require(cancelled['cancel_requested'] and cancelled['state']=='running','mutation cancellation was falsely final')
        release_gate();unresolved = wait_operation(switching['spec']['id'],'requires_recovery');wait_ready('a');preserve('a')
        require(details('a')['current_release_id']==release_a['id'],'actual new release hidden after cancelled switch')
        recovery, _ = request_operation('a','recover',recovery_operation_id=unresolved['spec']['id'],confirm_data_compatibility=True)
        result = wait_operation(recovery['spec']['id'],'cancelled',after=recovery['updated_at'])
        require(result['outcome']['returned_to_previous'],'cancelled result lacks confirmed compensation')
        wait_ready('a');preserve('a');require(version('a')==original_versions['a'],'Recover did not restore previous code')
        require(details('a')['current_release_id']==restored_release['id'],'Recover returned wrong previous release identity')
        require(app(bases['a'],'GET','/state/post_deploy')['value']=='survives-all-rollbacks','Recover lost newer data')
        report['checks']['post_mutation_cancel_requires_recovery_then_confirmed_cancelled'] = True
        operation('a','snapshot')
        report['checks']['next_operation_acquires_released_recovery_locks']=True
        for key in projects:
            preserve(key)
            current = cli_json('inventory','--project',projects[key])[0]
            require(next(item for item in current['mounts'] if item['target']=='/data')==data_mounts[key],'data bind identity changed')
            for release in details(key)['releases']:
                own_tags.update(image['retention_tag'] for image in release['images'])
        report['checks']['all_persistent_bind_identities_preserved'] = True
        evidence=disk_read_after_shutdown()
        require(private_probe not in json.dumps(evidence),'write-only health inputs leaked to SQLite public records')
        require(len(evidence['records']['runtime_switch_observation'])>=5,'runtime switch identities missing durable observations')
        require(any(any(signal['source']=='local_functional' and signal['state']=='healthy' for signal in item['signals']) for item in evidence['records']['check_observation']),'functional provenance not persisted')
        report['checks']['durable_switch_and_functional_provenance_without_private_inputs']=True
        report['status'] = 'passed'
    except ScenarioComplete:
        pass
    except Exception as error:
        report['exception_metadata'] = exception_metadata(error)
        report['error'] = ("subprocess timed out; argv and captured output omitted" if isinstance(error, subprocess.TimeoutExpired)
                           else str(error).replace(private_probe,'[redacted synthetic input]'))
        report['failure_containers'] = failure_container_observation()
        if executor_started:
            try:
                report['executor_logs'] = command([docker,'logs','--tail','40',executor_name],success=False,timeout=4).stdout[-5000:]
                report['executor_db_fdinfo_at_failure'] = db_file_observation(timeout=4)
            except Exception as diagnostic_error:
                report['failure_diagnostic_error'] = exception_metadata(diagnostic_error)
            if (args.capture_live_sqlite or executor_stopped) and not args.preserve_on_failure:
                try:
                    report['failure_sql_evidence'] = sql_evidence()
                except Exception:
                    pass
    finally:
        preserved = should_preserve_fixture(args.preserve_on_failure, report['status'])
        report['resources_preserved'] = preserved
        if preserved:
            report['cleanup_status'] = 'preserved_on_failure'
            report['preserved_fixture'] = {'daemon_directory':str(root), 'daemon_directory_created':root_created,
                'executor_name':executor_name, 'executor_started':executor_started, 'executor_stopped':executor_stopped,
                'compose_projects':projects, 'started_projects':started_projects, 'service_ids':service_ids,
                'local_launch_directory':str(launch), 'helper_label':helper_label,
                'known_owned_image_tags':sorted(own_tags)}
        else:
            if executor_started and not executor_stopped:
                for key in projects:
                    try:
                        for release in details(key)['releases']:
                            own_tags.update(image['retention_tag'] for image in release['images'])
                    except Exception:
                        pass
            if executor_started:
                command([docker,'rm','--force',executor_name],success=False)
            for key in reversed(started_projects):
                cleanup = command(composes[key]+['down','--remove-orphans'],success=False)
                if cleanup.returncode:
                    report['cleanup_error'] = cleanup.stderr[-2000:];report['status']='failed'
            for sid in service_ids.values():
                owned=command([docker,'image','ls','--format','{{.Repository}}:{{.Tag}}','--filter','reference=ctf-manager/'+sid+':*'],success=False).stdout.split()
                own_tags.update(tag for tag in owned if tag.startswith('ctf-manager/'+sid+':'))
            for tag in sorted(own_tags):
                command([docker,'image','rm',tag],success=False)
            if root_created:
                try:
                    helper("import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);[(shutil.rmtree(x) if x.is_dir() and not x.is_symlink() else x.unlink()) for x in p.iterdir()]")
                    report['isolated_native_directory_contents_removed'] = True
                    report['empty_daemon_directory_retained'] = str(root)
                except Exception as error:
                    report['cleanup_error'] = str(error);report['status']='failed'
            report['cleanup_status'] = 'failed' if report.get('cleanup_error') else 'complete'
        try:
            after_other = starts(timeout=10 if preserved else 180)
            report['external_observation'] = {'preexisting_count':len(before_other),'preexisting_ids_absent_after':len(set(before_other)-set(after_other)),
                                              'preexisting_started_at_changed':sum(after_other[key]!=value for key,value in before_other.items() if key in after_other),
                                              'scope':'read-only snapshot; unrelated test/project activity is not frozen'}
        except Exception as observation_error:
            report['external_observation'] = {'preexisting_count':len(before_other), 'unavailable':True,
                                              'exception_metadata':exception_metadata(observation_error)}
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True,exist_ok=True)
        # Synthetic probe inputs must not become a durable public report on failure.
        encoded = json.dumps(report,indent=2).replace(private_probe,'[redacted synthetic input]')+'\n'
        args.report.write_text(encoded)
        if not preserved:
            shutil.rmtree(launch)
    print(json.dumps({'status':report['status'],'report':str(args.report),'checks':report['checks'],'error':report.get('error'),'external_observation':report['external_observation'],'preserved_fixture':report.get('preserved_fixture')},indent=2))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':
    sys.exit(main())
