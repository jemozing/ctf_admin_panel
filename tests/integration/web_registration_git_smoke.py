#!/usr/bin/env python3
"""Exercise web import + real public HTTPS Git on a disposable Compose stack.

Only this run's native volume, panel, app/database and image tags are touched.
The game uses the bundled fixture image; LICENSE is its managed Git test input.
This proves candidate handoff, not execution of the upstream SibirCTF service.
Build both runtime images before running. No CLI registration/approval is used.
"""

import argparse
import copy
import hashlib
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


ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "web-registration-smoke-password"
GIT_URL = "https://github.com/SibirCTF/2025-cybersibir-service-ncdex.git"
GIT_COMMIT = "435b7108d3b8c2693467a9e4be8a5c71b0936d64"


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=240, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} {args[1:3]}: {(result.stderr + result.stdout)[-4000:]}")
    return result.stdout


class RegistrationNegativesComplete(Exception):
    pass


def classified_draft(draft):
    result = copy.deepcopy(draft)
    result['name'] = 'Web registration fixture'
    result['managed_paths'] = [{'path': 'LICENSE', 'kind': 'code'}]
    for storage in result['data_paths']:
        if storage['kind'] == 'writable_layer':
            storage['loss_accepted'] = True
    return result


def assert_rejected_registration(request, csrf, case, path, payload, *, status=400, message_contains=None):
    before_services = request('/api/services')[1]
    before_operations = request('/api/operations')[1]
    actual, body = request(path, payload, csrf)
    assert actual == status, (case, actual, body.get('code'))
    assert body.get('code') == ('conflict' if status == 409 else 'invalid_registration'), (case, body.get('code'))
    if message_contains:
        assert message_contains in body.get('message', ''), (case, 'expected rejection reason absent')
    assert request('/api/services')[1] == before_services, (case, 'registry changed')
    assert request('/api/operations')[1] == before_operations, (case, 'operation created/changed')
    return {'case': case, 'status': actual, 'code': body['code'], 'registry_and_operation_list_unchanged': True}


def registration_negatives_before_approval(request, expect, csrf, draft, state, patch_profile, runtime_check, owned_ids):
    cases = []
    valid = classified_draft(draft)
    for case, storage_kind, reason in (
        ('unclassified_actual_named_volume', 'named_volume', 'unclassified_runtime_mount'),
        ('unclassified_writable_layer', 'writable_layer', 'unclassified_writable_layer'),
    ):
        value = copy.deepcopy(valid)
        value['data_paths'] = [item for item in value['data_paths'] if item['kind'] != storage_kind]
        cases.append(assert_rejected_registration(request, csrf, case, '/api/registration/proposals',
                                                  {'service': value}, message_contains=reason))
        runtime_check()
    value = copy.deepcopy(valid)
    for item in value['data_paths']:
        if item['kind'] == 'writable_layer':
            item.update(significant=True, loss_accepted=False)
    cases.append(assert_rejected_registration(request, csrf, 'significant_unsupported_writable_layer',
        '/api/registration/proposals', {'service': value}, message_contains='blocks recreation'))
    runtime_check()
    for field, path in (('project_directory', '/etc'), ('source_directory', state + '/services/forbidden-workspace')):
        value = copy.deepcopy(valid)
        value[field] = path
        cases.append(assert_rejected_registration(request, csrf, 'immutable_' + field, '/api/registration/proposals',
                                                  {'service': value}, message_contains='identity changed'))
        runtime_check()
    try:
        for mode, reason in (('privileged', 'unsupported_privilege'), ('host_network', 'unsupported_network_mode')):
            patch_profile(mode)
            status, body = request('/api/registration/inspect', {'project_directory': state + '/services/game'}, csrf)
            if status == 400:
                assert body.get('code') == 'invalid_registration'
                cases.append({'case': mode + '_profile', 'status': status, 'code': body['code'], 'rejected_at': 'inspect'})
            else:
                assert status == 200 and body.get('service')
                owned_ids.add(body['service']['id'])
                cases.append(assert_rejected_registration(request, csrf, mode + '_profile', '/api/registration/proposals',
                    {'service': classified_draft(body['service'])}, message_contains=reason))
            runtime_check()
        patch_profile('external_env')
        cases.append(assert_rejected_registration(request, csrf, 'external_env_file', '/api/registration/inspect',
                                                  {'project_directory': state + '/services/game'}))
        runtime_check()
    finally:
        patch_profile('restore')
    cases.append(assert_rejected_registration(request, csrf, 'forbidden_discovery_path', '/api/registration/inspect',
                                              {'project_directory': '/etc'}))
    runtime_check()
    return cases


def registration_conflicts_after_approval(request, expect, csrf, state, service_id, runtime_check, owned_ids):
    cases = []
    for case, directory in (('distinct_id_same_compose_project', state + '/services/game'),
                            ('distinct_project_overlapping_active_root', state + '/services/game/overlap')):
        draft = expect('/api/registration/inspect', {'project_directory': directory}, csrf)['service']
        owned_ids.add(draft['id'])
        assert draft['id'] != service_id
        proposal = expect('/api/registration/proposals', {'service': classified_draft(draft)}, csrf)
        assert proposal['service']['id'] == draft['id']
        result = assert_rejected_registration(request, csrf, case, '/api/registration/approve',
            {'proposal_id': proposal['id'], 'digest': proposal['digest']}, status=409)
        result['distinct_service_id'] = True
        result['valid_proposal_reached_approve'] = True
        cases.append(result)
        runtime_check()
    return cases


def protected_inventory(docker, ids=None):
    selected = ids if ids is not None else command([docker, 'ps', '--all', '--quiet', '--no-trunc']).splitlines()
    if not selected:
        return {}
    # No Config/Env/Args. Exact identity, process start and data mounts only.
    fmt = '{"id":{{json .Id}},"image":{{json .Image}},"started_at":{{json .State.StartedAt}},"state":{{json .State.Status}},"pid":{{json .State.Pid}},"mounts":{{json .Mounts}}}'
    rows = [json.loads(line) for line in command([docker, 'inspect', '--format', fmt, *selected]).splitlines()]
    for item in rows:
        item['mounts'] = sorted([{key: mount.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'RW')}
                                for mount in item['mounts']], key=lambda mount: mount['Destination'])
    return {item['id']: item for item in rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/web-registration-git-smoke-2026-10-19.json")
    parser.add_argument('--registration-negatives-only', action='store_true', help='isolated real HTTP A02/A13/profile/path refusals; no Git, Fetch, Build, Deploy or Rollback')
    parser.add_argument('--expected-preexisting-count', type=int, help='negative mode defaults to12; verify existing containers before creating any fixture resources')
    args = parser.parse_args()
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker is required")
    endpoint = os.environ.get("DOCKER_HOST") or json.loads(command([docker, "context", "inspect"]))[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix:///"):
        parser.error("an explicit local Unix Docker daemon is required")
    protected = protected_inventory(docker)
    expected_count = args.expected_preexisting_count if args.expected_preexisting_count is not None else (12 if args.registration_negatives_only else None)
    if expected_count is not None and (expected_count < 0 or len(protected) != expected_count):
        parser.error('preexisting container count differs; no fixture resources created')
    docker_socket = endpoint.removeprefix("unix://")
    project = "ctfm-webgit-" + uuid.uuid4().hex[:12]
    game = project + "-game"
    overlapping_game = project + '-overlap'
    volume = project + "-state"
    image = project + "-fixture:local"
    command([docker, "volume", "create", volume])
    state = json.loads(command([docker, "volume", "inspect", volume]))[0]["Mountpoint"]
    local = Path(tempfile.mkdtemp(prefix=project + "-")).resolve()
    helper = [docker, "run", "--rm", "--network", "none", "--mount", f"type=bind,source={state},target={state}", "--mount", f"type=bind,source={ROOT},target={ROOT},readonly", "--mount", f"type=bind,source={docker_socket},target=/var/run/docker.sock", "python:3.11-slim", "python3", "-c"]
    native_docker = [docker, "run", "--rm", "--network", "none", "--mount", f"type=bind,source={state},target={state}", "--mount", f"type=bind,source={docker_socket},target=/var/run/docker.sock", "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local"]
    game_compose = native_docker + ["compose", "--project-name", game, "--file", state + "/services/game/compose.yaml"]
    overlap_compose = native_docker + ['compose', '--project-name', overlapping_game, '--file', state + '/services/game/overlap/compose.yaml']
    overlap_started = False
    own_service_ids = set()
    compose = None
    report = {"test": "web-registration-negatives" if args.registration_negatives_only else "web-registration-git", "status": "failed", "project": project, "game_project": game, "scope": "isolated Admin HTTP registration refusals; no Git or game release operations" if args.registration_negatives_only else "bundled image-only app/database; LICENSE managed input from public SibirCTF Git; no upstream service execution", "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'preexisting_count': len(protected)}
    try:
        setup = r'''
import json,os,subprocess,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);image=sys.argv[3];negatives=sys.argv[4]=='1'
os.chown(root,0,0);os.chmod(root,0o755)
p=subprocess.run(['python3',str(repo/'scripts/compose-bootstrap.py'),'--root',str(root)],capture_output=True,text=True)
if p.returncode:raise RuntimeError(p.stderr)
sys.path.insert(0,str(repo/'tests/fixtures'))
from prepare import prepare_fixture
game=root/'services/game';prepare_fixture('named-volume',game)
p=game/'compose.yaml';p.write_text(p.read_text().replace('    build: ./code\n','    image: '+image+'\n    mem_limit: 128m\n    cpus: 0.5\n    pids_limit: 64\n'))
(game/'LICENSE').write_text('baseline fixture license\n')
if negatives:
 (root/'.negative-compose.original').write_bytes(p.read_bytes())
 (root/'config/external.env').write_text('CTFM_NEGATIVE_PROFILE=synthetic\n')
 nested=game/'overlap';nested.mkdir();(nested/'LICENSE').write_text('nested independent fixture license\n')
 profile={'services':{'app':{'image':image,'mem_limit':'128m','cpus':0.5,'pids_limit':64,'shm_size':'64m','read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
   'volumes':[{'type':'volume','source':'data','target':'/data'}],
   'ports':[{'target':8080,'host_ip':'127.0.0.1','protocol':'tcp'}]}},'volumes':{'data':{}}}
 (nested/'compose.yaml').write_text(json.dumps(profile))
print(json.dumps({'environment':(root/'config/compose.env').read_text(),'mounts':(root/'config/compose.mounts.yaml').read_text()}))
'''
        prepared = json.loads(command(helper + [setup, state, str(ROOT), image, '1' if args.registration_negatives_only else '0']))
        command(native_docker + ["build", "--tag", image, state + "/services/game/code"])
        command(game_compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
        if args.registration_negatives_only:
            overlap_started = True
            command(overlap_compose + ['up', '-d', '--no-build', '--wait', '--wait-timeout', '60'])
        game_ids = command([docker, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + game]).splitlines()
        # Inspect full IDs, not the short IDs returned by docker ps.
        before = {v["Id"]: v["State"]["StartedAt"] for v in json.loads(command([docker, "inspect", *game_ids]))}
        owned_game_ids = game_ids + (command([docker, 'ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + overlapping_game]).splitlines() if args.registration_negatives_only else [])
        owned_before = protected_inventory(docker, owned_game_ids)
        app_id = command([docker, "ps", "--quiet", "--filter", "label=com.docker.compose.project=" + game, "--filter", "label=com.docker.compose.service=app"]).strip()
        app_info = json.loads(command([docker, "inspect", app_id]))[0]
        game_url = "http://127.0.0.1:" + app_info["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
        flag = "flag-" + uuid.uuid4().hex
        req = urllib.request.Request(game_url + "/flags/webgit", data=json.dumps({"value": flag}).encode(), headers={"Content-Type": "application/json"}, method="PUT")
        with urllib.request.urlopen(req, timeout=10) as response:
            assert response.status in (200, 201)
        (local / "mounts.yaml").write_text(prepared["mounts"])
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = prepared["environment"].replace(state + "/config/compose.mounts.yaml", str(local / "mounts.yaml")).replace("CTFM_DOCKER_SOCKET=/var/run/docker.sock", "CTFM_DOCKER_SOCKET=" + docker_socket).replace("CTFM_PORT=8765", "CTFM_PORT=" + str(port)).replace("CTFM_ALLOWED_HOSTS=localhost:8765,127.0.0.1:8765", f"CTFM_ALLOWED_HOSTS=localhost:{port},127.0.0.1:{port},127.0.0.1:8765")
        (local / "compose.env").write_text(environment)
        compose = [docker, "compose", "--project-name", project, "--env-file", str(local / "compose.env")]
        command(compose + ["run", "--rm", "--no-deps", "-T", "dashboard", "init-admin", "--state", "/var/lib/ctf-manager", "--username", "admin"], input=PASSWORD + "\n")
        command(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
        base = f"http://127.0.0.1:{port}"

        def client():
            return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        admin = client()

        def request(path, payload=None, csrf=None, opener=admin):
            headers, data = {}, None
            if payload is not None:
                data = json.dumps(payload).encode()
                headers = {"Content-Type": "application/json", "Origin": base}
                if csrf:
                    headers["X-CSRF-Token"] = csrf
            try:
                with opener.open(urllib.request.Request(base + path, data=data, headers=headers), timeout=30) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())

        def expect(path, payload=None, csrf=None, status=200, opener=admin):
            actual, body = request(path, payload, csrf, opener)
            assert actual == status, (path, actual, body)
            return body

        def login(name, opener):
            expect("/api/auth/login", {"username": name, "password": PASSWORD}, opener=opener)
            return expect("/api/auth/session", opener=opener)["csrf_token"]

        csrf = login("admin", admin)
        def runtime_check():
            assert protected_inventory(docker, list(protected)) == protected, 'preexisting container identity/start/mounts changed'
            assert protected_inventory(docker, owned_game_ids) == owned_before, 'fixture container identity/start/mounts changed'
            with urllib.request.urlopen(game_url + '/flags/webgit', timeout=10) as response:
                assert json.loads(response.read())['value'] == flag, 'fixture data changed'

        def patch_profile(mode):
            code = '''from pathlib import Path
import sys
root=Path(sys.argv[1]);mode=sys.argv[3];original=(root/'.negative-compose.original').read_text()
fields={'privileged':'    privileged: true\\n','host_network':'    network_mode: host\\n','external_env':'    env_file: ["'+str(root/'config/external.env')+'"]\\n'}
text=original if mode=='restore' else original.replace('  app:\\n','  app:\\n'+fields[mode],1)
(root/'services/game/compose.yaml').write_text(text)
'''
            command(helper + [code, state, str(ROOT), mode])

        options = expect("/api/registration/options")
        assert options["discovery_roots"] == [state + "/services"]
        assert request("/api/registration/inspect", {"project_directory": state + "/services/game"})[0] == 403
        assert request("/api/registration/inspect", {"project_directory": "/etc"}, csrf)[0] == 400
        draft = expect("/api/registration/inspect", {"project_directory": state + "/services/game"}, csrf)["service"]
        own_service_ids.add(draft['id'])
        if args.registration_negatives_only:
            report['negative_cases'] = registration_negatives_before_approval(request, expect, csrf, draft, state, patch_profile, runtime_check, own_service_ids)
        draft = classified_draft(draft)
        proposal = expect("/api/registration/proposals", {"service": draft}, csrf)
        approval_request = {"proposal_id": proposal["id"], "digest": proposal["digest"]}
        assert request("/api/registration/approve", {**approval_request, "digest": "sha256:" + "0" * 64}, csrf)[0] in (400, 409)
        approved = expect("/api/registration/approve", approval_request, csrf)
        service_id = approved["service"]["id"]

        def wait_job(job):
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                current = expect("/api/operations/" + job["spec"]["id"])
                if current["state"] in ("succeeded", "failed", "cancelled", "requires_recovery", "interrupted"):
                    return current
                time.sleep(0.2)
            raise AssertionError("operation did not complete")

        if approved.get("operation"):
            job = wait_job(approved["operation"])
            assert job["state"] == "succeeded", job
        repeated = expect("/api/registration/approve", approval_request, csrf)
        assert repeated["service"]["id"] == service_id and repeated["initialized"]
        assert len(expect("/api/services")) == 1
        details = expect("/api/services/" + service_id)
        assert details["current_release_id"]
        assert request("/api/registration/proposals", {"service": draft}, csrf)[0] in (400, 409)
        report.update(web_registration_without_cli=True, digest_checked=True, approval_retry_idempotent=True, baseline_initialized=True, duplicate_registration_rejected=True, path_and_csrf_rejected=True)

        if args.registration_negatives_only:
            report['negative_cases'].extend(registration_conflicts_after_approval(request, expect, csrf, state, service_id, runtime_check, own_service_ids))
            runtime_check()
            assert len(expect('/api/services')) == 1 and len(expect('/api/operations')) == 1
            report.update(no_fetch_build_deploy_rollback=True, same_project_distinct_id_approve_rejected=True,
                          overlapping_project_root_approve_rejected=True, all_refusals_preserve_game_data_and_runtime=True,
                          profile_restored=True, fixture_game_containers=3,
                          resource_caps={'dashboard_mib':256,'executor_mib':384,'fixture_game_mib_each':128,'fixture_game_pids_each':64,'total_caps_mib':1024},
                          runtime=json.loads(command([docker, 'version', '--format', '{{json .Server}}'])), status='passed')
            report['images'] = {name: json.loads(command([docker, 'inspect', command(compose + ['ps', '--quiet', name]).strip()]))[0]['Image']
                                for name in ('dashboard', 'executor')}
            report['image_platforms'] = {name: command([docker, 'image', 'inspect', '--format', '{{.Os}}/{{.Architecture}}', identity]).strip()
                                         for name, identity in report['images'].items()}
            report['limitations'] = ['UUID fixture only; existing real services are observed without changes.',
                                     'Unsupported Compose keys are written only to the fixture source for normalization/proposal refusal; no privileged/host-network container is started.',
                                     'Native guest/image architecture is recorded; physical host virtualization backend and full MVP acceptance are not inferred.']
            raise RegistrationNegativesComplete

        source_path = "/api/services/" + service_id + "/source"
        config = {"url": GIT_URL, "ref": GIT_COMMIT}
        assert request(source_path, {"url": "file:///etc/passwd", "ref": "HEAD"}, csrf)[0] == 400
        assert request(source_path, {"url": "https://127.0.0.1/repo.git", "ref": "HEAD"}, csrf)[0] == 400
        token = "ctfm-smoke-not-a-real-token"
        saved = expect(source_path, {**config, "token": token}, csrf)
        assert saved["has_credentials"] and token not in json.dumps(saved)
        assert token not in json.dumps(expect(source_path))
        expect(source_path, {**config, "clear_credentials": True}, csrf)

        def operation(action, expected="succeeded", **fields):
            body = {"service_id": service_id, "action": action, "idempotency_key": uuid.uuid4().hex, **fields}
            preview = expect("/api/preview", body, csrf)
            body["plan_digest"] = preview["plan_digest"]
            job = expect("/api/operations", body, csrf, status=202)
            retried = expect("/api/operations", body, csrf, status=202)
            assert retried["spec"]["id"] == job["spec"]["id"]
            result = wait_job(job)
            assert result["state"] == expected, result
            return result

        fetched = operation("fetch_source")
        source = expect(source_path)
        assert source["last_fetch"]["commit"] == GIT_COMMIT, source
        candidate = expect("/api/services/" + service_id)["candidate_id"]
        assert source["last_fetch"]["snapshot_id"] == candidate
        operation("build", candidate_id=candidate)
        built = expect("/api/services/" + service_id)
        assert any(v.get("git_source", {}).get("commit") == GIT_COMMIT for v in built["releases"])
        expect(source_path, {**config, "ref": "ctfm-missing-ref-" + uuid.uuid4().hex}, csrf)
        operation("fetch_source", expected="failed")
        assert expect("/api/services/" + service_id)["candidate_id"] == candidate
        expect(source_path, config, csrf)
        report.update(real_public_https_git=True, git_url=GIT_URL, git_commit=GIT_COMMIT, git_candidate_built_with_exact_provenance=True, failed_fetch_preserves_candidate=True, token_write_only=True, restricted_transports_rejected=True, fetch_idempotent=True)

        for role in ("viewer", "defender"):
            expect("/api/users", {"username": role, "password": PASSWORD, "role": role}, csrf, status=201)
            who = client()
            role_csrf = login(role, who)
            assert request("/api/registration/options", opener=who)[0] == 403
            assert request("/api/registration/approve", approval_request, role_csrf, who)[0] == 403
            assert request(source_path, config, role_csrf, who)[0] == 403
            fetch_request = {"service_id": service_id, "action": "fetch_source", "idempotency_key": uuid.uuid4().hex}
            assert request("/api/preview", fetch_request, role_csrf, who)[0] == (403 if role == "viewer" else 200)
        after = {v["Id"]: v["State"]["StartedAt"] for v in json.loads(command([docker, "inspect", *game_ids]))}
        assert before == after
        with urllib.request.urlopen(game_url + "/flags/webgit", timeout=10) as response:
            assert json.loads(response.read())["value"] == flag
        report.update(admin_only_registration_and_source=True, defender_fetch_allowed=True, viewer_fetch_denied=True, game_ids_started_at_and_flag_preserved=True)
        report["images"] = {name: json.loads(command([docker, "inspect", command(compose + ["ps", "--quiet", name]).strip()]))[0]["Image"] for name in ("dashboard", "executor")}
        report["runtime"] = json.loads(command([docker, "version", "--format", "{{json .Server}} "]))
        report["status"] = "passed"
    except RegistrationNegativesComplete:
        pass
    except Exception as error:
        report["error"] = str(error)
        if compose:
            report["panel_logs"] = command(compose + ["logs", "--no-color", "--tail", "25"])[-5000:]
        raise
    finally:
        cleanup_errors = []
        for cleanup in ([compose + ["down", "--timeout", "10"]] if compose else []) + ([overlap_compose + ['down', '--volumes', '--timeout', '10']] if overlap_started else []) + [game_compose + ["down", "--volumes", "--timeout", "10"]]:
            try:
                command(cleanup)
            except Exception as error:
                cleanup_errors.append(str(error))
        # Retention tags belong only to the registered service in this disposed DB.
        if 'service_id' in locals():
            own_service_ids.add(service_id)
        for owned_id in own_service_ids:
            try:
                tags = command([docker, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "reference=ctf-manager/" + owned_id + ":*"]).splitlines()
                if tags:
                    command([docker, "image", "rm", *tags])
            except Exception as error:
                cleanup_errors.append(str(error))
        for cleanup in ([docker, "image", "rm", image], [docker, "volume", "rm", volume]):
            try:
                command(cleanup)
            except Exception as error:
                cleanup_errors.append(str(error))
        shutil.rmtree(local)
        try:
            report['preexisting_exact_identity_started_at_pid_mounts_preserved'] = protected_inventory(docker, list(protected)) == protected
        except Exception as observation_error:
            report['preexisting_exact_identity_started_at_pid_mounts_preserved'] = False
            report['protected_observation_error_type'] = type(observation_error).__name__
        report["cleanup_errors"] = cleanup_errors
        report["isolated_stack_cleaned_up"] = not cleanup_errors
        if not report['preexisting_exact_identity_started_at_pid_mounts_preserved']:
            report['status'] = 'failed'
        if cleanup_errors and report["status"] == "passed":
            report["status"] = "cleanup_failed"
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["status"] != "passed":
        raise RuntimeError("Smoke did not pass; inspect saved report")


if __name__ == "__main__":
    main()
