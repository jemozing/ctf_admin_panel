#!/usr/bin/env python3
"""Run pinned SibirCTF release cycles on the existing native VM via Admin HTTP.

No setup, source edits, container cleanup or data deletion. Durable private
checkpoints precede every operation submission. Resume uses the exact saved
idempotency key/request; ambiguous writes never create a fresh operation.
"""
import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PRESETS = {
    'bioguard': ('2025-cybersibir-service-BioGuard', '0d5dffae3460823715a266d5674d2110837c4bea', ['web']),
    'ncdex': ('2025-cybersibir-service-ncdex', '435b7108d3b8c2693467a9e4be8a5c71b0936d64', ['app']),
    'bank': ('2025-cybersibir-service-bank', '4a7d4eafb2e8030aa230316e3f191908a2b0437a', ['cyber-bank-api', 'cyber-bank-front']),
    'neli234': ('2025-cybersibir-service-neLi234', '28d8a11498675233e87394e4d89956ad0938abfd', ['controller']),
    'eyesee': ('2025-cybersibir-service-eyesee', '2eda1b05fe6e025c3f1bec25f762f3ad01d6a74c', ['eyesee-service']),
}
TERMINAL = {'succeeded', 'failed', 'cancelled', 'requires_recovery', 'interrupted'}
IDENTITY = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$')


class ControllerError(RuntimeError):
    """Messages are harness-owned and contain no request/response/probe values."""


def owned_error_message(error, probe_error_type=None):
    if isinstance(error, ControllerError) or (probe_error_type is not None and isinstance(error, probe_error_type)):
        return str(error)
    return None


def require(condition, message):
    if not condition:
        raise ControllerError(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def start_attempt(state):
    state.pop('safe_error', None)
    state.pop('api_read_retries', None)
    attempt = {'started_at': now(), 'status': 'running', 'selected_service_keys': list(state.get('selected_service_keys', []))}
    state.setdefault('attempts', []).append(attempt)
    return attempt


def fingerprint(value):
    return 'sha256:' + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.geteuid() and info.st_nlink == 1,
                'private state/credentials must be owned 0600 regular files without hard links')
        return json.load(stream)


def private_write(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.is_symlink(), 'symbolic-link checkpoint/report refused')
    if path.exists():
        private_read(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RuntimeError('HTTP redirect refused')


class Client:
    def __init__(self, base):
        self.base = base.rstrip('/')
        parts = urllib.parse.urlsplit(self.base)
        require(parts.scheme == 'http' and parts.hostname in ('127.0.0.1', 'localhost', '::1')
                and not parts.username and not parts.password and not parts.path and not parts.query and not parts.fragment,
                'native cycle API must be a loopback HTTP origin without credentials/path')
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = None
        self.read_request_count = 0
        self.read_retry_count = 0
        self.read_retry_reasons = {}

    def read_retry_summary(self):
        return {'scope': 'current controller invocation; functional cycles only, not performance measurements',
                'read_request_count': self.read_request_count, 'read_retry_count': self.read_retry_count,
                'retry_reasons': dict(self.read_retry_reasons), 'max_attempts_per_get': 6,
                'backoff_seconds': 2, 'transient_http_statuses': [502, 503, 504],
                'post_requests_automatically_retried': False}

    def request(self, path, payload=None, expected=200):
        require(path.startswith('/api/') and '?' not in path and '#' not in path, 'unexpected API route')
        headers, body = {}, None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers = {'Content-Type': 'application/json', 'Origin': self.base}
            if self.csrf:
                headers['X-CSRF-Token'] = self.csrf
        # Reads can retry safely. Writes only resume via their checkpointed key.
        attempts = 6 if payload is None else 1
        retry_reason = None
        for attempt in range(attempts):
            if payload is None:
                self.read_request_count += 1
                if attempt:
                    self.read_retry_count += 1
                    self.read_retry_reasons[retry_reason] = self.read_retry_reasons.get(retry_reason, 0) + 1
            try:
                request = urllib.request.Request(self.base + path, data=body, headers=headers)
                with self.opener.open(request, timeout=30) as response:
                    require(response.status == expected, 'unexpected HTTP status')
                    data = response.read(4 * 1024 * 1024 + 1)
                    require(len(data) <= 4 * 1024 * 1024, 'API response limit exceeded')
                    return json.loads(data)
            except urllib.error.HTTPError as error:
                code = 'unknown'
                try:
                    supplied = json.loads(error.read(16384)).get('code', '')
                    if isinstance(supplied, str) and re.fullmatch(r'[a-z_]{1,80}', supplied):
                        code = supplied
                except (ValueError, AttributeError, OSError, http.client.HTTPException):
                    pass
                if payload is None and error.code in (502, 503, 504) and attempt + 1 < attempts:
                    retry_reason = 'HTTP_' + str(error.code)
                    time.sleep(2)
                    continue
                raise ControllerError('HTTP ' + str(error.code) + ' code=' + code) from None
            except (OSError, http.client.HTTPException, ValueError):
                if payload is not None or attempt + 1 == attempts:
                    raise ControllerError('HTTP transport/JSON failure; request and response omitted') from None
                retry_reason = 'transport_or_json'
                time.sleep(2)

    def login(self, credentials):
        require(isinstance(credentials.get('username'), str) and isinstance(credentials.get('password'), str), 'credentials missing')
        self.request('/api/auth/login', {'username': credentials['username'], 'password': credentials['password']})
        session = self.request('/api/auth/session')
        require(session.get('user', {}).get('role') == 'admin', 'Admin session required')
        self.csrf = session['csrf_token']


def command_json(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'Docker observation failed; output omitted')
    require(len(result.stdout) <= 1024 * 1024, 'Docker observation response limit exceeded')
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def runtime_observation(detail):
    """Inspect only known container IDs and whitelist fields; never read Env/Args."""
    components = {item['id']: item['component'] for item in detail['containers']}
    require(components and all(re.fullmatch(r'[0-9a-f]{64}', identity) for identity in components), 'invalid/empty runtime inventory')
    fmt = '{"id":{{json .Id}},"image_id":{{json .Image}},"started_at":{{json .State.StartedAt}},"state":{{json .State.Status}},"oom_killed":{{json .State.OOMKilled}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"not_configured"{{end}},"mounts":{{json .Mounts}}}'
    result = {}
    for item in command_json(['docker', 'inspect', '--format', fmt, *components]):
        require(item['id'] in components, 'unexpected inspected container')
        require(item['state'] == 'running' and not item['oom_killed'] and item['health'] in ('healthy', 'not_configured'), 'container stopped/unhealthy/OOM')
        item['mounts'] = sorted([{key: mount.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'RW')}
                                 for mount in item['mounts']], key=lambda mount: mount['Destination'])
        result[components[item['id']]] = item
    require(len(result) == len(components), 'runtime observation incomplete')
    return result


def runtime_identity(item):
    return {key: item[key] for key in ('id', 'image_id', 'started_at', 'mounts')}


def assert_preserved(before, after, targets, *, all_components=False):
    require(set(before) == set(after), 'runtime component set changed')
    for component in before:
        if all_components or component not in targets:
            require(runtime_identity(before[component]) == runtime_identity(after[component]), 'container identity/StartedAt/mounts changed outside allowed targets')
        else:
            require(before[component]['mounts'] == after[component]['mounts'], 'target persistent/config mount identity changed')


def code_entries(project, managed):
    """Read only approved code; hash content and ownership/modes without data paths."""
    result = {}
    for policy in managed:
        relative = policy['path']
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'invalid managed path')
        excluded = [(Path(relative) / value).as_posix() for value in policy.get('exclusions', [])]
        pending = [project / relative]
        while pending:
            path = pending.pop()
            name = path.relative_to(project).as_posix()
            if any(name == value or name.startswith(value + '/') for value in excluded):
                continue
            info = path.lstat()
            item = {'path': name, 'size': 0, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
            if stat.S_ISDIR(info.st_mode):
                item['type'] = 'directory'
                pending.extend(sorted(path.iterdir(), reverse=True))
            elif stat.S_ISREG(info.st_mode):
                item.update(type='file', size=info.st_size)
                digest = hashlib.sha256()
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, 'rb') as stream:
                    require(os.path.samestat(info, os.fstat(stream.fileno())), 'managed code replaced while reading')
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                after = path.lstat()
                require((info.st_size, info.st_mtime_ns, info.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino), 'managed code changed while reading')
                item['digest'] = 'sha256:' + digest.hexdigest()
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                item.update(type='symlink', link_target=target, size=len(target.encode()), digest='sha256:' + hashlib.sha256(target.encode()).hexdigest())
            else:
                raise RuntimeError('special object in managed code')
            result[name] = item
    return sorted(result.values(), key=lambda item: item['path'])


def code_summary(entries):
    content = [{key: value for key, value in entry.items() if key not in ('mode', 'uid', 'gid')} for entry in entries]
    return {'content_sha256': fingerprint(content), 'metadata_sha256': fingerprint(entries),
            'entry_count': len(entries), 'bytes': sum(entry['size'] for entry in entries)}


def verify_snapshot(root, service, release):
    identity = release['snapshot_id']
    require(IDENTITY.fullmatch(identity) is not None, 'invalid snapshot identity')
    path = root / 'executor/snapshots' / identity / 'snapshot.json'
    require(not path.is_symlink() and path.is_file(), 'snapshot metadata unavailable')
    snapshot = json.loads(path.read_bytes())
    require(snapshot['id'] == identity and snapshot['service_id'] == service['id']
            and snapshot['state'] == 'complete' and snapshot['manifest_digest'] == release['tree_digest'], 'snapshot/release provenance mismatch')
    expected = snapshot['manifest']['entries']
    actual = code_entries(Path(service['project_directory']), service['managed_paths'])
    require(actual == expected, 'active code bytes/mode/UID/GID differ from immutable snapshot')
    return code_summary(actual)


def public_operation(job):
    return {'id': job['spec']['id'], 'action': job['spec']['kind'], 'state': job['state'],
            'created_at': job.get('created_at'), 'updated_at': job.get('updated_at'),
            'mutation_started': job.get('mutation_started', False)}


def eyesee_empty_store_proof(client, root, state):
    saved = state['services']['eyesee']
    detail = client.request('/api/services/' + saved['service_id'])
    runtime = runtime_observation(detail)
    assert_preserved(saved['baseline']['runtime'], runtime, saved['targets'])
    storage = runtime['eyesee-storage']
    mounts = [item for item in storage['mounts'] if item['Destination'] == '/data']
    require(len(mounts) == 1 and mounts[0]['Type'] == 'volume'
            and mounts[0]['Name'] == 'ctfm-demo-sibir-eyesee_minio-data', 'unexpected EyeSee data volume')
    source = Path(mounts[0]['Source'])
    require(source.is_absolute() and source.resolve() == source and source.is_dir(), 'EyeSee native data volume is not a real local directory')
    counts = {}
    for bucket in ('prescriptions', 'relations'):
        path = source / bucket
        require(path.is_dir() and not path.is_symlink(), 'EyeSee game bucket is unavailable for an empty-store guard')
        # No object payload is opened. Any entry, including unexpected metadata,
        # makes this conservative fresh-store guard reject the first Add.
        with os.scandir(path) as entries:
            counts[bucket] = 1 if next(entries, None) is not None else 0
    return {'prescription_objects': counts['prescriptions'], 'relation_objects': counts['relations'],
            'storage_id': storage['id'], 'observed_at_unix': time.time(),
            'method': 'read-only native empty-directory guard on both known MinIO game buckets; nonzero is a lower bound'}


class Cycles:
    def __init__(self, client, root, checkpoint_path, state, probes, operation_timeout=900):
        self.client, self.root, self.path, self.state, self.probes = client, root, checkpoint_path, state, probes
        self.operation_timeout = operation_timeout

    def save(self):
        self.state['updated_at'] = now()
        if hasattr(self.client, 'read_retry_summary'):
            self.state['api_read_retries'] = self.client.read_retry_summary()
        private_write(self.path, self.state)

    def details(self, service_id, release_id=None):
        deadline = time.monotonic() + 120
        while True:
            detail = self.client.request('/api/services/' + service_id)
            ready = all(item['state'] == 'running' and item['health'] in ('healthy', 'not_configured') for item in detail['containers'])
            if ready and (release_id is None or detail.get('current_release_id') == release_id):
                return detail
            require(time.monotonic() < deadline, 'runtime/readiness did not converge to the expected release')
            time.sleep(.5)

    def operation(self, key, action, saved, **fields):
        self.state['active_stage'] = {'service': key, 'phase': action}
        self.save()
        step = saved.setdefault('operations', {}).setdefault(action, {})
        if not step.get('request'):
            attempt_suffix = '-attempt-' + str(step['attempt']) if step.get('attempt', 1) > 1 else ''
            step['request'] = {'service_id': saved['service_id'], 'action': action,
                               'idempotency_key': 'native-sibir-' + self.state['run_id'] + '-' + key + '-' + action + attempt_suffix, **fields}
            self.save()  # Exact key/input survives a crash before preview/submission.
        request = step['request']
        require(all(request.get(name) == value for name, value in fields.items()), 'saved operation inputs differ')
        if not request.get('plan_digest'):
            preview = self.client.request('/api/preview', request)
            require(not preview.get('active_file_drift'), 'active managed file drift requires review; no implicit acceptance')
            request['plan_digest'] = preview['plan_digest']
            step['preview'] = {'changed_file_count': len(preview.get('changed_files', [])),
                               'policy_revision': preview['policy_revision'], 'current_tree_digest': preview['current_tree_digest']}
            self.save()  # Save review and exact payload BEFORE the write.
        if not step.get('id'):
            job = self.client.request('/api/operations', request, expected=202)
            require(job['spec']['service_id'] == saved['service_id'] and job['spec']['kind'] == action, 'submitted job identity differs')
            require(job['spec'].get('idempotency_key') == request['idempotency_key'], 'submitted job idempotency identity differs')
            step['id'] = job['spec']['id']
            self.save()
        deadline = time.monotonic() + self.operation_timeout
        started = time.monotonic()
        while True:
            job = self.client.request('/api/operations/' + step['id'])
            if job['state'] in TERMINAL:
                step['result'] = public_operation(job)
                step.setdefault('observed_wait_seconds', round(time.monotonic() - started, 3))
                self.save()
                require(job['state'] == 'succeeded', 'operation ended in ' + job['state'] + '; preserved for diagnosis')
                return job
            require(time.monotonic() < deadline, 'operation wait deadline exceeded; exact job retained for resume')
            time.sleep(.5)

    def retry_failed_pre_mutation(self, key, action):
        require(key in PRESETS and action in ('fetch_source', 'build'), 'explicit retry only supports known services and fetch_source/build')
        saved = self.state['services'].get(key)
        require(saved and saved.get('baseline') and saved.get('before_data_written'), 'retry requires the original verified baseline and seeded data')
        step = saved.get('operations', {}).get(action)
        require(step, 'no original operation exists for explicit retry')
        # A resumed command can still contain the opt-in flag after the new
        # attempt was durably authorized. Continue that exact attempt, never
        # reset an ambiguous write or a running/succeeded replacement job.
        if step.get('retry_history_id') and not step.get('id'):
            return
        require(step.get('id') and step.get('request'), 'ambiguous/unsubmitted original must resume its exact request before a retry can be authorized')
        self.state['active_stage'] = {'service': key, 'phase': 'validate_failed_' + action + '_retry'}
        self.save()
        job = self.client.request('/api/operations/' + step['id'])
        require(job['spec']['id'] == step['id'] and job['spec']['service_id'] == saved['service_id']
                and job['spec']['kind'] == action and job['spec']['idempotency_key'] == step['request']['idempotency_key'], 'failed operation identity differs from checkpoint')
        if step.get('retry_history_id') and job['state'] != 'failed':
            return
        require(job['state'] == 'failed' and job.get('mutation_started') is False, 'retry requires an API-confirmed failed job before mutation')
        require(not saved.get('deployed') and not saved.get('built_release'), 'retry cannot reset a cycle that already recorded a built/deployed release')
        detail = self.details(saved['service_id'], saved['baseline']['release']['id'])
        service = detail['service']
        require(service['id'] == saved['service_id']
                and service['project_directory'] == str(self.root / 'services' / ('sibir-' + key))
                and service['compose_project'] == 'ctfm-demo-sibir-' + key
                and service['managed_paths'] == [{'path': 'vuln-service', 'kind': 'code'}]
                and sorted(service['targets']) == sorted(saved['targets']), 'retry service policy differs from reviewed identity/map')
        assert_preserved(saved['baseline']['runtime'], runtime_observation(detail), saved['targets'], all_components=True)
        require(verify_snapshot(self.root, service, saved['baseline']['release']) == saved['baseline']['code'], 'failed operation changed baseline code')
        if action == 'build':
            require(not any(item['id'] not in saved['baseline']['known_release_ids']
                            and item['snapshot_id'] == saved.get('candidate_id') for item in detail['releases']),
                    'failed Build already published a release; inspect it instead of silently rebuilding')
        probe = self.guarded_probe(key, saved, 'verify')
        # Close the verification window before replacing the step.
        detail = self.details(saved['service_id'], saved['baseline']['release']['id'])
        assert_preserved(saved['baseline']['runtime'], runtime_observation(detail), saved['targets'], all_components=True)
        require(verify_snapshot(self.root, service, saved['baseline']['release']) == saved['baseline']['code'], 'baseline code changed during retry verification')
        histories = saved.setdefault('retry_history', [])
        prior = next((item for item in histories if item['old_operation_id'] == step['id']
                      and item['step_sha256'] == fingerprint(step) and item['status'] == 'authorized_before_replacement'), None)
        if prior is None:
            prior = {'id': uuid.uuid4().hex, 'action': action, 'old_operation_id': step['id'],
                     'step_sha256': fingerprint(step), 'step': copy.deepcopy(step), 'api_job': job,
                     'verified_at': now(), 'baseline_runtime_code_and_game_data_unchanged': True,
                     'probe': probe, 'new_attempt': step.get('attempt', 1) + 1,
                     'status': 'authorized_before_replacement'}
            histories.append(prior)
            self.save()  # Exact old request/job/history is durable while old step still exists.
        saved['operations'][action] = {'attempt': prior['new_attempt'], 'retry_of': step['id'], 'retry_history_id': prior['id']}
        prior['status'] = 'replacement_checkpointed'
        self.save()  # New Preview/submission may start only after this second durable checkpoint.

    def guarded_probe(self, key, saved, method):
        self.state['active_stage'] = {'service': key, 'phase': 'probe_' + method}
        self.save()
        detail = self.details(saved['service_id'])
        actual = runtime_observation(detail)
        # Especially important for neuroLinks: never query stale RAM keys after
        # an auxiliary restart. Check ID/StartedAt before every protocol probe.
        assert_preserved(saved['baseline']['runtime'], actual, saved['targets'])
        value = getattr(self.probes, method)(key)
        saved.setdefault('probes', {})[method] = value
        self.save()
        return value

    def run_service(self, key):
        repository, commit, targets = PRESETS[key]
        saved = self.state['services'].setdefault(key, {'targets': targets, 'status': 'running'})
        self.save()
        registry = self.client.request('/api/services')
        matches = [item for item in registry if item['project_directory'] == str(self.root / 'services' / ('sibir-' + key))]
        require(len(matches) == 1, 'expected one existing service registration')
        service = matches[0]
        require(service['compose_project'] == 'ctfm-demo-sibir-' + key and sorted(service['targets']) == sorted(targets), 'registered Compose identity/targets differ')
        require(service['managed_paths'] == [{'path': 'vuln-service', 'kind': 'code'}], 'unexpected managed map; no game data may be read as code')
        if saved.get('service_id'):
            require(saved['service_id'] == service['id'], 'saved service identity changed')
        saved['service_id'] = service['id']
        source = self.client.request('/api/services/' + service['id'] + '/source')
        require(source.get('configured') and source['url'] == 'https://github.com/SibirCTF/' + repository + '.git'
                and source['ref'] == commit and source.get('subdirectory', '') == '', 'pinned Git configuration differs; refusing to change it')
        saved['git'] = {'url': source['url'], 'commit': commit, 'source_revision': source['revision']}
        if not saved.get('baseline'):
            active = self.client.request('/api/operations')
            require(not any(job['spec']['service_id'] == service['id'] and job['state'] not in TERMINAL for job in active), 'another operation is active for this service')
            detail = self.details(service['id'])
            baseline_id = detail.get('current_release_id')
            require(baseline_id, 'active baseline release is not established')
            release = next(item for item in detail['releases'] if item['id'] == baseline_id)
            saved['baseline'] = {'release': release, 'runtime': runtime_observation(detail),
                                 'code': verify_snapshot(self.root, service, release),
                                 'known_release_ids': [item['id'] for item in detail['releases']]}
            self.save()  # Baseline references/identities are durable before seeds/jobs.
        if saved.get('status') == 'passed':
            detail = self.details(service['id'], saved['baseline']['release']['id'])
            assert_preserved(saved['baseline']['runtime'], runtime_observation(detail), targets)
            verify_snapshot(self.root, service, saved['baseline']['release'])
            self.guarded_probe(key, saved, 'verify')
            return saved
        if not saved.get('before_data_written'):
            self.guarded_probe(key, saved, 'prepare')
            saved['before_data_written'] = True
            self.save()
        self.operation(key, 'fetch_source', saved)
        if not saved.get('candidate_id'):
            source = self.client.request('/api/services/' + service['id'] + '/source')
            detail = self.details(service['id'])
            require(source.get('last_fetch', {}).get('commit') == commit
                    and source['last_fetch']['snapshot_id'] == detail['candidate_id'], 'fetched candidate/commit differs')
            saved['candidate_id'] = detail['candidate_id']
            self.save()
        self.operation(key, 'build', saved, candidate_id=saved['candidate_id'])
        if not saved.get('built_release'):
            detail = self.details(service['id'], saved['baseline']['release']['id'])
            built = [item for item in detail['releases'] if item['id'] not in saved['baseline']['known_release_ids']
                     and item['snapshot_id'] == saved['candidate_id'] and item.get('git_source', {}).get('commit') == commit]
            require(len(built) == 1 and built[0].get('build_evidence_digest'), 'unique ready Git-built release not found')
            saved['built_release'] = built[0]
            actual = runtime_observation(detail)
            assert_preserved(saved['baseline']['runtime'], actual, targets, all_components=True)
            require(verify_snapshot(self.root, service, saved['baseline']['release']) == saved['baseline']['code'], 'Fetch/Build changed active code')
            saved['fetch_build_preserved_active_runtime_and_code'] = True
            self.save()
            self.guarded_probe(key, saved, 'verify')
        self.operation(key, 'deploy', saved, release_id=saved['built_release']['id'], confirm_data_compatibility=True)
        if not saved.get('deployed'):
            detail = self.details(service['id'], saved['built_release']['id'])
            actual = runtime_observation(detail)
            assert_preserved(saved['baseline']['runtime'], actual, targets)
            expected = {item['component']: item['image_id'] for item in saved['built_release']['images']}
            require({name: item['image_id'] for name, item in actual.items()} == expected, 'deployed exact images differ')
            code = verify_snapshot(self.root, service, saved['built_release'])
            saved['deployed'] = {'runtime': actual, 'code': code,
                'source_content_changed': code['content_sha256'] != saved['baseline']['code']['content_sha256'],
                'target_image_changed': {name: actual[name]['image_id'] != saved['baseline']['runtime'][name]['image_id'] for name in targets},
                'target_container_recreated': {name: actual[name]['id'] != saved['baseline']['runtime'][name]['id'] for name in targets}}
            self.save()
        if key == 'eyesee':
            saved['after_data_write_scope'] = {'executed': False,
                'reason': 'upstream deterministic UUID resets after restart and could overwrite the baseline prescription',
                'new_after_deploy_data_guarantee': False, 'existing_before_deploy_data_preservation_checked': True}
            self.save()
        elif not saved.get('after_data_written'):
            self.guarded_probe(key, saved, 'write_after_deploy')
            saved['after_data_written'] = True
            self.save()
        self.guarded_probe(key, saved, 'verify')
        self.operation(key, 'rollback', saved, release_id=saved['baseline']['release']['id'], confirm_data_compatibility=True)
        detail = self.details(service['id'], saved['baseline']['release']['id'])
        actual = runtime_observation(detail)
        assert_preserved(saved['baseline']['runtime'], actual, targets)
        require({name: item['image_id'] for name, item in actual.items()}
                == {name: item['image_id'] for name, item in saved['baseline']['runtime'].items()}, 'rollback did not restore exact baseline images')
        require(verify_snapshot(self.root, service, saved['baseline']['release']) == saved['baseline']['code'], 'rollback did not restore baseline bytes/mode/UID/GID')
        saved['rolled_back'] = {'runtime': actual, 'exact_images_restored': True, 'exact_code_metadata_restored': True,
                               'auxiliary_container_ids_started_at_mounts_preserved': True}
        self.save()
        self.guarded_probe(key, saved, 'verify')
        saved['status'] = 'passed'
        self.save()
        print(json.dumps({'service': key, 'status': 'passed', 'source_content_changed': saved['deployed']['source_content_changed'],
                          'target_image_changed': saved['deployed']['target_image_changed']}), flush=True)
        return saved


def public_report(state, status, error_type=None):
    return {'test': 'native-five-sibir-pinned-release-cycles', 'status': status, 'run_id': state['run_id'],
        'started_at': state['started_at'], 'updated_at': now(), 'error_type': error_type,
        'selected_service_keys': list(state.get('selected_service_keys', [])),
        'status_scope': 'requested service subset for this invocation; earlier service results are retained for resumable progress',
        'all_five_service_cycles_complete': status == 'passed' and set(state['services']) == set(PRESETS)
            and all(state['services'][key].get('status') == 'passed' for key in PRESETS),
        'scope': 'selected existing SibirCTF services; Admin HTTP pinned Fetch/Build/Deploy/Rollback; synthetic baseline and post-Deploy data with the explicit EyeSee limitation; no source marker edits or cleanup',
        'limitations': ['One pinned upstream revision per service; source content and cached image IDs may equal the imported baseline and are reported explicitly.',
                        'neuroLinks auxiliary memory is volatile; identity/StartedAt are checked before reading saved keys.',
                        'EyeSee after-Deploy Add is intentionally skipped: upstream deterministic UUID state resets and could overwrite baseline data. Its baseline prescription preservation is checked; no new-after-Deploy write guarantee is claimed.',
                        'Regular cycles only; no host failure, load benchmark, browser/RBAC or private Git provider claim.'],
        'active_stage': state.get('active_stage'), 'safe_error': state.get('safe_error') if error_type else None,
        'api_read_retries': state.get('api_read_retries'),
        'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'services': {key: {name: value for name, value in saved.items() if name not in ('operations', 'retry_history')}
                     | {'operations': {action: {name: value for name, value in step.items() if name != 'request'}
                                       for action, step in saved.get('operations', {}).items()},
                        'retry_history': [{name: value for name, value in item.items() if name not in ('step', 'api_job')}
                                          | {'old_operation': public_operation(item['api_job'])} for item in saved.get('retry_history', [])]}
                     for key, saved in state['services'].items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:8765')
    parser.add_argument('--root', type=Path, default=Path('/srv/ctf-manager'))
    parser.add_argument('--services', default=','.join(PRESETS))
    parser.add_argument('--credentials', type=Path)
    parser.add_argument('--checkpoint-dir', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--operation-timeout', type=int, default=900)
    parser.add_argument('--retry-failed-pre-mutation', action='append', default=[], metavar='SERVICE:ACTION',
                        help='explicitly authorize a new fetch_source/build attempt only after API failed+no-mutation and baseline/runtime/game preservation checks; old request/job history is retained')
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'existing native Linux host root is required')
    require(args.root.is_absolute() and args.root == args.root.resolve(), 'canonical native root required')
    keys = args.services.split(',')
    require(keys and len(keys) == len(set(keys)) and all(key in PRESETS for key in keys), 'unknown/duplicate services')
    retries = [value.split(':') for value in args.retry_failed_pre_mutation]
    require(all(len(value) == 2 and value[0] in keys and value[1] in ('fetch_source', 'build') for value in retries)
            and len({tuple(value) for value in retries}) == len(retries), 'retry selection must be unique selected SERVICE:fetch_source or SERVICE:build')
    require(60 <= args.operation_timeout <= 3600, 'operation timeout must be60..3600 seconds')
    directory = args.checkpoint_dir or args.root / 'config/native-sibir-cycles'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and not directory.is_symlink() and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.geteuid(), 'checkpoint directory must be owned0700 without symbolic links')
    lock = os.open(directory / '.controller.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        raise RuntimeError('another controller owns this checkpoint') from None
    path = directory / 'checkpoint.json'
    state = private_read(path) if path.exists() else {'run_id': uuid.uuid4().hex[:12], 'started_at': now(),
        'base': args.base.rstrip('/'), 'root': str(args.root), 'services': {}}
    require(state['base'] == args.base.rstrip('/') and state['root'] == str(args.root), 'checkpoint belongs to another panel/root')
    state['selected_service_keys'] = keys[:]
    private_write(path, state)
    report_path = args.report or directory / 'report.json'
    attempt = start_attempt(state)
    private_write(path, state)
    status, error_type = 'failed', None
    client = None
    probe_error_type = None
    try:
        from native_sibir_probes import ProbeAdapter, ProbeError
        probe_error_type = ProbeError
        client = Client(args.base)
        credentials = private_read(args.credentials or args.root / 'config/access.json')
        client.login(credentials)
        credentials.clear()
        probes = ProbeAdapter(args.root, directory / 'probes', namespace=state['run_id'],
                              eyesee_empty_store_proof=lambda: eyesee_empty_store_proof(client, args.root, state))
        cycles = Cycles(client, args.root, path, state, probes, args.operation_timeout)
        for key, action in retries:
            cycles.retry_failed_pre_mutation(key, action)
        for key in keys:
            cycles.run_service(key)
            private_write(report_path, public_report(state, 'running'))
        status = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        error_type = type(error).__name__
        state['last_error_type'] = error_type
        safe_error = owned_error_message(error, probe_error_type)
        if safe_error is not None:
            state['safe_error'] = safe_error
        state['failed_at'] = now()
        private_write(path, state)
        # Exception strings, HTTP bodies, cookies and probe payloads are omitted.
        print(json.dumps({'status': 'failed', 'error_type': error_type, 'safe_error': state.get('safe_error'),
                          'active_stage': state.get('active_stage'), 'checkpoint_preserved': True}), flush=True)
    finally:
        if client is not None:
            state['api_read_retries'] = client.read_retry_summary()
            attempt['api_read_retries'] = client.read_retry_summary()
        attempt.update(status=status, finished_at=now(), error_type=error_type)
        private_write(path, state)
        private_write(report_path, public_report(state, status, error_type))
        attempt_report = report_path.with_name(report_path.stem + '.attempt-' + str(len(state['attempts'])) + report_path.suffix)
        private_write(attempt_report, public_report(state, status, error_type))
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
    return 0 if status == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
