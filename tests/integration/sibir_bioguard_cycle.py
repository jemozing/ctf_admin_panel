#!/usr/bin/env python3
"""Prepare a persistent real BioGuard service and probe its data over HTTP.

This helper never registers a service or submits dashboard operations. Run setup
once, then use the dashboard for registration, Git fetch, Build, Deploy and
Rollback. Run seed before switching releases and check/evidence after each step.
Setup intentionally uses a separate local Compose profile: upstream SQLite is
otherwise stored in the disposable application layer. The only source edit is
an explicit imported-baseline HTML marker, removed by the exact Git candidate.
"""

import argparse
import hashlib
import html
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import time
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "var/preview"
DAEMON = "/srv/ctf-manager-preview"
PROJECT = "ctfm-preview-sibir-bioguard"
SERVICE_DIRECTORY = DAEMON + "/services/sibir-bioguard"
COMPOSE_FILE = SERVICE_DIRECTORY + "/ctfm.runtime.yaml"
RUNTIME_CONFIG_DIRECTORY = DAEMON + "/services/sibir-bioguard-runtime-config"
GIT_URL = "https://github.com/SibirCTF/2025-cybersibir-service-BioGuard.git"
GIT_COMMIT = "0d5dffae3460823715a266d5674d2110837c4bea"
SOURCE = ROOT / "tests/fixtures/vendor/2025-cybersibir-service-BioGuard/vuln-service"
BASELINE_MARKER = '<p id="ctfm-baseline-marker">CTFM imported local baseline</p>'
IMAGE = PROJECT + ":baseline"


def command(arguments, *, timeout=180):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
    result = subprocess.run(arguments, capture_output=True, text=True, env=environment, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command {Path(arguments[0]).name} failed: {(result.stderr + result.stdout)[-4000:]}")
    return result.stdout


def private_json(filename, value):
    filename.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def read_private_json(filename):
    info = filename.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError(f"Private regular file with mode 0600 required: {filename}")
    return json.loads(filename.read_text())


class Docker:
    def __init__(self):
        self.binary = shutil.which("docker")
        if not self.binary:
            raise RuntimeError("Docker is required")
        endpoint = os.environ.get("DOCKER_HOST") or json.loads(self.run("context", "inspect"))[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix:///"):
            raise RuntimeError("An explicit local Unix Docker daemon is required")
        self.socket = endpoint.removeprefix("unix://")

    def run(self, *arguments, timeout=180):
        return command([self.binary, *arguments], timeout=timeout)

    def helper(self, code, *arguments, writable=False):
        mount = f"type=bind,source={DAEMON},target={DAEMON}" + ("" if writable else ",readonly")
        return self.run("run", "--rm", "--network", "none", "--mount", mount,
                        "--mount", f"type=bind,source={ROOT},target={ROOT},readonly",
                        "python:3.11-slim", "python3", "-c", code, DAEMON, str(ROOT), *map(str, arguments))

    def compose(self, *arguments, timeout=900):
        # Both Compose and BuildKit must see native Linux paths, not macOS bind
        # translations. This reuses the installed executor's Docker CLI only.
        # Buildx authenticates registry pulls from the CLI side as well as the
        # daemon. The setup builder needs ordinary bridge egress for this; it
        # does not use host networking or join existing game networks.
        return self.run("run", "--rm", "--network", "bridge",
                        "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                        "--mount", f"type=bind,source={self.socket},target=/var/run/docker.sock",
                        "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                        "compose", "--project-name", PROJECT, "--project-directory", SERVICE_DIRECTORY,
                        "--file", COMPOSE_FILE, *arguments, timeout=timeout)

    def container(self):
        identifiers = self.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT,
                               "--filter", "label=com.docker.compose.service=web").splitlines()
        if len(identifiers) != 1:
            raise RuntimeError("Expected exactly one owned BioGuard web container")
        value = json.loads(self.run("inspect", identifiers[0]))[0]
        labels = value["Config"].get("Labels", {})
        if labels.get("com.docker.compose.project.working_dir") != SERVICE_DIRECTORY:
            raise RuntimeError("Compose project belongs to a different directory")
        configuration_label = labels.get("com.docker.compose.project.config_files", "")
        frozen_compose = re.fullmatch(re.escape(DAEMON) + r"/executor/compose-operation-[0-9]+/compose\.json", configuration_label)
        if configuration_label != COMPOSE_FILE and not frozen_compose:
            raise RuntimeError("Compose project has unexpected configuration files")
        return value


def game_url(container):
    bindings = container["NetworkSettings"].get("Ports", {}).get("4444/tcp") or []
    if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("BioGuard must publish exactly one loopback-only HTTP port")
    return "http://127.0.0.1:" + bindings[0]["HostPort"]


SETUP = r'''
import hashlib,json,os,shutil,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);project,commit,baseline_marker=sys.argv[3:6]
preview_marker=root/'.ctfm-preview.json'
expected_preview={'purpose':'ctf-manager persistent local preview','repository':str(repo)}
if preview_marker.is_symlink() or not preview_marker.is_file() or json.loads(preview_marker.read_text())!=expected_preview:
    raise RuntimeError('Native root is not this repository preview; refusing changes')
game=root/'services/sibir-bioguard'; marker=game/'.ctfm-sibir-bioguard.json'
expected={'purpose':'persistent real SibirCTF BioGuard cycle','repository':str(repo),'project':project,'git_commit':commit}
fresh=not game.exists()
if fresh:
    game.mkdir(mode=0o755)
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as output:json.dump(expected,output)
    source=repo/'tests/fixtures/vendor/2025-cybersibir-service-BioGuard/vuln-service'
    shutil.copytree(source,game/'vuln-service',ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git'))
    index=game/'vuln-service/BioGuard/templates/BioGuard/index.html'
    original=index.read_text()
    if original.count('<h1>BioGuard</h1>')!=1 or 'ctfm-baseline-marker' in original:
        raise RuntimeError('Unexpected upstream template; refusing baseline modification')
    index.write_text(original.replace('<h1>BioGuard</h1>','<h1>BioGuard</h1>\n        '+baseline_marker))
    configuration=game/'runtime-config';configuration.mkdir(mode=0o755)
    (configuration/'ctfm_settings.py').write_text('from health_corp.settings import *\nDATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "/data/db.sqlite3"}}\n')
    profile={'services':{'web':{
        'build':{'context':'./vuln-service'},'image':project+':baseline',
        'ports':[{'target':4444,'host_ip':'127.0.0.1','protocol':'tcp'}],
        'environment':{'DJANGO_SETTINGS_MODULE':'ctfm_settings','PYTHONPATH':'/runtime-config:/app','PYTHONDONTWRITEBYTECODE':'1'},
        'entrypoint':['/bin/sh','-c','python manage.py migrate --noinput && exec python manage.py runserver 0.0.0.0:4444 --noreload'],
        'volumes':[{'type':'volume','source':'sqlite-data','target':'/data'},
                   {'type':'bind','source':'./runtime-config','target':'/runtime-config','read_only':True,'bind':{'create_host_path':False}}],
        'restart':'unless-stopped','shm_size':'64m','mem_limit':'512m','cpus':1.0,'pids_limit':128,
        'logging':{'driver':'json-file','options':{'max-size':'20m','max-file':'5'}},
        'healthcheck':{'test':['CMD','python','-c','import urllib.request; urllib.request.urlopen("http://127.0.0.1:4444/", timeout=2).read()'],
                       'interval':'2s','timeout':'3s','retries':30,'start_period':'5s'}
    }},'volumes':{'sqlite-data':{}}}
    (game/'ctfm.runtime.yaml').write_text(json.dumps(profile,indent=2)+'\n')
else:
    if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:
        raise RuntimeError('Existing service directory is not owned by this helper; refusing changes')
    settings_present=(game/'runtime-config/ctfm_settings.py').is_file() or (root/'services/sibir-bioguard-runtime-config/ctfm_settings.py').is_file()
    if not (game/'ctfm.runtime.yaml').is_file() or not settings_present:
        raise RuntimeError('Owned setup is incomplete; inspect it manually before retrying')
print(json.dumps({'fresh':fresh,'project_directory':str(game),'compose_file':str(game/'ctfm.runtime.yaml')}))
'''


EXTERNALIZE_CONFIG = r'''
import json,os,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]); project,commit,phase=sys.argv[3:6]
game=root/'services/sibir-bioguard'; old=game/'runtime-config'
external=root/'services/sibir-bioguard-runtime-config'
expected={'purpose':'persistent real SibirCTF BioGuard cycle','repository':str(repo),'project':project,'git_commit':commit}
marker=game/'.ctfm-sibir-bioguard.json'
if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:
    raise RuntimeError('Service directory does not have the expected ownership marker')
db=root/'executor/executor.db'
if not db.is_file():raise RuntimeError('Cannot verify that this service is unregistered')
connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
try:
    for row in connection.execute('SELECT payload FROM services'):
        service=json.loads(row[0])
        if service.get('project_directory')==str(game) or service.get('compose_project')==project:
            raise RuntimeError('Service is already registered; runtime policy must not be changed by this helper')
finally:connection.close()
settings=b'from health_corp.settings import *\nDATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "/data/db.sqlite3"}}\n'
def exact_settings(directory):
    path=directory/'ctfm_settings.py'
    if directory.is_symlink() or path.is_symlink() or not path.is_file() or path.read_bytes()!=settings:
        raise RuntimeError('Local runtime settings differ from the exact helper-owned bytes')
def sync_directory(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
external_marker=external/'.ctfm-runtime-config.json'
external_owner={'purpose':'frozen BioGuard runtime settings','project':project,'service_directory':str(game)}
if phase=='prepare':
    if old.exists():
        exact_settings(old)
        if {path.name for path in old.iterdir()}!={'ctfm_settings.py'}:
            raise RuntimeError('Original runtime-config has unexpected entries; refusing to remove it')
    if not external.exists():
        if not old.exists():raise RuntimeError('Missing original settings for owned migration')
        external.mkdir(mode=0o755)
        for path,data,mode in ((external_marker,json.dumps(external_owner).encode(),0o600),(external/'ctfm_settings.py',settings,0o444)):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
            with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
        sync_directory(external)
    if external.is_symlink() or external_marker.is_symlink() or not external_marker.is_file() or json.loads(external_marker.read_text())!=external_owner:
        raise RuntimeError('External runtime directory is not owned by this service')
    exact_settings(external)
    profile_path=game/'ctfm.runtime.yaml'
    if profile_path.is_symlink():raise RuntimeError('Compose profile cannot be a symbolic link')
    profile=json.loads(profile_path.read_text())
    matches=[mount for mount in profile['services']['web']['volumes'] if mount.get('target')=='/runtime-config']
    if len(matches)!=1 or matches[0].get('type')!='bind' or not matches[0].get('read_only') or matches[0].get('bind')!={'create_host_path':False}:
        raise RuntimeError('Unexpected runtime-config mount policy')
    mount=matches[0]
    if mount.get('source') not in ('./runtime-config',str(external)):
        raise RuntimeError('Unexpected existing runtime-config source')
    changed=mount['source']!=str(external)
    if changed:
        mount['source']=str(external)
        temporary=game/'.ctfm.runtime.externalize.tmp'
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'w') as output:json.dump(profile,output,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())
        os.replace(temporary,profile_path);sync_directory(game)
    print(json.dumps({'profile_changed':changed,'runtime_config_directory':str(external)}))
elif phase=='finish':
    exact_settings(external)
    profile=json.loads((game/'ctfm.runtime.yaml').read_text())
    if not any(mount.get('target')=='/runtime-config' and mount.get('source')==str(external) for mount in profile['services']['web']['volumes']):
        raise RuntimeError('External runtime configuration is not the active Compose input')
    if old.exists():
        exact_settings(old)
        if {path.name for path in old.iterdir()}!={'ctfm_settings.py'}:
            raise RuntimeError('Original runtime-config contains unexpected entries')
        (old/'ctfm_settings.py').unlink();old.rmdir();sync_directory(game)
    print(json.dumps({'old_runtime_config_removed':not old.exists(),'runtime_config_directory':str(external)}))
else:raise RuntimeError('Unexpected migration phase')
'''


def externalize_config(docker):
    """One-time profile migration, refused once the executor has a registration."""
    previous = docker.container()
    prepared = json.loads(docker.helper(EXTERNALIZE_CONFIG, PROJECT, GIT_COMMIT, "prepare", writable=True))
    # Only this application is recreated; neither down nor volume deletion is
    # used. This also safely resumes after a previous profile-only interruption.
    docker.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "120", "web")
    current = docker.container()
    for old_mount in previous.get("Mounts", []):
        if old_mount["Type"] == "volume" and not any(new.get("Name") == old_mount.get("Name") and new["Destination"] == old_mount["Destination"]
                                                      for new in current.get("Mounts", [])):
            raise RuntimeError("A persistent volume identity changed during profile migration")
    finished = json.loads(docker.helper(EXTERNALIZE_CONFIG, PROJECT, GIT_COMMIT, "finish", writable=True))
    return {**evidence(docker), **prepared, **finished, "previous_container_id": previous["Id"],
            "registered_service_mutated": False, "persistent_volumes_preserved": True}


def setup(docker):
    # Check project ownership before any potentially destructive Compose action.
    existing = docker.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT).splitlines()
    if existing:
        docker.container()
    prepared = json.loads(docker.helper(SETUP, PROJECT, GIT_COMMIT, BASELINE_MARKER, writable=True))
    if prepared["fresh"] and existing:
        raise RuntimeError("Refusing to change an existing project without a previous owned setup")
    volume = PROJECT + "_sqlite-data"
    volumes = docker.run("volume", "ls", "--quiet", "--filter", "name=^" + volume + "$").splitlines()
    if volumes:
        value = json.loads(docker.run("volume", "inspect", volume))[0]
        if value.get("Labels", {}).get("com.docker.compose.project") != PROJECT:
            raise RuntimeError("Expected SQLite volume name is already owned by another project")
    # A rerun never rebuilds/recreates an already running release, including one
    # deployed by the dashboard after initial setup.
    if not existing:
        docker.helper(EXTERNALIZE_CONFIG, PROJECT, GIT_COMMIT, "prepare", writable=True)
        docker.compose("up", "-d", "--build", "--wait", "--wait-timeout", "120", timeout=900)
        docker.helper(EXTERNALIZE_CONFIG, PROJECT, GIT_COMMIT, "finish", writable=True)
    result = evidence(docker)
    result.update(prepared)
    result["registration_hint"] = {"managed_paths": [{"path": "vuln-service", "kind": "code"}],
                                   "git_url": GIT_URL, "git_ref": GIT_COMMIT, "git_subdirectory": "",
                                   "writable_layer_loss_accepted": True,
                                   "runtime_config_bind_significant": False, "sqlite_volume_significant": True}
    return result


class CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = None

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag == "input" and values.get("name") == "csrfmiddlewaretoken":
            self.token = values.get("value")


class GameClient:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, path):
        with self.opener.open(self.base + path, timeout=15) as response:
            return response.geturl(), response.read().decode()

    def post_form(self, path, values):
        _, page = self.get(path)
        parser = CSRFParser()
        parser.feed(page)
        if not parser.token:
            raise RuntimeError("Django form has no CSRF token: " + path)
        data = urllib.parse.urlencode({**values, "csrfmiddlewaretoken": parser.token}).encode()
        request = urllib.request.Request(self.base + path, data=data,
                                         headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": self.base, "Referer": self.base + path})
        with self.opener.open(request, timeout=15) as response:
            return response.geturl(), response.read().decode()

    def login_profile(self, values):
        destination, _ = self.post_form("/login", {"username": values["username"], "password": values["password"]})
        if urllib.parse.urlsplit(destination).path != "/profile":
            raise RuntimeError("BioGuard patient login did not reach the profile")
        destination, profile = self.get("/profile")
        if urllib.parse.urlsplit(destination).path != "/profile" or html.escape(values["diagnosis"]) not in profile:
            raise RuntimeError("Synthetic game data is missing from the authenticated patient profile")
        return profile


def seed_or_check(docker, credentials_file, *, seed=False, expected_marker="either"):
    container = docker.container()
    client = GameClient(game_url(container))
    new_patient = False
    if credentials_file.exists():
        patient = read_private_json(credentials_file)
        if patient.get("project") != PROJECT:
            raise RuntimeError("Patient credentials belong to another Compose project")
    elif seed:
        patient = {"project": PROJECT, "username": "ctfm_" + secrets.token_hex(6),
                   "password": secrets.token_urlsafe(24), "diagnosis": "CTFM_FLAG_" + secrets.token_hex(16)}
        private_json(credentials_file, patient)
        new_patient = True
    else:
        raise RuntimeError("Seed credentials are missing; run seed before checking preservation")
    if new_patient:
        destination, _ = client.post_form("/register", {"username": patient["username"], "password1": patient["password"],
                                                         "password2": patient["password"], "first_name": "CTFM", "last_name": "Preservation",
                                                         "email": "ctfm@example.invalid", "birth_year": "2000", "diagnosis": patient["diagnosis"],
                                                         "appointments": "", "vip": "false"})
        if urllib.parse.urlsplit(destination).path != "/login":
            raise RuntimeError("BioGuard patient registration did not redirect to login")
    profile = client.login_profile(patient)
    _, page = client.get("/")
    marker = BASELINE_MARKER in page
    if expected_marker != "either" and marker != (expected_marker == "present"):
        raise RuntimeError("Unexpected imported-baseline HTML marker state")
    return {"project": PROJECT, "url": client.base, "patient_created": new_patient,
            "patient_login_successful": True, "diagnosis_preserved": True,
            "diagnosis_sha256": hashlib.sha256(patient["diagnosis"].encode()).hexdigest(),
            "profile_sha256": hashlib.sha256(profile.encode()).hexdigest(),
            "baseline_marker_present": marker, "index_sha256": hashlib.sha256(page.encode()).hexdigest(),
            "container_id": container["Id"], "image_id": container["Image"], "started_at": container["State"]["StartedAt"]}


def evidence(docker):
    container = docker.container()
    volumes = []
    for mount in container.get("Mounts", []):
        if mount["Type"] == "volume":
            value = json.loads(docker.run("volume", "inspect", mount["Name"]))[0]
            volumes.append({"name": value["Name"], "mountpoint": value["Mountpoint"], "created_at": value.get("CreatedAt"),
                            "driver": value["Driver"], "labels": value.get("Labels"), "target": mount["Destination"]})
    tree = json.loads(docker.helper(r'''
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])/'services/sibir-bioguard'; files={}
marker=root/'.ctfm-sibir-bioguard.json'
if marker.is_symlink() or not marker.is_file():raise RuntimeError('Missing owned marker')
for name in ('ctfm.runtime.yaml','vuln-service/BioGuard/templates/BioGuard/index.html','vuln-service/Dockerfile'):
    path=root/name
    if path.is_symlink() or not path.is_file():raise RuntimeError('Unexpected source file')
    files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
profile=json.loads((root/'ctfm.runtime.yaml').read_text())
mount=next(mount for mount in profile['services']['web']['volumes'] if mount.get('target')=='/runtime-config')
configuration=Path(mount['source'])
if not configuration.is_absolute():configuration=root/configuration
settings=configuration/'ctfm_settings.py'
if configuration.is_symlink() or settings.is_symlink() or not settings.is_file():raise RuntimeError('Unexpected runtime settings')
files[str(settings)]=hashlib.sha256(settings.read_bytes()).hexdigest()
print(json.dumps({'files_sha256':files,'baseline_marker_on_disk':b'ctfm-baseline-marker' in (root/'vuln-service/BioGuard/templates/BioGuard/index.html').read_bytes()}))
'''))
    url = game_url(container)
    result = {"project": PROJECT, "project_directory": SERVICE_DIRECTORY, "url": url,
              "git_url": GIT_URL, "git_commit": GIT_COMMIT, "git_subdirectory": "",
              "container_id": container["Id"], "image_id": container["Image"], "started_at": container["State"]["StartedAt"],
              "status": container["State"]["Status"], "health": container["State"].get("Health", {}).get("Status"),
              "mounts": [{key: mount.get(key) for key in ("Type", "Name", "Source", "Destination", "RW")} for mount in container.get("Mounts", [])],
              "volumes": volumes, "source": tree,
              "upstream_compose_used": False,
              "profile_differences": ["Local Compose builds the unchanged upstream Dockerfile in ./vuln-service",
                                      "SQLite uses a named volume at /data through a separate frozen read-only settings bind",
                                      "Django migrate executes before runserver; automatic reload is disabled",
                                      "HTTP is published on a random loopback port; runtime resources and log rotation are bounded",
                                      "Imported baseline alone adds a documented HTML marker; exact Git candidate removes it"]}
    try:
        with urllib.request.urlopen(url + "/", timeout=10) as response:
            page = response.read()
            result.update(http_status=response.status, baseline_marker_served=BASELINE_MARKER.encode() in page,
                          index_sha256=hashlib.sha256(page).hexdigest())
    except OSError as error:
        result["http_error"] = str(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "externalize-config", "seed", "check", "evidence"))
    parser.add_argument("--before-registration", action="store_true", help="Acknowledge one-time migration before web registration; the helper also checks the executor database")
    parser.add_argument("--credentials-file", type=Path, default=LOCAL / "sibir-bioguard-patient.json")
    parser.add_argument("--expect-marker", choices=("present", "absent", "either"), default="either")
    parser.add_argument("--output", type=Path, help="Save the public result JSON; never includes patient credentials")
    arguments = parser.parse_args()
    if arguments.action == "externalize-config" and not arguments.before_registration:
        parser.error("externalize-config requires --before-registration")
    docker = Docker()
    if arguments.action == "setup":
        result = setup(docker)
    elif arguments.action == "externalize-config":
        result = externalize_config(docker)
    elif arguments.action in ("seed", "check"):
        result = seed_or_check(docker, arguments.credentials_file, seed=arguments.action == "seed", expected_marker=arguments.expect_marker)
    else:
        result = evidence(docker)
    result.update(action=arguments.action, recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
