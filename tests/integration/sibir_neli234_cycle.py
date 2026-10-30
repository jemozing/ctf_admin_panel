#!/usr/bin/env python3
"""Isolated real neuroLinks setup and normal TCP preservation probes.

Dashboard registration and operations are deliberately absent. The controller's
relative SQLite filename is preserved by a frozen working_dir=/data profile.
The opaque neurolink holds game data in memory and is a stateful dependency;
only controller may be targeted by dashboard Build/Deploy/Rollback.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import tempfile
import time

from sibir_bioguard_cycle import Docker as BaseDocker, ROOT, DAEMON, LOCAL, private_json, read_private_json

PROJECT = "ctfm-preview-sibir-neli234"
SERVICE_DIRECTORY = DAEMON + "/services/sibir-neli234"
COMPOSE_FILE = SERVICE_DIRECTORY + "/ctfm.runtime.yaml"
GIT_URL = "https://github.com/SibirCTF/2025-cybersibir-service-neLi234.git"
GIT_COMMIT = "28d8a11498675233e87394e4d89956ad0938abfd"
BASELINE_MARKER = "CTFM imported local baseline"


class Docker(BaseDocker):
    def build_initial(self, component, platform):
        context = SERVICE_DIRECTORY + "/vuln-service/" + component
        return self.run("run", "--rm", "--network", "bridge",
                        "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                        "--mount", f"type=bind,source={self.socket},target=/var/run/docker.sock",
                        "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                        "build", "--platform", platform, "--tag", PROJECT + ":baseline-" + component,
                        "--file", context + "/Dockerfile", context, timeout=1200)

    def compose(self, *arguments, timeout=900):
        return self.run("run", "--rm", "--network", "bridge",
                        "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                        "--mount", f"type=bind,source={self.socket},target=/var/run/docker.sock",
                        "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                        "compose", "--project-name", PROJECT, "--project-directory", SERVICE_DIRECTORY,
                        "--file", COMPOSE_FILE, *arguments, timeout=timeout)

    def container(self, component="controller"):
        identifiers = self.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT,
                               "--filter", "label=com.docker.compose.service=" + component).splitlines()
        if len(identifiers) != 1:
            raise RuntimeError("Expected exactly one owned neuroLinks " + component + " container")
        value = json.loads(self.run("inspect", identifiers[0]))[0]
        labels = value["Config"].get("Labels", {})
        if labels.get("com.docker.compose.project.working_dir") != SERVICE_DIRECTORY:
            raise RuntimeError("Compose project belongs to another directory")
        configuration_label = labels.get("com.docker.compose.project.config_files", "")
        frozen = re.fullmatch(re.escape(DAEMON) + r"/executor/compose-operation-[0-9]+/compose\.json", configuration_label)
        if configuration_label != COMPOSE_FILE and not frozen:
            raise RuntimeError("Unexpected Compose configuration")
        return value


SETUP = r'''
import hashlib,json,os,shutil,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);project,commit,baseline_marker=sys.argv[3:6]
preview_marker=root/'.ctfm-preview.json'
if preview_marker.is_symlink() or json.loads(preview_marker.read_text())!={'purpose':'ctf-manager persistent local preview','repository':str(repo)}:
    raise RuntimeError('Not this repository preview root')
game=root/'services/sibir-neli234';marker=game/'.ctfm-sibir-neli234.json'
expected={'purpose':'persistent real SibirCTF neuroLinks cycle','repository':str(repo),'project':project,'git_commit':commit}
fresh=not game.exists()
if fresh:
    game.mkdir(mode=0o755)
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as output:json.dump(expected,output)
    shutil.copytree(repo/'tests/fixtures/vendor/2025-cybersibir-service-neLi234/vuln-service',game/'vuln-service',ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git'))
    source=game/'vuln-service/controller/src/server.cpp';original=source.read_text()
    if original.count('Choose an option:')!=1 or baseline_marker in original:raise RuntimeError('Unexpected upstream controller source')
    source.write_text(original.replace('Choose an option:','Choose an option ('+baseline_marker+'):'))
    bounded={'restart':'unless-stopped','shm_size':'64m','cpus':1.0,'pids_limit':128,
             'logging':{'driver':'json-file','options':{'max-size':'20m','max-file':'5'}}}
    controller={**bounded,'build':{'context':'./vuln-service/controller'},'image':project+':baseline-controller',
                'ports':[{'target':2340,'host_ip':'127.0.0.1','protocol':'tcp'}],
                'working_dir':'/data','volumes':[{'type':'volume','source':'sqlite-data','target':'/data'}],
                'read_only':True,'mem_limit':'256m',
                'depends_on':{'neurolink':{'condition':'service_healthy'}},
                'healthcheck':{'test':['CMD-SHELL',"grep -qE ':0924 +[0-9A-F:]+ +0A ' /proc/net/tcp /proc/net/tcp6"],
                               'interval':'2s','timeout':'3s','retries':30,'start_period':'5s'}}
    neurolink={**bounded,'build':{'context':'./vuln-service/neurolink'},'image':project+':baseline-neurolink',
               'expose':['8080'],'mem_limit':'256m',
               'healthcheck':{'test':['CMD-SHELL',"grep -qE ':1F90 +[0-9A-F:]+ +0A ' /proc/net/tcp /proc/net/tcp6"],
                              'interval':'2s','timeout':'3s','retries':30,'start_period':'5s'}}
    (game/'ctfm.runtime.yaml').write_text(json.dumps({'services':{'controller':controller,'neurolink':neurolink},'volumes':{'sqlite-data':{}}},indent=2)+'\n')
else:
    if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:
        raise RuntimeError('Existing directory is not owned by this helper')
    if not (game/'ctfm.runtime.yaml').is_file():raise RuntimeError('Incomplete owned setup; inspect before resuming')
print(json.dumps({'fresh':fresh,'project_directory':str(game),'compose_file':str(game/'ctfm.runtime.yaml')}))
'''


ADAPT_PROFILE = r'''
import hashlib,json,os,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);project,commit=sys.argv[3:5]
game=root/'services/sibir-neli234';marker=game/'.ctfm-sibir-neli234.json'
expected={'purpose':'persistent real SibirCTF neuroLinks cycle','repository':str(repo),'project':project,'git_commit':commit}
if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:
    raise RuntimeError('Missing matching owned setup marker')
db=root/'executor/executor.db'
if not db.is_file():raise RuntimeError('Cannot verify unregistered state')
connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
try:
    for row in connection.execute('SELECT payload FROM services'):
        service=json.loads(row[0])
        if service.get('project_directory')==str(game) or service.get('compose_project')==project:
            raise RuntimeError('Service is registered; refusing profile preparation changes')
finally:connection.close()
path=game/'ctfm.runtime.yaml'
if path.is_symlink() or not path.is_file():raise RuntimeError('Unexpected profile path')
original=path.read_bytes();profile=json.loads(original)
if set(profile['services'])!={'controller','neurolink'}:raise RuntimeError('Unexpected service set')
controller=profile['services']['controller'];auxiliary=profile['services']['neurolink']
if controller.get('read_only') is not True or controller.get('working_dir')!='/data':
    raise RuntimeError('Controller protection or data directory changed')
if controller.get('volumes')!=[{'type':'volume','source':'sqlite-data','target':'/data'}]:
    raise RuntimeError('Unexpected controller persistent mount')
for component,platform in ((controller,'linux/arm64'),(auxiliary,'linux/amd64')):
    if component.get('platform') not in (None,platform):raise RuntimeError('Unexpected previous platform')
    if component.get('shm_size')!='64m':raise RuntimeError('Explicit shm_size protection changed')
    component.pop('platform',None)
if controller.get('tmpfs') not in (None,['/tmp:rw,nosuid,nodev,size=64m']):raise RuntimeError('Unexpected previous tmpfs')
controller.pop('tmpfs',None)
updated=(json.dumps(profile,indent=2)+'\n').encode();changed=updated!=original
if changed:
    temporary=game/'.ctfm.runtime.adapt.tmp'
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as output:output.write(updated);output.flush();os.fsync(output.fileno())
    os.replace(temporary,path)
    fd=os.open(game,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
print(json.dumps({'profile_changed':changed,'old_profile_sha256':hashlib.sha256(original).hexdigest(),
    'new_profile_sha256':hashlib.sha256(updated).hexdigest(),'controller_read_only':True,
    'unsupported_runtime_keys_removed':['platform','tmpfs'],'registered_service_mutated':False}))
'''


def adapt_profile(docker):
    previous = {name:docker.container(name) for name in ("controller","neurolink")}
    prepared = json.loads(docker.helper(ADAPT_PROFILE,PROJECT,GIT_COMMIT,writable=True))
    # platform changes do not change the running image or a HostConfig field.
    # Only controller has an actual unsupported tmpfs mount to remove; --no-deps
    # deliberately keeps the opaque auxiliary's in-memory store untouched.
    if previous["controller"]["HostConfig"].get("Tmpfs"):
        docker.compose("up","-d","--no-build","--pull","never","--no-deps","--wait","--wait-timeout","120","controller")
    current = {name:docker.container(name) for name in ("controller","neurolink")}
    for field in ("Id","Image"):
        if current["neurolink"][field] != previous["neurolink"][field]:
            raise RuntimeError("Opaque neurolink identity changed during controller-only profile preparation")
    if current["neurolink"]["State"]["StartedAt"] != previous["neurolink"]["State"]["StartedAt"]:
        raise RuntimeError("Opaque neurolink restarted during profile preparation")
    if current["controller"]["Image"] != previous["controller"]["Image"]:
        raise RuntimeError("Controller image changed during profile-only preparation")
    if current["controller"]["HostConfig"].get("Tmpfs") or not current["controller"]["HostConfig"].get("ReadonlyRootfs"):
        raise RuntimeError("Unsupported tmpfs remains or read-only root protection changed")
    old_mounts = [(m.get("Name"),m["Destination"]) for m in previous["controller"].get("Mounts",[]) if m["Type"]=="volume"]
    new_mounts = [(m.get("Name"),m["Destination"]) for m in current["controller"].get("Mounts",[]) if m["Type"]=="volume"]
    if old_mounts != new_mounts:
        raise RuntimeError("Persistent SQLite mount changed during profile preparation")
    return {**evidence(docker),**prepared,"previous_controller_container_id":previous["controller"]["Id"],
            "auxiliary_container_preserved":True,"auxiliary_started_at_preserved":True,"sqlite_volume_preserved":True}


def endpoint(container):
    bindings = container["NetworkSettings"].get("Ports", {}).get("2340/tcp") or []
    if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("Expected one loopback-only TCP port")
    return "127.0.0.1", int(bindings[0]["HostPort"])


class GameClient:
    def __init__(self, host, port):
        self.connection = socket.create_connection((host, port), timeout=10)
        self.connection.settimeout(10)
        self.prompt = self.until(b"2. Login\n")

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.connection.close()

    def until(self, token):
        value = b""
        while token not in value:
            piece = self.connection.recv(4096)
            if not piece:
                raise RuntimeError("Unexpected EOF in neuroLinks protocol")
            value += piece
            if len(value) > 16384:
                raise RuntimeError("Unexpected oversized neuroLinks response")
        return value

    def send(self, value):
        self.connection.sendall((value + "\n").encode())

    def register(self, values):
        self.send("1"); self.until(b"Enter username: ")
        self.send(values["username"]); self.until(b"Enter password: ")
        self.send(values["password"])
        result = self.until(b"2. Login\n")
        if b"Registration successful!" not in result:
            raise RuntimeError("Synthetic user registration failed")

    def login(self, values):
        self.send("2"); self.until(b"Username: ")
        self.send(values["username"]); self.until(b"Password: ")
        self.send(values["password"])
        if b"Login successful!\n" not in self.until(b"\n"):
            raise RuntimeError("Synthetic user login failed")

    def command(self, value, expected=None):
        self.send(value)
        response = self.connection.recv(4096).decode().strip()
        if expected is not None and response != expected:
            raise RuntimeError("Unexpected neuroLinks application response")
        return response


def setup(docker, *, prepare_only=False):
    existing = docker.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT).splitlines()
    if existing:
        docker.container(); docker.container("neurolink")
    prepared = json.loads(docker.helper(SETUP, PROJECT, GIT_COMMIT, BASELINE_MARKER, writable=True))
    if prepared["fresh"] and existing:
        raise RuntimeError("Existing containers have no matching owned setup")
    if prepare_only:
        return prepared
    if not existing:
        volume = PROJECT + "_sqlite-data"
        if docker.run("volume", "ls", "--quiet", "--filter", "name=^" + volume + "$").splitlines():
            value = json.loads(docker.run("volume", "inspect", volume))[0]
            if value.get("Labels", {}).get("com.docker.compose.project") != PROJECT:
                raise RuntimeError("Persistent volume is owned by another project")
        # Runtime `platform` is not reconciled by the MVP. Select architectures
        # explicitly only for this initial build, then freeze image IDs through
        # dashboard baseline import; subsequent target controller builds are
        # native arm64. The amd64 auxiliary is never a target.
        docker.build_initial("controller","linux/arm64")
        docker.build_initial("neurolink","linux/amd64")
        docker.compose("up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "120", timeout=1200)
    result = evidence(docker)
    result.update(prepared)
    result["registration_hint"] = {"managed_paths":[{"path":"vuln-service","kind":"code"}],
        "git_url":GIT_URL,"git_ref":GIT_COMMIT,"git_subdirectory":"",
        "target_components":["controller"],"component_roles":{"controller":"application","neurolink":"database"},
        "data_paths":{"controller:/data":"significant; preserve named volume", "neurolink:memory":"significant; do not recreate"}}
    return result


def seed_or_check(docker, credentials_file, *, seed=False, expected_marker="either"):
    controller = docker.container(); neurolink = docker.container("neurolink")
    host,port = endpoint(controller)
    new_data = False
    if credentials_file.exists():
        values = read_private_json(credentials_file)
        if values.get("project") != PROJECT:
            raise RuntimeError("Synthetic credentials belong to another project")
    elif seed:
        values = {"project":PROJECT,"username":"ctfm_"+secrets.token_hex(6),"password":secrets.token_urlsafe(24),
                  "thought":"CTFM_thought_"+secrets.token_hex(8),"ad":"CTFM_SQLITE_"+secrets.token_hex(16),
                  "concept":"CTFM_concept_"+secrets.token_hex(8),"solution":"CTFM_RAM_"+secrets.token_hex(16)}
        # Write only after both normal protocol stores succeed, so a partial
        # seed cannot be mistaken for a completed preservation baseline.
        with GameClient(host,port) as client:
            client.register(values); client.login(values)
            client.command("intrusivethought "+values["thought"]+":"+values["ad"],"Added successfully")
            internalized = client.command("internalize "+values["concept"]+"="+values["solution"])
            match = re.fullmatch(r"Internalized: ([0-9a-fA-F]+)",internalized)
            if not match:
                raise RuntimeError("Opaque neurolink normal protocol did not store the synthetic concept")
            values["concept_key"] = match[1]
        private_json(credentials_file, values)
        new_data = True
    else:
        raise RuntimeError("Missing seed credentials")
    with GameClient(host,port) as client:
        marker = BASELINE_MARKER.encode() in client.prompt
        if expected_marker != "either" and marker != (expected_marker == "present"):
            raise RuntimeError("Unexpected imported baseline TCP prompt marker")
        client.login(values)
        client.command("impulseintrusive "+values["thought"],"Found: "+values["ad"])
        client.command("eject "+values["concept_key"],"Ejected: "+values["concept"]+"="+values["solution"])
        for record in values.get("after_deploy_records",[]):
            client.command("impulseintrusive "+record["thought"],"Found: "+record["ad"])
            client.command("eject "+record["concept_key"],"Ejected: "+record["concept"]+"="+record["solution"])
    return {"project":PROJECT,"endpoint":f"tcp://{host}:{port}","data_created":new_data,
            "fresh_login_successful":True,"sqlite_thought_preserved":True,"neurolink_concept_preserved":True,
            "thought_sha256":hashlib.sha256(values["ad"].encode()).hexdigest(),
            "concept_sha256":hashlib.sha256(values["solution"].encode()).hexdigest(),
            "after_deploy_records_count":len(values.get("after_deploy_records",[])),
            "after_deploy_records_preserved":bool(values.get("after_deploy_records")),
            "after_deploy_record_hashes":[{"thought_sha256":hashlib.sha256(record["ad"].encode()).hexdigest(),
                "concept_sha256":hashlib.sha256(record["solution"].encode()).hexdigest()} for record in values.get("after_deploy_records",[])],
            "baseline_marker_present":marker,"container_id":controller["Id"],"image_id":controller["Image"],
            "started_at":controller["State"]["StartedAt"],"neurolink_container_id":neurolink["Id"],
            "neurolink_image_id":neurolink["Image"],"neurolink_started_at":neurolink["State"]["StartedAt"]}


def append_after_deploy(docker,credentials_file):
    """Write new game data under the Git release, then verify with a fresh login."""
    values=read_private_json(credentials_file)
    if values.get("project")!=PROJECT or values.get("after_deploy_records"):
        raise RuntimeError("Expected original owned seed without an existing post-Deploy record")
    before=evidence(docker)
    if before["baseline_marker_served"] or before["source"]["baseline_marker_on_disk"]:
        raise RuntimeError("Post-Deploy data must be created under the Git code, before Rollback")
    record={"thought":"CTFM_after_deploy_thought_"+secrets.token_hex(8),"ad":"CTFM_AFTER_SQLITE_"+secrets.token_hex(16),
            "concept":"CTFM_after_deploy_concept_"+secrets.token_hex(8),"solution":"CTFM_AFTER_RAM_"+secrets.token_hex(16)}
    host,port=endpoint(docker.container())
    with GameClient(host,port) as client:
        if BASELINE_MARKER.encode() in client.prompt:raise RuntimeError("Controller switched before normal post-Deploy write")
        client.login(values)
        client.command("intrusivethought "+record["thought"]+":"+record["ad"],"Added successfully")
        response=client.command("internalize "+record["concept"]+"="+record["solution"])
        match=re.fullmatch(r"Internalized: ([0-9a-fA-F]+)",response)
        if not match:raise RuntimeError("Post-Deploy RAM concept write failed")
        record["concept_key"]=match[1]
    values["after_deploy_records"]=[record]
    descriptor,temporary=tempfile.mkstemp(prefix=".sibir-neli234-user-",dir=credentials_file.parent)
    try:
        with os.fdopen(descriptor,"w") as output:
            json.dump(values,output,indent=2);output.write("\n");output.flush();os.fsync(output.fileno())
        # read_private_json above required an owned regular private file. The
        # replacement also has mode 0600 and never publishes credentials.
        os.replace(temporary,credentials_file)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    probe=seed_or_check(docker,credentials_file,expected_marker="absent")
    after=evidence(docker)
    for component in ("controller","neurolink"):
        for key in ("container_id","image_id","started_at"):
            if before["containers"][component][key]!=after["containers"][component][key]:
                raise RuntimeError("Runtime switched while creating post-Deploy data")
    if before["sqlite_volume"]["schema_sha256"]!=after["sqlite_volume"]["schema_sha256"]:
        raise RuntimeError("Schema changed during a normal post-Deploy data write")
    if after["sqlite_volume"]["thoughts_count"]!=before["sqlite_volume"]["thoughts_count"]+1:
        raise RuntimeError("Expected exactly one additional SQLite thought")
    return {"project":PROJECT,"method":"Normal authenticated TCP intrusivethought/internalize writes, then fresh login reads original and new records",
        "before":before,"after":after,"probe":probe,"created_under_git_release":True,"application_data_written_after_deploy":True,
        "dashboard_or_docker_service_operation_submitted":False,"credentials_included":False}


def evidence(docker):
    containers = {}
    volumes = []
    for component in ("controller","neurolink"):
        value = docker.container(component)
        containers[component] = {"container_id":value["Id"],"image_id":value["Image"],"started_at":value["State"]["StartedAt"],
            "status":value["State"]["Status"],"health":value["State"].get("Health",{}).get("Status"),
            "working_dir":value["Config"].get("WorkingDir"),"read_only_rootfs":value["HostConfig"].get("ReadonlyRootfs"),
            "mounts":[{key:mount.get(key) for key in ("Type","Name","Source","Destination","RW")} for mount in value.get("Mounts",[])],
            "writable_layer_diff":docker.run("diff",value["Id"]).splitlines()}
        image = json.loads(docker.run("image","inspect",value["Image"]))[0]
        containers[component]["platform"] = image["Os"]+"/"+image["Architecture"]
        for mount in value.get("Mounts",[]):
            if mount["Type"] == "volume":
                vol = json.loads(docker.run("volume","inspect",mount["Name"]))[0]
                volumes.append({"name":vol["Name"],"mountpoint":vol["Mountpoint"],"created_at":vol.get("CreatedAt"),
                                "driver":vol["Driver"],"labels":vol.get("Labels"),"component":component,"target":mount["Destination"]})
    source = json.loads(docker.helper(r'''
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])/'services/sibir-neli234'
if root.is_symlink() or not (root/'.ctfm-sibir-neli234.json').is_file():raise RuntimeError('Missing owned setup marker')
paths=('ctfm.runtime.yaml','vuln-service/controller/src/server.cpp','vuln-service/controller/Dockerfile','vuln-service/neurolink/Dockerfile','vuln-service/neurolink/neurolink')
files={}
for name in paths:
    path=root/name
    if path.is_symlink() or not path.is_file():raise RuntimeError('Unexpected source path')
    files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps({'files_sha256':files,'baseline_marker_on_disk':b'CTFM imported local baseline' in (root/'vuln-service/controller/src/server.cpp').read_bytes()}))
'''))
    controller = docker.container()
    host,port = endpoint(controller)
    with GameClient(host,port) as client:
        prompt_marker = BASELINE_MARKER.encode() in client.prompt
    # Only metadata and path names are public. No synthetic user credentials or
    # in-memory game payload are dumped from either component.
    audit = docker.run("exec",docker.container("neurolink")["Id"],"/bin/sh","-c",
        "find /app -maxdepth 2 -type f -printf '%P\\n'; printf '\\nFD_TARGETS\\n'; for f in /proc/1/fd/*; do readlink \"$f\"; done").splitlines()
    sqlite_volume = json.loads(docker.run("run","--rm","--network","none",
        "--mount",f"type=volume,source={PROJECT}_sqlite-data,target=/data,readonly",
        "python:3.11-slim","python3","-c",r'''
import hashlib,json,sqlite3
from pathlib import Path
path=Path('/data/messages.db')
if path.is_symlink() or not path.is_file():raise RuntimeError('Missing controller SQLite file in named volume')
connection=sqlite3.connect('file:/data/messages.db?mode=ro',uri=True)
try:
    schema=connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    print(json.dumps({'relative_filename':'messages.db','bytes':path.stat().st_size,
        'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'schema_sha256':hashlib.sha256(json.dumps(schema).encode()).hexdigest(),
        'integrity':connection.execute('PRAGMA quick_check').fetchone()[0],
        'users_count':connection.execute('SELECT COUNT(*) FROM Users').fetchone()[0],
        'thoughts_count':connection.execute('SELECT COUNT(*) FROM Thoughts').fetchone()[0]}))
finally:connection.close()
'''))
    return {"project":PROJECT,"project_directory":SERVICE_DIRECTORY,"endpoint":f"tcp://{host}:{port}",
            "git_url":GIT_URL,"git_commit":GIT_COMMIT,"git_subdirectory":"","containers":containers,"volumes":volumes,
            "source":source,"baseline_marker_served":prompt_marker,"neurolink_file_and_fd_audit":audit,"sqlite_volume":sqlite_volume,
            "data_preservation_scope":{"controller_sqlite":"durable named volume",
                "neurolink":"RAM state preserved by excluding this dependency from controller recreation",
                "neurolink_restart_durability_verified":False,"neurolink_recreation_allowed":False,
                "opaque_binary_source_available":False},
            "target_components":["controller"],"upstream_compose_used":False,
            "profile_differences":["Unchanged upstream Dockerfiles build both components; controller native arm64, opaque neurolink amd64 via emulation",
                "Controller working_dir=/data moves relative messages.db into a preserved named volume; executable/schema unchanged",
                "Controller root filesystem read-only with no tmpfs; only loopback random TCP port exposed",
                "Neurolink is a stateful dependency excluded from target recreation; in-memory data survives this controller cycle only",
                "Socket-listen healthchecks, resource bounds, bounded logs and healthy dependency ordering are frozen in local Compose",
                "Imported baseline adds a visible TCP menu marker in controller source; exact Git candidate removes it"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("prepare","setup","adapt-profile","seed","append-after-deploy","check","evidence"))
    parser.add_argument("--before-registration",action="store_true",help="Acknowledge preparation-only profile adaptation; executor database is also checked")
    parser.add_argument("--credentials-file",type=Path,default=LOCAL/"sibir-neli234-user.json")
    parser.add_argument("--expect-marker",choices=("present","absent","either"),default="either")
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    if args.action == "adapt-profile" and not args.before_registration:
        parser.error("adapt-profile requires --before-registration")
    docker = Docker()
    if args.action in ("prepare","setup"):
        result=setup(docker,prepare_only=args.action=="prepare")
    elif args.action == "adapt-profile":
        result=adapt_profile(docker)
    elif args.action == "append-after-deploy":
        result=append_after_deploy(docker,args.credentials_file)
    elif args.action in ("seed","check"):
        result=seed_or_check(docker,args.credentials_file,seed=args.action=="seed",expected_marker=args.expect_marker)
    else:
        result=evidence(docker)
    result.update(action=args.action,recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                  helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    encoded=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(encoded)
    print(encoded,end="")


if __name__ == "__main__":
    main()
