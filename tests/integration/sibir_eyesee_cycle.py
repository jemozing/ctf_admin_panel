#!/usr/bin/env python3
"""Prepare/probe a real EyeSee instance; all panel mutations are browser-only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "var/preview"
DAEMON = "/srv/ctf-manager-preview"
PROJECT = "ctfm-preview-sibir-eyesee"
DIRECTORY = DAEMON + "/services/sibir-eyesee"
COMPOSE = DIRECTORY + "/ctfm.runtime.yaml"
REPOSITORY = "https://github.com/SibirCTF/2025-cybersibir-service-eyesee.git"
COMMIT = "2eda1b05fe6e025c3f1bec25f762f3ad01d6a74c"
VENDOR = ROOT / "tests/fixtures/vendor/2025-cybersibir-service-eyesee"
LABEL = "org.ctfm.imported-baseline"


class Docker:
    def __init__(self):
        self.binary = shutil.which("docker")
        endpoint = os.environ.get("DOCKER_HOST") or json.loads(self.run("context", "inspect"))[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix:///"):
            raise RuntimeError("Local Unix daemon required")
        self.socket = endpoint.removeprefix("unix://")

    def run(self, *args, timeout=180):
        env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
        result = subprocess.run([self.binary, *args], capture_output=True, text=True, env=env, timeout=timeout)
        if result.returncode:
            raise RuntimeError((result.stderr + result.stdout)[-6000:])
        return result.stdout

    def helper(self, code, *args, writable=False):
        return self.run("run", "--rm", "--network", "none", "--mount", f"type=bind,source={DAEMON},target={DAEMON}" + ("" if writable else ",readonly"),
                        "--mount", f"type=bind,source={ROOT},target={ROOT},readonly", "python:3.11-slim", "python3", "-c", code, DAEMON, str(ROOT), *map(str, args))

    def compose(self, *args):
        return self.run("run", "--rm", "--network", "bridge", "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                        "--mount", f"type=bind,source={self.socket},target=/var/run/docker.sock", "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                        "compose", "--project-name", PROJECT, "--project-directory", DIRECTORY, "--file", COMPOSE, *args, timeout=900)

    def containers(self):
        ids = self.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT).splitlines()
        if len(ids) != 2:
            raise RuntimeError("Expected exactly two owned EyeSee containers")
        values = json.loads(self.run("inspect", *ids))
        components = {}
        for v in values:
            labels = v["Config"].get("Labels", {})
            config = labels.get("com.docker.compose.project.config_files", "")
            if labels.get("com.docker.compose.project.working_dir") != DIRECTORY or not (config == COMPOSE or re.fullmatch(re.escape(DAEMON) + r"/executor/compose-operation-[0-9]+/compose.json", config)):
                raise RuntimeError("Unexpected EyeSee ownership/configuration labels")
            components[labels["com.docker.compose.service"]] = v
        if set(components) != {"eyesee-service", "eyesee-storage"}:
            raise RuntimeError("Unexpected EyeSee component set")
        return components


PREPARE = r'''
import json,os,shutil,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]); project,commit=sys.argv[3:5]
preview=root/'.ctfm-preview.json'
if preview.is_symlink() or json.loads(preview.read_text())!={'purpose':'ctf-manager persistent local preview','repository':str(repo)}:
    raise RuntimeError('Not this repository native preview')
game=root/'services/sibir-eyesee';marker=game/'.ctfm-sibir-eyesee.json'
expected={'purpose':'persistent real SibirCTF EyeSee cycle','repository':str(repo),'project':project,'commit':commit}
fresh=not game.exists()
if fresh:
    game.mkdir(mode=0o755)
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(expected,f)
    shutil.copytree(repo/'tests/fixtures/vendor/2025-cybersibir-service-eyesee/vuln-service',game/'vuln-service')
    dockerfile=game/'vuln-service/Dockerfile'
    dockerfile.write_text(dockerfile.read_text()+'\nLABEL org.ctfm.imported-baseline="EyeSee local baseline"\n')
    common={'restart':'unless-stopped','shm_size':'64m','pids_limit':128,'logging':{'driver':'json-file','options':{'max-size':'20m','max-file':'3'}}}
    storage={**common,'image':'ctfm-preview-sibir-eyesee-minio:source-8c2c92f7',
      'environment':{'MINIO_ROOT_USER':'ADMIN','MINIO_ROOT_PASSWORD':'PASSWORD','MINIO_BROWSER':'off'},
      'command':['server','/data','--console-address',':9001'],'volumes':[{'type':'volume','source':'minio-data','target':'/data'}],
      'mem_limit':'512m','cpus':0.5,
      'healthcheck':{'test':['CMD','python3','-c','import urllib.request;urllib.request.urlopen("http://localhost:9000/minio/health/live",timeout=2).read()'],'interval':'2s','timeout':'3s','retries':30,'start_period':'5s'}}
    app={**common,'image':project+':baseline','build':{'context':'./vuln-service'},'read_only':True,
      'ports':[{'target':25910,'host_ip':'127.0.0.1','protocol':'tcp'}],'mem_limit':'256m','cpus':0.5,
      'depends_on':{'eyesee-storage':{'condition':'service_healthy'}}}
    profile={'services':{'eyesee-storage':storage,'eyesee-service':app},'volumes':{'minio-data':{}}}
    (game/'ctfm.runtime.yaml').write_text(json.dumps(profile,indent=2)+'\n')
else:
    if game.is_symlink() or marker.is_symlink() or json.loads(marker.read_text())!=expected:
        raise RuntimeError('Existing EyeSee directory not owned')
# One-time recovery from unavailable historical registry images, before register.
profile_path=game/'ctfm.runtime.yaml';profile=json.loads(profile_path.read_text())
if profile['services']['eyesee-storage']['image'].startswith('quay.io/'):
    db=root/'executor/executor.db'
    with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True) as connection:
        if any(json.loads(row[0]).get('compose_project')==project for row in connection.execute('SELECT payload FROM services')):
            raise RuntimeError('Cannot change registered runtime profile')
    storage=profile['services']['eyesee-storage']
    storage['image']='ctfm-preview-sibir-eyesee-minio:source-8c2c92f7'
    storage['healthcheck']['test']=['CMD','python3','-c','import urllib.request;urllib.request.urlopen("http://localhost:9000/minio/health/live",timeout=2).read()']
    for service in profile['services'].values():service['shm_size']='64m'
    profile_path.write_text(json.dumps(profile,indent=2)+'\n')
binary=repo/'var/preview/eyesee-minio-binary'
if not binary.is_file():raise RuntimeError('Build pinned MinIO source binary first')
build=root/'services/sibir-eyesee-storage-build';build.mkdir(exist_ok=True)
shutil.copy2(binary,build/'minio');(build/'minio').chmod(0o755)
(build/'Dockerfile').write_text('FROM python:3.11-slim\nCOPY --chmod=0755 minio /usr/local/bin/minio\nENTRYPOINT ["/usr/local/bin/minio"]\n')
print(json.dumps({'fresh':fresh,'project_directory':str(game),'compose_file':str(game/'ctfm.runtime.yaml')}))
'''


def endpoint(containers):
    ports = containers["eyesee-service"]["NetworkSettings"]["Ports"].get("25910/tcp") or []
    if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("EyeSee gRPC must be loopback only")
    return "127.0.0.1:" + ports[0]["HostPort"]


def messages():
    # Only protoc-generated message types are imported, not the organizer checker.
    spec = importlib.util.spec_from_file_location("ctfm_eyesee_messages", VENDOR / "checker_eyesee/proto/service_pb2.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rpc_call(address, method, request, response_type):
    import grpc
    with grpc.insecure_channel(address) as channel:
        call = channel.unary_unary("/service.proto.EyeSeeService/" + method,
                                  request_serializer=type(request).SerializeToString, response_deserializer=response_type.FromString)
        return call(request, timeout=15)


def probe(docker, seed=False):
    containers = docker.containers()
    address = endpoint(containers)
    pb = messages()
    health = rpc_call(address, "ServiceHealthCheck", pb.ServiceHealthCheckRequest(), pb.ServiceHealthCheckResponse)
    if health.status != "OK":
        raise RuntimeError("EyeSee gRPC health failed")
    filename = LOCAL / "sibir-eyesee-prescription.json"
    created = False
    if filename.exists():
        st = filename.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise RuntimeError("Private regular 0600 probe file required")
        record = json.loads(filename.read_text())
        if record["project"] != PROJECT:
            raise RuntimeError("Wrong prescription project")
    elif seed:
        record = {"project": PROJECT, "patient_id": str(uuid.uuid4()), "patient_name": "CTFM preservation " + uuid.uuid4().hex,
                  "doctor_name": "Synthetic doctor", "modifications": ["CTFM immutable prescription"], "features": [uuid.uuid4().hex]}
        request = pb.AddPrescriptionRequest(**{k: record[k] for k in ("patient_id", "patient_name", "doctor_name", "modifications", "features")}, od_spf=1.5, od_cyl=0.5, od_ax=90, os_spf=1.5, os_cyl=0.5, os_ax=90)
        added = rpc_call(address, "AddPrescription", request, pb.AddPrescriptionResponse)
        record["id"] = added.id
        uuid.UUID(record["id"])
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(record, f)
        created = True
    else:
        raise RuntimeError("Seed prescription missing")
    result = rpc_call(address, "CheckPrescription", pb.CheckPrescriptionRequest(id=record["id"]), pb.CheckPrescriptionResponse)
    for key in ("patient_id", "patient_name", "doctor_name", "modifications", "features"):
        actual = getattr(result, key)
        if key in ("features", "modifications"):
            actual = list(actual)
        if actual != record[key]:
            raise RuntimeError("Prescription data was not preserved: " + key)
    ids = rpc_call(address, "GetPrescriptionIDs", pb.GetPrescriptionIDsRequest(patient_id=record["patient_id"]), pb.GetPrescriptionIDsResponse)
    if record["id"] not in ids.ids:
        raise RuntimeError("Prescription relation missing")
    return {"project": PROJECT, "grpc_endpoint": address, "service_health": health.status, "prescription_created": created,
            "prescription_id": record["id"], "prescription_sha256": hashlib.sha256(result.SerializeToString(deterministic=True)).hexdigest(),
            "prescription_preserved": True, "relation_preserved": True}


def evidence(docker):
    containers = docker.containers()
    values = {}
    volumes = []
    for name, c in containers.items():
        values[name] = {"id": c["Id"], "image_id": c["Image"], "started_at": c["State"]["StartedAt"], "state": c["State"]["Status"],
                       "health": c["State"].get("Health", {}).get("Status"), "baseline_label": c["Config"].get("Labels", {}).get(LABEL),
                       "mounts": [{k: m.get(k) for k in ("Type", "Name", "Source", "Destination", "RW")} for m in c.get("Mounts", [])]}
        for m in c.get("Mounts", []):
            if m["Type"] == "volume":
                v = json.loads(docker.run("volume", "inspect", m["Name"]))[0]
                volumes.append({"name": v["Name"], "mountpoint": v["Mountpoint"], "created_at": v.get("CreatedAt"), "target": m["Destination"], "component": name})
    tree = json.loads(docker.helper(r'''
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1])/'services/sibir-eyesee'
if not (p/'.ctfm-sibir-eyesee.json').is_file():raise RuntimeError('No ownership marker')
files={name:hashlib.sha256((p/name).read_bytes()).hexdigest() for name in ('ctfm.runtime.yaml','vuln-service/Dockerfile','vuln-service/eyesee')}
print(json.dumps({'files_sha256':files,'baseline_marker_on_disk':b'org.ctfm.imported-baseline' in (p/'vuln-service/Dockerfile').read_bytes()}))
'''))
    return {"project": PROJECT, "project_directory": DIRECTORY, "git_url": REPOSITORY, "git_commit": COMMIT,
            "grpc_endpoint": endpoint(containers), "containers": values, "volumes": volumes, "source": tree,
            "profile_differences": ["Explicit named MinIO volume; storage excluded from targets", "Loopback random gRPC port and resource/log limits", "Upstream amd64 production Dockerfile packages supplied binary under emulation; no EyeSee Go source rebuild claimed", "Imported baseline adds Docker image LABEL only; exact Git removes it", "Historical MinIO images denied access and binary archive returned410; local Linux/arm64 binary built from official RELEASE.2025-02-28T09-55-16Z source commit8c2c92f7afdc8386b000c0cb57ecec2ee1f5bcb0, packaged on python3.11-slim"]}


def setup(docker):
    actual = subprocess.run(["git", "-C", str(VENDOR), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if actual != COMMIT:
        raise RuntimeError("Unexpected pinned vendor SHA")
    existing = docker.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT).splitlines()
    if existing:
        docker.containers()
    preparation = json.loads(docker.helper(PREPARE, PROJECT, COMMIT, writable=True))
    if preparation["fresh"] and existing:
        raise RuntimeError("Unowned existing containers")
    if not existing:
        volume = PROJECT + "_minio-data"
        names = docker.run("volume", "ls", "--quiet", "--filter", "name=^" + volume + "$").splitlines()
        if names:
            v = json.loads(docker.run("volume", "inspect", volume))[0]
            if v.get("Labels", {}).get("com.docker.compose.project") != PROJECT:
                raise RuntimeError("Unowned MinIO volume")
        docker.run("run", "--rm", "--network", "bridge", "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                   "--mount", f"type=bind,source={docker.socket},target=/var/run/docker.sock", "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                   "build", "--tag", "ctfm-preview-sibir-eyesee-minio:source-8c2c92f7", DAEMON + "/services/sibir-eyesee-storage-build", timeout=300)
        docker.compose("up", "--detach", "--build", "--wait", "--wait-timeout", "120")
    # Startup RPC also waits for emulated app and MinIO buckets to be ready.
    pb = messages()
    for attempt in range(45):
        try:
            c = docker.containers()
            if rpc_call(endpoint(c), "ServiceHealthCheck", pb.ServiceHealthCheckRequest(), pb.ServiceHealthCheckResponse).status == "OK":
                break
        except Exception:
            if attempt == 44:
                raise
            time.sleep(1)
    return {**evidence(docker), "preparation": preparation,
            "registration_hint": {"managed_paths": ["vuln-service"], "targets": ["eyesee-service"], "data_component": "eyesee-storage", "named_volume_significant": True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "seed", "check", "evidence"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    docker = Docker()
    result = setup(docker) if args.action == "setup" else probe(docker, args.action == "seed") if args.action in ("seed", "check") else evidence(docker)
    result.update(action=args.action, recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
