#!/usr/bin/env python3
"""Bootstrap real CyberBank; panel owns registration and all release operations.

The frozen local profile isolates PostgreSQL and generated product PNGs in named
volumes. Both application images use the upstream Dockerfiles unchanged. A
visible baseline-only HTML marker proves the exact Git source was deployed.
"""
import argparse
import hashlib
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
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "var/preview"
DAEMON = "/srv/ctf-manager-preview"
PROJECT = "ctfm-preview-sibir-bank"
SERVICE_DIRECTORY = DAEMON + "/services/sibir-bank"
COMPOSE_FILE = SERVICE_DIRECTORY + "/ctfm.runtime.yaml"
CONFIG_DIRECTORY = SERVICE_DIRECTORY + "/secrets"
GIT_URL = "https://github.com/SibirCTF/2025-cybersibir-service-bank.git"
GIT_COMMIT = "4a7d4eafb2e8030aa230316e3f191908a2b0437a"
BASELINE_MARKER = '<p id="ctfm-baseline-marker">CTFM imported local baseline</p>'
COMPONENTS = ("cyber-bank-postgres", "cyber-bank-api", "cyber-bank-front")


def command(arguments, timeout=180):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
    result = subprocess.run(arguments, capture_output=True, text=True, env=environment, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{Path(arguments[0]).name} failed: {(result.stderr + result.stdout)[-5000:]}")
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
        raise RuntimeError("Private regular file mode 0600 required")
    return json.loads(filename.read_text())


class Docker:
    def __init__(self):
        self.binary = shutil.which("docker")
        if not self.binary:
            raise RuntimeError("Docker required")
        endpoint = os.environ.get("DOCKER_HOST") or json.loads(self.run("context", "inspect"))[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix:///"):
            raise RuntimeError("Local Unix Docker daemon required")
        self.socket = endpoint.removeprefix("unix://")

    def run(self, *arguments, timeout=180):
        return command([self.binary, *arguments], timeout=timeout)

    def helper(self, code, *arguments, writable=False):
        mount = f"type=bind,source={DAEMON},target={DAEMON}" + ("" if writable else ",readonly")
        return self.run("run", "--rm", "--network", "none", "--mount", mount,
                        "--mount", f"type=bind,source={ROOT},target={ROOT},readonly",
                        "python:3.11-slim", "python3", "-c", code, DAEMON, str(ROOT), *map(str, arguments))

    def compose(self, *arguments, timeout=1200):
        return self.run("run", "--rm", "--network", "bridge",
                        "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                        "--mount", f"type=bind,source={self.socket},target=/var/run/docker.sock",
                        "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                        "compose", "--parallel", "1", "--project-name", PROJECT,
                        "--project-directory", SERVICE_DIRECTORY, "--file", COMPOSE_FILE,
                        *arguments, timeout=timeout)

    def containers(self, partial=False):
        result = {}
        for component in COMPONENTS:
            ids = self.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT,
                           "--filter", "label=com.docker.compose.service=" + component).splitlines()
            if not ids and partial:
                continue
            if len(ids) != 1:
                raise RuntimeError("Expected one owned container: " + component)
            value = json.loads(self.run("inspect", ids[0]))[0]
            labels = value["Config"].get("Labels", {})
            if labels.get("com.docker.compose.project.working_dir") != SERVICE_DIRECTORY:
                raise RuntimeError("Project belongs to another directory")
            conf = labels.get("com.docker.compose.project.config_files", "")
            if conf != COMPOSE_FILE and not re.fullmatch(re.escape(DAEMON) + r"/executor/compose-operation-[0-9]+/compose\.json", conf):
                raise RuntimeError("Unexpected Compose configuration")
            result[component] = value
        return result


def game_url(containers):
    ports = containers["cyber-bank-front"]["NetworkSettings"].get("Ports", {}).get("1337/tcp") or []
    if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("Expected one loopback-only front port")
    return "http://127.0.0.1:" + ports[0]["HostPort"]


SETUP = r'''
import json,os,secrets,shutil,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);project,commit,baseline_marker=sys.argv[3:6]
preview=root/'.ctfm-preview.json'
if preview.is_symlink() or not preview.is_file() or json.loads(preview.read_text())!={'purpose':'ctf-manager persistent local preview','repository':str(repo)}:
    raise RuntimeError('Native root ownership mismatch')
game=root/'services/sibir-bank';config=game/'secrets'
marker=game/'.ctfm-sibir-bank.json'
expected={'purpose':'persistent real SibirCTF CyberBank cycle','repository':str(repo),'project':project,'git_commit':commit}
fresh=not game.exists()
partial=game.exists() and not (game/'ctfm.runtime.yaml').exists()
if partial:
    if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:raise RuntimeError('Partial project ownership mismatch')
    db=root/'executor/executor.db'
    connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
    try:
        for row in connection.execute('SELECT payload FROM services'):
            service=json.loads(row[0])
            if service.get('project_directory')==str(game) or service.get('compose_project')==project:raise RuntimeError('Registered service cannot be reinitialized')
    finally:connection.close()
if fresh or partial:
    if fresh and config.exists():raise RuntimeError('Unexpected existing sibling config')
    game.mkdir(mode=0o755,exist_ok=partial);config.mkdir(mode=0o755,exist_ok=partial)
    def write(path,data,mode):
        if path.exists():
            if path.is_symlink() or path.read_text()!=data:raise RuntimeError('Unexpected partial setup file: '+str(path))
            return
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'w') as stream:stream.write(data)
    write(marker,json.dumps(expected),0o600)
    write(config/'.ctfm-runtime-config.json',json.dumps({'purpose':'frozen CyberBank runtime settings','project':project,'service_directory':str(game)}),0o600)
    if not (game/'vuln-service').exists():shutil.copytree(repo/'tests/fixtures/vendor/2025-cybersibir-service-bank/vuln-service',game/'vuln-service',ignore=shutil.ignore_patterns('.git','node_modules','build','__pycache__','*.pyc'))
    page=game/'vuln-service/front/public/index.html';original=page.read_text()
    if original.count('  <body>\n')!=1 or 'ctfm-baseline-marker' in original:raise RuntimeError('Unexpected upstream HTML')
    page.write_text(original.replace('  <body>\n','  <body>\n    '+baseline_marker+'\n'))
    env='DB_NAME=ctfm_bank\nDB_USER=ctfm_bank\nDB_PASS='+secrets.token_hex(24)+'\nSESSION_SECRET='+secrets.token_hex(32)+'\nDEBUG=false\nREACT_HOST=http://127.0.0.1\n'
    write(config/'api.env',env,0o600)
    postgres_env='POSTGRES_DB=ctfm_bank\nPOSTGRES_USER=ctfm_bank\nPOSTGRES_PASSWORD='+next(line.split('=',1)[1] for line in env.splitlines() if line.startswith('DB_PASS='))+'\n'
    write(config/'postgres.env',postgres_env,0o600)
    logging={'driver':'json-file','options':{'max-size':'20m','max-file':'5'}}
    def limits(memory,pids):return {'restart':'unless-stopped','mem_limit':memory,'cpus':1.0,'pids_limit':pids,'shm_size':'64m','logging':logging}
    profile={'services':{
      'cyber-bank-postgres':{**limits('384m',128),'image':'postgres:17-alpine','env_file':[str(config/'postgres.env')],
        'volumes':[{'type':'volume','source':'postgres-data','target':'/var/lib/postgresql/data'}],
        'healthcheck':{'test':['CMD-SHELL','pg_isready -U ctfm_bank -d ctfm_bank'],'interval':'2s','timeout':'3s','retries':60}},
      'cyber-bank-api':{**limits('768m',256),'build':{'context':'./vuln-service/cyberBank'},'image':project+'-api:baseline',
        'command':['bash','./run.sh'],'env_file':[str(config/'api.env')],
        'volumes':[{'type':'volume','source':'generated-images','target':'/app/build/static/images'}],
        'depends_on':{'cyber-bank-postgres':{'condition':'service_healthy'}},
        'healthcheck':{'test':['CMD','node','-e',"fetch('http://127.0.0.1:37773/products').then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"],
                       'interval':'3s','timeout':'4s','retries':60,'start_period':'45s'}},
      'cyber-bank-front':{**limits('128m',128),'build':{'context':'./vuln-service/front'},'image':project+'-front:baseline',
        'environment':{'EXPRESS_HOST':'cyber-bank-api'},'depends_on':{'cyber-bank-api':{'condition':'service_healthy'}},
        'ports':[{'target':1337,'host_ip':'127.0.0.1','protocol':'tcp'}],
        'healthcheck':{'test':['CMD','wget','-q','-O','/dev/null','http://127.0.0.1:1337/'],'interval':'3s','timeout':'3s','retries':30}}
    },'volumes':{'postgres-data':{},'generated-images':{}}}
    write(game/'ctfm.runtime.yaml',json.dumps(profile,indent=2)+'\n',0o644)
else:
    if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:raise RuntimeError('Existing project ownership mismatch')
    if not (game/'ctfm.runtime.yaml').is_file() or not (config/'api.env').is_file() or not (config/'postgres.env').is_file():raise RuntimeError('Incomplete owned profile')
print(json.dumps({'fresh':fresh,'project_directory':str(game),'compose_file':str(game/'ctfm.runtime.yaml'),'runtime_config_directory':str(config)}))
'''


def setup(docker, prepare_only=False):
    existing = docker.containers(partial=True)
    prepared = json.loads(docker.helper(SETUP, PROJECT, GIT_COMMIT, BASELINE_MARKER, writable=True))
    if existing and prepared["fresh"]:
        raise RuntimeError("Existing project was not previously owned")
    for suffix in ("postgres-data", "generated-images"):
        name = PROJECT + "_" + suffix
        if docker.run("volume", "ls", "--quiet", "--filter", "name=^" + name + "$").strip():
            volume = json.loads(docker.run("volume", "inspect", name))[0]
            if volume.get("Labels", {}).get("com.docker.compose.project") != PROJECT:
                raise RuntimeError("Volume owned by another project: " + name)
    if prepare_only:
        return prepared
    # Reruns never rebuild or recreate any already complete application project.
    if len(existing) != len(COMPONENTS):
        docker.compose("up", "-d", "--build", "--wait", "--wait-timeout", "240")
    result = evidence(docker)
    result.update(prepared)
    result["registration_hint"] = {
        "managed_paths": [{"path": "vuln-service", "kind": "code"}],
        "git_url": GIT_URL, "git_ref": GIT_COMMIT, "git_subdirectory": "",
        "application_components": ["cyber-bank-api", "cyber-bank-front"],
        "data_components": ["cyber-bank-postgres"], "writable_layer_loss_accepted": True,
        "preserve_named_volumes": [PROJECT + "_postgres-data", PROJECT + "_generated-images"]}
    return result


class GameClient:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, value=None):
        headers = {}
        if value is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=None if value is None else json.dumps(value).encode(), headers=headers)
        with self.opener.open(req, timeout=30) as response:
            data = response.read()
            try:
                return json.loads(data)
            except (ValueError, UnicodeDecodeError):
                return data


def seed_or_check(docker, credentials_file, seed=False, expected_marker="either"):
    containers = docker.containers()
    client = GameClient(game_url(containers))
    created = False
    if credentials_file.exists():
        identity = read_private_json(credentials_file)
        if identity.get("project") != PROJECT:
            raise RuntimeError("Credentials belong to another project")
    elif seed:
        identity = {"project": PROJECT, "username": "ctfm_" + secrets.token_hex(6),
                    "password": secrets.token_urlsafe(24), "content": "CTFM_FLAG_" + secrets.token_hex(16),
                    "description": "CTFM preservation " + secrets.token_hex(6), "comment": "CTFM comment " + secrets.token_hex(6)}
        private_json(credentials_file, identity)
        created = True
    else:
        raise RuntimeError("Seed credentials missing")
    if created:
        client.request("/api/register", {"username": identity["username"], "password": identity["password"]})
    client.request("/api/login", {"username": identity["username"], "password": identity["password"]})
    user = client.request("/api/user")
    if user.get("name") != identity["username"]:
        raise RuntimeError("Fresh CyberBank login did not reach expected user")
    products = client.request("/api/products")
    owned = [p for p in products if p.get("description") == identity["description"]]
    if not owned and seed:
        product = client.request("/api/products/create", {"description": identity["description"], "content": identity["content"], "price": 17})
        client.request(f"/api/products/{product['id']}/comment", {"content": identity["comment"]})
        owned = [client.request(f"/api/products/{product['id']}")]
    if len(owned) != 1:
        raise RuntimeError("Synthetic product missing or duplicated")
    product = client.request(f"/api/products/{owned[0]['id']}")
    if product.get("content") != identity["content"] or product.get("price") != 17:
        raise RuntimeError("Synthetic product data was not preserved")
    if not any(comment.get("content") == identity["comment"] for comment in product.get("comments", [])):
        raise RuntimeError("Synthetic comment was not preserved")
    image = client.request("/api/public/images/" + product["image_path"])
    if not isinstance(image, bytes) or not image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("Generated PNG cannot be read")
    image_hash = hashlib.sha256(image).hexdigest()
    pin = credentials_file.with_name("sibir-bank-data-pin.json")
    value = {"project": PROJECT, "product_id": product["id"], "user_id": user["id"], "image_path": product["image_path"], "image_sha256": image_hash}
    if pin.exists():
        if read_private_json(pin) != value:
            raise RuntimeError("Persistent product/image identity changed")
    elif seed:
        private_json(pin, value)
    else:
        raise RuntimeError("Data identity pin missing")
    page = client.request("/")
    marker = b"ctfm-baseline-marker" in page
    if expected_marker != "either" and marker != (expected_marker == "present"):
        raise RuntimeError("Unexpected baseline HTML marker state")
    return {"project": PROJECT, "url": client.base, "user_created": created, "fresh_login_successful": True,
            "product_preserved": True, "comment_preserved": True, "generated_png_preserved": True,
            "product_id": product["id"], "user_id": user["id"], "image_path": product["image_path"], "image_sha256": image_hash,
            "content_sha256": hashlib.sha256(identity["content"].encode()).hexdigest(),
            "comment_sha256": hashlib.sha256(identity["comment"].encode()).hexdigest(),
            "baseline_marker_present": marker, "index_sha256": hashlib.sha256(page).hexdigest()}


def evidence(docker):
    containers = docker.containers()
    public = {}
    volumes = {}
    for name, container in containers.items():
        public[name] = {"container_id": container["Id"], "image_id": container["Image"], "started_at": container["State"]["StartedAt"],
                        "status": container["State"]["Status"], "health": container["State"].get("Health", {}).get("Status"),
                        "mounts": [{k: mount.get(k) for k in ("Type", "Name", "Source", "Destination", "RW")} for mount in container.get("Mounts", [])]}
        for mount in container.get("Mounts", []):
            if mount["Type"] == "volume":
                value = json.loads(docker.run("volume", "inspect", mount["Name"]))[0]
                volumes[mount["Name"]] = {k: value.get(k) for k in ("Name", "Mountpoint", "CreatedAt", "Driver", "Labels")}
    tree = json.loads(docker.helper(r'''
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])/'services/sibir-bank'; config=root/'secrets'
if not (root/'.ctfm-sibir-bank.json').is_file():raise RuntimeError('Missing owner marker')
names=['ctfm.runtime.yaml','vuln-service/front/public/index.html','vuln-service/cyberBank/Dockerfile','vuln-service/front/Dockerfile']
files={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}
for name in ('api.env','postgres.env'):files[str(config/name)]=hashlib.sha256((config/name).read_bytes()).hexdigest()
print(json.dumps({'files_sha256':files,'baseline_marker_on_disk':b'ctfm-baseline-marker' in (root/'vuln-service/front/public/index.html').read_bytes()}))
'''))
    url = game_url(containers)
    with urllib.request.urlopen(url + "/", timeout=15) as response:
        page = response.read()
        status = response.status
    return {"project": PROJECT, "project_directory": SERVICE_DIRECTORY, "url": url,
            "git_url": GIT_URL, "git_commit": GIT_COMMIT, "git_subdirectory": "",
            "containers": public, "volumes": list(volumes.values()), "source": tree,
            "http_status": status, "baseline_marker_served": b"ctfm-baseline-marker" in page,
            "index_sha256": hashlib.sha256(page).hexdigest(), "upstream_compose_used": False,
            "profile_differences": ["Both unchanged upstream application Dockerfiles build actual API and React/nginx sources",
                "PostgreSQL is pinned to 17-alpine and kept in its own named data volume; DB is not a release target",
                "Generated product images alone use a dedicated named volume at /app/build/static/images",
                "Compiled code, dependencies and application source remain image/layer content; no active source binds",
                "Runtime secrets use frozen project-local env files in excluded secrets/ outside the managed Git tree",
                "Frontend HTTP is random loopback-only; database and API publish no host ports; runtime resources/logs bounded",
                "Imported local baseline adds a visible HTML marker, removed by the exact pinned Git source"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "setup", "seed", "check", "evidence"))
    parser.add_argument("--credentials-file", type=Path, default=LOCAL / "sibir-bank-user.json")
    parser.add_argument("--expect-marker", choices=("present", "absent", "either"), default="either")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    docker = Docker()
    if args.action in ("prepare", "setup"):
        result = setup(docker, prepare_only=args.action == "prepare")
    elif args.action in ("seed", "check"):
        result = seed_or_check(docker, args.credentials_file, seed=args.action == "seed", expected_marker=args.expect_marker)
    else:
        result = evidence(docker)
    result.update(action=args.action, recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
