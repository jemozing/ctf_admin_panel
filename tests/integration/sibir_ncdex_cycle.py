#!/usr/bin/env python3
"""Owned real ncdex runtime and legitimate HTTP data probes; panel mutations stay in UI.

The exact upstream Dockerfile builds the real Crystal application. A separate,
frozen local Compose profile corrects its otherwise unusable localhost DSN,
persists PostgreSQL, and replaces the upstream 16 GiB database tuning with
bounded local settings. Only the imported baseline contains an HTML marker.
"""

import argparse
import hashlib
import html
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

from sibir_bioguard_cycle import Docker as BaseDocker, private_json, read_private_json

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "var/preview"
DAEMON = "/srv/ctf-manager-preview"
PROJECT = "ctfm-preview-sibir-ncdex"
SERVICE_DIRECTORY = DAEMON + "/services/sibir-ncdex"
CONFIG_DIRECTORY = DAEMON + "/services/sibir-ncdex-runtime-config"
COMPOSE_FILE = SERVICE_DIRECTORY + "/ctfm.runtime.yaml"
GIT_URL = "https://github.com/SibirCTF/2025-cybersibir-service-ncdex.git"
GIT_COMMIT = "435b7108d3b8c2693467a9e4be8a5c71b0936d64"
BASELINE_MARKER = '<p id="ctfm-baseline-marker">CTFM imported local baseline</p>'


class Docker(BaseDocker):
    def compose(self, *arguments, timeout=1500):
        return self.run("run", "--rm", "--network", "bridge",
                        "--mount", f"type=bind,source={DAEMON},target={DAEMON}",
                        "--mount", f"type=bind,source={self.socket},target=/var/run/docker.sock",
                        "--entrypoint", "/usr/local/bin/docker", "ctf-manager-executor:local",
                        "compose", "--project-name", PROJECT, "--project-directory", SERVICE_DIRECTORY,
                        "--file", COMPOSE_FILE, *arguments, timeout=timeout)

    def container(self, component="app"):
        identifiers = self.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT,
                               "--filter", "label=com.docker.compose.service=" + component).splitlines()
        if len(identifiers) != 1:
            raise RuntimeError("Expected exactly one owned ncdex " + component + " container")
        value = json.loads(self.run("inspect", identifiers[0]))[0]
        labels = value["Config"].get("Labels", {})
        if labels.get("com.docker.compose.project.working_dir") != SERVICE_DIRECTORY:
            raise RuntimeError("Compose project belongs to a different directory")
        configuration = labels.get("com.docker.compose.project.config_files", "")
        frozen = re.fullmatch(re.escape(DAEMON) + r"/executor/compose-operation-[0-9]+/compose\.json", configuration)
        if configuration != COMPOSE_FILE and not frozen:
            raise RuntimeError("Unexpected Compose configuration files")
        return value


def game_url(container):
    bindings = container["NetworkSettings"].get("Ports", {}).get("7331/tcp") or []
    if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("ncdex must have exactly one loopback-only HTTP binding")
    return "http://127.0.0.1:" + bindings[0]["HostPort"]


SETUP = r'''
import hashlib,json,os,secrets,shutil,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);project,commit,baseline_marker=sys.argv[3:6]
preview=root/'.ctfm-preview.json'
if preview.is_symlink() or not preview.is_file() or json.loads(preview.read_text())!={'purpose':'ctf-manager persistent local preview','repository':str(repo)}:
    raise RuntimeError('Native root is not this repository preview')
game=root/'services/sibir-ncdex'; marker=game/'.ctfm-sibir-ncdex.json'
external=root/'services/sibir-ncdex-runtime-config'
expected={'purpose':'persistent real SibirCTF ncdex cycle','repository':str(repo),'project':project,'git_commit':commit}
fresh=not game.exists()
if fresh:
    if external.exists():raise RuntimeError('Unowned runtime config directory already exists')
    game.mkdir(mode=0o755)
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as output:json.dump(expected,output)
    source=repo/'tests/fixtures/vendor/2025-cybersibir-service-ncdex/vuln-service'
    shutil.copytree(source,game/'vuln-service',ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git'))
    home=game/'vuln-service/src/views/home.ecr'
    original=home.read_text()
    anchor='<div class="text-center neon-container">'
    if original.count(anchor)!=1 or 'ctfm-baseline-marker' in original:raise RuntimeError('Unexpected upstream template')
    home.write_text(original.replace(anchor,anchor+'\n    '+baseline_marker))
    external.mkdir(mode=0o755);(external/'app').mkdir(mode=0o755);(external/'init').mkdir(mode=0o755)
    password=secrets.token_hex(24)
    config='port: 7331\nname: "NightCity Data Exchange"\ndatabase: "postgres://postgres:'+password+'@db:5432/nde?initial_pool_size=1&max_pool_size=40&max_idle_pool_size=10&checkout_timeout=2.0&retry_attempts=5&retry_delay=0.5"\n'
    (external/'app/config.yml').write_text(config);(external/'app/config.yml').chmod(0o444)
    original_sql=(source/'src/db/migrations/init.sql').read_text()
    if original_sql.count('---\n')!=1:raise RuntimeError('Unexpected upstream database initialization')
    # Schema and seed remain byte-identical after the tuning-only separator.
    sql=original_sql.split('---\n',1)[1]
    (external/'init/001-schema.sql').write_text(sql);(external/'init/001-schema.sql').chmod(0o444)
    (external/'.ctfm-runtime-config.json').write_text(json.dumps({'purpose':'frozen ncdex runtime settings','project':project,'service_directory':str(game)}))
    (external/'.ctfm-runtime-config.json').chmod(0o600)
    logs={'driver':'json-file','options':{'max-size':'20m','max-file':'5'}}
    limits={'restart':'unless-stopped','shm_size':'64m','mem_limit':'512m','cpus':1.0,'pids_limit':128,'logging':logs}
    profile={'services':{
      'app':{**limits,'build':{'context':'./vuln-service'},'image':project+':baseline',
        'ports':[{'target':7331,'host_ip':'127.0.0.1','protocol':'tcp'}],
        'volumes':[{'type':'bind','source':str(external/'app'),'target':'/home/appuser/config','read_only':True,'bind':{'create_host_path':False}}],
        'depends_on':{'db':{'condition':'service_healthy'}},
        'healthcheck':{'test':['CMD','wget','-q','-O','/dev/null','http://127.0.0.1:7331/about'],'interval':'2s','timeout':'3s','retries':30,'start_period':'5s'}},
      'db':{**limits,'image':'postgres:17.4-alpine',
        'command':['postgres','-c','max_connections=80','-c','shared_buffers=64MB','-c','effective_cache_size=256MB','-c','maintenance_work_mem=32MB','-c','work_mem=2MB','-c','min_wal_size=80MB','-c','max_wal_size=256MB'],
        'environment':{'POSTGRES_USER':'postgres','POSTGRES_PASSWORD':password,'POSTGRES_DB':'nde'},
        'volumes':[{'type':'volume','source':'postgres-data','target':'/var/lib/postgresql/data'},
                   {'type':'bind','source':str(external/'init'),'target':'/docker-entrypoint-initdb.d','read_only':True,'bind':{'create_host_path':False}}],
        'healthcheck':{'test':['CMD','pg_isready','-U','postgres','-d','nde'],'interval':'2s','timeout':'3s','retries':30,'start_period':'5s'}}},
      'volumes':{'postgres-data':{}}}
    (game/'ctfm.runtime.yaml').write_text(json.dumps(profile,indent=2)+'\n')
    (game/'ctfm.runtime.yaml').chmod(0o600)
else:
    if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:
        raise RuntimeError('Existing service directory is not owned by this helper')
    if external.is_symlink() or not (external/'app/config.yml').is_file() or not (external/'init/001-schema.sql').is_file():
        raise RuntimeError('Owned runtime config is incomplete')
db=root/'executor/executor.db'
registered=False
if db.is_file():
    connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
    for row in connection.execute('SELECT payload FROM services'):
        value=json.loads(row[0]);registered |= value.get('project_directory')==str(game) or value.get('compose_project')==project
    connection.close()
print(json.dumps({'fresh':fresh,'registered':registered,'project_directory':str(game),'compose_file':str(game/'ctfm.runtime.yaml')}))
'''


def setup(docker):
    existing = docker.run("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + PROJECT).splitlines()
    prepared = json.loads(docker.helper(SETUP, PROJECT, GIT_COMMIT, BASELINE_MARKER, writable=True))
    if existing:
        for identifier in existing:
            value = json.loads(docker.run("inspect", identifier))[0]
            if value["Config"]["Labels"].get("com.docker.compose.project.working_dir") != SERVICE_DIRECTORY:
                raise RuntimeError("Existing project directory has a different owner")
    if prepared["fresh"] and existing:
        raise RuntimeError("Refusing to change an existing project without an ownership marker")
    volume_name = PROJECT + "_postgres-data"
    for name in docker.run("volume", "ls", "--quiet", "--filter", "name=^" + volume_name + "$").splitlines():
        volume = json.loads(docker.run("volume", "inspect", name))[0]
        if volume.get("Labels", {}).get("com.docker.compose.project") != PROJECT:
            raise RuntimeError("PostgreSQL volume belongs to a different project")
    running = {json.loads(docker.run("inspect", identifier))[0]["Config"]["Labels"].get("com.docker.compose.service") for identifier in existing}
    if running != {"app", "db"}:
        if prepared["registered"]:
            raise RuntimeError("An incomplete registered service must be recovered through the panel")
        docker.compose("up", "-d", "--build", "--wait", "--wait-timeout", "120", timeout=1800)
    return {**evidence(docker), **prepared,
            "registration_hint":{"managed_paths":[{"path":"vuln-service","kind":"code"}],
                                 "target_components":["app"],"application_components":["app"],"database_components":["db"],
                                 "git_url":GIT_URL,"git_ref":GIT_COMMIT,"git_subdirectory":"",
                                 "writable_layer_loss_accepted":True,"postgres_volume_significant":True}}


def normalize_shm(docker):
    """One-time supported-profile normalization, refused after registration."""
    before = evidence(docker)
    preparation = json.loads(docker.helper(r'''
import json,os,secrets,sqlite3,sys
from pathlib import Path
root,repo=map(Path,sys.argv[1:3]);project,commit=sys.argv[3:5]
game=root/'services/sibir-ncdex';marker=game/'.ctfm-sibir-ncdex.json'
expected={'purpose':'persistent real SibirCTF ncdex cycle','repository':str(repo),'project':project,'git_commit':commit}
if game.is_symlink() or marker.is_symlink() or not marker.is_file() or json.loads(marker.read_text())!=expected:
    raise RuntimeError('Existing service directory is not owned by this helper')
db=root/'executor/executor.db'
if not db.is_file():raise RuntimeError('Cannot verify the service is unregistered')
connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
try:
    for row in connection.execute('SELECT payload FROM services'):
        value=json.loads(row[0])
        if value.get('project_directory')==str(game) or value.get('compose_project')==project:
            raise RuntimeError('Service is registered; cannot mutate frozen runtime profile')
finally:connection.close()
profile_path=game/'ctfm.runtime.yaml'
if profile_path.is_symlink():raise RuntimeError('Unexpected symbolic link')
profile=json.loads(profile_path.read_text())
if set(profile.get('services',{}))!={'app','db'}:raise RuntimeError('Unexpected service components')
old={name:value.get('shm_size') for name,value in profile['services'].items()}
for value in profile['services'].values():value['shm_size']='64m'
temporary=game/('.ctfm-shm-'+secrets.token_hex(6)+'.tmp')
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as output:json.dump(profile,output,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())
os.replace(temporary,profile_path)
fd=os.open(game,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'registered_service_mutated':False,'previous_shm_size':old,'new_shm_size':{'app':'64m','db':'64m'}}))
''',PROJECT,GIT_COMMIT,writable=True))
    docker.compose("up","-d","--no-build","--wait","--wait-timeout","120")
    after = evidence(docker)
    if before["volumes"] != after["volumes"]:
        raise RuntimeError("Persistent volume identity changed during profile preparation")
    return {"project":PROJECT,"preparation":"explicit shared memory size before web registration",
            **preparation,"persistent_volumes_preserved":True,"before":before,"after":after}


class GameClient:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, path):
        with self.opener.open(self.base + path, timeout=20) as response:
            return response.geturl(), response.read().decode()

    def post(self, path, values):
        request = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(values).encode(),
                                         headers={"Content-Type":"application/x-www-form-urlencoded","Origin":self.base,"Referer":self.base+path})
        with self.opener.open(request, timeout=20) as response:
            return response.geturl(), response.read().decode()

    def login(self, record):
        self.post("/users/login", {"email":record["email"],"password":record["password"]})
        destination, profile = self.get("/users/profile")
        if urllib.parse.urlsplit(destination).path != "/users/profile" or html.escape(record["username"]) not in profile:
            raise RuntimeError("ncdex fresh authenticated profile login failed")
        return profile


def replace_private(path, value):
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    private_json(temporary, value)
    os.replace(temporary, path)


def seed_or_check(docker, credentials_file, *, seed=False, expected_marker="either"):
    container = docker.container()
    client = GameClient(game_url(container))
    created_user = created_record = False
    if credentials_file.exists():
        record = read_private_json(credentials_file)
        if record.get("project") != PROJECT:
            raise RuntimeError("Credentials belong to another project")
    elif seed:
        token = secrets.token_hex(8)
        record = {"project":PROJECT,"username":"ctfm_"+token,"email":"ctfm_"+token+"@example.invalid",
                  "password":secrets.token_urlsafe(24),"title":"CTFM preservation "+token,
                  "description":"CTFM_PERSISTENT_GAME_RECORD_"+secrets.token_hex(20),
                  "exploit":"CTFM_NONEXECUTABLE_DATA_"+secrets.token_hex(16)}
        private_json(credentials_file, record)
    else:
        raise RuntimeError("Missing seeded credentials")
    try:
        client.login(record)
    except RuntimeError:
        if not seed:raise
        destination, _ = client.post("/users/register", {key:record[key] for key in ("username","email","password")})
        if urllib.parse.urlsplit(destination).path != "/users/profile":
            raise RuntimeError("ncdex legitimate registration failed")
        created_user=True
    if "record_id" not in record:
        if not seed:raise RuntimeError("Persistent record ID is missing")
        destination, page = client.post("/vulnerabilities", {**{key:record[key] for key in ("title","description","exploit")},
                                                           "exploit_type":"rce","platform":"linux","price":"100"})
        match = re.fullmatch(r"/vulnerabilities/([0-9]+)", urllib.parse.urlsplit(destination).path)
        if not match or record["description"] not in page or record["exploit"] not in page:
            raise RuntimeError("ncdex legitimate persistent record creation failed")
        record["record_id"] = int(match.group(1));replace_private(credentials_file,record);created_record=True
    # A fresh cookie jar and password authentication prove data, not cached session state.
    client=GameClient(game_url(container));client.login(record)
    destination,page=client.get("/vulnerabilities/"+str(record["record_id"]))
    if not all(html.escape(record[key]) in page for key in ("title","description","exploit")):
        raise RuntimeError("Synthetic persistent game record was not returned to its authenticated owner")
    _,home=client.get("/");marker=BASELINE_MARKER in home
    if expected_marker!="either" and marker!=(expected_marker=="present"):
        raise RuntimeError("Unexpected imported baseline marker state")
    database=docker.container("db")
    return {"project":PROJECT,"url":client.base,"user_created":created_user,"record_created":created_record,
            "fresh_login_successful":True,"persistent_record_preserved":True,"record_id":record["record_id"],
            "description_sha256":hashlib.sha256(record["description"].encode()).hexdigest(),
            "record_payload_sha256":hashlib.sha256(json.dumps({key:record[key] for key in ("title","description","exploit")},sort_keys=True).encode()).hexdigest(),
            "baseline_marker_present":marker,"container_id":container["Id"],"image_id":container["Image"],"started_at":container["State"]["StartedAt"],
            "database_container_id":database["Id"],"database_started_at":database["State"]["StartedAt"]}


def evidence(docker):
    containers={component:docker.container(component) for component in ("app","db")}
    volumes=[]
    for component,container in containers.items():
        for mount in container.get("Mounts",[]):
            if mount["Type"]=="volume":
                volume=json.loads(docker.run("volume","inspect",mount["Name"]))[0]
                volumes.append({"component":component,"target":mount["Destination"],"name":volume["Name"],
                                "mountpoint":volume["Mountpoint"],"created_at":volume.get("CreatedAt"),"labels":volume.get("Labels")})
    tree=json.loads(docker.helper(r'''
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]);game=root/'services/sibir-ncdex';external=root/'services/sibir-ncdex-runtime-config'
files={}
for path in (game/'ctfm.runtime.yaml',game/'vuln-service/Dockerfile',game/'vuln-service/src/views/home.ecr',external/'app/config.yml',external/'init/001-schema.sql'):
    if path.is_symlink() or not path.is_file():raise RuntimeError('Unexpected source or frozen config path')
    files[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps({'files_sha256':files,'baseline_marker_on_disk':b'ctfm-baseline-marker' in (game/'vuln-service/src/views/home.ecr').read_bytes()}))
'''))
    app=containers["app"];url=game_url(app)
    with urllib.request.urlopen(url+"/",timeout=15) as response:
        page=response.read();status=response.status
    return {"project":PROJECT,"project_directory":SERVICE_DIRECTORY,"url":url,"git_url":GIT_URL,"git_commit":GIT_COMMIT,"git_subdirectory":"",
            "components":{name:{"container_id":value["Id"],"image_id":value["Image"],"started_at":value["State"]["StartedAt"],
                                "status":value["State"]["Status"],"health":value["State"].get("Health",{}).get("Status"),
                                "mounts":[{key:mount.get(key) for key in ("Type","Name","Source","Destination","RW")} for mount in value.get("Mounts",[])]}
                          for name,value in containers.items()},
            "volumes":volumes,"source":tree,"http_status":status,"baseline_marker_served":BASELINE_MARKER.encode() in page,
            "upstream_compose_used":False,"profile_differences":[
                "Real Crystal application builds with unchanged upstream Dockerfile in ./vuln-service",
                "Frozen sibling config corrects upstream localhost:7432 DSN to internal db:5432 with local credentials",
                "PostgreSQL has a named data volume; unchanged upstream schema and seed after tuning separator execute once from frozen readonly init bind",
                "Upstream 16 GiB ALTER SYSTEM tuning is omitted; explicit bounded PostgreSQL command settings and runtime limits are used",
                "Only app is an update target; database has no published host port and app HTTP is loopback-only",
                "Imported baseline alone adds an HTML marker; exact Git candidate removes it"],
            "organizer_checker_run":False,"exploit_scripts_run":False}


def manifest(docker, expected_marker):
    """Compare every active managed file with pinned Git blobs, read-only."""
    actual=json.loads(docker.helper(r'''
import hashlib,json,stat,sys
from pathlib import Path
game=Path(sys.argv[1])/'services/sibir-ncdex';source=game/'vuln-service'
if game.is_symlink() or source.is_symlink() or not source.is_dir():raise RuntimeError('Unexpected owned source directory')
files={}
for path in sorted(source.rglob('*')):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode):raise RuntimeError('Symbolic link in managed code')
    if stat.S_ISDIR(info.st_mode):continue
    if not stat.S_ISREG(info.st_mode):raise RuntimeError('Nonregular managed code')
    files[str(path.relative_to(game))]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(files))
'''))
    repository=ROOT/'tests/fixtures/vendor/2025-cybersibir-service-ncdex'
    entries=subprocess.check_output(['git','-C',str(repository),'ls-tree','-rz',GIT_COMMIT,'--','vuln-service'],timeout=30).split(b'\0')
    expected={};upstream_home=None
    for entry in entries:
        if not entry:continue
        metadata,name=entry.split(b'\t',1);mode,kind,object_id=metadata.split()
        if kind!=b'blob' or mode not in (b'100644',b'100755'):
            raise RuntimeError('Unsupported upstream managed entry')
        data=subprocess.check_output(['git','-C',str(repository),'cat-file','blob',object_id.decode()],timeout=30)
        if name==b'vuln-service/src/views/home.ecr':upstream_home=data
        expected[name.decode()]=hashlib.sha256(data).hexdigest()
    if upstream_home is None:raise RuntimeError('Missing pinned home template')
    upstream=dict(expected)
    if expected_marker=='present':
        anchor=b'<div class="text-center neon-container">'
        if upstream_home.count(anchor)!=1:raise RuntimeError('Unexpected pinned home template')
        marked=upstream_home.replace(anchor,anchor+b'\n    '+BASELINE_MARKER.encode())
        expected['vuln-service/src/views/home.ecr']=hashlib.sha256(marked).hexdigest()
    elif expected_marker!='absent':
        raise RuntimeError('manifest requires explicit --expect-marker present or absent')
    differences=[name for name in sorted(set(actual)|set(expected)) if actual.get(name)!=expected.get(name)]
    if differences:raise RuntimeError('Managed source does not match pinned Git and documented marker: '+', '.join(differences))
    return {'project':PROJECT,'git_commit':GIT_COMMIT,'expected_marker':expected_marker,
            'file_count':len(actual),'all_managed_file_hashes_match':True,'files_sha256':actual,
            'baseline_source_change_from_git':['vuln-service/src/views/home.ecr'] if expected_marker=='present' else [],
            'upstream_home_sha256':upstream['vuln-service/src/views/home.ecr']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("setup","normalize-shm","seed","check","evidence","manifest"))
    parser.add_argument("--before-registration",action="store_true")
    parser.add_argument("--credentials-file",type=Path,default=LOCAL/"sibir-ncdex-record.json")
    parser.add_argument("--expect-marker",choices=("present","absent","either"),default="either")
    parser.add_argument("--output",type=Path)
    arguments=parser.parse_args()
    if arguments.action=="normalize-shm" and not arguments.before_registration:
        parser.error("normalize-shm requires --before-registration and also verifies executor registration state")
    docker=Docker()
    if arguments.action=="setup":result=setup(docker)
    elif arguments.action=="normalize-shm":result=normalize_shm(docker)
    elif arguments.action=="manifest":result=manifest(docker,arguments.expect_marker)
    elif arguments.action in ("seed","check"):
        result=seed_or_check(docker,arguments.credentials_file,seed=arguments.action=="seed",expected_marker=arguments.expect_marker)
    else:result=evidence(docker)
    result.update(action=arguments.action,recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    encoded=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True,exist_ok=True);arguments.output.write_text(encoded)
    print(encoded,end="")


if __name__=="__main__":main()
