#!/usr/bin/env python3
"""Real daemon restart and registry-offline acceptance on an empty Linux VM.

Run only as root on an explicitly dedicated, native Linux/amd64 systemd host.
This script intentionally refuses any preexisting container, Compose volume or
non-default network. It restarts docker.service and temporarily rejects host
TCP registry HTTP/HTTPS traffic, guarded by an independent systemd watchdog.
It never changes SSH rules, daemon configuration, default firewall policy or
unrelated objects. No Docker or network action occurs merely by importing it.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
OWNER_LABEL = "ctfm.native-acceptance"
TERMINAL = {"succeeded", "failed", "cancelled", "interrupted", "requires_recovery"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(arguments, *, success=True, timeout=120, environment=None):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("COMPOSE_") and key not in
           ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    env.update(environment or {})
    result = subprocess.run(list(map(str, arguments)), text=True, capture_output=True,
                            timeout=timeout, env=env)
    if success and result.returncode:
        raise RuntimeError(f"{Path(str(arguments[0])).name} {list(map(str, arguments[1:3]))}: "
                           + (result.stderr + result.stdout)[-6000:])
    return result


def require_empty_host(containers, networks, volumes):
    """A stopped container is still an unrelated workload; do not exempt it."""
    require(not containers, "dedicated-host guard: preexisting running/stopped containers")
    require(not volumes, "dedicated-host guard: preexisting Compose volumes")
    require(all(item.get("Name") in ("bridge", "host", "none") for item in networks),
            "dedicated-host guard: preexisting non-default Docker networks")


def require_owned_containers(current, expected, nonce):
    require(set(current) == set(expected), "host-wide action refused: container identities changed")
    for identity, item in current.items():
        require(item["Name"] == expected[identity]["Name"], "owned container name changed")
        require(item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == nonce,
                "host-wide action refused: container lacks this run's exact owner nonce")
        require(item["Image"] == expected[identity]["Image"], "owned container image changed")


def require_daemon_profile(info, kernel):
    require(info.get("OSType") == "linux" and info.get("Architecture") in ("amd64", "x86_64"),
            "daemon must be native Linux/amd64")
    require(info.get("KernelVersion") == kernel, "Docker and harness kernels differ")
    require(not info.get("LiveRestoreEnabled"), "live-restore host requires a different restart scenario")
    require(not any(info.get(key) for key in ("HTTPProxy", "HTTPSProxy")),
            "daemon proxy unsupported for registry block")
    require(not info.get("RegistryConfig", {}).get("Mirrors"), "registry mirrors unsupported for registry block")
    require(info.get("Swarm", {}).get("LocalNodeState", "inactive") == "inactive", "refuse Swarm host")
    require(not any("rootless" in str(item) or "userns" in str(item) for item in info.get("SecurityOptions", [])),
            "rootless/userns-remap are not this accepted profile")


def require_socket_owner(inodes, held):
    require(bool(inodes) and any("socket:[" + inode + "]" in held for inode in inodes),
            "local Docker socket is not held by docker.service MainPID")


def safe_host_lock(path, owner_uid=0):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == owner_uid
                and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600,
                "host lock must be an unlinked-alias-free root-owned 0600 regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return os.fdopen(descriptor, "a")
    except BaseException:
        os.close(descriptor)
        raise


def ssh_server_port(configured, connection):
    observed = None
    if connection:
        fields = connection.split()
        require(len(fields) == 4 and fields[3].isdecimal(), "invalid SSH_CONNECTION; cannot prove SSH response exception")
        observed = int(fields[3])
    require(configured is None or observed is None or configured == observed,
            "configured SSH port differs from actual SSH_CONNECTION server port")
    port = configured if configured is not None else observed if observed is not None else 22
    validate_firewall_identity("CTFMND_0123456789ab", "ctfm-native-0123456789ab", port)
    return port


def validate_firewall_identity(chain, comment, ssh_port):
    require(re.fullmatch(r"CTFMND_[0-9a-f]{12}", chain), "invalid private firewall chain")
    require(re.fullmatch(r"ctfm-native-[0-9a-f]{12}", comment), "invalid firewall comment")
    require(type(ssh_port) is int and 1 <= ssh_port <= 65535, "invalid guest SSH server port")


def firewall_rules(chain, comment, ssh_port):
    validate_firewall_identity(chain, comment, ssh_port)
    # Preserve SSH responses even if a client happens to use local port 80/443.
    # A general ESTABLISHED exception would let pooled registry TLS bypass us.
    return [
        ["-p", "tcp", "--sport", str(ssh_port), "-m", "comment", "--comment", comment, "-j", "RETURN"],
        ["-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "comment", "--comment", comment,
         "-j", "REJECT", "--reject-with", "tcp-reset"],
    ]


def rejected_packets(output):
    total = 0
    for line in output.splitlines():
        columns = line.split()
        if len(columns) >= 3 and columns[0].isdecimal() and columns[2] == "REJECT":
            total += int(columns[0])
    return total


def cleanup_program(backends, chain, comment, rules, marker):
    """Only exact jumps/rules are removed; foreign chain content is retained."""
    payload = json.dumps({"backends": backends, "chain": chain, "comment": comment,
                          "rules": rules, "marker": str(marker)})
    return """#!/usr/bin/env python3
import json,subprocess,sys
from pathlib import Path
value=json.loads(PAYLOAD)
if '--watchdog' in sys.argv:Path(value['marker']).write_text('watchdog expired\\n')
failed=[]
for binary in value['backends']:
    prefix=[binary,'-w','5']
    jump=['-m','comment','--comment',value['comment'],'-j',value['chain']]
    def call(args):
        try:
            result=subprocess.run(prefix+args,capture_output=True,text=True,timeout=12)
            if result.returncode>1:failed.append(binary+': command error '+str(result.returncode))
            return result
        except (OSError,subprocess.TimeoutExpired) as error:
            failed.append(binary+': '+type(error).__name__)
            return subprocess.CompletedProcess(prefix+args,1,'','cleanup call failed')
    # Detach first: an orphan private chain cannot affect host traffic.
    if call(['-C','OUTPUT']+jump).returncode==0:
        if call(['-D','OUTPUT']+jump).returncode:failed.append(binary+': jump removal')
    if call(['-S',value['chain']]).returncode==0:
        for rule in value['rules']:
            if call(['-C',value['chain']]+rule).returncode==0:
                if call(['-D',value['chain']]+rule).returncode:failed.append(binary+': exact rule removal')
        # Never flush: unexpected foreign rules must not be deleted.
        if call(['-X',value['chain']]).returncode:failed.append(binary+': nonempty private chain retained')
    if call(['-C','OUTPUT']+jump).returncode==0:failed.append(binary+': jump remains')
print(json.dumps({'cleanup_errors':failed}))
raise SystemExit(1 if failed else 0)
""".replace("PAYLOAD", repr(payload))


class RegistryBlock:
    def __init__(self, nonce, ssh_port, run_command=run):
        require(re.fullmatch(r"[0-9a-f]{12}", nonce), "invalid run nonce")
        self.run = run_command
        self.chain = "CTFMND_" + nonce
        self.comment = "ctfm-native-" + nonce
        self.rules = firewall_rules(self.chain, self.comment, ssh_port)
        self.backends = [shutil.which(name) for name in ("iptables", "ip6tables")]
        require(all(self.backends), "both iptables and ip6tables are required")
        self.directory = Path("/run") / self.comment
        self.unit = self.comment + "-cleanup"
        self.marker = self.directory / "watchdog-fired"
        self.script = self.directory / "cleanup.py"
        self.armed = False
        self.active = False

    def begin(self):
        self.directory.mkdir(mode=0o700)
        require(self.directory.stat().st_uid == 0, "watchdog directory must be root owned")
        for binary in self.backends:
            self.run([binary, "-w", "5", "-S", "OUTPUT"])
            require(self.run([binary, "-w", "5", "-S", self.chain], success=False).returncode == 1,
                    "private firewall chain exists or cannot be safely inspected; refuse adoption")
        self.script.write_text(cleanup_program(self.backends, self.chain, self.comment, self.rules, self.marker))
        self.script.chmod(0o700)
        # Arm independently of this process/SSH BEFORE attaching the first rule.
        self.arm_watchdog()
        try:
            for binary in self.backends:
                self.run([binary, "-w", "5", "-N", self.chain])
                for rule in self.rules:
                    self.run([binary, "-w", "5", "-A", self.chain, *rule])
                self.run([binary, "-w", "5", "-I", "OUTPUT", "1", "-m", "comment", "--comment",
                          self.comment, "-j", self.chain])
            self.active = True
            self.assert_active()
        except BaseException:
            self.restore()
            raise

    def arm_watchdog(self):
        self.run(["systemd-run", "--quiet", "--unit", self.unit, "--on-active=180s",
                  "--timer-property=AccuracySec=1s", "--property=Type=oneshot",
                  sys.executable, self.script, "--watchdog"])
        self.armed = True
        self.run(["systemctl", "is-active", self.unit + ".timer"])
        require(self.run(["systemctl", "show", "--property=SubState", "--value",
                          self.unit + ".timer"]).stdout.strip() == "waiting", "watchdog timer is not waiting")
        require(not self.marker.exists(), "watchdog already expired")

    def assert_active(self):
        require(self.active and not self.marker.exists(), "registry-offline watchdog expired or block inactive")
        for binary in self.backends:
            self.run([binary, "-w", "5", "-C", "OUTPUT", "-m", "comment", "--comment", self.comment,
                      "-j", self.chain])
            for rule in self.rules:
                self.run([binary, "-w", "5", "-C", self.chain, *rule])

    def counters(self):
        self.assert_active()
        return {Path(binary).name: rejected_packets(self.run([binary, "-w", "5", "-L", self.chain,
                                                             "-v", "-n", "-x"]).stdout)
                for binary in self.backends}

    def restore(self):
        if not self.armed:
            return {"not_armed": True}
        result = self.run([sys.executable, self.script], success=False)
        detached = True
        for binary in self.backends:
            self.run([binary, "-w", "5", "-S", "OUTPUT"])
            absent = self.run([binary, "-w", "5", "-C", "OUTPUT", "-m", "comment",
                               "--comment", self.comment, "-j", self.chain], success=False).returncode == 1
            detached = detached and absent
        require(detached, "firewall jump still attached; keep independent watchdog armed")
        # Stop the watchdog only after host traffic is definitely detached.
        self.run(["systemctl", "stop", self.unit + ".timer", self.unit + ".service"])
        expired = self.marker.exists()
        self.active = False
        require(result.returncode == 0, "exact firewall cleanup failed: " + result.stdout + result.stderr)
        self.armed = False
        shutil.rmtree(self.directory)
        return {"both_output_jumps_removed": True, "private_chains_removed": True,
                "watchdog_fired": expired}


class NativeHost:
    def __init__(self, dedicated):
        require(dedicated, "--dedicated-host is required for real host-wide faults")
        require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"),
                "requires a native Linux/amd64 host")
        require(os.geteuid() == 0 and Path("/run/systemd/system").is_dir(), "requires root and systemd")
        require(Path("/proc/1/comm").read_text().strip() == "systemd", "refuse nested/container PID namespace")
        require(not Path("/.dockerenv").exists(), "refuse running this harness inside Docker")
        require(shutil.which("docker") and shutil.which("systemd-run"), "Docker/systemd-run required")
        self.socket = Path("/run/docker.sock")
        metadata = self.socket.stat()
        require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 0, "requires root-owned local Docker socket")
        self.docker = [shutil.which("docker"), "--host", "unix://" + str(self.socket)]
        self.info = self.json("info", "--format", "{{json .}}")
        require_daemon_profile(self.info, platform.release())
        self.identity()
        # containerd can fetch layers through a proxy independently of dockerd.
        # Inspect live process environments privately; never emit credentials.
        for unit in ("docker.service", "containerd.service"):
            pid = int(run(["systemctl", "show", "--property=MainPID", "--value", unit]).stdout.strip() or "0")
            if pid > 1:
                environment = (Path("/proc") / str(pid) / "environ").read_bytes().split(b"\0")
                require(not any(item.split(b"=", 1)[0].lower() in (b"http_proxy", b"https_proxy", b"all_proxy")
                                and item.partition(b"=")[2] for item in environment),
                        "live daemon/containerd proxy unsupported for registry block")

    def command(self, *parts, **kwargs):
        return run([*self.docker, *parts], **kwargs)

    def json(self, *parts):
        return json.loads(self.command(*parts).stdout)

    def containers(self):
        ids = self.command("ps", "--all", "--quiet", "--no-trunc").stdout.split()
        return {item["Id"]: item for item in self.json("inspect", *ids)} if ids else {}

    def initial_guard(self):
        networks = self.json("network", "inspect", *self.command("network", "ls", "--quiet").stdout.split())
        volumes = self.command("volume", "ls", "--quiet", "--filter", "label=com.docker.compose.project").stdout.split()
        require_empty_host(self.containers(), networks, volumes)

    def identity(self):
        pid = int(run(["systemctl", "show", "--property=MainPID", "--value", "docker.service"]).stdout.strip())
        require(pid > 1, "docker.service has no live MainPID")
        process = Path("/proc") / str(pid)
        require(Path(os.readlink(process / "exe")).name == "dockerd", "systemd MainPID is not dockerd")
        require(os.readlink(process / "ns/net") == os.readlink("/proc/self/ns/net"), "dockerd not in host network namespace")
        command_line = (process / "cmdline").read_bytes().split(b"\0")
        require(not any(b"tcp://" in item for item in command_line), "unexpected TCP daemon listener")
        inodes = {fields[6] for line in Path("/proc/net/unix").read_text().splitlines()[1:]
                  if len(fields := line.split()) >= 8 and fields[7] in ("/run/docker.sock", "/var/run/docker.sock")}
        held = set()
        for entry in (process / "fd").iterdir():
            try:
                held.add(os.readlink(entry))
            except FileNotFoundError:
                pass  # An unrelated descriptor may close while inventorying it.
        require_socket_owner(inodes, held)
        fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "start_ticks": fields[19], "socket": str(self.socket)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dedicated-host", action="store_true", help="attest this entire VM is disposable and exclusively reserved for this test")
    parser.add_argument("--executor-image", default="ctf-manager-executor:local")
    parser.add_argument("--ssh-server-port", type=int, help="actual guest sshd port; defaults to SSH_CONNECTION server port or local 22")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/native-daemon-smoke-2026-10-29.json")
    args = parser.parse_args()
    nonce = uuid.uuid4().hex[:12]
    project, service_id = "ctfm-native-daemon-" + nonce, "native-daemon-" + nonce
    directory = Path("/srv") / project
    executor_name = project + "-executor"
    report = {"test": "native-daemon-restart-and-registry-offline", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(), "project": project,
              "scope": "entire explicitly dedicated VM; only new UUID synthetic game/executor registered",
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "checks": {},
              "limitations": ["real docker.service restart with live-restore disabled; not kernel/VM power loss",
                              "temporary host OUTPUT TCP80/443 denial, IPv4 and IPv6; no proxy/mirror profiles",
                              "synthetic bind-code/bind-data fixture; no database dependency restart claim",
                              "local functional result is verified by independent fixture HTTP probes; no configured external organizer checker"]}
    host = block = None
    lock = None
    owned = {}
    network_id = None
    created_directory = False
    restart_attempted = False
    tags = {}
    probe_ref = "docker.io/library/hello-world:latest"

    def save():
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")

    def own_snapshot():
        nonlocal owned
        current = host.containers()
        for item in current.values():
            require(item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == nonce,
                    "unexpected foreign container; refuse further host-wide actions")
            require(item["Name"] in ("/" + executor_name, "/" + project + "-app-1"), "unexpected owned component")
        owned = current
        return current

    def cli(*parts, success=True):
        return host.command("exec", executor_name, "/usr/local/bin/ctf-manager", "--config",
                            directory / "config/executor.json", *parts, success=success)

    def cli_json(*parts):
        return json.loads(cli(*parts).stdout)

    def request_file(name, value):
        path = directory / "requests" / name
        path.write_text(json.dumps(value) + "\n")
        path.chmod(0o600)
        return str(path)

    def prepare_request(action, **fields):
        value = {"service_id": service_id, "action": action, "initiator": "native-daemon-test",
                 "idempotency_key": uuid.uuid4().hex, **fields}
        path = request_file("request.json", value)
        value["plan_digest"] = cli_json("preview", "--request", path)["plan_digest"]
        request_file("request.json", value)
        return value, path

    def wait_operation(identity, expected, changed_from=None):
        until = time.monotonic() + 120
        while time.monotonic() < until:
            if block and block.active:
                block.assert_active()
            result = cli_json("operation", "--operation", identity)
            if changed_from and result["updated_at"] == changed_from:
                time.sleep(.15)
                continue
            if result["state"] in TERMINAL:
                require(result["state"] in expected, "unexpected operation outcome: " + json.dumps(result))
                return result
            time.sleep(.15)
        raise RuntimeError("operation deadline exceeded")

    def operation(action, **fields):
        value, path = prepare_request(action, **fields)
        accepted = cli_json("submit", "--request", path)
        result = wait_operation(accepted["spec"]["id"], {"succeeded"})
        require(cli_json("submit", "--request", path)["spec"]["id"] == result["spec"]["id"], "idempotency changed identity")
        report.setdefault("operations", []).append(result)
        return result

    def http(method, path, value=None):
        body = None if value is None else json.dumps({"value": value}).encode()
        request = urllib.request.Request(base + path, data=body, method=method,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=3) as response:
            require(response.status == 200, "fixture HTTP failure")
            return json.load(response)

    def ready():
        until = time.monotonic() + 60
        while time.monotonic() < until:
            try:
                return http("GET", "/health")
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(.2)
        raise RuntimeError("fixture readiness deadline exceeded")

    def check_data():
        require(http("GET", "/flags/" + nonce)["value"] == flag, "fixture flag lost")
        require(http("GET", "/state/" + nonce)["value"] == state_value, "fixture state lost")

    def executor_ready():
        until = time.monotonic() + 30
        while time.monotonic() < until:
            if cli("status", success=False).returncode == 0:
                return
            time.sleep(.2)
        raise RuntimeError("executor readiness deadline exceeded")

    def database_operation(identity):
        with sqlite3.connect("file:" + str(directory / "executor/executor.db") + "?mode=ro", uri=True) as db:
            payload = db.execute("SELECT payload FROM operations WHERE id=?", (identity,)).fetchone()
            locks = [list(row) for row in db.execute("SELECT resource,operation_id FROM locks WHERE operation_id=? ORDER BY resource", (identity,))]
        require(payload is not None, "durable operation missing")
        return {"operation": json.loads(payload[0]), "locks": locks}

    def pull_probe(expect_success):
        result = host.command("pull", probe_ref, success=False, timeout=40)
        if expect_success:
            require(result.returncode == 0, "daemon registry connectivity control failed: " + result.stderr[-2000:])
            image = host.json("image", "inspect", probe_ref)[0]
            tags[probe_ref] = image["Id"]
            host.command("image", "rm", "--no-prune", probe_ref)
            require(host.command("image", "inspect", probe_ref, success=False).returncode != 0, "probe image remains cached by reference")
            return {"exit_code": 0, "reference": probe_ref, "image_id": image["Id"], "tag_removed": True}
        output = (result.stderr + result.stdout).lower()
        require(result.returncode != 0 and any(token in output for token in
                ("connection refused", "connection reset", "network is unreachable", "no route to host", "timeout", "timed out", "eof")),
                "blocked daemon pull did not fail as a network error: " + output[-2000:])
        require(host.command("image", "inspect", probe_ref, success=False).returncode != 0, "blocked pull unexpectedly published an image")
        return {"exit_code": result.returncode, "reference": probe_ref, "error": output[-2000:]}

    try:
        args.ssh_server_port = ssh_server_port(args.ssh_server_port, os.environ.get("SSH_CONNECTION"))
        validate_firewall_identity("CTFMND_" + nonce, "ctfm-native-" + nonce, args.ssh_server_port)
        host = NativeHost(args.dedicated_host)
        lock = safe_host_lock("/run/lock/ctfm-native-acceptance.lock")
        host.initial_guard()
        report["host"] = {key: host.info.get(key) for key in ("ID", "OSType", "Architecture", "KernelVersion", "OperatingSystem", "NCPU", "MemTotal", "DockerRootDir", "ServerVersion", "LiveRestoreEnabled")}
        require(host.command("image", "inspect", probe_ref, success=False).returncode != 0,
                "uncached pull probe image already exists; refuse deleting a preexisting tag")
        require(not host.command("image", "ls", "--quiet", "--filter", "reference=" + project + "*").stdout.strip(),
                "UUID fixture image namespace already exists")
        require(not host.command("image", "ls", "--quiet", "--filter",
                                 "reference=ctf-manager/" + service_id + ":*").stdout.strip(),
                "UUID service retention namespace already exists")
        image = host.json("image", "inspect", args.executor_image)[0]
        require(image["Os"] == "linux" and image["Architecture"] == "amd64", "executor image must be native amd64")
        report["executor_image_id"] = image_id = image["Id"]
        directory.mkdir(mode=0o755)
        created_directory = True
        for name in ("services", "workspaces", "config", "requests"):
            (directory / name).mkdir(mode=0o755 if name != "requests" else 0o700)
        (directory / "executor").mkdir(mode=0o700)
        (directory / "runtime").mkdir(mode=0o750)
        os.chown(directory / "runtime", 0, 10001)
        sys.path.insert(0, str(ROOT / "tests/fixtures"))
        from prepare import prepare_fixture
        active = prepare_fixture("bind-mount", directory / "services/game")
        (active / ".env").write_text("CTFM_FIXTURE_UID=10001\nCTFM_FIXTURE_GID=10001\n")
        os.chown(active / "data", 10001, 10001)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        base = "http://127.0.0.1:" + str(port)
        model = (active / "compose.yaml").read_text()
        require(model.count("  app:\n") == 1, "fixture schema changed")
        model = model.replace("  app:\n", "  app:\n    labels:\n      " + OWNER_LABEL + ": " + nonce + "\n")
        model = model.replace("      - target: 8080", "      - target: 8080\n        published: \"" + str(port) + "\"")
        (active / "compose.yaml").write_text(model)
        shutil.copytree(active, directory / "workspaces/game", ignore=shutil.ignore_patterns("data"))
        wrapper = directory / "config/compose-wrapper"
        wrapper.write_text("#!/bin/sh\nset -eu\nprintf '%s\\0' \"$@\" >> '" + str(directory / "config/compose-argv") + "'\n"
                           "for a in \"$@\"; do if [ -f '" + str(directory / "config/offline") + "' ] && { [ \"$a\" = build ] || [ \"$a\" = pull ]; }; then exit 97; fi; done\n"
                           "action=\nfor a in \"$@\"; do [ \"$a\" != up ] || action=up; done\n"
                           "if [ \"$action\" = up ] && [ -f '" + str(directory / "config/gate") + "' ]; then touch '" + str(directory / "config/gate-reached") + "'; while [ -f '" + str(directory / "config/gate") + "' ]; do sleep .05; done; fi\n"
                           "exec /usr/local/libexec/docker/cli-plugins/docker-compose \"$@\"\n")
        wrapper.chmod(0o700)
        git_wrapper = directory / "config/git-wrapper"
        git_wrapper.write_text("#!/bin/sh\nset -eu\nprintf '%s\\0' \"$@\" >> '" + str(directory / "config/git-argv") + "'\n"
                               "if [ -f '" + str(directory / "config/offline") + "' ]; then exit 98; fi\nexec /usr/bin/git \"$@\"\n")
        git_wrapper.chmod(0o755)
        git_argv = directory / "config/git-argv"
        git_argv.touch(mode=0o600)
        os.chown(git_argv, 65534, 65534)
        config = {"state_directory": str(directory / "executor"), "socket": str(directory / "runtime/executor.sock"),
                  "docker_host": "unix:///var/run/docker.sock", "docker_binary": "/usr/local/bin/docker",
                  "compose_binary": str(wrapper), "discovery_roots": [str(directory / "services")],
                  "workspace_roots": [str(directory / "workspaces")], "web_uid": 10001, "development": False}
        (directory / "config/executor.json").write_text(json.dumps(config))
        (directory / "config/executor.json").chmod(0o600)
        compose = [*host.docker, "compose", "--project-name", project, "--file", str(active / "compose.yaml")]
        build_tag = project + "-app:latest"
        # Register exact names before Compose so partial startup can be cleaned.
        run([*compose, "up", "--detach", "--build"], timeout=300)
        tags[build_tag] = host.json("image", "inspect", build_tag)[0]["Id"]
        network = host.json("network", "inspect", project + "_default")[0]
        require(network.get("Labels", {}).get("com.docker.compose.project") == project, "fixture network identity mismatch")
        network_id = network["Id"]
        ready()
        flag, state_value = "CTFM_TEST_FLAG_" + nonce, "CTFM_TEST_STATE_" + nonce
        http("PUT", "/flags/" + nonce, flag)
        http("PUT", "/state/" + nonce, state_value)
        initial_version = http("GET", "/version")
        data_inode = (active / "data").stat().st_ino
        host.command("run", "--detach", "--name", executor_name, "--label", OWNER_LABEL + "=" + nonce,
                     "--user", "0:10001", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
                     "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
                     "--security-opt", "no-new-privileges:true", "--stop-timeout", "2",
                     "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777",
                     "--mount", f"type=bind,source={directory},target={directory}",
                     "--mount", f"type=bind,source={host.socket},target=/var/run/docker.sock",
                     "--mount", f"type=bind,source={git_wrapper},target=/usr/local/bin/git,readonly",
                     image_id, "--config", directory / "config/executor.json", "executor")
        executor_ready()
        report["executor_platform_checks"] = cli_json("doctor")
        require(next(item["detail"] for item in report["executor_platform_checks"] if item["name"] == "platform")
                == "linux/amd64", "executor binary did not report native Linux/amd64")
        own_snapshot()
        inventory = cli_json("inventory", "--project", project)
        require(len(inventory) == 1 and inventory[0]["component"] == "app", "fixture component mismatch")
        initial = inventory[0]
        policy = {"schema_version": 1, "id": service_id, "name": "Native daemon fixture " + nonce,
                  "project_directory": str(active), "source_directory": str(directory / "workspaces/game"),
                  "compose_project": project, "compose_files": ["compose.yaml"],
                  "managed_paths": [{"path": "code", "kind": "code"}, {"path": "compose.yaml", "kind": "configuration"}, {"path": ".env", "kind": "configuration"}],
                  "data_paths": [{"name": "data", "kind": "bind", "source": str(active / "data"), "target": "/data", "component": "app", "significant": True, "loss_accepted": False},
                                 {"name": "layer", "kind": "writable_layer", "target": "/tmp", "component": "app", "significant": False, "loss_accepted": True}],
                  "targets": ["app"], "containers": [{"component": "app", "id": initial["id"], "image_id": initial["image_id"], "role": "application"}],
                  "policy_revision": 1, "file_map_revision": 1}
        proposal = cli_json("propose", "--service", request_file("service.json", policy))
        cli_json("approve", "--proposal", proposal["id"], "--digest", proposal["digest"])
        operation("snapshot")
        baseline = cli_json("service", "--service", service_id)["current_release_id"]
        (directory / "workspaces/game/code/VERSION").write_text("native-target-" + nonce + "\n")
        operation("prepare")
        candidate = cli_json("service", "--service", service_id)["candidate_id"]
        operation("build", candidate_id=candidate)
        details = cli_json("service", "--service", service_id)
        target = next(item for item in details["releases"] if item["id"] != baseline)
        for release in details["releases"]:
            for image in release["images"]:
                tags[image["retention_tag"]] = image["image_id"]
        (directory / "config/gate").touch()
        value, path = prepare_request("deploy", release_id=target["id"], confirm_data_compatibility=True)
        accepted = cli_json("submit", "--request", path)
        identity = accepted["spec"]["id"]
        until = time.monotonic() + 90
        while not (directory / "config/gate-reached").exists():
            require(time.monotonic() < until, "Compose gate not reached")
            time.sleep(.1)
        before = database_operation(identity)
        require(before["operation"]["state"] == "running" and before["operation"]["mutation_started"] and before["locks"], "gate lacks durable mutation/locks")
        require((active / "code/VERSION").read_text().strip() == "native-target-" + nonce, "gate is not after real file Apply")
        expected = own_snapshot()
        game = next(item for item in expected.values() if item["Name"] != "/" + executor_name)
        require(not game["State"]["Running"], "game was not stopped before daemon restart")
        old_identity = host.identity()
        require_owned_containers(host.containers(), expected, nonce)
        report["restart_checkpoint"] = {"daemon_before": old_identity, "durable": before,
                                         "application_stopped": True, "target_files_applied": True}
        save()
        restart_attempted = True
        run(["systemctl", "restart", "docker.service"], timeout=90)
        until = time.monotonic() + 60
        while host.command("info", success=False, timeout=10).returncode:
            require(time.monotonic() < until, "Docker failed to return after real restart")
            time.sleep(.5)
        new_identity = host.identity()
        require(old_identity != new_identity and old_identity["pid"] != new_identity["pid"], "docker.service was not replaced")
        current_info = host.json("info", "--format", "{{json .}}")
        require(current_info["ID"] == host.info["ID"] and current_info["DockerRootDir"] == host.info["DockerRootDir"], "daemon restart changed identity/storage")
        require_owned_containers(host.containers(), expected, nonce)
        (directory / "config/gate").unlink()
        host.command("start", executor_name)
        executor_ready()
        unresolved = cli_json("operation", "--operation", identity)
        require(unresolved["state"] in ("interrupted", "requires_recovery") and unresolved["mutation_started"], "daemon restart falsely finalized operation")
        require(database_operation(identity)["locks"] == before["locks"], "daemon restart lost unresolved locks")
        time.sleep(.8)
        unchanged = host.containers()
        require_owned_containers(unchanged, expected, nonce)
        require(not unchanged[game["Id"]]["State"]["Running"], "executor blindly restarted game")
        require((active / "code/VERSION").read_text().strip() == "native-target-" + nonce, "executor blindly replayed files")
        require(cli_json("submit", "--request", path)["spec"]["id"] == identity, "retry duplicated interrupted deployment")
        _, recovery_path = prepare_request("recover", recovery_operation_id=identity, confirm_data_compatibility=True)
        recovery = cli_json("submit", "--request", recovery_path)
        require(recovery["spec"]["id"] == identity, "recovery lost original operation identity")
        recovered = wait_operation(identity, {"failed"}, recovery["updated_at"])
        require(recovered["outcome"]["returned_to_previous"] and not database_operation(identity)["locks"], "recovery not confirmed or locks remain")
        ready()
        check_data()
        require(http("GET", "/version") == initial_version and cli_json("service", "--service", service_id)["current_release_id"] == baseline, "wrong baseline after recovery")
        report["daemon_restart"] = {"before": old_identity, "after": new_identity, "operation_id": identity,
                                    "unresolved_after_restart": unresolved["state"], "locks_preserved": True,
                                    "no_blind_replay": True, "fresh_recover": recovered,
                                    "flags_state_and_data_bind_preserved": True}
        report["checks"]["actual_daemon_restart_preserves_recovery_path_and_data"] = True
        operation("deploy", release_id=target["id"], confirm_data_compatibility=True)
        ready()
        require(http("GET", "/version")["version"] == "native-target-" + nonce,
                "target was not actually serving before registry-offline rollback")
        require(cli_json("service", "--service", service_id)["current_release_id"] == target["id"],
                "target release not current before registry-offline rollback")
        later_key = nonce + "_later"
        http("PUT", "/state/" + later_key, "written-after-deploy")
        report["registry_connectivity_before_block"] = pull_probe(True)
        expected = own_snapshot()
        require_owned_containers(host.containers(), expected, nonce)
        (directory / "config/offline").touch(mode=0o644)
        compose_log = directory / "config/compose-argv"
        git_log = directory / "config/git-argv"
        compose_offset = compose_log.stat().st_size
        git_before = git_log.read_bytes() if git_log.exists() else b""
        block = RegistryBlock(nonce, args.ssh_server_port)
        block.begin()
        before_counters = block.counters()
        report["blocked_daemon_pull"] = pull_probe(False)
        after_counters = block.counters()
        require(sum(after_counters.values()) > sum(before_counters.values()), "blocked daemon pull did not hit registry rejection rule")
        started = time.monotonic()
        rolled_back = operation("rollback", release_id=baseline, confirm_data_compatibility=True)
        block.assert_active()
        ready()
        check_data()
        require(http("GET", "/state/" + later_key)["value"] == "written-after-deploy", "rollback lost data created after Deploy")
        require(http("GET", "/version") == initial_version, "offline rollback did not restore baseline files")
        require((active / "data").stat().st_ino == data_inode, "data bind directory changed")
        actual = cli_json("inventory", "--project", project)
        require(actual[0]["image_id"] == initial["image_id"], "offline rollback did not use exact baseline image")
        argv = compose_log.read_bytes()[compose_offset:].split(b"\0")
        require(b"up" in argv and b"--no-build" in argv and b"--pull" in argv and b"never" in argv,
                "rollback Compose invocation is not local-only")
        require(b"build" not in argv and b"pull" not in argv, "rollback attempted build/pull")
        require((git_log.read_bytes() if git_log.exists() else b"") == git_before, "rollback invoked Git")
        report["offline_rollback"] = {"operation": rolled_back, "seconds": time.monotonic() - started,
                                      "counter_scope": "entire dedicated host OUTPUT; before/after counters correlated with blocked real daemon pull",
                                      "before_rejected_packets": before_counters, "after_pull_rejected_packets": after_counters,
                                      "end_rejected_packets": block.counters(), "both_ip_families_blocked": True,
                                      "cached_exact_image": True, "build_pull_git_not_called": True,
                                      "initial_and_after_deploy_data_preserved": True}
        report["firewall_cleanup"] = block.restore()
        require(not report["firewall_cleanup"]["watchdog_fired"], "offline window expired before verification")
        (directory / "config/offline").unlink()
        report["registry_connectivity_after_cleanup"] = pull_probe(True)
        report["checks"]["daemon_registry_blocked_but_exact_local_rollback_succeeds"] = True
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = str(error)
        if host and created_directory:
            try:
                report["executor_log_tail"] = host.command("logs", "--tail", "40", executor_name,
                                                           success=False, timeout=10).stdout[-6000:]
            except BaseException as log_error:
                report["executor_log_error"] = str(log_error)
    finally:
        cleanup_errors = []
        if block and block.armed:
            try:
                report["firewall_cleanup"] = block.restore()
            except BaseException as error:
                cleanup_errors.append("firewall: " + str(error))
        if host and created_directory:
            try:
                if restart_attempted and host.command("info", success=False, timeout=10).returncode:
                    run(["systemctl", "start", "docker.service"], timeout=90)
                current = host.containers()
                for identity, item in current.items():
                    if item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == nonce and item["Name"] in ("/" + executor_name, "/" + project + "-app-1"):
                        host.command("rm", "--force", identity)
                observed_network = host.command("network", "inspect", network_id or project + "_default", success=False)
                if observed_network.returncode == 0:
                    network = json.loads(observed_network.stdout)[0]
                    require(network.get("Labels", {}).get("com.docker.compose.project") == project, "network owner changed")
                    host.command("network", "rm", network["Id"])
                # Compose may create its tag before reporting a failed startup.
                observed_build = host.command("image", "inspect", project + "-app:latest", success=False)
                if observed_build.returncode == 0:
                    tags.setdefault(project + "-app:latest", json.loads(observed_build.stdout)[0]["Id"])
                refs = host.command("image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter",
                                    "reference=ctf-manager/" + service_id + ":*").stdout.splitlines()
                for ref in refs:
                    require(ref.startswith("ctf-manager/" + service_id + ":"), "unexpected retention namespace")
                    tags.setdefault(ref, host.json("image", "inspect", ref)[0]["Id"])
                for tag, image_id in tags.items():
                    observed = host.command("image", "inspect", tag, success=False)
                    if observed.returncode == 0:
                        require(json.loads(observed.stdout)[0]["Id"] == image_id, "owned image tag identity changed")
                        host.command("image", "rm", "--no-prune", tag)
                remaining = [item["Id"] for item in host.containers().values()
                             if item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == nonce]
                require(not remaining, "owned container remains")
                require(directory.parent == Path("/srv") and directory.name == project and directory.stat().st_uid == 0,
                        "refuse unsafe directory cleanup")
                shutil.rmtree(directory)
                report["cleanup"] = {"own_containers_removed": True, "own_network_removed": True,
                                     "own_tags_removed": True, "own_native_directory_removed": True}
            except BaseException as error:
                cleanup_errors.append("fixture: " + str(error))
        if lock:
            lock.close()
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            report["status"] = "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
    print(json.dumps({key: report.get(key) for key in ("status", "checks", "error", "cleanup_errors")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt("SIGTERM")))
    raise SystemExit(main())
