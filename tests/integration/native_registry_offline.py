#!/usr/bin/env python3
"""Registry-offline acceptance beside explicitly inventoried persistent games.

Capture and review a private protected inventory first, then pass that exact file
with --dedicated-host. No daemon/containerd/VM restart or game operation occurs.
Only this run's UUID synthetic fixture is registered and switched. Host OUTPUT
TCP80/443 is temporarily denied, with SSH and exact protected-container IP
exceptions. A root-owned systemd watchdog is armed before either family changes.
Importing this module performs no Docker, network or filesystem mutations.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from native_daemon_smoke import (NativeHost, OWNER_LABEL, RegistryBlock, TERMINAL,
                                 cleanup_program, require, run, safe_host_lock,
                                 ssh_server_port)

ROOT = Path(__file__).resolve().parents[2]
GIB = 1024**3


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def private_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "inventory must be a root-owned 0600 regular file without aliases")
        return json.load(source)


def write_json(path, value, *, new=False):
    """Private atomic report; a capture never overwrites an existing review."""
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "output must be an absolute non-symlink path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent
    while parent != parent.parent:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, "output ancestors must be real root-owned directories without group/world write")
        parent = parent.parent
    if new:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "w") as target:
            json.dump(value, target, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        return
    if path.exists():
        private_json(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w") as target:
        json.dump(value, target, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    temporary.replace(path)


def selected_labels(labels):
    return {key: value for key, value in (labels or {}).items()
            if key.startswith("com.docker.compose.") or key == OWNER_LABEL}


def container_view(item):
    state = item.get("State") or {}
    networks = item.get("NetworkSettings", {}).get("Networks") or {}
    return {
        "id": item["Id"], "name": item["Name"], "image_id": item["Image"],
        "started_at": state.get("StartedAt"), "running": state.get("Running"),
        "status": state.get("Status"), "pid": state.get("Pid"),
        "oom_killed": state.get("OOMKilled"), "restart_count": item.get("RestartCount"),
        "config_digest": digest(item.get("Config")), "host_config_digest": digest(item.get("HostConfig")),
        "labels": selected_labels(item.get("Config", {}).get("Labels")),
        "ports": item.get("NetworkSettings", {}).get("Ports") or {},
        "mounts": sorted([{key: mount.get(key) for key in
                           ("Type", "Name", "Source", "Destination", "Driver", "Mode", "RW", "Propagation")}
                          for mount in item.get("Mounts", [])], key=lambda value: (value["Destination"] or "", value["Type"] or "")),
        "networks": {name: {key: network.get(key) for key in
                            ("NetworkID", "EndpointID", "IPAddress", "IPPrefixLen", "GlobalIPv6Address", "GlobalIPv6PrefixLen", "MacAddress")}
                     for name, network in sorted(networks.items())},
    }


def image_view(item):
    # Credentials/environment never enter the inventory. Hash immutable layers.
    return {"id": item["Id"], "os": item.get("Os"), "architecture": item.get("Architecture"),
            "rootfs_digest": digest(item.get("RootFS")),
            "repo_tags": sorted(item.get("RepoTags") or [])}


def network_view(item):
    return {"id": item["Id"], "name": item["Name"], "driver": item.get("Driver"),
            "scope": item.get("Scope"), "created": item.get("Created"),
            "internal": item.get("Internal"), "enable_ipv4": item.get("EnableIPv4"),
            "enable_ipv6": item.get("EnableIPv6"), "ipam_digest": digest(item.get("IPAM")),
            "options_digest": digest(item.get("Options")), "labels": selected_labels(item.get("Labels"))}


def volume_view(item):
    return {"name": item["Name"], "driver": item.get("Driver"), "scope": item.get("Scope"),
            "created_at": item.get("CreatedAt"), "mountpoint": item.get("Mountpoint"),
            "options_digest": digest(item.get("Options")), "labels": selected_labels(item.get("Labels"))}


def inspect_objects(host, kind):
    parts = ("image", "ls", "--all", "--quiet", "--no-trunc") if kind == "image" else (kind, "ls", "--quiet")
    identities = sorted(set(host.command(*parts).stdout.split()))
    return host.json(kind, "inspect", *identities) if identities else []


def capture_inventory(host, expected_count):
    containers = host.containers()
    require(len(containers) == expected_count, "protected inventory container count differs from explicit expected count")
    for item in containers.values():
        state = item.get("State") or {}
        require(state.get("Running") and not state.get("OOMKilled")
                and (state.get("Health") or {}).get("Status", "healthy") == "healthy",
                "all protected containers must already be running and healthy")
        require(item.get("HostConfig", {}).get("NetworkMode") != "host",
                "host-network protected containers need a separately reviewed exception policy")
        require(not item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL),
                "do not adopt a leftover native acceptance fixture as persistent inventory")
    result = {"schema_version": 1, "test": "protected-native-registry-inventory",
              "captured_at": datetime.now(timezone.utc).isoformat(),
              "host": {key: host.info.get(key) for key in ("ID", "DockerRootDir", "KernelVersion", "OSType", "Architecture")},
              "daemon": host.identity(), "expected_container_count": expected_count,
              "containers": {identity: container_view(item) for identity, item in containers.items()},
              "images": {item["Id"]: image_view(item) for item in inspect_objects(host, "image")},
              "networks": {item["Id"]: network_view(item) for item in inspect_objects(host, "network")},
              "volumes": {item["Name"]: volume_view(item) for item in inspect_objects(host, "volume")}}
    protected_destinations(result["containers"])
    return result


def protected_destinations(containers):
    """Exact verified IPs only: OUTPUT is evaluated after Docker's OUTPUT DNAT."""
    result, owners = {4: set(), 6: set()}, {}
    for identity, item in containers.items():
        for network in item["networks"].values():
            for field, family in (("IPAddress", 4), ("GlobalIPv6Address", 6)):
                raw = network.get(field)
                if not raw:
                    continue
                address = ipaddress.ip_address(raw)
                require(address.version == family and not address.is_unspecified
                        and not address.is_multicast and not address.is_loopback, "unusable protected Docker destination")
                normalized = str(address)
                require(normalized not in owners or owners[normalized] == identity,
                        "ambiguous Docker destination shared by distinct protected containers")
                owners[normalized] = identity
                result[family].add(normalized)
    require(sum(map(len, result.values())) <= 128, "protected destination budget exceeded")
    return {family: sorted(addresses) for family, addresses in result.items()}


def destination_rules(common, addresses, family, comment):
    rules = [common[0]]
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        require(address.version == family and "/" not in raw, "firewall exception family mismatch or CIDR")
        rules.append(["-p", "tcp", "-d", str(address) + ("/32" if family == 4 else "/128"),
                      "-m", "comment", "--comment", comment, "-j", "RETURN"])
    return [*rules, common[1]]


def family_cleanup_program(rules_by_backend, chain, comment, marker):
    """Reuse the reviewed exact-rule cleanup independently for each backend."""
    programs = [cleanup_program([binary], chain, comment, rules, marker)
                for binary, rules in rules_by_backend.items()]
    # Each embedded cleanup raises SystemExit; preserve errors across families.
    return ("#!/usr/bin/env python3\nimport sys\nprograms=" + repr(programs)
            + "\nfailed=False\nfor source in programs:\n"
              " try:exec(compile(source,'private-firewall-cleanup','exec'),{'__name__':'__main__'})\n"
              " except SystemExit as error:failed=failed or error.code not in (None,0)\n"
              " except BaseException:failed=True\n"
              "raise SystemExit(1 if failed else 0)\n")


class ProtectedRegistryBlock(RegistryBlock):
    def __init__(self, nonce, ssh_port, destinations, run_command=run):
        super().__init__(nonce, ssh_port, run_command=run_command)
        self.rules_by_backend = {
            binary: destination_rules(self.rules, destinations[family], family, self.comment)
            for binary, family in zip(self.backends, (4, 6))}

    def begin(self):
        self.directory.mkdir(mode=0o700)
        require(self.directory.stat().st_uid == 0, "watchdog directory must be root owned")
        for binary in self.backends:
            self.run([binary, "-w", "5", "-S", "OUTPUT"])
            require(self.run([binary, "-w", "5", "-S", self.chain], success=False).returncode == 1,
                    "private firewall chain exists or cannot be safely inspected")
        self.script.write_text(family_cleanup_program(self.rules_by_backend, self.chain, self.comment, self.marker))
        self.script.chmod(0o700)
        self.arm_watchdog()
        try:
            for binary, rules in self.rules_by_backend.items():
                self.run([binary, "-w", "5", "-N", self.chain])
                for rule in rules:
                    self.run([binary, "-w", "5", "-A", self.chain, *rule])
                self.run([binary, "-w", "5", "-I", "OUTPUT", "1", "-m", "comment",
                          "--comment", self.comment, "-j", self.chain])
            self.active = True
            self.assert_active()
        except BaseException:
            self.restore()
            raise

    def assert_active(self):
        require(self.active and not self.marker.exists(), "registry block inactive or watchdog expired")
        for binary, rules in self.rules_by_backend.items():
            self.run([binary, "-w", "5", "-C", "OUTPUT", "-m", "comment", "--comment", self.comment, "-j", self.chain])
            for rule in rules:
                self.run([binary, "-w", "5", "-C", self.chain, *rule])


def assert_protected(host, protected, nonce=None, project=None):
    require(protected.get("schema_version") == 1 and protected.get("test") == "protected-native-registry-inventory",
            "unexpected protected inventory format")
    require(len(protected["containers"]) == protected["expected_container_count"], "invalid protected container count")
    require(host.identity() == protected["daemon"], "daemon identity changed; no restart is authorized")
    info = host.json("info", "--format", "{{json .}}")
    require({key: info.get(key) for key in protected["host"]} == protected["host"], "protected daemon host identity changed")
    current = host.containers()
    for identity, expected in protected["containers"].items():
        require(identity in current and container_view(current[identity]) == expected,
                "protected container identity, state, configuration, mounts or endpoint changed: " + expected["name"])
        state = current[identity].get("State") or {}
        require((state.get("Health") or {}).get("Status", "healthy") == "healthy", "protected container became unhealthy")
    extras = {identity: item for identity, item in current.items() if identity not in protected["containers"]}
    for item in extras.values():
        require(nonce and project and item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == nonce
                and item["Name"] in ("/" + project + "-app-1", "/" + project + "-executor"),
                "unreviewed extra container; refusing host-wide registry block")
    require(len(extras) <= 2, "unexpected synthetic component count")
    for identity, expected in protected["images"].items():
        observed = host.json("image", "inspect", identity)[0]
        actual = image_view(observed)
        # A private tag for an identical fixture may be added, never remove any
        # protected tag or replace the immutable image/layer identity.
        require(all(actual[key] == expected[key] for key in ("id", "os", "architecture", "rootfs_digest"))
                and set(expected["repo_tags"]) <= set(actual["repo_tags"]), "protected image or original tags changed")
    volumes = {item["Name"]: volume_view(item) for item in inspect_objects(host, "volume")}
    require(volumes == protected["volumes"], "protected volume identity/options changed or unexpected volume created")
    networks = {item["Id"]: item for item in inspect_objects(host, "network")}
    for identity, expected in protected["networks"].items():
        require(identity in networks and network_view(networks[identity]) == expected, "protected network identity/options changed")
    for identity, item in networks.items():
        if identity not in protected["networks"]:
            require(nonce and item.get("Labels", {}).get(OWNER_LABEL) == nonce
                    and item.get("Labels", {}).get("com.docker.compose.project") == project,
                    "unexpected non-protected network")
    return {"protected_container_count": len(protected["containers"]), "own_container_count": len(extras),
            "container_ids_images_pids_started_at_mounts_endpoints_unchanged": True,
            "original_image_tags_preserved": True, "volume_and_network_identity_preserved": True}


def resource_preflight(directory, minimum_memory_mib, minimum_free_mib):
    memory = {key.rstrip(":"): int(value) * 1024 for key, value, *_ in
              (line.split() for line in Path("/proc/meminfo").read_text().splitlines())}
    space = os.statvfs(directory)
    require(memory["MemAvailable"] >= minimum_memory_mib * 1024**2, "insufficient MemAvailable for additional bounded fixture")
    require(space.f_bavail * space.f_frsize >= minimum_free_mib * 1024**2 and space.f_favail >= 1024,
            "insufficient free bytes/inodes; protected artifacts are never pruned")
    return {"mem_available_bytes": memory["MemAvailable"], "free_bytes": space.f_bavail * space.f_frsize,
            "free_inodes": space.f_favail}


def validate_http_control(url, protected):
    address = urllib.parse.urlsplit(url)
    require(address.scheme == "http" and address.hostname == "127.0.0.1"
            and not address.username and not address.password and not address.query and not address.fragment,
            "HTTP control must be an explicit loopback HTTP URL without credentials or query")
    port = address.port or 80
    matches = [(identity, item) for identity, item in protected["containers"].items()
               if any(re.fullmatch(r"[0-9]+/tcp", target)
                      and binding.get("HostIp") in ("127.0.0.1", "0.0.0.0", "")
                      and binding.get("HostPort") == str(port)
                      for target, bindings in item.get("ports", {}).items() for binding in bindings or [])]
    require(len(matches) == 1, "HTTP control must match exactly one protected Docker TCP publication")
    require(any(network.get("IPAddress") for network in matches[0][1]["networks"].values()),
            "HTTP control has no protected IPv4 destination")
    return matches[0][0]


def http_control(url):
    # Fixed GET selected by the operator; no redirects or cookies, body hashed
    # rather than copied to the report. This verifies OUTPUT-DNAT exceptions.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise RuntimeError("protected HTTP control redirect refused")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=5) as response:
        content = response.read(256 * 1024 + 1)
        require(response.status == 200 and len(content) <= 256 * 1024, "protected HTTP control status/size invalid")
        return {"status": response.status, "bytes": len(content), "body_sha256": hashlib.sha256(content).hexdigest()}


class Fixture:
    def __init__(self, host, protected, nonce, image_id, report):
        self.host, self.protected, self.nonce, self.image_id, self.report = host, protected, nonce, image_id, report
        self.project = "ctfm-registry-offline-" + nonce
        self.service_id = "registry-offline-" + nonce
        self.directory = Path("/srv") / self.project
        self.active = self.directory / "services/game"
        self.executor = self.project + "-executor"
        self.tags, self.created = {}, False
        self.block = None
        self.http_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def guard(self):
        return assert_protected(self.host, self.protected, self.nonce, self.project)

    def cli(self, *parts, success=True):
        return self.host.command("exec", self.executor, "/usr/local/bin/ctf-manager", "--config",
                                 self.directory / "config/executor.json", *parts, success=success)

    def cj(self, *parts):
        return json.loads(self.cli(*parts).stdout)

    def request_file(self, value):
        path = self.directory / "requests/request.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return str(path)

    def operation(self, action, **fields):
        self.guard()
        value = {"service_id": self.service_id, "action": action, "initiator": "registry-offline-test",
                 "idempotency_key": uuid.uuid4().hex, **fields}
        path = self.request_file(value)
        value["plan_digest"] = self.cj("preview", "--request", path)["plan_digest"]
        self.request_file(value)
        accepted = self.cj("submit", "--request", path)
        until = time.monotonic() + 100
        while time.monotonic() < until:
            if self.block and self.block.active:
                self.block.assert_active()
            observed = self.cj("operation", "--operation", accepted["spec"]["id"])
            if observed["state"] in TERMINAL:
                require(observed["state"] == "succeeded", "synthetic operation did not succeed: " + action)
                require(self.cj("submit", "--request", path)["spec"]["id"] == observed["spec"]["id"], "idempotency identity changed")
                self.report.setdefault("operations", []).append(observed)
                self.guard()
                return observed
            time.sleep(.15)
        raise RuntimeError("synthetic operation deadline exceeded: " + action)

    def http(self, method, path, value=None):
        body = None if value is None else json.dumps({"value": value}).encode()
        request = urllib.request.Request(self.base + path, data=body, method=method, headers={"Content-Type": "application/json"})
        with self.http_opener.open(request, timeout=3) as response:
            require(response.status == 200, "synthetic HTTP failure")
            return json.load(response)

    def ready(self):
        until = time.monotonic() + 45
        while time.monotonic() < until:
            try:
                return self.http("GET", "/health")
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(.2)
        raise RuntimeError("synthetic readiness deadline exceeded")

    def setup(self):
        require(not self.host.command("image", "ls", "--quiet", "--filter", "reference=" + self.project + "*").stdout.strip(),
                "UUID image namespace already exists")
        require(not self.host.command("image", "ls", "--quiet", "--filter", "reference=ctf-manager/" + self.service_id + ":*").stdout.strip(),
                "UUID retention namespace already exists")
        self.directory.mkdir(mode=0o755)
        self.created = True
        for name in ("services", "workspaces", "config", "requests", "executor", "runtime"):
            (self.directory / name).mkdir(mode=0o750 if name == "runtime" else 0o700 if name in ("requests", "executor") else 0o755)
        os.chown(self.directory / "runtime", 0, 10001)
        sys.path.insert(0, str(ROOT / "tests/fixtures"))
        from prepare import prepare_fixture
        prepare_fixture("bind-mount", self.active)
        (self.active / ".env").write_text("CTFM_FIXTURE_UID=10001\nCTFM_FIXTURE_GID=10001\n")
        os.chown(self.active / "data", 10001, 10001)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        self.base = "http://127.0.0.1:" + str(port)
        model = (self.active / "compose.yaml").read_text()
        require(model.count("  app:\n") == 1, "fixture schema changed")
        model = model.replace("  app:\n", "  app:\n    labels:\n      " + OWNER_LABEL + ": " + self.nonce
                              + "\n    mem_limit: 128m\n    memswap_limit: 128m\n    cpus: 0.5\n    pids_limit: 96\n")
        model = model.replace("      - target: 8080", "      - target: 8080\n        published: \"" + str(port) + "\"")
        model += "\nnetworks:\n  default:\n    labels:\n      " + OWNER_LABEL + ": " + self.nonce + "\n"
        (self.active / "compose.yaml").write_text(model)
        shutil.copytree(self.active, self.directory / "workspaces/game", ignore=shutil.ignore_patterns("data"))
        config_dir = self.directory / "config"
        wrapper = config_dir / "compose-wrapper"
        wrapper.write_text("#!/bin/sh\nset -eu\nprintf '%s\\0' \"$@\" >> '" + str(config_dir / "compose-argv") + "'\n"
                           "for a in \"$@\"; do if [ -f '" + str(config_dir / "offline")
                           + "' ] && { [ \"$a\" = build ] || [ \"$a\" = pull ]; }; then exit 97; fi; done\n"
                           "exec /usr/local/libexec/docker/cli-plugins/docker-compose \"$@\"\n")
        wrapper.chmod(0o700)
        git_wrapper = config_dir / "git-wrapper"
        git_wrapper.write_text("#!/bin/sh\nset -eu\nprintf '%s\\0' \"$@\" >> '" + str(config_dir / "git-argv") + "'\n"
                               "if [ -f '" + str(config_dir / "offline") + "' ]; then exit 98; fi\nexec /usr/bin/git \"$@\"\n")
        git_wrapper.chmod(0o755)
        git_log = config_dir / "git-argv"
        git_log.touch(mode=0o600)
        os.chown(git_log, 65534, 65534)
        config = {"state_directory": str(self.directory / "executor"), "socket": str(self.directory / "runtime/executor.sock"),
                  "docker_host": "unix:///var/run/docker.sock", "docker_binary": "/usr/local/bin/docker",
                  "compose_binary": str(wrapper), "discovery_roots": [str(self.directory / "services")],
                  "workspace_roots": [str(self.directory / "workspaces")], "web_uid": 10001, "development": False}
        (config_dir / "executor.json").write_text(json.dumps(config))
        (config_dir / "executor.json").chmod(0o600)
        self.host.command("compose", "--parallel", "1", "--project-name", self.project,
                          "--file", self.active / "compose.yaml", "up", "--detach", "--build", timeout=300)
        self.tags[self.project + "-app:latest"] = self.host.json("image", "inspect", self.project + "-app:latest")[0]["Id"]
        self.ready()
        self.host.command("run", "--detach", "--name", self.executor, "--label", OWNER_LABEL + "=" + self.nonce,
                          "--user", "0:10001", "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
                          "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
                          "--security-opt", "no-new-privileges:true", "--memory", "384m", "--memory-swap", "384m",
                          "--cpus", "1", "--pids-limit", "256",
                          "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777",
                          "--mount", f"type=bind,source={self.directory},target={self.directory}",
                          "--mount", f"type=bind,source={self.host.socket},target=/var/run/docker.sock",
                          "--mount", f"type=bind,source={git_wrapper},target=/usr/local/bin/git,readonly",
                          self.image_id, "--config", config_dir / "executor.json", "executor")
        until = time.monotonic() + 30
        while self.cli("status", success=False).returncode:
            require(time.monotonic() < until, "synthetic executor readiness deadline exceeded")
            time.sleep(.2)
        self.guard()
        initial = self.cj("inventory", "--project", self.project)
        require(len(initial) == 1 and initial[0]["component"] == "app", "unexpected synthetic components")
        self.initial_image = initial[0]["image_id"]
        policy = {"schema_version": 1, "id": self.service_id, "name": "Registry offline " + self.nonce,
                  "project_directory": str(self.active), "source_directory": str(self.directory / "workspaces/game"),
                  "compose_project": self.project, "compose_files": ["compose.yaml"],
                  "managed_paths": [{"path": "code", "kind": "code"}, {"path": "compose.yaml", "kind": "configuration"}, {"path": ".env", "kind": "configuration"}],
                  "data_paths": [{"name": "data", "kind": "bind", "source": str(self.active / "data"), "target": "/data", "component": "app", "significant": True, "loss_accepted": False},
                                 {"name": "layer", "kind": "writable_layer", "target": "/tmp", "component": "app", "significant": False, "loss_accepted": True}],
                  "targets": ["app"], "containers": [{"component": "app", "id": initial[0]["id"], "image_id": self.initial_image, "role": "application"}],
                  "policy_revision": 1, "file_map_revision": 1}
        proposal = self.cj("propose", "--service", self.request_file(policy))
        self.cj("approve", "--proposal", proposal["id"], "--digest", proposal["digest"])
        self.operation("snapshot")
        self.baseline = self.cj("service", "--service", self.service_id)["current_release_id"]
        self.initial_version = self.http("GET", "/version")
        self.http("PUT", "/flags/" + self.nonce, "synthetic-flag-" + self.nonce)
        (self.directory / "workspaces/game/code/VERSION").write_text("offline-target-" + self.nonce + "\n")
        self.operation("prepare")
        candidate = self.cj("service", "--service", self.service_id)["candidate_id"]
        self.operation("build", candidate_id=candidate)
        details = self.cj("service", "--service", self.service_id)
        target = next(item for item in details["releases"] if item["id"] != self.baseline)
        for release in details["releases"]:
            for image in release["images"]:
                self.tags[image["retention_tag"]] = image["image_id"]
        self.operation("deploy", release_id=target["id"], confirm_data_compatibility=True)
        self.ready()
        require(self.http("GET", "/version")["version"] == "offline-target-" + self.nonce, "synthetic Deploy not observed")
        self.http("PUT", "/state/" + self.nonce, "written-after-deploy")
        self.data_inode = (self.active / "data").stat().st_ino

    def rollback(self):
        (self.directory / "config/offline").touch(mode=0o644)
        compose_log, git_log = (self.directory / "config" / name for name in ("compose-argv", "git-argv"))
        offset, git_before = compose_log.stat().st_size, git_log.read_bytes()
        started = time.monotonic()
        self.operation("rollback", release_id=self.baseline, confirm_data_compatibility=True)
        self.ready()
        self.block.assert_active()
        require(self.http("GET", "/version") == self.initial_version, "offline Rollback version mismatch")
        require(self.http("GET", "/flags/" + self.nonce)["value"] == "synthetic-flag-" + self.nonce
                and self.http("GET", "/state/" + self.nonce)["value"] == "written-after-deploy", "offline Rollback lost synthetic data")
        require((self.active / "data").stat().st_ino == self.data_inode, "synthetic data bind directory changed")
        require(self.cj("inventory", "--project", self.project)[0]["image_id"] == self.initial_image, "Rollback image not exact baseline")
        arguments = compose_log.read_bytes()[offset:].split(b"\0")
        require(all(value in arguments for value in (b"up", b"--no-build", b"--pull", b"never"))
                and b"build" not in arguments and b"pull" not in arguments, "Rollback attempted non-local Compose execution")
        require(git_log.read_bytes() == git_before, "Rollback invoked Git")
        return {"seconds": time.monotonic() - started, "cached_exact_image": True,
                "build_pull_git_not_called": True, "before_and_after_deploy_data_preserved": True}

    def cleanup(self):
        if not self.created:
            return {"not_created": True}
        for identity, item in self.host.containers().items():
            if identity in self.protected["containers"]:
                continue
            if item.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == self.nonce:
                require(item["Name"] in ("/" + self.project + "-app-1", "/" + self.executor), "unexpected own cleanup component")
                self.host.command("rm", "--force", identity)
        for network in inspect_objects(self.host, "network"):
            if network["Id"] in self.protected["networks"]:
                continue
            if network.get("Labels", {}).get(OWNER_LABEL) == self.nonce:
                require(network.get("Labels", {}).get("com.docker.compose.project") == self.project, "owned network project mismatch")
                self.host.command("network", "rm", network["Id"])
        # Discover partial startup/build tags only inside namespaces absent at preflight.
        for pattern in (self.project + "-*", "ctf-manager/" + self.service_id + ":*"):
            refs = self.host.command("image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "reference=" + pattern).stdout.splitlines()
            for reference in refs:
                self.tags.setdefault(reference, self.host.json("image", "inspect", reference)[0]["Id"])
        for reference, identity in self.tags.items():
            observed = self.host.command("image", "inspect", reference, success=False)
            if observed.returncode == 0:
                image = json.loads(observed.stdout)[0]
                require(image["Id"] == identity, "owned image tag changed")
                protected_image = self.protected["images"].get(identity)
                require(not protected_image or set(image.get("RepoTags") or []) - {reference}, "cannot remove last tag of preexisting image")
                self.host.command("image", "rm", "--no-prune", reference)
        self.guard()
        require(self.directory.parent == Path("/srv") and self.directory.name == self.project
                and self.directory.lstat().st_uid == 0 and not self.directory.is_symlink(), "unsafe synthetic directory cleanup")
        shutil.rmtree(self.directory)
        return {"own_containers_network_tags_directory_removed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dedicated-host", action="store_true", help="attest exclusive controlled use of this populated test VM")
    parser.add_argument("--capture-protected-inventory", type=Path, help="read-only Docker capture; write a new private file and exit")
    parser.add_argument("--protected-inventory", type=Path, help="reviewed root-owned 0600 inventory; required for fault run")
    parser.add_argument("--expected-protected-count", type=int, default=12)
    parser.add_argument("--executor-image", default="ctf-manager-executor:local")
    parser.add_argument("--ssh-server-port", type=int)
    parser.add_argument("--min-available-memory-mib", type=int, default=768)
    parser.add_argument("--min-free-mib", type=int, default=1024)
    parser.add_argument("--protected-http-control", action="append",
                        help="GET of an exact protected loopback TCP publication; default current Bank http://127.0.0.1:18013/")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/native-registry-offline-2026-10-29.json")
    args = parser.parse_args()
    require(args.expected_protected_count > 0 and args.min_available_memory_mib >= 512 and args.min_free_mib >= 512,
            "invalid protection/resource bounds")
    require(bool(args.capture_protected_inventory) != bool(args.protected_inventory), "choose capture OR a reviewed protected inventory")
    host = NativeHost(args.dedicated_host)
    lock = safe_host_lock("/run/lock/ctfm-native-acceptance.lock")
    if args.capture_protected_inventory:
        inventory = capture_inventory(host, args.expected_protected_count)
        write_json(args.capture_protected_inventory, inventory, new=True)
        print(json.dumps({"status": "captured_only", "protected_count": len(inventory["containers"]),
                          "inventory": str(args.capture_protected_inventory), "sha256": digest(inventory)}))
        lock.close()
        return 0
    protected = private_json(args.protected_inventory)
    require(protected["expected_container_count"] == args.expected_protected_count, "explicit protected count differs from review")
    assert_protected(host, protected)
    controls = args.protected_http_control or ["http://127.0.0.1:18013/"]
    require(len(controls) == len(set(controls)) and 1 <= len(controls) <= 12, "invalid HTTP control set")
    for url in controls:
        validate_http_control(url, protected)
    nonce = uuid.uuid4().hex[:12]
    report = {"test": "native-registry-offline-preserving-populated-host", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(), "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_watchdog_harness_sha256": hashlib.sha256((ROOT / "tests/integration/native_daemon_smoke.py").read_bytes()).hexdigest(),
              "protected_inventory_sha256": digest(protected), "checks": {},
              "limitations": ["No Docker/containerd/VM restart; does not prove A15 daemon restart",
                              "Host OUTPUT TCP80/443 denial; exact protected Docker-IP exceptions preserve OUTPUT DNAT paths",
                              "Packet counters cover this dedicated host, correlated with an actual uncached daemon pull",
                              "Protected metadata/pids/health are compared; independent normal-player data probes/backup belong to the outer acceptance run",
                              "Synthetic bind-data Rollback; no claim of database migration rollback or physical power loss"]}
    fixture, block = None, None
    probe_ref = "docker.io/library/hello-world:latest"
    probe_tag_id = None
    def save():
        write_json(args.report, report)
    def probe(online):
        nonlocal probe_tag_id
        require(host.command("image", "inspect", probe_ref, success=False).returncode != 0, "probe tag already cached")
        result = host.command("pull", probe_ref, success=False, timeout=35)
        if online:
            require(result.returncode == 0, "registry connectivity positive control failed")
            image = host.json("image", "inspect", probe_ref)[0]
            probe_tag_id = image["Id"]
            original = protected["images"].get(probe_tag_id)
            require(not original or set(image.get("RepoTags") or []) - {probe_ref, "hello-world:latest"},
                    "probe aliases a preexisting untagged image; refuse removing its last tag")
            host.command("image", "rm", "--no-prune", probe_ref)
            probe_tag_id = None
            require(host.command("image", "inspect", probe_ref, success=False).returncode != 0, "probe tag remains cached")
            return {"exit_code": 0, "reference": probe_ref, "image_id": image["Id"], "tag_removed": True}
        output = (result.stderr + result.stdout).lower()
        categories = [item for item in ("connection refused", "connection reset", "network is unreachable", "no route to host", "timeout", "timed out", "eof") if item in output]
        require(result.returncode != 0 and categories, "blocked daemon pull did not fail with a network error")
        require(host.command("image", "inspect", probe_ref, success=False).returncode != 0, "blocked pull published an image")
        return {"exit_code": result.returncode, "reference": probe_ref, "network_error_categories": categories,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest()}
    try:
        require(host.command("image", "inspect", probe_ref, success=False).returncode != 0, "probe tag preexists; choose an uncached control before this run")
        report["protected_before"] = assert_protected(host, protected)
        control_before = {url: http_control(url) for url in controls}
        report["protected_http_controls_before"] = control_before
        report["resources_before"] = resource_preflight("/srv", args.min_available_memory_mib, args.min_free_mib)
        image = host.json("image", "inspect", args.executor_image)[0]
        require(image["Os"] == "linux" and image["Architecture"] == "amd64", "executor image must be native Linux/amd64")
        report["executor_image_id"] = image["Id"]
        fixture = Fixture(host, protected, nonce, image["Id"], report)
        report.update(project=fixture.project, service_id=fixture.service_id,
                      synthetic_directory=str(fixture.directory),
                      synthetic_memory_caps_mib={"app": 128, "executor": 384},
                      protected_inventory_path=str(args.protected_inventory))
        fixture.setup()
        save()
        report["online_control_before"] = probe(True)
        destinations = protected_destinations(protected["containers"])
        # Registry endpoints must not overlap any exact Docker exception.
        for hostname in ("registry-1.docker.io", "auth.docker.io"):
            resolved = {str(ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
            require(resolved and not resolved.intersection(set(destinations[4]) | set(destinations[6])),
                    "registry DNS overlaps protected Docker destinations")
        report["protected_destinations"] = {str(key): value for key, value in destinations.items()}
        fixture.guard()
        report["resources_before_block"] = resource_preflight("/srv", args.min_available_memory_mib, args.min_free_mib)
        block = ProtectedRegistryBlock(nonce, ssh_server_port(args.ssh_server_port, os.environ.get("SSH_CONNECTION")), destinations)
        fixture.block = block
        report["phase"] = "before_registry_block"
        report["firewall_plan"] = {"chain": block.chain, "watchdog_unit": block.unit,
                                   "private_watchdog_directory": str(block.directory),
                                   "rules_by_backend": block.rules_by_backend}
        save()
        block.begin()
        report["protected_during_block"] = fixture.guard()
        require({url: http_control(url) for url in controls} == control_before,
                "protected loopback HTTP control changed during registry block")
        report["protected_http_controls_during_block"] = {"unchanged": True, "count": len(controls)}
        before = block.counters()
        report["blocked_daemon_pull"] = probe(False)
        after = block.counters()
        require(sum(after.values()) > sum(before.values()), "failed daemon pull did not hit REJECT rules")
        report["offline_rollback"] = fixture.rollback()
        report["reject_packets"] = {"before": before, "after_pull": after, "after_rollback": block.counters()}
        report["protected_after_rollback"] = fixture.guard()
        report["firewall_cleanup"] = block.restore()
        require(not report["firewall_cleanup"]["watchdog_fired"], "offline watchdog expired before verification")
        report["online_control_after"] = probe(True)
        require({url: http_control(url) for url in controls} == control_before,
                "protected loopback HTTP control changed after registry restoration")
        report["checks"] = {"actual_daemon_pull_blocked": True, "cached_local_rollback_preserves_synthetic_data": True,
                            "protected_containers_images_pids_started_at_mounts_volumes_networks_preserved": True,
                            "no_daemon_or_protected_container_restart": True}
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = str(error)
    finally:
        errors = []
        if block and block.armed:
            try:
                report["firewall_cleanup"] = block.restore()
            except BaseException as error:
                errors.append("firewall cleanup: " + str(error))
        if probe_tag_id:
            try:
                image = host.json("image", "inspect", probe_ref)[0]
                require(image["Id"] == probe_tag_id, "probe tag identity changed")
                require(probe_tag_id not in protected["images"] or set(image.get("RepoTags") or []) - {probe_ref, "hello-world:latest"},
                        "preexisting image retained; probe tag cannot safely be removed")
                host.command("image", "rm", "--no-prune", probe_ref)
            except BaseException as error:
                errors.append("probe cleanup: " + str(error))
        if fixture:
            try:
                report["fixture_cleanup"] = fixture.cleanup()
            except BaseException as error:
                errors.append("fixture cleanup: " + str(error))
        try:
            report["protected_final"] = assert_protected(host, protected)
            if "protected_http_controls_before" in report:
                require({url: http_control(url) for url in controls} == report["protected_http_controls_before"],
                        "protected HTTP control changed at final postflight")
            report["resources_after"] = resource_preflight("/srv", 512, 512)
        except BaseException as error:
            errors.append("protected postflight: " + str(error))
        if errors:
            report["cleanup_errors"] = errors
            report["status"] = "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["phase"] = "finished"
        save()
        lock.close()
    print(json.dumps({key: report.get(key) for key in ("status", "checks", "error", "cleanup_errors")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt("SIGTERM")))
    raise SystemExit(main())
