#!/usr/bin/env python3
"""Measure the actual Compose panel with five synthetic two-container services.

Only uniquely named fixture projects and a new /srv directory on the local
Docker daemon are used. The shared daemon is never restarted or reconfigured.
The default run lasts five measured minutes after warmup. It is deliberately
reported as an alternate-host result unless the reference host really matches.
"""
import argparse
import base64
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
import math
import os
import platform
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

from resource_profiles import (HOST_ONLINE_MEMORY_SOURCE, PROFILE_NAMES, acceptance_fields,
                               assess_resource_profile, hardware_matches, online_memory_from_lsmem)

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "isolated-observation-load-password"


def run(args, *, input=None, timeout=180, check=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
    result = subprocess.run(args, input=input, capture_output=True, text=True,
                            timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} {args[1:3]}: {(result.stderr + result.stdout)[-5000:]}")
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_host_online_memory(info):
    # On a macOS client /sys or lsmem would describe a different host. Docker's
    # local socket plus matching Linux kernel scopes this probe to this daemon.
    if sys.platform != "linux" or info.get("OSType") != "linux" or platform.release() != info.get("KernelVersion"):
        return {"source": "unavailable", "physical_memory_bytes": None,
                "reason": "local client is not the Linux host kernel reported by Docker"}
    try:
        result = subprocess.run(["lsmem", "--json", "--bytes", "--output", "RANGE,SIZE,STATE"],
                                env={**os.environ, "LC_ALL": "C"}, text=True,
                                capture_output=True, timeout=5)
        if result.returncode:
            raise ValueError("lsmem did not provide online memory evidence")
        payload = json.loads(result.stdout)
        memory = online_memory_from_lsmem(payload)
        return {"source": HOST_ONLINE_MEMORY_SOURCE, "physical_memory_bytes": memory,
                "online_ranges": [item for item in payload["memory"] if str(item.get("state", "")).lower() == "online"],
                "kernel_version": platform.release()}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"source": "unavailable", "physical_memory_bytes": None,
                "reason": "valid local lsmem online ranges are unavailable; strict MemTotal fallback applies"}


def cleanup_inventory(docker, projects, service_ids, fixture_image):
    """Observe only the exact UUID project labels and private repositories."""
    result = {"containers": [], "networks": [], "volumes": [], "image_tags": [], "errors": []}
    for project in projects:
        for key, command in (("containers", ["container", "ls", "--all", "--quiet"]),
                             ("networks", ["network", "ls", "--quiet"]),
                             ("volumes", ["volume", "ls", "--quiet"])):
            observed = run([docker, *command, "--filter", "label=com.docker.compose.project=" + project], check=False, timeout=10)
            if observed.returncode:
                result["errors"].append(key + ": " + project)
            else:
                result[key].extend(observed.stdout.splitlines())
    references = ["ctf-manager/" + sid + ":*" for sid in service_ids] + [fixture_image]
    for reference in references:
        observed = run([docker, "image", "ls", "--filter", "reference=" + reference,
                        "--format", "{{.Repository}}:{{.Tag}}"], check=False, timeout=10)
        if observed.returncode:
            result["errors"].append("image_tags: " + reference)
        else:
            result["image_tags"].extend(observed.stdout.splitlines())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--review-seconds", type=int, default=0,
                        help="leave the finished fixture running for optional browser review; excluded from measured load")
    parser.add_argument("--reference-host", action="store_true",
                        help="attest the selected resource profile runs on a dedicated Linux host; architecture and resources are checked separately, physical NVMe is not attested")
    parser.add_argument("--resource-profile", choices=PROFILE_NAMES, default="legacy-8g",
                        help="legacy 4-CPU/8-GiB reference or explicit 4-CPU/4-GiB/40-GB competition target; default preserves the legacy profile")
    parser.add_argument("--configured-disk-gb", type=int,
                        help="operator declaration of nominal virtual disk size in GB; competition-4g requires 40, this is not filesystem capacity or physical NVMe evidence")
    parser.add_argument("--lifecycle-under-load", action="store_true",
                        help="after measurement, down/up only this panel while all five games keep writing and logging")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/observation-load-2026-10-19.json")
    args = parser.parse_args()
    if args.configured_disk_gb is not None and args.configured_disk_gb <= 0:
        parser.error("--configured-disk-gb must be positive")
    require(args.seconds >= 20, "at least 20 seconds are needed; use >=300 for CPU acceptance")
    require(0 <= args.review_seconds <= 600, "review window must be between zero and 600 seconds")
    docker = shutil.which("docker")
    require(docker, "Docker CLI is required")
    endpoint = os.environ.get("DOCKER_HOST") or json.loads(run([docker, "context", "inspect"]).stdout)[0]["Endpoints"]["docker"]["Host"]
    require(endpoint.startswith("unix:///"), "only a local Unix Docker daemon is supported")
    socket_path = endpoint.removeprefix("unix://")
    # Freeze all product images before setup. Retagging :local during a long
    # measurement must not silently change the panel used by down/up later.
    pinned_images = {name: json.loads(run([docker, "image", "inspect", "ctf-manager-" + name + ":local"]).stdout)[0]["Id"]
                     for name in ("dashboard", "executor")}
    token = uuid.uuid4().hex[:10]
    project = "ctfm-load-" + token
    root = Path("/srv") / project
    install = root / "panel"
    launch = Path(tempfile.mkdtemp(prefix=project + "-"))
    projects = [project + "-game" + str(i) for i in range(5)]
    service_ids = ["load-" + token + "-" + str(i) for i in range(5)]
    fixture_image = project + ":fixture"
    compose = None
    stop = threading.Event()
    streams = [{"service_id": sid, "messages": 0, "bytes": 0, "log_payloads": 0, "observations": []} for sid in service_ids]
    stream_sockets, threads = [None] * 5, []
    report = {"test": "observation-load", "status": "running", "started_at": datetime.now(timezone.utc).isoformat(),
              "project": project, "service_ids": service_ids, "daemon_directory": str(root),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "selected_resource_profile": args.resource_profile,
              "reference_acceptance": "not_claimed", "competition_acceptance": "not_claimed",
              "resource_profile_acceptance": "not_claimed",
              "scope": "five new synthetic services; ten game containers; own two-container panel",
              "limitations": ["no claim of real 60-minute wall-clock soak", "WebSocket logs use bounded tail polling, not a lossless archive"]}

    def checkpoint(phase):
        # Persist evidence before slow cleanup/review, so an interrupted caller
        # can resume teardown without losing a completed measurement interval.
        report["phase"] = phase
        args.report.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.report.with_name(args.report.name + ".tmp-" + token)
        with temporary.open("w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(args.report)

    checkpoint("starting")

    def helper(code, *values):
        return run([docker, "run", "--rm", "--network", "none", "--mount", f"type=bind,source={root},target={root}",
                    "--mount", f"type=bind,source={ROOT},target={ROOT},readonly", "--mount", f"type=bind,source={socket_path},target=/var/run/docker.sock",
                    "python:3.11-slim", "python3", "-c", code, str(root), str(ROOT), *map(str, values)]).stdout

    def game(i, *parts, check=True):
        return run([docker, "run", "--rm", "--network", "none", "--mount", f"type=bind,source={root},target={root}",
                    "--mount", f"type=bind,source={socket_path},target=/var/run/docker.sock", "--entrypoint", "/usr/local/bin/docker",
                    pinned_images["executor"], "compose", "--project-name", projects[i], "--file", str(root / f"services/game{i}/compose.yaml"), *parts], check=check)

    def cli(*parts):
        return json.loads(run(compose + ["exec", "-T", "executor", "/usr/local/bin/ctf-manager", "--config", "/etc/ctf-manager/executor.json", *parts]).stdout)

    def record_resource_profile(info, filesystem_capacity=None):
        physical = report.get("physical_memory_evidence", {})
        observation = assess_resource_profile(info, args.resource_profile,
                                              dedicated_host_attested=args.reference_host,
                                              configured_disk_gb=args.configured_disk_gb,
                                              filesystem_capacity=filesystem_capacity,
                                              physical_memory_bytes=physical.get("physical_memory_bytes"),
                                              physical_memory_source=physical.get("source"))
        report["resource_profile"] = observation
        # Preserve the old CPU/RAM-only field as the 8-GiB comparison. Explicit
        # architecture and selected-profile gates are added to host acceptance.
        report["reference_hardware_match"] = hardware_matches(info, "legacy-8g")
        report["reference_host_attested"] = args.reference_host
        report["reference_host_match"] = args.resource_profile == "legacy-8g" and observation["host_match"]
        report["competition_host_match"] = args.resource_profile == "competition-4g" and observation["host_match"]
        report.update(acceptance_fields(observation, "not_measured"))

    try:
        info = json.loads(run([docker, "info", "--format", "{{json .}}"]).stdout)
        report["runtime"] = {k: info.get(k) for k in ("OperatingSystem", "OSType", "Architecture", "NCPU", "MemTotal", "KernelVersion", "ServerVersion", "Driver", "DockerRootDir")}
        report["physical_memory_evidence"] = read_host_online_memory(info)
        record_resource_profile(info)
        report["host_compose"] = run([docker, "compose", "version"]).stdout.strip()
        run([docker, "run", "--rm", "--network", "none", "--volume", f"{root}:{root}", "python:3.11-slim", "python3", "-c", "import pathlib,sys; assert not any(pathlib.Path(sys.argv[1]).iterdir())", str(root)])
        capacity = json.loads(helper("import json,os,sys; p=sys.argv[1]; s=os.statvfs(p); print(json.dumps({'path':p,'source':'statvfs_approved_daemon_side_fixture_root','total_bytes':s.f_blocks*s.f_frsize,'available_bytes':s.f_bavail*s.f_frsize,'total_inodes':s.f_files,'available_inodes':s.f_favail}))"))
        record_resource_profile(info, capacity)
        if not report["resource_profile"]["host_match"]:
            report["limitations"].append("selected resource profile " + args.resource_profile + " is " + report["resource_profile"]["state"] + "; target acceptance is not claimed")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        setup = r'''
import json, os, subprocess, sys
from pathlib import Path
root, repo, image = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
os.chmod(root,0o755)
for name in ('services','workspaces'): (root/name).mkdir(mode=0o755)
sys.path.insert(0,str(repo/'tests/fixtures'))
from prepare import prepare_fixture
for i in range(5):
    active=prepare_fixture('named-volume',root/f'services/game{i}')
    code=active/'code/app.py'
    text=code.read_text()
    assert text.count('        server_version = "CTFMFixture/1"') == 1
    assert text.count('    make_server(Config.from_environment()') == 1
    text=text.replace('        server_version = "CTFMFixture/1"','        server_version = "CTFMFixture/1"\n\n        def log_message(self, *args): pass')
    # Each of five app containers emits forty 1024-byte lines/sec. The five
    # database containers stay active, with health/HTTP access logs disabled.
    text=text.replace('    make_server(Config.from_environment()', """    import threading, time
    def emit():
        sequence = 0
        deadline = time.monotonic()
        while True:
            print(("load-sequence-%012d " % sequence).ljust(1023, "x"), flush=True)
            sequence += 1
            deadline += .025
            time.sleep(max(0, deadline-time.monotonic()))
    if os.environ.get("FIXTURE_ROLE", "app") == "app":
        threading.Thread(target=emit, daemon=True).start()
    make_server(Config.from_environment()""")
    code.write_text(text)
    compile(text,str(code),'exec')
    assert (active/'compose.yaml').read_text().count('    build: ./code') == 2
    model=(active/'compose.yaml').read_text().replace('    build: ./code','    image: '+image)
    (active/'compose.yaml').write_text(model)
    (root/f'workspaces/game{i}').mkdir(mode=0o700)
result=subprocess.run(['python3',str(repo/'scripts/compose-bootstrap.py'),'--root',str(root/'panel'),'--discovery-root',str(root/'services'),'--workspace-root',str(root/'workspaces'),'--host-metrics'],capture_output=True,text=True)
if result.returncode: raise RuntimeError(result.stderr)
print(json.dumps({'environment':(root/'panel/config/compose.env').read_text(),'mounts':(root/'panel/config/compose.mounts.yaml').read_text()}))
'''
        prepared = json.loads(helper(setup, fixture_image))
        run([docker, "run", "--rm", "--network", "none", "--mount", f"type=bind,source={root},target={root}",
             "--mount", f"type=bind,source={socket_path},target=/var/run/docker.sock", "--entrypoint", "/usr/local/bin/docker", pinned_images["executor"],
             "build", "--tag", fixture_image, str(root / "services/game0/code")], timeout=300)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(lambda i: game(i, "up", "--detach", "--no-build", "--wait", "--wait-timeout", "60"), range(5)))
        mounts_file = launch / "compose.mounts.yaml"
        frozen_mounts = json.loads(prepared["mounts"])
        for name, image_id in pinned_images.items():
            frozen_mounts["services"].setdefault(name, {})["image"] = image_id
        mounts_file.write_text(json.dumps(frozen_mounts))
        environment = prepared["environment"].replace(str(install / "config/compose.mounts.yaml"), str(mounts_file))
        environment = environment.replace("CTFM_DOCKER_SOCKET=/var/run/docker.sock", "CTFM_DOCKER_SOCKET=" + socket_path)
        environment = environment.replace("CTFM_PORT=8765", "CTFM_PORT=" + str(port)).replace("CTFM_ALLOWED_HOSTS=localhost:8765,127.0.0.1:8765", f"CTFM_ALLOWED_HOSTS=127.0.0.1:{port},127.0.0.1:8765")
        env_file = launch / "compose.env"
        env_file.write_text(environment)
        compose = [docker, "compose", "--project-name", project, "--env-file", str(env_file)]
        run(compose + ["run", "--rm", "--no-deps", "-T", "dashboard", "init-admin", "--state", "/var/lib/ctf-manager", "--username", "admin"], input=PASSWORD + "\n")
        run(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
        ids = {name: run(compose + ["ps", "--quiet", name]).stdout.strip() for name in ("dashboard", "executor")}
        report["images"] = {name: json.loads(run([docker, "inspect", value]).stdout)[0]["Image"] for name, value in ids.items()}
        report["executor_compose"] = run(compose + ["exec", "-T", "executor", "/usr/local/bin/docker", "compose", "version"]).stdout.strip()
        report["fixture_image"] = json.loads(run([docker, "image", "inspect", fixture_image]).stdout)[0]["Id"]
        # Registration uses the same production approval path as the installed CLI.
        game_ids = []
        flag = "LOAD_TEST_FLAG_" + token
        for i in range(5):
            initial = cli("inventory", "--project", projects[i])
            require(len(initial) == 2, "fixture inventory must contain two containers")
            game_ids.extend(x["id"] for x in initial)
            app = next(x["id"] for x in initial if x["component"] == "app")
            run([docker, "exec", app, "python", "-c", "import urllib.request,json,sys; r=urllib.request.Request('http://127.0.0.1:8080/flags/load_test',data=json.dumps({'value':sys.argv[1]}).encode(),method='PUT',headers={'Content-Type':'application/json'}); assert urllib.request.urlopen(r).status==200", flag])
            policy = {"schema_version": 1, "id": service_ids[i], "name": "Load fixture " + str(i), "project_directory": str(root / f"services/game{i}"),
                      "source_directory": str(root / f"workspaces/game{i}"), "compose_project": projects[i], "compose_files": ["compose.yaml"],
                      "managed_paths": [{"path": "code", "kind": "code"}, {"path": "compose.yaml", "kind": "configuration"}],
                      "data_paths": [{"name": "database-data", "kind": "named_volume", "source": projects[i] + "_database-data", "target": "/data", "component": "database", "significant": True, "loss_accepted": False},
                                     *[{"name": name + "-layer", "kind": "writable_layer", "target": "/tmp", "component": name, "significant": False, "loss_accepted": True} for name in ("app", "database")]],
                      "targets": ["app"], "containers": [{"component": x["component"], "id": x["id"], "image_id": x["image_id"], "role": "database" if x["component"] == "database" else "application"} for x in initial],
                      "policy_revision": 1, "file_map_revision": 1}
            helper("import json,sys; from pathlib import Path; p=Path(sys.argv[1])/'panel/config/service.json'; p.write_text(sys.argv[3]); p.chmod(0o600)", json.dumps(policy))
            proposal = cli("propose", "--service", "/etc/ctf-manager/service.json")
            cli("approve", "--proposal", proposal["id"], "--digest", proposal["digest"])
        initial_starts = {x["Id"]: x["State"]["StartedAt"] for x in json.loads(run([docker, "inspect", *game_ids]).stdout)}
        base = f"http://127.0.0.1:{port}"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        def request(path, body=None, csrf=None):
            headers = {"Origin": base}
            if csrf: headers["X-CSRF-Token"] = csrf
            if body is not None: headers["Content-Type"] = "application/json"
            with opener.open(urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=headers), timeout=10) as response:
                return json.load(response)

        request("/api/auth/login", {"username": "admin", "password": PASSWORD})
        csrf = request("/api/auth/session")["csrf_token"]
        cookie = "; ".join(c.name + "=" + c.value for c in jar)
        require(len(request("/api/services")) == 5, "five services were not registered")
        # Five actual authenticated WebSocket log clients; stdlib framing avoids
        # dependency or mock overhead. All consume data throughout the run.
        def stream(index):
            sock = None
            result = streams[index]
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=10)
                stream_sockets[index] = sock
                key = base64.b64encode(os.urandom(16)).decode()
                sock.sendall((f"GET /api/stream?service_id={service_ids[index]}&component=app HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {base}\r\nCookie: {cookie}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n").encode())
                buffer = b""
                while b"\r\n\r\n" not in buffer:
                    chunk = sock.recv(4096)
                    require(chunk, "WebSocket closed before upgrade")
                    buffer += chunk
                    require(len(buffer) <= 65536, "WebSocket response header exceeds limit")
                header, pending = buffer.split(b"\r\n\r\n", 1)
                require(b"101 Switching Protocols" in header, "WebSocket upgrade failed: " + repr(header))
                expected_accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                require(expected_accept.lower() in header.lower(), "WebSocket upgrade accept digest mismatch")

                def read(size):
                    nonlocal pending
                    while len(pending) < size:
                        chunk = sock.recv(min(65536, size - len(pending)))
                        if not chunk: raise EOFError("WebSocket closed")
                        pending += chunk
                    value, pending = pending[:size], pending[size:]
                    return value

                message = bytearray()
                message_type = None
                while not stop.is_set():
                    a, b = read(2)
                    require(not a & 0x70 and not b & 0x80, "unexpected compressed or masked server frame")
                    opcode, final = a & 15, bool(a & 0x80)
                    length = b & 127
                    if length == 126: length = struct.unpack("!H", read(2))[0]
                    elif length == 127: length = struct.unpack("!Q", read(8))[0]
                    require(length <= 1024 * 1024, "unbounded stream frame")
                    data = read(length)
                    if opcode == 8:
                        require(stop.is_set(), "WebSocket closed during measured load")
                        break
                    if opcode == 9:
                        require(final and length <= 125, "invalid WebSocket ping")
                        mask = os.urandom(4)
                        sock.sendall(bytes((0x8a, 0x80 | length)) + mask + bytes(value ^ mask[pos % 4] for pos, value in enumerate(data)))
                        continue
                    if opcode == 10: continue
                    if opcode in (1, 2):
                        require(message_type is None, "nested WebSocket data message")
                        message_type = opcode
                    else: require(opcode == 0 and message_type is not None, "unexpected WebSocket continuation")
                    message.extend(data)
                    require(len(message) <= 1024 * 1024, "unbounded stream message")
                    if not final: continue
                    require(message_type == 1, "expected JSON text stream")
                    payload = json.loads(message)
                    result["bytes"] += len(message)
                    message.clear(); message_type = None
                    require(payload.get("executor") == "ok" and not payload.get("logs_error") and not payload.get("truncated") and not payload.get("logs", {}).get("truncated"), "log stream returned unavailable/error/truncation")
                    result["messages"] += 1
                    content = payload.get("logs", {}).get("content", "")
                    if content:
                        result["log_payloads"] += 1
                        lines = content.splitlines(keepends=True)
                        sequences = [int(match.group(1)) for line in lines if (match := re.match(r"^load-sequence-(\d{12}) ", line))]
                        require(sequences and all(len(line.encode()) == 1024 for line in lines), "fixture did not emit the declared 1024-byte sequence lines")
                        require(len(sequences) == len(lines), "unexpected non-fixture log line")
                        result["observations"].append({"monotonic": time.monotonic(), "sequence": max(sequences), "tail_lines": len(lines)})
            except Exception as error:
                if not stop.is_set(): result["error"] = str(error)
            finally:
                if sock: sock.close()

        for i in range(5):
            thread = threading.Thread(target=stream, args=(i,), daemon=True)
            thread.start(); threads.append(thread)
        time.sleep(10)
        host = request("/api/metrics/host")
        report["host_metrics_initial"] = host
        require(host.get("available") and not host.get("stale"), "host metrics are not available with explicit mounts")
        require(host["latest"].get("scope") == "docker_engine_host" and host["latest"].get("source") == "approved_host_proc_files", "host metrics source does not attest Docker Engine host")
        require(host["latest"]["memory_total_bytes"] == info["MemTotal"] and host["latest"]["core_count"] == info["NCPU"], "host CPU/memory disagree with actual Docker host")
        executor_info = json.loads(run([docker, "inspect", ids["executor"]]).stdout)[0]
        host_mounts = [item for item in executor_info["Mounts"] if item["Destination"].startswith("/run/ctf-manager-host/")]
        require(len(host_mounts) == 5 and all(not item["RW"] for item in host_mounts), "host source mounts are incomplete or writable")
        require(not executor_info["HostConfig"]["Privileged"] and executor_info["HostConfig"].get("PidMode") != "host" and executor_info["HostConfig"].get("NetworkMode") != "host", "host metrics unexpectedly require privileged host namespaces")
        own_net = run([docker, "exec", ids["executor"], "cat", "/proc/net/dev"]).stdout
        own_interfaces = sorted(line.split(":", 1)[0].strip() for line in own_net.splitlines() if ":" in line)
        host_interfaces = sorted(item["name"] for item in host["latest"].get("network_interfaces", []))
        require(set(host_interfaces) - set(own_interfaces), "host network observation did not differ from executor namespace")
        report["host_source_evidence"] = {"cpu_and_memory_match_docker_info": True, "exact_read_only_mounts": [{"source": item["Source"], "target": item["Destination"], "read_only": not item["RW"]} for item in host_mounts], "executor_interfaces": own_interfaces, "host_interfaces": host_interfaces, "host_namespaces": False, "privileged": False}
        require(host["latest"].get("cpu_percent") is not None and host["latest"].get("memory_total_bytes"), "explicit host CPU/memory samples are missing")

        def process_sample():
            result = {}
            for name, container_id in ids.items():
                raw = run([docker, "exec", container_id, "/bin/sh", "-c", "cat /proc/1/status /sys/fs/cgroup/cpu.stat"]).stdout
                fields = {line.split()[0].rstrip(":"): line.split()[1] for line in raw.splitlines() if len(line.split()) >= 2}
                result[name] = {"rss_bytes": int(fields["VmRSS"]) * 1024, "cpu_usec": int(fields["usage_usec"])}
            return {"elapsed": time.monotonic() - start, "processes": result}

        start = time.monotonic()
        samples = [process_sample()]
        latencies, failures = [], []
        next_request, next_sample, next_metrics, next_progress, iteration = start, start + 10, start + 5, start + 60, 0
        metrics_polls = 0
        while time.monotonic() - start < args.seconds + samples[0]["elapsed"]:
            now = time.monotonic()
            if now >= next_request:
                began = time.monotonic()
                try:
                    require(request("/api/status").get("executor") == "ok", "executor unavailable under load")
                    details = request("/api/services/" + service_ids[iteration % 5])
                    require(len(details.get("containers", [])) == 2, "service state response invalid")
                    latencies.append((time.monotonic() - began) * 1000)
                except Exception as error: failures.append(str(error))
                iteration += 1
                next_request += .5
            if now >= next_sample:
                samples.append(process_sample()); next_sample += 10
            if now >= next_metrics:
                try:
                    require(request("/api/metrics/host")["retention_seconds"] == 3600, "host history poll failed")
                    require(request(f"/api/services/{service_ids[metrics_polls % 5]}/metrics")["retention_seconds"] == 3600, "container history poll failed")
                    metrics_polls += 1
                except Exception as error:
                    failures.append(str(error))
                next_metrics += 5
            if now >= next_progress:
                report["partial_measurement"] = {"seconds": now-start, "api_iterations": iteration, "api_failures": failures, "process_samples": samples}
                checkpoint("measuring")
                print(json.dumps({"phase": "measuring", "seconds": round(now-start), "api_iterations": iteration, "api_failures": len(failures)}), flush=True)
                next_progress += 60
            time.sleep(max(.001, min(.05, next_request-time.monotonic())))
        samples.append(process_sample())
        measured_end = time.monotonic()
        elapsed = samples[-1]["elapsed"] - samples[0]["elapsed"]
        cpu = sum(samples[-1]["processes"][name]["cpu_usec"] - samples[0]["processes"][name]["cpu_usec"] for name in ids) / 1e6 / elapsed
        rss = max(sum(p["rss_bytes"] for p in sample["processes"].values()) for sample in samples)
        ordered = sorted(latencies)
        p95 = ordered[max(0, math.ceil(.95 * len(ordered))-1)] if ordered else None
        report["measurement"] = {"seconds": elapsed, "services": 5, "game_containers": 10, "log_clients": 5, "log_input_lines_per_second": 200, "log_line_bytes_including_newline": 1024,
                                 "api_target_iterations_per_second": 2, "api_actual_iterations_per_second": iteration / elapsed, "api_calls_per_iteration": 2, "api_paths": ["/api/status", "/api/services/<round-robin-service-id>"], "api_iterations": len(latencies), "api_failures": failures,
                                 "metrics_http_poll_interval_seconds": 5, "metrics_http_poll_pairs": metrics_polls,
                                 "api_pair_p95_ms": p95, "rss_sum_peak_bytes": rss, "cpu_sum_average_cores": cpu,
                                 "cpu_includes": "all processes in two panel cgroups, including healthchecks and sampling exec overhead", "rss_includes": "main web and executor VmRSS, excludes game/daemon/BuildKit/browser", "process_samples": samples}
        report["thresholds"] = {"rss_le_256MiB": rss <= 256 * 1024**2, "cpu_le_point1_core": cpu <= .1, "state_api_pair_p95_le_500ms": p95 is not None and p95 <= 500, "five_minute_measurement": elapsed >= 300}
        report.pop("partial_measurement", None)
        checkpoint("measurement_complete")
        for sid in service_ids:
            metrics = request(f"/api/services/{sid}/metrics")
            require(metrics["retention_seconds"] == 3600 and metrics["available"] and not metrics["stale"], "container metrics retention or availability invalid")
            require(len(metrics["latest"]["containers"]) == 2, "container metrics lost registered component")
            require(metrics.get("history_storage") == "memory" and metrics.get("history_component") in metrics.get("available_components", []), "container history selector/reset contract invalid")
            require(len(metrics["history"]) >= args.seconds // 5, "container history lost observations")
            require(all(len(sample["containers"]) == 1 and sample["containers"][0]["component"] == metrics["history_component"] for sample in metrics["history"]), "container history contains a different component")
        final_host = request("/api/metrics/host")
        require(final_host["retention_seconds"] == 3600 and len(final_host["history"]) >= args.seconds // 5, "host history lost observations")
        report["host_history_samples"] = len(final_host["history"])
        final_starts = {x["Id"]: x["State"]["StartedAt"] for x in json.loads(run([docker, "inspect", *game_ids]).stdout)}
        require(initial_starts == final_starts, "observation load restarted a game container")
        for i in range(5):
            app = next(x["id"] for x in cli("inventory", "--project", projects[i]) if x["component"] == "app")
            run([docker, "exec", app, "python", "-c", "import urllib.request,json,sys; assert json.load(urllib.request.urlopen('http://127.0.0.1:8080/flags/load_test'))['value']==sys.argv[1]", flag])
        report["games_preserved"] = {"container_started_at_unchanged": True, "flags_preserved": 5}
        # Queue latency is measured outside the observation-only CPU interval.
        operation = {"service_id": service_ids[0], "action": "snapshot", "idempotency_key": uuid.uuid4().hex}
        preview = request("/api/preview", operation, csrf)
        operation["plan_digest"] = preview["plan_digest"]
        began = time.monotonic()
        accepted = request("/api/operations", operation, csrf)
        report["job_submit_ms"] = (time.monotonic()-began)*1000
        require(accepted["spec"]["id"], "submit omitted operation id")
        report["thresholds"]["job_submit_le_1000ms"] = report["job_submit_ms"] <= 1000
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            job = request("/api/operations/" + accepted["spec"]["id"])
            if job["state"] in ("succeeded", "failed", "cancelled", "requires_recovery", "interrupted"): break
            time.sleep(.25)
        report["post_load_operation"] = job
        report["post_load_operation_events"] = request("/api/operations/" + accepted["spec"]["id"] + "/events")
        require(job["state"] == "succeeded", "post-load snapshot operation did not succeed")
        report["post_load_operation_state"] = job["state"]
        stop.set()
        for sock in stream_sockets:
            if sock:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        for thread in threads: thread.join(timeout=4)
        require(not any(thread.is_alive() for thread in threads), "log client failed to stop")
        measured_rates = []
        for result in streams:
            observations = [item for item in result["observations"] if start <= item["monotonic"] <= measured_end]
            require(len(observations) >= 2, "not enough measured log observations")
            span = observations[-1]["monotonic"] - observations[0]["monotonic"]
            rate = (observations[-1]["sequence"] - observations[0]["sequence"]) / span
            measured_rates.append(rate)
            result["measured_source_lines_per_second"] = rate
            result["observations"] = [{**item, "elapsed": item["monotonic"] - start} for item in observations]
            for item in result["observations"]: del item["monotonic"]
        report["measurement"]["observed_total_source_lines_per_second"] = sum(measured_rates)
        report["thresholds"]["observed_log_input_ge_190_lines_per_second"] = sum(measured_rates) >= 190
        report["streams"] = streams
        require(len(streams) == 5 and all(not x.get("error") and x["log_payloads"] >= args.seconds // 3 for x in streams), "log clients failed during load")
        require(not failures, "API failures under load")
        report["status"] = "passed" if all(report["thresholds"].values()) else "thresholds_not_met"
        report.update(acceptance_fields(report["resource_profile"], report["status"]))
        if args.lifecycle_under_load:
            # Log generators remain inside the unchanged app containers. Probe
            # requests run inside each game, independent of the panel network
            # and credentials, so stopping the panel cannot stop the workload.
            probe_code = r'''
import json, sys, time, urllib.request
flag, token = sys.argv[1:3]
observations = []
deadline = time.monotonic() + 25
iteration = 0
while time.monotonic() < deadline:
    with urllib.request.urlopen('http://127.0.0.1:8080/flags/load_test', timeout=2) as response:
        assert json.load(response)['value'] == flag
    value = token + '-' + str(iteration)
    request = urllib.request.Request('http://127.0.0.1:8080/state/panel_lifecycle', data=json.dumps({'value':value}).encode(), method='PUT', headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=2) as response:
        assert response.status == 200
    with urllib.request.urlopen('http://127.0.0.1:8080/state/panel_lifecycle', timeout=2) as response:
        assert json.load(response)['value'] == value
    observations.append(time.time())
    iteration += 1
    time.sleep(.1)
print(json.dumps({'iterations':iteration,'observations':observations,'last_value':value}))
'''
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                probes = [pool.submit(run, [docker, "exec", container_id, "python", "-c", probe_code, flag, token])
                          for container_id in game_ids
                          if json.loads(run([docker, "inspect", container_id]).stdout)[0]["Config"]["Labels"]["com.docker.compose.service"] == "app"]
                require(len(probes) == 5, "lifecycle probes require five distinct apps")
                time.sleep(1)
                run(compose + ["down", "--timeout", "10"])
                down_at = time.time()
                time.sleep(3)
                up_at = time.time()
                run(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "60"])
                outcomes = [json.loads(probe.result().stdout) for probe in probes]
            while_down = [sum(down_at <= at <= up_at for at in outcome["observations"]) for outcome in outcomes]
            require(all(count >= 2 for count in while_down), "a game stopped serving/writing while the panel was down")
            after_lifecycle = {x["Id"]: x["State"]["StartedAt"] for x in json.loads(run([docker, "inspect", *game_ids]).stdout)}
            require(initial_starts == after_lifecycle, "panel down/up restarted a game container")
            try:
                request("/api/auth/session")
                raise RuntimeError("old dashboard session survived panel recreation")
            except urllib.error.HTTPError as error:
                require(error.code == 401, "unexpected response to revoked session")
            request("/api/auth/login", {"username": "admin", "password": PASSWORD})
            require(request("/api/status").get("executor") == "ok" and len(request("/api/services")) == 5,
                    "panel did not recover registry/IPC after recreation")
            report["lifecycle_under_load"] = {"scope": "only own two-container panel down/up; five games continue emitting 200 lines/s",
                                             "game_container_ids_and_started_at_preserved": True,
                                             "continuous_read_write_flag_probes": 5,
                                             "probe_iterations": [outcome["iterations"] for outcome in outcomes],
                                             "probe_iterations_while_panel_down": while_down,
                                             "confirmed_panel_down_seconds": up_at - down_at,
                                             "registry_and_ipc_restored": True,
                                             "old_session_revoked": True,
                                             "excluded_from_measurement": True}
        checkpoint("checks_complete")
        if args.review_seconds:
            report["visual_review"] = {"url": base, "seconds": args.review_seconds, "excluded_from_measurement": True}
            print(json.dumps({"visual_review_url": base, "user": "admin", "seconds": args.review_seconds, "note": "load measurement completed; optional browser review window"}), flush=True)
            review_until = time.monotonic() + args.review_seconds
            while time.monotonic() < review_until: time.sleep(min(1, max(0, review_until - time.monotonic())))
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        checkpoint("failed")
        raise
    finally:
        stop.set()
        report["cleanup_status"] = "in_progress"
        checkpoint("cleanup")
        if compose:
            run(compose + ["down", "--timeout", "10"], check=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(lambda i: game(i, "down", "--volumes", "--timeout", "5", check=False), range(5)))
        # Imported baseline pins belong to this UUID service repository. Remove
        # only exact tags still addressing our fixture image; never image IDs,
        # force removal, shared parents, or unrelated service repositories.
        cleaned_tags = []
        for sid in service_ids:
            pins = run([docker, "image", "ls", "--filter", "reference=ctf-manager/" + sid + ":*", "--format", "{{.Repository}}:{{.Tag}}"], check=False).stdout.splitlines()
            for tag in pins:
                identity = run([docker, "image", "inspect", tag, "--format", "{{.Id}}"], check=False).stdout.strip()
                if identity == report.get("fixture_image"):
                    if run([docker, "image", "rm", "--no-prune", tag], check=False).returncode == 0: cleaned_tags.append(tag)
        report["removed_own_retention_tags"] = cleaned_tags
        run([docker, "image", "rm", "--no-prune", fixture_image], check=False)
        try:
            remaining = cleanup_inventory(docker, [project, *projects], service_ids, fixture_image)
            report["cleanup_inventory"] = remaining
            require(not any(remaining.values()), "own resources remain or cleanup queries failed; daemon directory retained")
            helper("import shutil,sys; from pathlib import Path; p=Path(sys.argv[1]); [shutil.rmtree(c) if c.is_dir() else c.unlink() for c in p.iterdir()]")
            report["cleanup"] = "own containers, networks, volumes, fixture tag and directory contents removed; empty unique /srv directory remains"
        except Exception as error: report["cleanup_error"] = str(error)
        shutil.rmtree(launch, ignore_errors=True)
        report["cleanup_status"] = "failed" if report.get("cleanup_error") else "complete"
        if "resource_profile" in report:
            report.update(acceptance_fields(report["resource_profile"], report["status"] if report["cleanup_status"] == "complete" else "cleanup_failed"))
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        checkpoint("finished")
    print(json.dumps({k: v for k, v in report.items() if k not in ("host_metrics_initial", "measurement")}, indent=2))
    if report["status"] != "passed" or report["cleanup_status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
