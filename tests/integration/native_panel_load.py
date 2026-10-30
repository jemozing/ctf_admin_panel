#!/usr/bin/env python3
"""Observe the installed native panel and its five existing real game projects.

No containers are created, started, stopped or removed. Explicit --inject-stdout
adds only marked synthetic log lines to five inspected application stdout FIFOs.
Native PID descriptors, process start times and exact container inventories guard
those writers. Player data are independently read through the saved game probes.
"""
import argparse
import base64
from datetime import datetime, timezone
import errno
import hashlib
import http.client
import http.cookiejar
import json
import math
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from native_sibir_probes import ProbeAdapter, private_read, private_write

GAME_COMPONENTS = {"bioguard": {"web"}, "ncdex": {"app", "db"},
                   "bank": {"cyber-bank-api", "cyber-bank-front", "cyber-bank-postgres"},
                   "neli234": {"controller", "neurolink"}, "eyesee": {"eyesee-service", "eyesee-storage"}}
LOG_COMPONENTS = {"bioguard": "web", "ncdex": "app", "bank": "cyber-bank-front", "neli234": "controller", "eyesee": "eyesee-service"}
WIRE_KEYS = {"bioguard": "bioguard", "ncdex": "ncdex", "bank": "bank", "neli234": "neurolinks", "eyesee": "eyesee"}
KEYS = list(GAME_COMPONENTS)
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
LETTER_HEX = "abcdefghijklmnop"


def encode_integer(value, width):
    require(type(value) is int and 0 <= value < 16**width, "synthetic integer exceeds its encoding bound")
    return "".join(LETTER_HEX[int(character, 16)] for character in f"{value:0{width}x}")


def decode_integer(value):
    require(value and all(character in LETTER_HEX for character in value), "invalid letter-encoded synthetic integer")
    return int("".join(f"{LETTER_HEX.index(character):x}" for character in value), 16)


def check_sampler_gap(last, current, limit=5):
    gap = current - last
    require(0 <= gap <= limit, "native sampler gap exceeded five seconds; timing interval invalid")
    return gap


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def docker(*arguments):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("COMPOSE_") and key not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    result = subprocess.run(["docker", "--host", "unix:///run/docker.sock", *arguments], env=environment,
                            capture_output=True, text=True, timeout=12)
    require(result.returncode == 0, "read-only Docker observation failed; output omitted")
    require(len(result.stdout) <= 4 * 1024 * 1024, "Docker observation exceeded bound")
    return result.stdout


def inventory():
    identities = docker("ps", "--all", "--quiet", "--no-trunc").split()
    require(len(identities) == 12 and all(CONTAINER_ID.fullmatch(value) for value in identities), "exactly the installed twelve containers are required")
    # Whitelist metadata at the CLI; Env, command arguments and secret files are
    # never fetched or exported by the sampler.
    fmt = '{"id":{{json .Id}},"name":{{json .Name}},"image_id":{{json .Image}},"pid":{{json .State.Pid}},"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}},"oom_killed":{{json .State.OOMKilled}},"restart_count":{{json .RestartCount}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"not_configured"{{end}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"component":{{json (index .Config.Labels "com.docker.compose.service")}},"tty":{{json .Config.Tty}},"pid_mode":{{json .HostConfig.PidMode}},"log_driver":{{json .HostConfig.LogConfig.Type}},"mounts":{{json .Mounts}}}'
    result = {}
    for line in docker("inspect", "--format", fmt, *identities).splitlines():
        value = json.loads(line)
        require(value["running"] and not value["oom_killed"] and value["health"] in ("healthy", "not_configured"), "protected container is stopped, unhealthy or OOM")
        require(IMAGE_ID.fullmatch(value["image_id"]) and value["pid"] > 1, "invalid protected image/PID identity")
        value["mounts"] = sorted([{key: item.get(key) for key in ("Type", "Name", "Source", "Destination", "RW")}
                                  for item in value["mounts"]], key=lambda item: item["Destination"])
        result[value["id"]] = value
    require(len(result) == 12, "incomplete protected inventory")
    expected = {("ctf-manager", "dashboard"), ("ctf-manager", "executor")}
    expected |= {("ctfm-demo-sibir-" + key, component) for key, components in GAME_COMPONENTS.items() for component in components}
    require({(value["project"], value["component"]) for value in result.values()} == expected, "foreign project/component or replicas in installed host inventory")
    return result


def preserved(before, after):
    require(set(before) == set(after), "protected container IDs changed")
    fields = ("id", "name", "image_id", "pid", "started_at", "restart_count", "mounts", "project", "component")
    for identity in before:
        require(all(before[identity][field] == after[identity][field] for field in fields), "protected runtime identity/StartedAt/mounts changed")


def process_identity(pid):
    text = (Path("/proc") / str(pid) / "stat").read_text()
    fields = text.rsplit(") ", 1)[1].split()
    require(fields[0] not in ("Z", "X"), "protected process exited")
    return fields[19]


class PinnedProcess:
    def __init__(self, container, *, stdout=False):
        self.value, self.pid, self.stdout_fd, self.pidfd = container, container["pid"], None, None
        try:
            self.start_ticks = process_identity(self.pid)
            self.pidfd = os.pidfd_open(self.pid)
            cgroup = (Path("/proc") / str(self.pid) / "cgroup").read_text().strip().splitlines()
            selected = [line[3:] for line in cgroup if line.startswith("0::")]
            require(len(selected) == 1 and container["id"] in selected[0], "PID is not in its exact Docker cgroup v2")
            relative = selected[0].lstrip("/")
            require(".." not in Path(relative).parts, "unsafe kernel cgroup path")
            self.cgroup = Path("/sys/fs/cgroup") / relative
            require((self.cgroup / "cpu.stat").is_file(), "container CPU cgroup unavailable")
            require(container["pid_mode"] != "host", "host PID namespace profile is unsupported")
            if stdout:
                require(not container["tty"] and container["log_driver"] == "json-file", "stdout injection requires non-TTY json-file application logs")
                target = Path("/proc") / str(self.pid) / "fd/1"
                before = target.stat()
                require(stat.S_ISFIFO(before.st_mode), "application stdout is not a FIFO; refuse file/device writes")
                self.stdout_fd = os.open(target, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                observed, after = os.fstat(self.stdout_fd), target.stat()
                require(stat.S_ISFIFO(observed.st_mode) and (before.st_dev, before.st_ino) == (observed.st_dev, observed.st_ino) == (after.st_dev, after.st_ino), "stdout FIFO changed while pinning")
                require(os.fpathconf(self.stdout_fd, "PC_PIPE_BUF") >= 1024, "stdout atomic-write bound is smaller than a synthetic line")
                self.pipe_identity = (observed.st_dev, observed.st_ino)
            self.assert_alive()
        except BaseException:
            self.close()
            raise

    def assert_alive(self):
        require(not select.select([self.pidfd], [], [], 0)[0] and process_identity(self.pid) == self.start_ticks, "protected process was replaced/exited")
        if self.stdout_fd is not None:
            current = (Path("/proc") / str(self.pid) / "fd/1").stat()
            require((current.st_dev, current.st_ino) == self.pipe_identity, "application changed its stdout FIFO")

    def sample(self):
        self.assert_alive()
        fields = {}
        for line in (Path("/proc") / str(self.pid) / "status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                fields["rss_bytes"] = int(line.split()[1]) * 1024
        cpu = {line.split()[0]: int(line.split()[1]) for line in (self.cgroup / "cpu.stat").read_text().splitlines()}
        require("rss_bytes" in fields and "usage_usec" in cpu, "native RSS/CPU sample missing")
        return {**fields, "cpu_usec": cpu["usage_usec"]}

    def close(self):
        for field in ("stdout_fd", "pidfd"):
            descriptor = getattr(self, field, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, field, None)


def synthetic_line(nonce, key, sequence, timestamp_ns):
    # Pure letters avoid changing the expected signature when a known public
    # environment flag such as PYTHONDONTWRITEBYTECODE=1 is conservatively
    # redacted by the product. No vault values are read and redaction is intact.
    require(nonce and all(character in LETTER_HEX for character in nonce), "invalid letter-only run marker")
    prefix = f"ctfm-load-{nonce}-{WIRE_KEYS[key]} seq={encode_integer(sequence, 12)} t={encode_integer(timestamp_ns, 20)} ".encode()
    require(len(prefix) < 1024, "synthetic prefix exceeded line bound")
    return prefix + b"x" * (1023 - len(prefix)) + b"\n"


def resource_guard(root, minimum_memory, minimum_disk):
    memory = {line.split(":", 1)[0]: int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith(("MemAvailable:", "MemTotal:", "SwapFree:"))}
    capacity = os.statvfs(root)
    available = capacity.f_bavail * capacity.f_frsize
    require(memory.get("MemAvailable", 0) >= minimum_memory, "host MemAvailable safety floor reached; stopping synthetic load")
    require(available >= minimum_disk and capacity.f_favail >= 4096, "host disk/inode safety floor reached; stopping synthetic load")
    return {"mem_available_bytes": memory["MemAvailable"], "disk_available_bytes": available, "available_inodes": capacity.f_favail}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise RuntimeError("panel redirect refused")


class API:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.address = urllib.parse.urlsplit(self.base)
        require(self.address.scheme == "http" and self.address.hostname in ("127.0.0.1", "localhost") and not self.address.username and not self.address.password and not self.address.path and not self.address.query and not self.address.fragment, "native load API must use a loopback HTTP origin")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, path, value=None):
        headers, body = {}, None
        if value is not None:
            body = json.dumps(value).encode()
            headers = {"Content-Type": "application/json", "Origin": self.base}
        try:
            with self.opener.open(urllib.request.Request(self.base + path, data=body, headers=headers), timeout=5) as response:
                require(response.status == 200, "unexpected panel status")
                content = response.read(4 * 1024 * 1024 + 1)
                require(len(content) <= 4 * 1024 * 1024, "panel response exceeded bound")
                return json.loads(content)
        except (OSError, http.client.HTTPException, ValueError):
            raise RuntimeError("panel HTTP/JSON request failed; no retries or response contents exported") from None

    def login(self, credentials):
        self.request("/api/auth/login", {key: credentials[key] for key in ("username", "password")})
        require(self.request("/api/auth/session")["user"]["role"] == "admin", "Admin session required for observed logs")
        self.cookie = "; ".join(item.name + "=" + item.value for item in self.jar)


def history_summary(value):
    require(value.get("available") and not value.get("stale") and value.get("retention_seconds") == 3600,
            "metrics are missing/stale or do not declare sixty-minute retention")
    history = value.get("history", [])
    require(history and len(history) <= 721, "metrics history empty or exceeds declared bounded retention")
    times = [datetime.fromisoformat(item["at"].replace("Z", "+00:00")).timestamp() for item in history]
    require(all(b >= a for a, b in zip(times, times[1:])), "metrics history timestamps went backwards")
    return {"samples": len(history), "span_seconds": times[-1] - times[0], "latest_at": history[-1]["at"],
            "retention_seconds": 3600, "history_storage": value.get("history_storage")}


def masked_frame(opcode, data):
    require(len(data) <= 125, "control frame exceeded bound")
    mask = os.urandom(4)
    return bytes((0x80 | opcode, 0x80 | len(data))) + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(data))


class Stream:
    def __init__(self, api, key, service_id, component, nonce, limit, stop, fail):
        self.api, self.key, self.service_id, self.component = api, key, service_id, component
        self.stop, self.fail = stop, fail
        self.ready, self.lock = threading.Event(), threading.Lock()
        self.socket = None
        self.observed = bytearray(limit)
        self.pattern = re.compile(r"^ctfm-load-" + re.escape(nonce) + "-" + re.escape(WIRE_KEYS[key]) + r" seq=([a-p]{12}) t=([a-p]{20}) ")
        self.stats = {"messages": 0, "bytes": 0, "synthetic_line_observations": 0, "unique_synthetic_sequences": 0,
                      "duplicate_tail_observations": 0, "unmatched_line_observations": 0,
                      "first_delivery_latency_ms_max": 0.0, "error": None}

    def snapshot(self):
        with self.lock:
            return dict(self.stats)

    def run(self):
        try:
            self.socket = sock = socket.create_connection((self.api.address.hostname, self.api.address.port or 80), timeout=5)
            sock.settimeout(5)
            token = base64.b64encode(os.urandom(16)).decode()
            query = urllib.parse.urlencode({"service_id": self.service_id, "component": self.component})
            sock.sendall((f"GET /api/stream?{query} HTTP/1.1\r\nHost: {self.api.address.netloc}\r\nOrigin: {self.api.base}\r\nCookie: {self.api.cookie}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {token}\r\n\r\n").encode())
            pending = b""
            while b"\r\n\r\n" not in pending:
                piece = sock.recv(4096)
                require(piece, "WebSocket closed before handshake")
                pending += piece
                require(len(pending) <= 65536, "WebSocket handshake exceeded bound")
            header, pending = pending.split(b"\r\n\r\n", 1)
            accept = base64.b64encode(hashlib.sha1((token + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            require(header.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 101 ") and accept.lower() in header.lower(), "WebSocket handshake rejected")
            self.ready.set()

            def read(length):
                nonlocal pending
                while len(pending) < length:
                    piece = sock.recv(min(65536, length - len(pending)))
                    require(piece, "WebSocket closed during load")
                    pending += piece
                result, pending = pending[:length], pending[length:]
                return result

            message, message_type = bytearray(), None
            while not self.stop.is_set():
                a, b = read(2)
                require(not a & 0x70 and not b & 0x80, "unexpected WebSocket extension/server mask")
                opcode, final, length = a & 15, bool(a & 0x80), b & 127
                if length == 126:
                    length = struct.unpack("!H", read(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", read(8))[0]
                require(length <= 1024 * 1024, "WebSocket frame exceeded 1 MiB")
                data = read(length)
                if opcode == 8:
                    require(self.stop.is_set(), "WebSocket closed before end of observation")
                    break
                if opcode == 9:
                    require(final and length <= 125, "invalid ping")
                    sock.sendall(masked_frame(10, data))
                    continue
                if opcode == 10:
                    continue
                if opcode in (1, 2):
                    require(message_type is None, "nested WebSocket message")
                    message_type = opcode
                else:
                    require(opcode == 0 and message_type is not None, "unexpected WebSocket continuation")
                message.extend(data)
                require(len(message) <= 1024 * 1024, "WebSocket message exceeded 1 MiB")
                if not final:
                    continue
                require(message_type == 1, "log WebSocket did not return JSON text")
                value = json.loads(message)
                size = len(message)
                message.clear()
                message_type = None
                require(value.get("executor") == "ok" and not value.get("logs_error") and not value.get("truncated")
                        and not value.get("logs", {}).get("truncated"), "WebSocket reports unavailable/truncated logs")
                with self.lock:
                    self.stats["messages"] += 1
                    self.stats["bytes"] += size
                    for line in value.get("logs", {}).get("content", "").splitlines(keepends=True):
                        match = self.pattern.match(line)
                        if not match:
                            self.stats["unmatched_line_observations"] += 1
                            continue
                        require(len(line.encode()) == 1024, "synthetic line was changed/truncated")
                        sequence, written_ns = decode_integer(match[1]), decode_integer(match[2])
                        require(sequence < len(self.observed), "synthetic sequence exceeded bounded run")
                        self.stats["synthetic_line_observations"] += 1
                        if self.observed[sequence]:
                            self.stats["duplicate_tail_observations"] += 1
                        else:
                            self.observed[sequence] = 1
                            self.stats["unique_synthetic_sequences"] += 1
                            latency = (time.monotonic_ns() - written_ns) / 1e6
                            require(0 <= latency <= 60000, "synthetic delivery clock/lag exceeded guard")
                            self.stats["first_delivery_latency_ms_max"] = max(latency, self.stats["first_delivery_latency_ms_max"])
        except Exception as error:
            if not self.stop.is_set():
                with self.lock:
                    self.stats["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
                self.fail("WebSocket " + self.key + " failed: " + self.stats["error"])
        finally:
            if self.socket:
                self.socket.close()

    def close(self):
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Injector:
    def __init__(self, pinned, key, nonce, limit, start, go, stop, fail):
        self.pinned, self.key, self.nonce, self.start = pinned, key, nonce, start
        self.go, self.stop, self.fail, self.lock = go, stop, fail, threading.Lock()
        self.written = bytearray(limit)
        self.stats = {"attempted_lines": 0, "written_lines": 0, "written_bytes": 0,
                      "backpressure_dropped_lines": 0, "scheduler_skipped_lines": 0, "partial_writes": 0,
                      "first_successful_write_elapsed": None, "last_successful_write_elapsed": None,
                      "maximum_successful_write_gap_seconds": 0, "error": None}

    def snapshot(self):
        with self.lock:
            return dict(self.stats)

    def run(self):
        self.go.wait()
        sequence, next_at, next_guard = 0, self.start[0], 0
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                if next_guard and now - next_guard > 4:
                    raise RuntimeError("injector scheduling gap exceeded five seconds; sustained log workload invalid")
                if now < next_at:
                    self.stop.wait(min(next_at - now, .025))
                    continue
                skipped = max(0, int((now - next_at) * 40) - 1)
                sequence += skipped
                require(sequence < len(self.written), "injector sequence exceeded bounded run")
                if now >= next_guard:
                    self.pinned.assert_alive()
                    next_guard = now + 1
                # pidfd remains tied to the original process even if its numeric
                # PID is recycled; the opened descriptor is its original FIFO.
                require(not select.select([self.pinned.pidfd], [], [], 0)[0], "application process exited during stdout injection")
                if self.stop.is_set():
                    break
                data = synthetic_line(self.nonce, self.key, sequence, time.monotonic_ns())
                written, dropped = 0, False
                try:
                    written = os.write(self.pinned.stdout_fd, data)
                except BlockingIOError:
                    dropped = True
                with self.lock:
                    self.stats["attempted_lines"] += 1
                    self.stats["scheduler_skipped_lines"] += skipped
                    if dropped:
                        self.stats["backpressure_dropped_lines"] += 1
                    else:
                        self.stats["written_bytes"] += written
                        if written == 1024:
                            self.written[sequence] = 1
                            self.stats["written_lines"] += 1
                            elapsed = time.monotonic() - self.start[0]
                            if self.stats["first_successful_write_elapsed"] is None:
                                self.stats["first_successful_write_elapsed"] = elapsed
                            if self.stats["last_successful_write_elapsed"] is not None:
                                self.stats["maximum_successful_write_gap_seconds"] = max(elapsed - self.stats["last_successful_write_elapsed"], self.stats["maximum_successful_write_gap_seconds"])
                            self.stats["last_successful_write_elapsed"] = elapsed
                        else:
                            self.stats["partial_writes"] += 1
                require(dropped or written == 1024, "atomic stdout injection returned a partial write")
                sequence += 1
                next_at = max(next_at + (skipped + 1) / 40, now - .025)
        except Exception as error:
            if not self.stop.is_set():
                with self.lock:
                    self.stats["error"] = type(error).__name__
                self.fail("stdout injector " + self.key + " failed (" + type(error).__name__ + ")")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/srv/ctf-manager"))
    parser.add_argument("--base", default="http://127.0.0.1:8765")
    parser.add_argument("--credentials", type=Path)
    parser.add_argument("--probe-checkpoints", type=Path)
    parser.add_argument("--preflight-no-data-checks", action="store_true", help="only for a <300s connectivity/log preflight; never claims game data preservation")
    parser.add_argument("--protected-inventory", type=Path, help="prior load/preflight report whose exact twelve identities must still match")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--inject-stdout", action="store_true", help="explicitly authorize marked 40x1024-byte lines/sec on each of five application stdout FIFOs")
    parser.add_argument("--minimum-memory-mib", type=int, default=512)
    parser.add_argument("--minimum-disk-mib", type=int, default=1024)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require(args.inject_stdout and 20 <= args.seconds <= 7200, "explicit --inject-stdout and 20..7200 seconds required")
    require((args.preflight_no_data_checks and args.seconds < 300)
            or (not args.preflight_no_data_checks and args.probe_checkpoints is not None),
            "full observation requires saved player probes; data-skip is limited to short explicit preflight")
    require(args.minimum_memory_mib >= 384 and args.minimum_disk_mib >= 1024, "safety floors cannot be reduced below 384 MiB RAM / 1 GiB disk")
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64") and os.geteuid() == 0
            and hasattr(os, "pidfd_open"), "requires native Linux/amd64 root with pidfd support")
    require(Path("/proc/1/comm").read_text().strip() == "systemd" and not Path("/.dockerenv").exists(), "run directly on the native VM")
    require(args.root.is_absolute() and args.root.resolve() == args.root, "native root must be a real canonical directory")
    info = json.loads(docker("info", "--format", "{{json .}}"))
    require(info["OSType"] == "linux" and info["Architecture"] in ("x86_64", "amd64")
            and info["KernelVersion"] == platform.release(), "Docker daemon is not this native Linux/amd64 kernel")
    minimum_memory, minimum_disk = args.minimum_memory_mib * 1024**2, args.minimum_disk_mib * 1024**2
    protected = inventory()
    if args.protected_inventory:
        previous = private_read(args.protected_inventory)
        preserved(previous["protected_inventory"], protected)
    nonce = "".join(LETTER_HEX[int(character, 16)] for character in uuid.uuid4().hex[:20])
    report = {"test": "installed-real-services-native-panel-load", "status": "running", "started_at": utc(),
              "run_id": nonce, "seconds_requested": args.seconds, "protected_inventory": protected,
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "runtime": {key: info.get(key) for key in ("ServerVersion", "OperatingSystem", "Architecture", "KernelVersion", "NCPU", "MemTotal")},
              "scope": "existing installed panel and five real SibirCTF services; no additional containers or lifecycle operations",
              "rss_sum_peak_bytes": 0,
              "log_load": {"source": "explicit synthetic host writes to inspected application stdout FIFOs", "target_lines_per_second": 200,
                           "per_service_lines_per_second": 40, "line_bytes_including_newline": 1024,
                           "marker_encoding": "hexadecimal integers mapped to letters a..p; no numeric flag literal in signature",
                           "unmatched_lines_are_not_classified_as_real_application_traffic": True,
                           "not_real_application_traffic": True, "not_lossless_log_archive_acceptance": True},
              "limits": {"minimum_mem_available_bytes": minimum_memory, "minimum_disk_available_bytes": minimum_disk, "minimum_free_inodes": 4096},
              "sampler_timing": {"interval_limit_seconds": 5, "last_tick_elapsed": 0.0, "maximum_gap_seconds": 0.0, "invalid": False},
              "limitations": ["Client/sampler run on this VM; their CPU/RSS are excluded from panel cgroup/main-process metrics but consume host resources",
                              "RSS is the sum of two main Go process VmRSS values; excludes games, daemon, cache and transient child RSS",
                              "cgroup CPU includes panel child processes/healthchecks; no docker exec sampling",
                              "Only explicit synthetic stdout emission is the declared 200-line/sec workload; ordinary game traffic is independent",
                              "No power loss, daemon restart, panel restart or occupied-worker enqueue latency test",
                              "neuroLinks RAM is checked only while exact auxiliary ID/StartedAt is preserved"]}
    stop, inject_stop, go, measuring = threading.Event(), threading.Event(), threading.Event(), threading.Event()
    errors, error_lock, sample_lock = [], threading.Lock(), threading.Lock()
    pinned, panel, streams, injectors, threads, injector_threads, samples = [], {}, {}, {}, [], [], []
    api_failures, latencies, metrics_polls = [], [], 0
    start_box = [0.0]

    def fail(message):
        with error_lock:
            if message not in errors:
                errors.append(message)
        stop.set()
        inject_stop.set()

    def checkpoint(phase):
        report["phase"] = phase
        report["streams"] = {key: value.snapshot() for key, value in streams.items()}
        report["injection"] = {key: value.snapshot() for key, value in injectors.items()}
        with sample_lock:
            report["process_samples"] = list(samples)
        report["errors"] = list(errors)
        private_write(args.report, report)

    try:
        probes = None
        if args.preflight_no_data_checks:
            report["data_before"] = {"status": "not_performed_explicit_short_preflight"}
        else:
            require((args.probe_checkpoints / "identity.json").is_file(), "completed private player probe checkpoints required")
            probes = ProbeAdapter(args.root, args.probe_checkpoints)
            report["data_before"] = {key: probes.verify(key) for key in KEYS}
        preserved(protected, inventory())
        api = API(args.base)
        credentials = private_read(args.credentials or args.root / "config/access.json")
        api.login(credentials)
        credentials.clear()
        require(api.request("/api/status").get("executor") == "ok", "installed executor unavailable")
        require(not any(item["state"] in ("queued", "running", "interrupted", "requires_recovery")
                        for item in api.request("/api/operations")), "finish active/unresolved product operations before measuring observation overhead")
        registry = api.request("/api/services")
        selected = {}
        for key in KEYS:
            matches = [item for item in registry if item["project_directory"] == str(args.root / "services" / ("sibir-" + key))
                       and item["compose_project"] == "ctfm-demo-sibir-" + key]
            require(len(matches) == 1, "expected real service registry entry missing/ambiguous")
            selected[key] = matches[0]["id"]
        report["service_ids"] = selected
        for component in ("dashboard", "executor"):
            value = next(item for item in protected.values() if item["project"] == "ctf-manager" and item["component"] == component)
            panel[component] = process = PinnedProcess(value)
            pinned.append(process)
        limit = args.seconds * 40 + 5000
        for key in KEYS:
            value = next(item for item in protected.values() if item["project"] == "ctfm-demo-sibir-" + key and item["component"] == LOG_COMPONENTS[key])
            process = PinnedProcess(value, stdout=True)
            pinned.append(process)
            streams[key] = Stream(api, key, selected[key], LOG_COMPONENTS[key], nonce, limit, stop, fail)
            injectors[key] = Injector(process, key, nonce, limit, start_box, go, inject_stop, fail)
            thread = threading.Thread(target=streams[key].run, daemon=True)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + 30
        while not all(value.ready.is_set() for value in streams.values()):
            require(not stop.is_set() and time.monotonic() < deadline, "five authenticated WebSockets did not become ready")
            time.sleep(.1)
        initial_history = {"host": history_summary(api.request("/api/metrics/host"))}
        initial_history.update({key: history_summary(api.request("/api/services/" + selected[key] + "/metrics")) for key in KEYS})
        report["history_initial"] = initial_history
        guard = resource_guard(args.root, minimum_memory, minimum_disk)
        report["resource_minima"] = guard

        def sample():
            began = time.monotonic()
            processes = {name: value.sample() for name, value in panel.items()}
            ended = time.monotonic()
            return {"elapsed": ended - start_box[0], "observed_at_utc": utc(), "sample_duration_seconds": ended - began, "processes": processes}

        def sampler():
            next_inventory, next_sample = time.monotonic(), time.monotonic()
            while not stop.wait(1):
                try:
                    with sample_lock:
                        if measuring.is_set():
                            elapsed = time.monotonic() - start_box[0]
                            timing = report["sampler_timing"]
                            gap = elapsed - timing["last_tick_elapsed"]
                            timing["maximum_gap_seconds"] = max(gap, timing["maximum_gap_seconds"])
                            timing["last_tick_elapsed"] = elapsed
                            timing["invalid"] = timing["invalid"] or gap > 5
                            check_sampler_gap(elapsed - gap, elapsed)
                    guard = resource_guard(args.root, minimum_memory, minimum_disk)
                    with sample_lock:
                        report["resource_minima"] = {name: min(value, report["resource_minima"][name]) for name, value in guard.items()}
                    for value in pinned:
                        value.assert_alive()
                    current = sample()
                    require(current["sample_duration_seconds"] <= 5, "native process sample stalled beyond five seconds")
                    with sample_lock:
                        if measuring.is_set():
                            report["rss_sum_peak_bytes"] = max(report.get("rss_sum_peak_bytes", 0), sum(value["rss_bytes"] for value in current["processes"].values()))
                            if time.monotonic() >= next_sample:
                                samples.append(current)
                                next_sample = time.monotonic() + 10
                    if time.monotonic() >= next_inventory:
                        preserved(protected, inventory())
                        next_inventory = time.monotonic() + 30
                except Exception as error:
                    fail("native sampler safety guard: " + type(error).__name__ + ": " + str(error))
                    break

        start_box[0] = time.monotonic()
        report["measurement_started_at_utc"] = utc()
        samples.append(sample())
        measuring.set()
        for value in injectors.values():
            thread = threading.Thread(target=value.run, daemon=True)
            thread.start()
            threads.append(thread)
            injector_threads.append((thread, value))
        sampler_thread = threading.Thread(target=sampler, daemon=True)
        sampler_thread.start()
        threads.append(sampler_thread)
        go.set()
        checkpoint("measuring")
        next_api, next_metrics, next_progress, iteration = start_box[0], start_box[0], start_box[0] + 30, 0
        while time.monotonic() - start_box[0] < args.seconds and not stop.is_set():
            now = time.monotonic()
            if now >= next_api:
                began = time.monotonic()
                try:
                    require(api.request("/api/status").get("executor") == "ok", "executor unavailable under load")
                    key = KEYS[iteration % 5]
                    detail = api.request("/api/services/" + selected[key])
                    require({value["component"] for value in detail["containers"]} == GAME_COMPONENTS[key]
                            and all(value["state"] == "running" and value["health"] in ("healthy", "not_configured") for value in detail["containers"]), "runtime detail is stopped/unhealthy/incomplete")
                    latencies.append((time.monotonic() - began) * 1000)
                except Exception as error:
                    api_failures.append(type(error).__name__)
                    fail("status/detail API failed under load")
                iteration += 1
                next_api += .5
                if next_api < time.monotonic() - .5:
                    next_api = time.monotonic()
            if now >= next_metrics and not stop.is_set():
                try:
                    current_history = {"host": history_summary(api.request("/api/metrics/host"))}
                    for key in KEYS:
                        require(not stop.is_set(), "load aborted before metrics request")
                        current_history[key] = history_summary(api.request("/api/services/" + selected[key] + "/metrics"))
                    report["history_latest"] = current_history
                    metrics_polls += 1
                except Exception as error:
                    fail("host/service metrics poll failed: " + type(error).__name__)
                next_metrics += 5
                if next_metrics < time.monotonic() - 5:
                    next_metrics = time.monotonic()
            if now >= next_progress:
                report["partial_measurement"] = {"seconds": now - start_box[0], "api_iterations": iteration, "api_failures": len(api_failures), "metrics_poll_rounds": metrics_polls}
                checkpoint("measuring")
                print(json.dumps({"phase": "measuring", **report["partial_measurement"]}), flush=True)
                next_progress = time.monotonic() + 30
            stop.wait(.01)
        inject_stop.set()
        with sample_lock:
            measuring.clear()
            final_sample = sample()
            samples.append(final_sample)
            timing = report["sampler_timing"]
            trailing = final_sample["elapsed"] - timing["last_tick_elapsed"]
            timing["maximum_gap_seconds"] = max(trailing, timing["maximum_gap_seconds"])
            timing["invalid"] = timing["invalid"] or trailing > 5 or final_sample["sample_duration_seconds"] > 5
            report["measurement_stopped_at_utc"] = utc()
            report["observed_interval_seconds"] = final_sample["elapsed"] - samples[0]["elapsed"]
        elapsed = final_sample["elapsed"] - samples[0]["elapsed"]
        for thread, _value in injector_threads:
            thread.join(timeout=5)
        require(not any(thread.is_alive() for thread, _value in injector_threads), "stdout injector did not stop; keep its FIFO descriptor pinned")
        require(not stop.is_set(), "load aborted by runtime/resource/client guard")
        require(not report["sampler_timing"]["invalid"], "native sampler continuity failed; timing acceptance forbidden")
        # Drain the panel's two-second tail polls after the last injected line;
        # excluded from the CPU/RSS measurement interval.
        for _ in range(50):
            require(not stop.is_set(), "log clients failed during final drain")
            time.sleep(.1)
        cpu_usec = sum(final_sample["processes"][name]["cpu_usec"] - samples[0]["processes"][name]["cpu_usec"] for name in panel)
        require(cpu_usec >= 0, "panel cgroup CPU counters reset")
        cpu = cpu_usec / 1e6 / elapsed
        rss = max(report.get("rss_sum_peak_bytes", 0), *(sum(value["rss_bytes"] for value in item["processes"].values()) for item in (samples[0], final_sample)))
        ordered = sorted(latencies)
        p95 = ordered[max(0, math.ceil(.95 * len(ordered)) - 1)] if ordered else None
        report["measurement"] = {"seconds": elapsed, "status_detail_pair_p95_ms": p95, "api_pair_iterations": iteration,
                                 "api_pair_target_per_second": 2, "api_pair_actual_per_second": iteration / elapsed,
                                 "api_failures": api_failures, "host_and_all_five_service_poll_rounds": metrics_polls,
                                 "panel_cpu_average_cores": cpu, "panel_main_rss_peak_bytes": rss}
        report["thresholds"] = {"api_pair_p95_le_500ms": p95 is not None and p95 <= 500,
                                "api_pairs_at_least_1_9_per_second": iteration / elapsed >= 1.9,
                                "metrics_rounds_at_least_95_percent_of_5s_target": metrics_polls >= .95 * elapsed / 5,
                                "rss_le_256MiB": rss <= 256 * 1024**2,
                                "five_minute_cpu_interval": elapsed >= 300,
                                "cpu_le_point1_core": cpu <= .1,
                                "full_hour_observed": elapsed >= 3600}
        delivery = {}
        for key in KEYS:
            emitted, received = injectors[key], streams[key]
            expected, seen = emitted.snapshot()["written_lines"], 0
            for sequence, value in enumerate(received.observed):
                if value:
                    require(emitted.written[sequence], "WS observed an un-emitted synthetic sequence")
                    seen += 1
            delivery[key] = {"successfully_emitted": expected, "distinct_observed_on_actual_ws": seen,
                             "delivery_ratio": seen / expected if expected else 0,
                             "emitted_lines_per_second": expected / elapsed,
                             "nominal_target_lines": 40 * elapsed,
                             "emission_deficit_lines": max(0, 40 * elapsed - expected)}
            require(expected > 0 and seen / expected >= .99 and expected / elapsed >= 39.5,
                    "declared synthetic emission/delivery workload was not sustained")
        report["actual_delivery"] = delivery
        require(all(report["thresholds"][key] for key in ("api_pair_p95_le_500ms", "api_pairs_at_least_1_9_per_second", "rss_le_256MiB", "metrics_rounds_at_least_95_percent_of_5s_target")), "observation API/RSS/metrics-rate thresholds failed")
        if args.seconds >= 300:
            require(report["thresholds"]["cpu_le_point1_core"], "panel average CPU threshold failed")
        if args.seconds >= 3600:
            final_history = {"host": history_summary(api.request("/api/metrics/host"))}
            final_history.update({key: history_summary(api.request("/api/services/" + selected[key] + "/metrics")) for key in KEYS})
            require(all(value["span_seconds"] >= 3580 and value["samples"] >= 700 for value in final_history.values()), "real sixty-minute host/service history was not retained")
            report["history_final"] = final_history
        preserved(protected, inventory())
        # The auxiliary invariants are checked immediately before any RAM-key
        # read, rather than using old keys after a hidden process restart.
        report["data_after"] = {key: probes.verify(key) for key in KEYS} if probes else {"status": "not_performed_explicit_short_preflight"}
        preserved(protected, inventory())
        report["all_twelve_runtime_identities_preserved"] = True
        report["resource_acceptance"] = "passed_full_hour" if args.seconds >= 3600 else "not_claimed_preflight" if args.seconds < 300 else "passed_five_minute_observation_only"
        report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["status"] = "failed"
    finally:
        inject_stop.set()
        measuring.clear()
        stop.set()
        go.set()
        for value in streams.values():
            value.close()
        for thread in threads:
            thread.join(timeout=15)
        active_writers = {id(value.pinned) for thread, value in injector_threads if thread.is_alive()}
        sampler_active = "sampler_thread" in locals() and sampler_thread.is_alive()
        for value in pinned:
            # Never recycle a numeric descriptor while a writer may still use
            # it. A failed daemon thread keeps its own pinned descriptors until
            # this Python process exits; no later file can inherit that number.
            if id(value) not in active_writers and not sampler_active:
                value.close()
        if active_writers or sampler_active:
            report["status"] = "failed"
            report["cleanup_error"] = "sampler/injector thread did not stop; descriptors retained until process exit"
        report["own_threads_stopped"] = not any(thread.is_alive() for thread in threads)
        if start_box[0]:
            observed_interval = report.get("observed_interval_seconds")
            report["emission_diagnostics"] = {}
            for key, value in injectors.items():
                statistics = value.snapshot()
                first, last = statistics["first_successful_write_elapsed"], statistics["last_successful_write_elapsed"]
                report["emission_diagnostics"][key] = {
                    "successful_write_span_seconds": last - first if first is not None and last is not None else None,
                    "first_successful_write_elapsed": first, "last_successful_write_elapsed": last,
                    "successfully_written_lines": statistics["written_lines"],
                    "actual_lines_per_observed_second": statistics["written_lines"] / observed_interval if observed_interval else None,
                    "nominal_target_lines_for_observed_interval": 40 * observed_interval if observed_interval else None,
                    "deficit_lines_for_observed_interval": max(0, 40 * observed_interval - statistics["written_lines"]) if observed_interval else None,
                    "trailing_idle_seconds": max(0, observed_interval - last) if observed_interval is not None and last is not None else None}
        if report["status"] != "passed":
            report["resource_acceptance"] = "not_claimed_failed_run"
        report["finished_at"] = utc()
        checkpoint("complete" if report["status"] == "passed" else "failed")
        print(json.dumps({"status": report["status"], "resource_acceptance": report.get("resource_acceptance"), "error": report.get("error"), "report": str(args.report)}), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("SIGTERM")))
    raise SystemExit(main())
