#!/usr/bin/env python3
"""Real proxy/recorder process smoke on isolated loopback fixtures.

No Docker, SSH, VM, panel, game project or host network setting is used. Both
binaries and every mutable artifact live in a new private temporary directory.
Only hashes and synthetic result metadata leave that directory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def private_file(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(value if isinstance(value, str) else json.dumps(value, separators=(",", ":")))


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("local-control", timeout=4)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def call_unix(path, token, method, target, value=None, expected=200):
    connection = UnixHTTP(path)
    try:
        body = None if value is None else json.dumps(value).encode()
        headers = {"Authorization": "Bearer " + token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(4 * 1024 * 1024 + 1)
        require(len(data) <= 4 * 1024 * 1024, "bounded control response exceeded")
        require(response.status == expected, "private control returned unexpected HTTP status")
        return json.loads(data)
    finally:
        connection.close()


def request(port, method="GET", path="/ping", body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(2 * 1024 * 1024 + 1)
        require(len(data) <= 2 * 1024 * 1024, "fixture response exceeded bound")
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def wait_until(test, message, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = test()
            if value:
                return value
        except (OSError, http.client.HTTPException, ValueError, RuntimeError):
            pass
        time.sleep(.1)
    raise RuntimeError(message)


class Upstream:
    def __init__(self, name, secret):
        self.name, self.secret, self.requests = name, secret, []
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def echo(self):
                size = int(self.headers.get("Content-Length", "0"))
                require(0 <= size <= 262144, "synthetic upstream body exceeded limit")
                body = self.rfile.read(size)
                with owner.lock:
                    owner.requests.append({"method": self.command, "path": self.path, "body": body,
                                           "authorization": self.headers.get("Authorization"),
                                           "forwarded_for": self.headers.get("X-Forwarded-For")})
                result = json.dumps({"upstream": owner.name, "method": self.command, "path": self.path,
                                     "body": body.decode("utf-8"), "known_secret": owner.secret}).encode()
                self.send_response(201 if self.command == "mIxEd" else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=" + owner.secret)
                self.send_header("Content-Length", str(len(result)))
                self.end_headers()
                self.wfile.write(result)

            do_GET = do_POST = do_mIxEd = echo

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server.server_port

    def count(self):
        with self.lock:
            return len(self.requests)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class Process:
    def __init__(self, arguments, log):
        self.arguments, self.log, self.process = arguments, log, None

    def start(self):
        require(self.process is None, "process already started")
        self.output = self.log.open("ab")
        os.chmod(self.log, 0o600)
        environment = {key: value for key, value in os.environ.items()
                       if not key.lower().endswith("_proxy") and not key.startswith("CTFM_")}
        self.process = subprocess.Popen(self.arguments, stdin=subprocess.DEVNULL, stdout=self.output,
                                        stderr=subprocess.STDOUT, env=environment)

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.output.close()
        self.process = None


def route(identity, service, listen, upstream, mode):
    return {"id": identity, "service_id": service, "component": "app",
            "listen": f"127.0.0.1:{listen}", "upstream": f"http://127.0.0.1:{upstream}", "protocol": "http1",
            "capture": {"mode": "bounded_body", "max_body_bytes": 65536,
                        "body_patterns": ["CTFM_SMOKE_[a-f0-9]+"]},
            "waf": {"mode": mode, "rate_per_second": .1 if mode == "enforce" else 1000,
                    "burst": 2 if mode == "enforce" else 100, "violation_threshold": 2,
                    "violation_window_seconds": 10, "ban_ttl_seconds": 60,
                    "max_ip_states": 64, "state_ttl_seconds": 60, "overflow_mode": "reject_new"},
            "limits": {"max_concurrent": 16, "max_header_bytes": 16384, "read_header_timeout_seconds": 3,
                       "upstream_response_header_timeout_seconds": 3, "idle_timeout_seconds": 5,
                       "max_connection_seconds": 30, "max_body_bytes": 1048576}}


def run(args, report):
    processes, upstreams = [], []
    with tempfile.TemporaryDirectory(prefix="ctfm-http-proxy-", dir="/tmp") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        for name in ("policy", "proxy-state", "traffic-state", "proxy-control", "traffic-control"):
            (root / name).mkdir(mode=0o700)
        executable = {}
        for name, source in (("proxy", args.proxy_binary), ("traffic", args.traffic_binary)):
            destination = root / ("ctfm-" + name)
            shutil.copy2(source.resolve(strict=True), destination)
            destination.chmod(0o700)
            executable[name] = destination
            report["binaries"][name] = {"path": str(source.resolve()), "sha256": digest(destination.read_bytes())}
        control, ingest, read = (secrets.token_urlsafe(48) for _ in range(3))
        for name, value in (("control-token", control), ("ingest-token", ingest), ("read-token", read)):
            private_file(root / name, value + "\n")
        control_secret = "CTFM_SMOKE_" + secrets.token_hex(16)
        alpha, beta = Upstream("alpha", control_secret), Upstream("beta", control_secret)
        upstreams.extend((alpha, beta))
        recorder_port, alpha_port, beta_port = free_port(), free_port(), free_port()
        require(len({recorder_port, alpha_port, beta_port, alpha.port, beta.port}) == 5, "fixture ephemeral port collision")
        policy = {"schema_version": 1, "revision": 1, "routes": [
            route("route-alpha", "service-alpha", alpha_port, alpha.port, "observe_only"),
            route("route-beta", "service-beta", beta_port, beta.port, "enforce")]}
        private_file(root / "policy/policy.json", policy)
        store_socket, proxy_socket = root / "traffic-control/recorder.sock", root / "proxy-control/proxy.sock"
        recorder = Process([str(executable["traffic"]), f"--listen=127.0.0.1:{recorder_port}",
                            f"--control-unix={store_socket}", f"--state={root / 'traffic-state'}",
                            f"--ingest-token-file={root / 'ingest-token'}", f"--read-token-file={root / 'read-token'}",
                            "--quota-bytes=16777216", "--per-service-bytes=4194304", "--minimum-free-bytes=1048576"], root / "recorder.log")
        proxy = Process([str(executable["proxy"]), f"--policy-file={root / 'policy/policy.json'}",
                         f"--state={root / 'proxy-state'}", "--control-listen=", f"--control-unix={proxy_socket}",
                         f"--control-token-file={root / 'control-token'}", f"--recorder-url=http://127.0.0.1:{recorder_port}",
                         f"--recorder-token-file={root / 'ingest-token'}"], root / "proxy.log")
        processes.extend((proxy, recorder))
        try:
            recorder.start()
            wait_until(lambda: call_unix(store_socket, read, "GET", "/v1/status").get("available"), "recorder did not become ready")
            proxy.start()
            status = wait_until(lambda: (value if (value := call_unix(proxy_socket, control, "GET", "/v1/status")).get("applied_revision") == 1 and value.get("routes") == 2 else None), "proxy policy not applied")
            report["checks"]["two_frozen_routes_applied"] = True
            report["first_collector_epoch"] = status["collector_epoch"]
            def recorded_page(target, predicate):
                value = call_unix(store_socket, read, "GET", target)
                return value if any(predicate(item) for item in value["records"]) else None
            body = json.dumps({"password": control_secret, "visible": "ordinary application data"}).encode()
            path = "/echo?second=2&first=one&first=again&token=" + control_secret
            code, _, response = request(alpha_port, "mIxEd", path, body,
                                        {"Content-Type": "application/json", "Authorization": "Bearer " + control_secret,
                                         "X-Forwarded-For": "198.51.100.99"})
            require(code == 201 and json.loads(response)["upstream"] == "alpha", "route-alpha did not reach its upstream")
            with alpha.lock:
                observed = alpha.requests[-1]
                require(observed["method"] == "mIxEd" and observed["path"] == path and observed["body"] == body,
                        "method/query/body changed before upstream")
                require(observed["authorization"] == "Bearer " + control_secret,
                        "application authorization was removed from forwarding")
                require(observed["forwarded_for"] == "127.0.0.1", "spoofed client XFF reached upstream")
            report["checks"]["method_query_duplicate_order_body_and_application_auth_preserved"] = True
            report["checks"]["untrusted_forwarded_ip_normalized"] = True
            for _ in range(2):
                require(request(beta_port)[0] == 200, "initial token bucket burst not forwarded")
            count_before_deny = beta.count()
            for _ in range(2):
                code, headers, _ = request(beta_port)
                require(code == 429 and int(headers.get("Retry-After", "0")) >= 1, "WAF did not return 429/Retry-After")
            require(beta.count() == count_before_deny, "WAF denied request reached upstream")
            bans = call_unix(proxy_socket, control, "GET", "/v1/bans?service_id=service-beta")
            require(len(bans["bans"]) == 1 and bans["bans"][0]["source"] == "automatic", "repeated violations did not create an automatic ban")
            report["checks"]["enforce_429_and_automatic_ban_before_upstream"] = True
            query = "/v1/exchanges?" + urllib.parse.urlencode({"service_id": "service-alpha", "method": "mIxEd"})
            alpha_page = wait_until(lambda: recorded_page(query, lambda item: item["state"] == "completed"), "completed alpha exchange not recorded")
            require(all(x["service_id"] == "service-alpha" for x in alpha_page["records"]), "service filter crossed scopes")
            target = next(x for x in alpha_page["records"] if x["state"] == "completed")
            detail = call_unix(store_socket, read, "GET", "/v1/exchanges/" + target["request_id"])
            require(control_secret not in json.dumps(detail) and control_secret not in json.dumps(alpha_page), "control secret escaped redaction")
            require(detail["request_body"].get("data") and detail["response_body"].get("data"), "bounded payload detail missing")
            beta_page = wait_until(lambda: recorded_page("/v1/exchanges?service_id=service-beta", lambda item: item["status"] == 429), "WAF denied exchange not recorded")
            require(all(x["service_id"] == "service-beta" for x in beta_page["records"]), "beta filter crossed scopes")
            all_page = call_unix(store_socket, read, "GET", "/v1/exchanges")
            require({x["service_id"] for x in all_page["records"]} == {"service-alpha", "service-beta"}, "global traffic page missed one service")
            require("request_body" not in json.dumps(all_page) and "request_headers" not in json.dumps(all_page), "metadata API returned payload fields")
            report["checks"]["global_and_service_filtered_metadata_and_sensitive_detail"] = True
            report["checks"]["header_query_body_secret_redaction"] = True
            scope = {"service_id": "service-beta", "ip": "127.0.0.1", "comment": "Synthetic process smoke"}
            call_unix(proxy_socket, control, "POST", "/v1/unban", scope)
            require(call_unix(proxy_socket, control, "GET", "/v1/bans?service_id=service-beta")["total"] == 0,
                    "manual unban did not remove the automatic ban")
            report["checks"]["manual_unban"] = True
            persisted = call_unix(proxy_socket, control, "POST", "/v1/bans", {**scope, "ttl_seconds": 15})
            old_expiry = persisted["expires_at"]
            proxy.stop()
            proxy.start()
            restarted = wait_until(lambda: (value if (value := call_unix(proxy_socket, control, "GET", "/v1/status")).get("applied_revision") == 1 else None), "proxy did not restore its policy")
            require(restarted["collector_epoch"] != report["first_collector_epoch"], "proxy restart did not publish a new epoch")
            loaded = call_unix(proxy_socket, control, "GET", "/v1/bans?service_id=service-beta")["bans"]
            require(len(loaded) == 1 and loaded[0]["expires_at"] == old_expiry, "restart lost or extended the ban TTL")
            require(request(beta_port)[0] == 429 and request(alpha_port)[0] == 200, "restored ban/policy scope was not enforced")
            wait_until(lambda: request(beta_port)[0] == 200, "persisted ban did not expire at its original TTL", seconds=18)
            report["checks"]["policy_ban_and_original_ttl_survive_proxy_restart"] = True
            before = call_unix(proxy_socket, control, "GET", "/v1/status")["counters"]["capture_dropped"]
            recorder.stop()
            hits = alpha.count()
            for _ in range(3):
                require(request(alpha_port)[0] == 200, "recorder outage stopped forwarding")
            require(alpha.count() == hits + 3, "recorder-down requests did not reach upstream")
            status = wait_until(lambda: (value if (value := call_unix(proxy_socket, control, "GET", "/v1/status"))["counters"]["capture_dropped"] > before else None), "recorder outage was not counted")
            report["checks"]["recorder_termination_does_not_block_forwarding"] = True
            report["recorder_outage_capture_dropped_delta"] = status["counters"]["capture_dropped"] - before
            secret = control_secret.encode()
            for file in (root / "traffic-state").iterdir():
                if file.is_file():
                    with file.open("rb") as stream:
                        tail = b""
                        while chunk := stream.read(1024 * 1024):
                            require(secret not in tail + chunk, "control secret persisted in recorder files")
                            tail = chunk[-len(secret):]
            report["checks"]["control_secret_absent_from_recorder_disk"] = True
            report["known_secret_sha256"] = digest(secret)
            report["upstream_request_counts"] = {"alpha": alpha.count(), "beta": beta.count()}
            report["status"] = "passed"
        finally:
            for process in processes:
                process.stop()
            for upstream in upstreams:
                upstream.close()
            report["own_processes_stopped"] = all(p.process is None for p in processes)
    report["private_fixture_removed_on_exit"] = not root.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-binary", type=Path, default=ROOT / "bin/ctfm-proxy")
    parser.add_argument("--traffic-binary", type=Path, default=ROOT / "bin/ctfm-traffic")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/http-proxy-process-smoke-2026-10-30.json")
    args = parser.parse_args()
    report = {"test": "http-proxy-recorder-isolated-process-smoke", "status": "failed", "started_at": stamp(),
              "runtime": {"os": platform.system(), "architecture": platform.machine()}, "binaries": {}, "checks": {},
              "harness_sha256": digest(Path(__file__).read_bytes()), "performance_acceptance": False,
              "scope": "standalone built proxy/recorder processes; synthetic loopback HTTP upstreams; private Unix controls",
              "limitations": ["No Docker Compose, VM, competition checker or occupied-port cutover acceptance",
                              "No dashboard/RBAC browser flow; component read/ingest credentials remain private",
                              "Small functional sequence only; no RPS, overhead or resource-budget claim"]}
    try:
        run(args, report)
    except BaseException as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        if isinstance(error, RuntimeError):
            report["error"] = str(error)
    finally:
        report["finished_at"] = stamp()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": report["checks"], "error": report.get("error"), "report": str(args.report)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
