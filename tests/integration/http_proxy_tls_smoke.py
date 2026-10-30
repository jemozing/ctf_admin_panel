#!/usr/bin/env python3
"""Trusted TLS smoke of copied proxy/recorder executables on private fixtures.

No Docker, SSH, VM, dashboard, game service, system trust store or host network
setting is used. Synthetic certificate/key files remain in a temporary private
profile tree. The real proxy main loads that tree through --tls-directory.
"""
import argparse
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import urllib.parse

import http_proxy_smoke as common

ROOT = Path(__file__).resolve().parents[2]
require = common.require


def replace_private(path, content):
    """Atomic fixture administration; never edits a real installation."""
    temporary = path.parent / (".fixture-" + secrets.token_hex(12))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content if isinstance(content, bytes) else json.dumps(content).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def make_profile(directory, identity, config):
    profile = directory / identity
    profile.mkdir(mode=0o700)
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                             "-days", "2", "-config", str(config), "-keyout", str(profile / "private-key.pem"),
                             "-out", str(profile / "certificate.pem")],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            timeout=30, check=False)
    require(result.returncode == 0, "synthetic certificate generation failed")
    for filename in ("certificate.pem", "private-key.pem"):
        (profile / filename).chmod(0o600)
    pem = (profile / "certificate.pem").read_text()
    fingerprint = "sha256:" + common.digest(ssl.PEM_cert_to_DER_cert(pem))
    return profile, fingerprint


def trusted_context(certificate):
    context = ssl.create_default_context(cafile=str(certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
            "TLS client must verify both certificate trust and hostname")
    return context


class TrustedTLSHTTP(http.client.HTTPConnection):
    def __init__(self, port, context, server_name="localhost"):
        super().__init__("127.0.0.1", port, timeout=5)
        self.context, self.server_name = context, server_name
        self.peer_fingerprint = self.tls_version = self.alpn = None

    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        try:
            self.sock = self.context.wrap_socket(raw, server_hostname=self.server_name)
        except BaseException:
            raw.close()
            raise
        self.peer_fingerprint = "sha256:" + common.digest(self.sock.getpeercert(binary_form=True))
        self.tls_version, self.alpn = self.sock.version(), self.sock.selected_alpn_protocol()


def tls_request(port, context, method="GET", path="/ping", body=None, headers=None,
                server_name="localhost", host=None):
    connection = TrustedTLSHTTP(port, context, server_name)
    try:
        actual_headers = {"Host": host or f"localhost:{port}", **(headers or {})}
        connection.request(method, path, body=body, headers=actual_headers)
        response = connection.getresponse()
        data = response.read(2 * 1024 * 1024 + 1)
        require(len(data) <= 2 * 1024 * 1024, "TLS fixture response exceeded bound")
        return response.status, data, {"fingerprint": connection.peer_fingerprint,
                                       "version": connection.tls_version, "alpn": connection.alpn}
    finally:
        connection.close()


class Upstream:
    def __init__(self, secret):
        self.requests, self.secret, self.lock = [], secret, threading.Lock()
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
                                           "forwarded_proto": self.headers.get("X-Forwarded-Proto"),
                                           "forwarded_for": self.headers.get("X-Forwarded-For"),
                                           "host": self.headers.get("Host")})
                result = json.dumps({"method": self.command, "path": self.path, "body": body.decode(),
                                     "known_secret": owner.secret, "visible": "TLS application response"}).encode()
                self.send_response(201 if self.command == "mIxEd" else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=" + owner.secret)
                self.send_header("Content-Length", str(len(result)))
                self.end_headers()
                self.wfile.write(result)

            do_GET = do_mIxEd = echo

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


def run(args, report):
    temporary = tempfile.TemporaryDirectory(prefix="ctfm-tls-", dir="/tmp")
    root, processes, upstream = Path(temporary.name), [], None
    root.chmod(0o700)
    try:
        for name in ("policy", "proxy-state", "traffic-state", "proxy-control", "traffic-control", "tls"):
            (root / name).mkdir(mode=0o700)
        executable = {}
        for name, source in (("proxy", args.proxy_binary), ("traffic", args.traffic_binary)):
            destination = root / ("ctfm-" + name)
            shutil.copy2(source.resolve(strict=True), destination)
            destination.chmod(0o700)
            executable[name] = destination
            report["binaries"][name] = {"path": str(source.resolve()), "sha256": common.digest(destination.read_bytes())}
        version = subprocess.run(["openssl", "version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 check=True, timeout=5).stdout.decode().strip()
        report["certificate_generator"] = version
        config = root / "openssl.cnf"
        common.private_file(config, """[req]
prompt = no
distinguished_name = subject
x509_extensions = extensions
[subject]
CN = localhost
[extensions]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
""")
        profile1, fingerprint1 = make_profile(root / "tls", "smoke-v1", config)
        context1 = trusted_context(profile1 / "certificate.pem")
        control, ingest, read = (secrets.token_urlsafe(48) for _ in range(3))
        for name, value in (("control-token", control), ("ingest-token", ingest), ("read-token", read)):
            common.private_file(root / name, value + "\n")
        known_secret = "CTFM_TLS_SMOKE_" + secrets.token_hex(16)
        upstream = Upstream(known_secret)
        recorder_port, tls_port = common.free_port(), common.free_port()
        require(len({recorder_port, tls_port, upstream.port}) == 3, "fixture ephemeral port collision")
        secure_route = common.route("route-tls", "service-tls", tls_port, upstream.port, "observe_only")
        secure_route.update({"protocol": "https1", "host": f"localhost:{tls_port}",
                             "tls": {"certificate_id": "smoke-v1"}})
        secure_route["capture"]["body_patterns"] = ["CTFM_TLS_SMOKE_[a-f0-9]+"]
        policy = {"schema_version": 1, "revision": 1, "routes": [secure_route]}
        policy_file = root / "policy/policy.json"
        common.private_file(policy_file, policy)
        store_socket, proxy_socket = root / "traffic-control/recorder.sock", root / "proxy-control/proxy.sock"
        recorder = common.Process([str(executable["traffic"]), f"--listen=127.0.0.1:{recorder_port}",
                                   f"--control-unix={store_socket}", f"--state={root / 'traffic-state'}",
                                   f"--ingest-token-file={root / 'ingest-token'}", f"--read-token-file={root / 'read-token'}",
                                   "--quota-bytes=16777216", "--per-service-bytes=4194304", "--minimum-free-bytes=1048576"], root / "recorder.log")
        proxy = common.Process([str(executable["proxy"]), f"--policy-file={policy_file}",
                                f"--state={root / 'proxy-state'}", f"--tls-directory={root / 'tls'}",
                                "--control-listen=", f"--control-unix={proxy_socket}",
                                f"--control-token-file={root / 'control-token'}", f"--recorder-url=http://127.0.0.1:{recorder_port}",
                                f"--recorder-token-file={root / 'ingest-token'}"], root / "proxy.log")
        processes.extend((proxy, recorder))

        def status():
            return common.call_unix(proxy_socket, control, "GET", "/v1/status")

        def applied(revision):
            current = status()
            return current if current.get("applied_revision") == revision and not current.get("last_error") else None

        def rejected(revision, lkg):
            current = status()
            return current if (current.get("desired_revision") == revision and
                               current.get("applied_revision") == lkg and current.get("last_error")) else None

        def desired(revision, certificate):
            wanted = copy.deepcopy(policy)
            wanted["revision"] = revision
            wanted["routes"][0]["tls"]["certificate_id"] = certificate
            replace_private(policy_file, wanted)

        recorder.start()
        common.wait_until(lambda: common.call_unix(store_socket, read, "GET", "/v1/status").get("available"),
                          "recorder did not become ready")
        proxy.start()
        first_status = common.wait_until(lambda: applied(1), "initial HTTPS policy did not become active")
        report["checks"]["real_main_loads_private_tls_profile"] = True
        body = json.dumps({"password": known_secret, "visible": "TLS application request"}).encode()
        path = "/echo?second=2&first=one&first=again&token=" + known_secret
        code, response, session = tls_request(tls_port, context1, "mIxEd", path, body,
                                              {"Content-Type": "application/json", "Authorization": "Bearer " + known_secret,
                                               "X-Forwarded-For": "198.51.100.99", "X-Forwarded-Proto": "http"})
        require(code == 201 and json.loads(response)["visible"] == "TLS application response", "trusted HTTPS did not reach upstream")
        require(session["fingerprint"] == fingerprint1 and session["alpn"] == "http/1.1", "unexpected TLS certificate or ALPN profile")
        with upstream.lock:
            observed = upstream.requests[-1]
            require(observed["method"] == "mIxEd" and observed["path"] == path and observed["body"] == body,
                    "TLS forwarding changed method, query order or request bytes")
            require(observed["authorization"] == "Bearer " + known_secret and observed["host"] == f"localhost:{tls_port}",
                    "TLS forwarding changed application authorization or Host")
            require(observed["forwarded_proto"] == "https" and observed["forwarded_for"] == "127.0.0.1",
                    "TLS forwarding trusted spoofed XFP/XFF instead of observed connection")
        report["checks"]["trusted_certificate_hostname_sni_and_http1_alpn"] = True
        report["checks"]["method_query_duplicate_order_body_auth_and_https_forwarded_proto_preserved"] = True
        report["negotiated_tls_version"] = session["version"]
        count = upstream.count()
        require(tls_request(tls_port, context1, host=f"127.0.0.1:{tls_port}")[0] == 421,
                "TLS request with mismatched exact HTTP Host reached the application")
        require(upstream.count() == count, "mismatched Host reached upstream")
        try:
            tls_request(tls_port, context1, server_name="127.0.0.1")
        except ssl.SSLError:
            pass
        else:
            raise RuntimeError("DNS route accepted an absent/mismatched TLS SNI")
        require(upstream.count() == count, "mismatched SNI reached upstream")
        report["checks"]["mismatched_host_and_sni_rejected_before_upstream"] = True
        untrusted = ssl.create_default_context()
        untrusted.set_alpn_protocols(["http/1.1"])
        try:
            tls_request(tls_port, untrusted)
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise RuntimeError("untrusted self-signed certificate was accepted without trust")
        report["checks"]["client_requires_explicit_fixture_ca_trust"] = True
        common.call_unix(proxy_socket, "invalid-private-control-token-0000000000", "GET", "/v1/tls/certificates", expected=401)
        metadata = common.call_unix(proxy_socket, control, "GET", "/v1/tls/certificates")
        public = next(item for item in metadata["certificates"] if item["id"] == "smoke-v1")
        serialized = json.dumps(metadata)
        require(public["valid"] and public["fingerprint_sha256"] == fingerprint1 and "localhost" in public["dns_names"] and
                "127.0.0.1" in public["ip_addresses"], "TLS certificate metadata does not match the presented certificate")
        require("-----BEGIN" not in serialized and "private-key.pem" not in serialized and "certificate.pem" not in serialized,
                "TLS metadata exposed certificate/key material or filesystem paths")
        require(set(public) <= {"id", "dns_names", "ip_addresses", "not_before", "not_after", "fingerprint_sha256", "valid", "error_code"},
                "TLS metadata returned unexpected material fields")
        report["checks"]["authenticated_tls_inventory_metadata_only_no_pem_or_keys"] = True
        query = "/v1/exchanges?" + urllib.parse.urlencode({"service_id": "service-tls", "method": "mIxEd"})

        def completed():
            page = common.call_unix(store_socket, read, "GET", query)
            return page if any(item["state"] == "completed" for item in page["records"]) else None

        page = common.wait_until(completed, "decrypted completed TLS exchange was not recorded")
        exchange = next(item for item in page["records"] if item["state"] == "completed")
        detail = common.call_unix(store_socket, read, "GET", "/v1/exchanges/" + exchange["request_id"])
        require(known_secret not in json.dumps(detail) and known_secret not in json.dumps(page), "TLS capture leaked synthetic secret")
        require("TLS application request" in detail["request_body"].get("data", "") and
                "TLS application response" in detail["response_body"].get("data", ""), "recorder did not capture decrypted TLS request/response bodies")
        require(detail["method"] == "mIxEd" and detail["status"] == 201, "recorded TLS exchange lost method or response status")
        require("request_headers" not in json.dumps(page) and "request_body" not in json.dumps(page), "metadata traffic page exposed decrypted payload")
        report["checks"]["decrypted_request_response_capture_with_header_query_body_redaction"] = True
        desired(2, "missing-profile")
        common.wait_until(lambda: rejected(2, 1), "missing TLS profile did not preserve the applied LKG")
        require(tls_request(tls_port, context1)[2]["fingerprint"] == fingerprint1, "missing profile displaced the current certificate")
        invalid = root / "tls/invalid-profile"
        invalid.mkdir(mode=0o700)
        common.private_file(invalid / "certificate.pem", "invalid synthetic certificate\n")
        common.private_file(invalid / "private-key.pem", "invalid synthetic private key\n")
        desired(3, "invalid-profile")
        common.wait_until(lambda: rejected(3, 1), "invalid TLS profile did not preserve the applied LKG")
        require(tls_request(tls_port, context1)[2]["fingerprint"] == fingerprint1, "invalid profile displaced the current certificate")
        report["checks"]["missing_and_invalid_desired_profiles_keep_lkg_serving"] = True
        profile2, fingerprint2 = make_profile(root / "tls", "smoke-v2", config)
        context2 = trusted_context(profile2 / "certificate.pem")
        require(fingerprint2 != fingerprint1, "rotation fixture reused the same certificate")
        desired(4, "smoke-v2")
        common.wait_until(lambda: applied(4), "new immutable TLS ID did not rotate on the existing listener")
        require(tls_request(tls_port, context2)[2]["fingerprint"] == fingerprint2, "rotated certificate not presented")
        report["checks"]["new_certificate_id_rotates_existing_tls_listener"] = True
        proxy.stop()
        proxy.start()
        restarted = common.wait_until(lambda: applied(4), "HTTPS LKG did not restore after process restart")
        require(restarted["collector_epoch"] != first_status["collector_epoch"], "TLS proxy restart retained the old collector epoch")
        require(tls_request(tls_port, context2)[2]["fingerprint"] == fingerprint2, "restart did not restore rotated TLS identity")
        report["checks"]["rotated_tls_lkg_and_pins_restore_after_process_restart"] = True
        original2 = {name: (profile2 / name).read_bytes() for name in ("certificate.pem", "private-key.pem")}
        replacement, fingerprint3 = make_profile(root / "tls", "smoke-v3", config)
        for name in original2:
            replace_private(profile2 / name, (replacement / name).read_bytes())
        desired(5, "smoke-v2")
        common.wait_until(lambda: rejected(5, 4), "changed immutable TLS ID was accepted")
        require(tls_request(tls_port, context2)[2]["fingerprint"] == fingerprint2, "changed ID displaced in-memory last-known-good TLS material")
        inventory = common.call_unix(proxy_socket, control, "GET", "/v1/tls/certificates")
        changed = next(item for item in inventory["certificates"] if item["id"] == "smoke-v2")
        require(not changed["valid"] and changed.get("error_code") == "immutable_profile_changed", "inventory hid immutable profile tampering")
        report["checks"]["changed_existing_certificate_id_refused_and_reported_invalid"] = True
        proxy.stop()
        proxy.start()
        common.wait_until(lambda: rejected(5, 0), "restart accepted changed immutable TLS identity")
        try:
            tls_request(tls_port, context2)
        except (ssl.SSLError, OSError, http.client.HTTPException):
            pass
        else:
            raise RuntimeError("restart served a changed immutable TLS profile")
        report["checks"]["persisted_pin_refuses_changed_profile_after_restart"] = True
        for name, content in original2.items():
            replace_private(profile2 / name, content)
        desired(6, "smoke-v2")
        common.wait_until(lambda: applied(6), "restored immutable material could not recover with a new desired revision")
        require(tls_request(tls_port, context2)[2]["fingerprint"] == fingerprint2, "recovered TLS profile did not match original immutable identity")
        report["checks"]["restored_immutable_material_recovers_on_new_revision"] = True
        for directory in (root / "tls", profile1, profile2, replacement, invalid):
            require(directory.stat().st_mode & 0o777 == 0o700 and directory.stat().st_uid == os.geteuid(), "TLS fixture directory permissions invalid")
            if directory != root / "tls":
                for name in ("certificate.pem", "private-key.pem"):
                    require((directory / name).stat().st_mode & 0o777 == 0o600, "TLS fixture material permissions invalid")
        report["checks"]["all_tls_profile_directories_0700_and_material_files_0600"] = True
        secret = known_secret.encode()
        for file in (root / "traffic-state").iterdir():
            if file.is_file():
                with file.open("rb") as stream:
                    tail = b""
                    while chunk := stream.read(1024 * 1024):
                        require(secret not in tail + chunk and b"-----BEGIN PRIVATE KEY-----" not in tail + chunk,
                                "recorder disk leaked synthetic secret or private key")
                        tail = chunk[-max(len(secret), 40):]
        report["checks"]["synthetic_secret_and_private_key_absent_from_recorder_disk"] = True
        report["certificate_fingerprints"] = {"initial": fingerprint1, "rotated": fingerprint2, "tampered": fingerprint3}
        report["known_secret_sha256"] = common.digest(secret)
        report["upstream_request_count"] = upstream.count()
        report["final_applied_revision"] = status()["applied_revision"]
        report["status"] = "passed"
    finally:
        for process in processes:
            process.stop()
        if upstream is not None:
            upstream.close()
        report["own_processes_stopped"] = all(process.process is None for process in processes)
        temporary.cleanup()
        report["private_fixture_removed_on_exit"] = not root.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-binary", type=Path, default=ROOT / "bin/ctfm-proxy")
    parser.add_argument("--traffic-binary", type=Path, default=ROOT / "bin/ctfm-traffic")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/http-proxy-tls-process-smoke-2026-10-30.json")
    args = parser.parse_args()
    report = {"test": "http-proxy-trusted-tls-isolated-process-smoke", "status": "failed", "started_at": common.stamp(),
              "runtime": {"os": platform.system(), "architecture": platform.machine()}, "binaries": {}, "checks": {},
              "harness_sha256": common.digest(Path(__file__).read_bytes()),
              "shared_harness_sha256": common.digest(Path(common.__file__).read_bytes()), "performance_acceptance": False,
              "client_tls_verification": {"check_hostname": True, "verify_mode": "CERT_REQUIRED", "trust": "private synthetic self-signed fixture CA"},
              "scope": "copied standalone proxy/recorder binaries; verified TLS to a synthetic loopback HTTP upstream; private Unix controls",
              "limitations": ["No Docker Compose, VM, dashboard RBAC/browser, occupied-port transfer or competition checker acceptance",
                              "No system trust-store change and no insecure TLS client context",
                              "Runtime profiles are private synthetic files; privileged production certificate-import CLI is not exercised",
                              "Small functional sequence only; no RPS, overhead or resource-budget claim"]}
    try:
        run(args, report)
    except BaseException as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        if isinstance(error, RuntimeError):
            report["error"] = str(error)
    finally:
        report["finished_at"] = common.stamp()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": report["checks"], "error": report.get("error"), "report": str(args.report)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
