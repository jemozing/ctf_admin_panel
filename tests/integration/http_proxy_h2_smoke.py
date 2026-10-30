#!/usr/bin/env python3
"""Trusted TLS HTTP/2/gRPC smoke of separate proxy, recorder and H2 fixture.

Only synthetic traffic and private loopback/Unix fixtures are used. No Docker,
SSH, VM, game service, system trust store or external service is contacted.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import struct
import subprocess
import tempfile
import urllib.parse

import http_proxy_smoke as common
from http_proxy_tls_smoke import make_profile, replace_private

ROOT = Path(__file__).resolve().parents[2]


def run(args, report):
    processes = []
    temporary = tempfile.TemporaryDirectory(prefix="ctfm-h2-", dir="/tmp")
    root = Path(temporary.name)
    root.chmod(0o700)
    try:
        for name in ("policy", "proxy-state", "traffic-state", "proxy-control", "traffic-control", "tls"):
            (root / name).mkdir(mode=0o700)
        environment = dict(os.environ, GOCACHE=str(ROOT / ".cache/go-build"),
                           GOMODCACHE=str(ROOT / ".cache/go-mod"), GOPROXY="off")
        binaries = {}
        for name, command, supplied in (("proxy", "./cmd/ctfm-proxy", args.proxy_binary),
                                         ("traffic", "./cmd/ctfm-traffic", args.traffic_binary),
                                         ("fixture", "./tests/integration/h2_fixture", None)):
            path = root / ("ctfm-" + name)
            if supplied:
                shutil.copy2(supplied.resolve(strict=True), path)
            else:
                built = subprocess.run(["go", "build", "-trimpath", "-o", str(path), command], cwd=ROOT,
                                       env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       timeout=90, check=False)
                common.require(built.returncode == 0, "synthetic H2 process compilation failed")
            path.chmod(0o700)
            binaries[name] = path
            report["binaries"][name] = {"sha256": common.digest(path.read_bytes()), "copied_supplied_binary": bool(supplied)}
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
""")
        profile, fingerprint = make_profile(root / "tls", "h2-fixture", config)
        control, ingest, read = (secrets.token_urlsafe(48) for _ in range(3))
        for name, token in (("control", control), ("ingest", ingest), ("read", read)):
            common.private_file(root / (name + "-token"), token + "\n")
        upstream_port, recorder_port, proxy_port = (common.free_port() for _ in range(3))
        common.require(len({upstream_port, recorder_port, proxy_port}) == 3, "fixture port collision")
        route = common.route("route-h2", "service-h2", proxy_port, upstream_port, "observe_only")
        route.update(protocol="https2", host=f"localhost:{proxy_port}", tls={"certificate_id": "h2-fixture"})
        route["capture"] = {"mode": "grpc_body", "max_body_bytes": 65536}
        policy = {"schema_version": 1, "revision": 1, "routes": [route]}
        policy_file = root / "policy/policy.json"
        common.private_file(policy_file, policy)
        store_socket = root / "traffic-control/recorder.sock"
        proxy_socket = root / "proxy-control/proxy.sock"
        upstream = common.Process([str(binaries["fixture"]), "--mode=upstream", f"--listen=127.0.0.1:{upstream_port}"], root / "upstream.log")
        recorder = common.Process([str(binaries["traffic"]), f"--listen=127.0.0.1:{recorder_port}",
                                   f"--control-unix={store_socket}", f"--state={root / 'traffic-state'}",
                                   f"--ingest-token-file={root / 'ingest-token'}", f"--read-token-file={root / 'read-token'}",
                                   "--quota-bytes=16777216", "--per-service-bytes=4194304", "--minimum-free-bytes=1048576"], root / "recorder.log")
        proxy = common.Process([str(binaries["proxy"]), f"--policy-file={policy_file}", f"--state={root / 'proxy-state'}",
                                f"--tls-directory={root / 'tls'}", "--control-listen=", f"--control-unix={proxy_socket}",
                                f"--control-token-file={root / 'control-token'}", f"--recorder-url=http://127.0.0.1:{recorder_port}",
                                f"--recorder-token-file={root / 'ingest-token'}"], root / "proxy.log")
        processes.extend((proxy, recorder, upstream))

        def check(name, condition):
            common.require(condition, name)
            report["checks"][name] = True

        def status():
            return common.call_unix(proxy_socket, control, "GET", "/v1/status")

        def applied(revision):
            value = status()
            return value if value.get("applied_revision") == revision and not value.get("last_error") else None

        def client(action):
            result = subprocess.run([str(binaries["fixture"]), "--mode=client", f"--target=127.0.0.1:{proxy_port}",
                                     f"--ca={profile / 'certificate.pem'}", f"--action={action}"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)
            common.require(result.returncode == 0 and len(result.stdout) < 16384, "H2 fixture client failed")
            return json.loads(result.stdout)

        def count():
            return json.loads(common.request(upstream_port, path="/metrics")[2])["calls"]

        upstream.start()
        common.wait_until(lambda: common.request(upstream_port, path="/metrics")[0] == 200, "H2 upstream not ready")
        recorder.start()
        common.wait_until(lambda: common.call_unix(store_socket, read, "GET", "/v1/status").get("available"), "recorder not ready")
        proxy.start()
        current = common.wait_until(lambda: applied(1), "HTTPS2 policy did not activate")
        check("real_proxy_main_advertises_explicit_https2", "https2" in current["supported_profiles"])
        common.call_unix(proxy_socket, control, "POST", "/v1/h2-preflight", {"upstreams": [route["upstream"]]})
        check("bounded_h2_preface_preflight_invokes_no_rpc", count() == 0)
        unary = client("unary")
        check("trusted_tls_hostname_h2_alpn", unary["h2"] and unary["alpn"] == "h2")
        check("binary_grpc_bytes_and_trailers_preserved", unary["status"] == 200 and unary["body_equal"] and unary["grpc_status"] == "0")
        check("application_auth_and_observed_forwarding_preserved", unary["auth_preserved"] and unary["forwarded_proto"] == "https" and unary["client_ip"] == "127.0.0.1")
        bidi = client("bidi")
        check("bidirectional_response_before_request_eof", bidi["h2"] and bidi["before_request_eof"] and bidi["second_equal"] and bidi["grpc_status"] == "0")
        multiple = client("multiplex")
        check("multiplexed_rpc_bodies_isolated", multiple["passed"] == multiple["total"] == 8)
        before = count()
        check("untrusted_tls_rejected", client("untrusted")["tls_rejected"] and count() == before)
        check("mismatched_authority_rejected_before_upstream", client("bad-host")["status"] == 421 and count() == before)

        def recorded():
            page = common.call_unix(store_socket, read, "GET", "/v1/exchanges?service_id=service-h2&limit=50")
            records = [item for item in page["records"] if item["status"] == 200 and item["state"] == "completed"]
            return (page, records) if len(records) >= 10 else None

        page, records = common.wait_until(recorded, "completed H2 captures not recorded")
        check("metadata_lists_exclude_bodies_and_headers", not any(key in json.dumps(page) for key in ("request_body", "response_body", "request_trailers", "h2-private-fixture")))
        example = next(item for item in records if item["url"].endswith("/Unary"))
        detail = common.call_unix(store_socket, read, "GET", "/v1/exchanges/" + urllib.parse.quote(example["request_id"], safe=""))
        payload = bytes((0, 255)) + b"flag!1"
        framed = struct.pack(">BI", 0, len(payload)) + payload
        check("explicit_raw_grpc_capture_preserves_exact_base64_bytes", detail["http_protocol"] == "h2" and detail["request_body"]["sensitive_raw"] and detail["response_body"]["sensitive_raw"] and base64.b64decode(detail["request_body"]["data"]) == framed and base64.b64decode(detail["response_body"]["data"]) == framed)
        check("authorization_and_trailer_secrets_still_redacted", detail["request_headers"]["Authorization"] == ["[REDACTED]"] and detail["response_trailers"]["X-Api-Key"] == ["[REDACTED]"] and detail["response_trailers"]["Grpc-Status"] == ["0"])
        invalid = copy.deepcopy(policy)
        invalid["revision"] = 2
        invalid["routes"][0]["tls"]["certificate_id"] = "missing-profile"
        replace_private(policy_file, invalid)
        common.wait_until(lambda: status()["desired_revision"] == 2 and status()["applied_revision"] == 1 and status().get("last_error"), "invalid TLS profile did not report retained LKG")
        check("invalid_h2_tls_profile_keeps_lkg", client("unary")["body_equal"])
        policy["revision"] = 3
        replace_private(policy_file, policy)
        common.wait_until(lambda: applied(3), "valid H2 policy did not recover")
        proxy.stop()
        proxy.start()
        common.wait_until(lambda: applied(3), "H2 LKG did not restore after restart")
        check("h2_lkg_and_immutable_certificate_survive_proxy_restart", client("unary")["body_equal"])
        recorder.stop()
        check("recorder_outage_does_not_block_h2_grpc", client("unary")["body_equal"])
        common.wait_until(lambda: status()["counters"]["capture_dropped"] > 0, "recorder outage loss not reported")
        check("recorder_outage_loss_is_explicit", status()["counters"]["capture_dropped"] > 0)
        for file in (root / "traffic-state").iterdir():
            if file.is_file():
                data = file.read_bytes()
                common.require(b"-----BEGIN PRIVATE KEY-----" not in data and b"h2-private-fixture" not in data and b"private-trailer" not in data, "recorder persisted TLS key or redacted header/trailer secret")
        check("tls_private_key_and_header_secrets_absent_from_recorder", True)
        report["certificate_fingerprint"] = fingerprint
        report["status"] = "passed"
    finally:
        for process in processes:
            process.stop()
        report["own_processes_stopped"] = all(process.process is None for process in processes)
        temporary.cleanup()
        report["private_fixture_removed_on_exit"] = not root.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-binary", type=Path)
    parser.add_argument("--traffic-binary", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise SystemExit("Report exists; choose a new path.")
    report = {"test": "http2-grpc-trusted-tls-isolated-process-smoke", "status": "failed", "started_at": common.stamp(),
              "runtime": {"os": platform.system(), "architecture": platform.machine()}, "binaries": {}, "checks": {},
              "scope": {"vm_touched": False, "docker_used": False, "live_af_packet": False, "synthetic_h2c_upstream": True,
                        "browser_rendering": False, "system_trust_modified": False},
              "harness_sha256": common.digest(Path(__file__).read_bytes()),
              "fixture_sha256": common.digest((ROOT / "tests/integration/h2_fixture/main.go").read_bytes()),
              "limitations": ["No native Linux/Compose, occupied-port cutover or competition checker acceptance", "No performance/capacity claim", "Opaque grpc_body is explicitly enabled; protobuf secrets are intentionally not automatically redacted"]}
    try:
        run(args, report)
    except BaseException as error:
        report["error_type"] = type(error).__name__
        if isinstance(error, RuntimeError):
            report["error"] = str(error)
    finally:
        report["finished_at"] = common.stamp()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "error": report.get("error"), "report": str(args.report)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
