#!/usr/bin/env python3
"""Prepare a NEW, separate Linux Proxy/WAF installation; never starts Docker.

Generated executor-proxy.json is an explicit bootstrap fragment to review and
merge into executor.json. Existing panel config, games and ports are untouched.
Use the generated Compose override only after enabling that reviewed fragment.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import sys


def require(value, message):
    if not value:
        raise RuntimeError(message)


def validate_root(root):
    require(root.is_absolute() and root.parent == Path("/srv") and root.name not in (".", ".."),
            "use a new dedicated /srv/<name> directory")
    require(str(root) == os.path.normpath(str(root)) and not root.exists() and not root.is_symlink(),
            "proxy root must be new and canonical; existing installs are never overwritten")
    parent = root.parent
    while True:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "proxy ancestors must be real root-owned directories without group/world write")
        if parent == parent.parent:
            break
        parent = parent.parent


def write(path, value, mode=0o600, uid=0, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as stream:
        if isinstance(value, str):
            stream.write(value)
        else:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), uid, gid)


def binding(source, target, read_only=False):
    return {"type": "bind", "source": str(source), "target": str(target),
            "read_only": read_only, "bind": {"create_host_path": False}}


def listen_endpoint_port(raw):
    host, _, port_text = raw.rpartition(":")
    ip = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    port = int(port_text)
    canonical_host = f"[{ip}]" if ip.version == 6 else str(ip)
    require(not ip.is_multicast and "%" not in raw and getattr(ip, "ipv4_mapped", None) is None
            and 1024 <= port <= 65535 and raw == f"{canonical_host}:{port}",
            "listen endpoints must be canonical literal IP:port pairs with unprivileged ports")
    return port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/srv/ctfm-proxy"))
    parser.add_argument("--listen-ip", action="append", help="allowed literal proxy bind IP; repeat if needed")
    parser.add_argument("--listen-endpoint", action="append", default=[],
                        help="additional exact proxy bind IP:port; repeat if needed")
    parser.add_argument("--port-min", type=int, default=19080)
    parser.add_argument("--port-max", type=int, default=19111)
    parser.add_argument("--backend-port-min", type=int)
    parser.add_argument("--backend-port-max", type=int)
    args = parser.parse_args()
    require(sys.platform.startswith("linux") and os.geteuid() == 0,
            "run as root on the dedicated Linux Docker host")
    require(1024 <= args.port_min <= args.port_max <= 65535 and args.port_max - args.port_min <= 1023,
            "approve a bounded unprivileged external-port range")
    require(len(args.listen_endpoint) <= 32 and len(set(args.listen_endpoint)) == len(args.listen_endpoint),
            "approve at most 32 unique exact listen endpoints")
    endpoint_ports = [listen_endpoint_port(raw) for raw in args.listen_endpoint]

    def overlaps_listeners(first, last):
        return (first <= args.port_max and args.port_min <= last
                or any(first <= port <= last for port in endpoint_ports))

    if args.backend_port_min is None and args.backend_port_max is None:
        backend_min = next((first for first in (29080, 39080, 49080)
                            if not overlaps_listeners(first, first + 31)), 0)
        backend_max = backend_min + 31
    else:
        backend_min = 29080 if args.backend_port_min is None else args.backend_port_min
        backend_max = 29111 if args.backend_port_max is None else args.backend_port_max
    require(1024 <= backend_min <= backend_max <= 65535 and backend_max - backend_min <= 1023
            and not overlaps_listeners(backend_min, backend_max),
            "approve a separate bounded unprivileged loopback backend-port range")
    ips = args.listen_ip or ["0.0.0.0", "127.0.0.1"]
    require(1 <= len(ips) <= 16 and len(set(ips)) == len(ips), "invalid allowed listen IP list")
    for raw in ips:
        ip = ipaddress.ip_address(raw)
        require(not ip.is_multicast and "%" not in raw and str(ip) == raw,
                "listen addresses must be canonical literal non-multicast IPs")
    validate_root(args.root)
    os.umask(0o077)
    args.root.mkdir(mode=0o755)
    args.root.chmod(0o755)
    for name, uid, gid, mode in (
        ("policy", 0, 10002, 0o750), ("proxy-state", 10002, 10002, 0o700),
        ("traffic-state", 10003, 10003, 0o700), ("proxy-control", 10002, 10002, 0o700),
        ("traffic-control", 10003, 10003, 0o700), ("secrets", 0, 0, 0o700),
        ("tls", 0, 10002, 0o750),
    ):
        path = args.root / name
        path.mkdir(mode=mode)
        path.chmod(mode)
        os.chown(path, uid, gid)
    (args.root / "policy/.control-lock").mkdir(mode=0o700)
    write(args.root / ".ctfm-proxy-bootstrap.json", {"purpose": "separate opt-in CTF HTTP data plane", "schema_version": 1})
    write(args.root / "policy/policy.json", {"schema_version": 1, "revision": 0, "routes": []}, 0o640, 0, 10002)
    control, ingest, read = (secrets.token_urlsafe(48) + "\n" for _ in range(3))
    for name, value, uid in (("proxy-control", control, 10002), ("executor-control", control, 0),
                             ("proxy-ingest", ingest, 10002), ("recorder-ingest", ingest, 10003),
                             ("recorder-read", read, 10003), ("executor-read", read, 0)):
        write(args.root / "secrets" / name, value, 0o600, uid, uid)
    proxy = {
        "enabled": True, "policy_directory": str(args.root / "policy"),
        "control_url": "unix://" + str(args.root / "proxy-control/proxy.sock"),
        "control_token_file": str(args.root / "secrets/executor-control"),
        "traffic_url": "unix://" + str(args.root / "traffic-control/recorder.sock"),
        "traffic_token_file": str(args.root / "secrets/executor-read"),
        "allowed_listen_ips": ips, "listen_port_min": args.port_min,
        "listen_port_max": args.port_max, "proxy_gid": 10002,
        "backend_port_min": backend_min, "backend_port_max": backend_max,
    }
    if args.listen_endpoint:
        proxy["allowed_listen_endpoints"] = args.listen_endpoint
    write(args.root / "executor-proxy.json", {"proxy": proxy})
    override = {"services": {"executor": {"volumes": [
        binding(args.root / "policy", args.root / "policy"),
        binding(args.root / "proxy-control", args.root / "proxy-control", True),
        binding(args.root / "traffic-control", args.root / "traffic-control", True),
        binding(args.root / "secrets/executor-control", args.root / "secrets/executor-control", True),
        binding(args.root / "secrets/executor-read", args.root / "secrets/executor-read", True),
    ]}}}
    write(args.root / "executor-proxy.override.yaml", override)
    write(args.root / "compose.env", "CTFM_PROXY_ROOT=" + str(args.root) + "\n", 0o644)
    print(json.dumps({"status": "prepared_only", "root": str(args.root),
                      "executor_fragment": str(args.root / "executor-proxy.json"),
                      "executor_override": str(args.root / "executor-proxy.override.yaml"),
                      "compose_env": str(args.root / "compose.env"),
                      "external_listeners_created": False, "containers_started": False,
                      "main_panel_config_modified": False, "credentials_printed": False}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print("Proxy bootstrap refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
