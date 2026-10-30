#!/usr/bin/env python3
"""Prepare a NEW, separate Linux passive packet capture installation.

Creates a disabled empty policy, private per-UID credential copies and an
executor config fragment. Never starts Docker or edits an existing panel.
"""
import argparse
import json
import os
from pathlib import Path
import re
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
            "capture root must be new and canonical; existing installs are never overwritten")
    parent = root.parent
    while True:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "capture ancestors must be real root-owned directories without group/world write")
        if parent == parent.parent:
            break
        parent = parent.parent


def validate_interfaces(values):
    require(1 <= len(values) <= 8 and len(set(values)) == len(values),
            "approve 1..8 unique exact observation interfaces")
    for name in values:
        require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", name) is not None,
                "interfaces must be exact bounded Docker bridge names, without wildcards")
    return sorted(values)


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/srv/ctfm-capture"))
    parser.add_argument("--interface", action="append", required=True,
                        help="exact bridge/veth/host interface allowed in the panel; repeat for each bridge")
    parser.add_argument("--protect-host-port",action="append",type=int,default=[],help="additional management port excluded from host-leg capture")
    args = parser.parse_args()
    require(len(args.protect_host_port)<=256 and len(set(args.protect_host_port))==len(args.protect_host_port) and all(1<=port<=65535 for port in args.protect_host_port),"protected host ports must be unique valid ports")
    require(sys.platform.startswith("linux") and os.geteuid() == 0,
            "run as root on the dedicated Linux Docker host")
    interfaces = validate_interfaces(args.interface)
    validate_root(args.root)
    os.umask(0o077)
    args.root.mkdir(mode=0o755)
    args.root.chmod(0o755)
    for name, uid in (("policy", 0), ("capture-control", 0),
                      ("packets-control", 10005), ("packets-state", 10005), ("secrets", 0)):
        path = args.root / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        os.chown(path, uid, uid)
    (args.root / "policy/.control-lock").mkdir(mode=0o700)
    write(args.root / ".ctfm-capture-bootstrap.json",
          {"purpose": "separate opt-in passive CTF packet capture", "schema_version": 1})
    write(args.root / "policy/policy.json",
          {"schema_version": 1, "revision": 1, "enabled": False, "snaplen": 0,
           "max_packets_per_second": 1000, "interfaces": []})
    control, ingest, read = (secrets.token_urlsafe(48) + "\n" for _ in range(3))
    for name, value, uid in (("capture-control", control, 0), ("executor-control", control, 0),
                             ("capture-ingest", ingest, 0), ("packets-ingest", ingest, 10005),
                             ("packets-read", read, 10005), ("executor-read", read, 0)):
        write(args.root / "secrets" / name, value, 0o600, uid, uid)
    capture = {
        "enabled": True, "policy_directory": str(args.root / "policy"),
        "control_url": "unix://" + str(args.root / "capture-control/capture.sock"),
        "control_token_file": str(args.root / "secrets/executor-control"),
        "packets_url": "unix://" + str(args.root / "packets-control/packets.sock"),
        "packets_token_file": str(args.root / "secrets/executor-read"),
        "allowed_interfaces": interfaces,
        "protected_host_ports": args.protect_host_port,
    }
    write(args.root / "executor_capture_patch.json", {"capture": capture})
    override = {"services": {"executor": {"volumes": [
        binding(args.root / "policy", args.root / "policy"),
        binding(args.root / "capture-control", args.root / "capture-control", True),
        binding(args.root / "packets-control", args.root / "packets-control", True),
        binding(args.root / "secrets/executor-control", args.root / "secrets/executor-control", True),
        binding(args.root / "secrets/executor-read", args.root / "secrets/executor-read", True),
    ]}}}
    write(args.root / "executor-capture.override.yaml", override)
    write(args.root / "compose.env", "CTFM_CAPTURE_ROOT=" + str(args.root) + "\n", 0o644)
    print(json.dumps({"status": "prepared_only", "root": str(args.root),
                      "executor_fragment": str(args.root / "executor_capture_patch.json"),
                      "executor_override": str(args.root / "executor-capture.override.yaml"),
                      "compose_env": str(args.root / "compose.env"),
                      "capture_enabled": False, "containers_started": False,
                      "main_panel_config_modified": False, "credentials_printed": False}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print("Capture bootstrap refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
