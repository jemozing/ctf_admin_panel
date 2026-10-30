#!/usr/bin/env python3
"""Fetch/verify five pinned SibirCTF fixtures; render and audit Compose without starting it.

Only git fetch/checkout and docker compose config are exposed. This program never
runs upstream scripts, builds images, starts containers, or deletes game volumes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "tests/real-services"
VENDOR = ROOT / "tests/fixtures/vendor"
LOCK = SPEC / "services.lock.json"
GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never"]


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def read_lock():
    manifest = json.loads(LOCK.read_text())
    services = manifest["services"]
    if manifest["schema_version"] != 1 or len(services) != 5:
        raise ValueError("Expected schema 1 and exactly five service fixtures")
    ids = set()
    for service in services:
        ident, repo = service["id"], service["vendor_directory"]
        if not re.fullmatch(r"[a-z0-9-]+", ident) or ident in ids:
            raise ValueError("Invalid/duplicate fixture id")
        ids.add(ident)
        if not re.fullmatch(r"[A-Za-z0-9-]+", repo) or "service-" not in repo:
            raise ValueError("Fixture must be a service repository")
        if service["repository"] != f"https://github.com/SibirCTF/{repo}.git":
            raise ValueError("Only explicitly locked SibirCTF HTTPS sources are allowed")
        if not re.fullmatch(r"[0-9a-f]{40}", service["commit"]):
            raise ValueError("A complete Git SHA-1 commit is required")
        if service["project_name"] != "ctfm-real-" + ident:
            raise ValueError("Invalid local Compose project name")
    return services


def checked_path(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes fixture root: {relative}")
    return path


def verify(service, directory=None):
    source = directory or checked_path(VENDOR, service["vendor_directory"])
    if source.is_symlink():
        raise ValueError(f"Refusing symlink checkout: {source}")
    revision = run(GIT + ["-C", str(source), "rev-parse", "HEAD"]).stdout.strip()
    if revision != service["commit"]:
        raise ValueError(f"{service['id']}: checkout commit does not match lock")
    if run(GIT + ["-C", str(source), "status", "--porcelain", "--untracked-files=all"]).stdout:
        raise ValueError(f"{service['id']}: checkout has local changes; keep test data outside vendor")
    remote = run(GIT + ["-C", str(source), "remote", "get-url", "origin"]).stdout.strip()
    if remote != service["repository"]:
        raise ValueError(f"{service['id']}: origin differs from lock")
    for relative, expected in service["reviewed_files_sha256"].items():
        path = checked_path(source, relative)
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"{service['id']}: reviewed file changed: {relative}")
    return source


def fetch(service):
    VENDOR.mkdir(parents=True, exist_ok=True)
    target = checked_path(VENDOR, service["vendor_directory"])
    if target.exists():
        verify(service, target)
        return
    temporary = Path(tempfile.mkdtemp(prefix=".ctfm-fetch-", dir=VENDOR))
    try:
        run(GIT + ["-c", "init.templateDir=", "init", str(temporary)])
        run(GIT + ["-C", str(temporary), "remote", "add", "origin", service["repository"]])
        run(GIT + ["-C", str(temporary), "fetch", "--depth=1", "--no-tags", "origin", service["commit"]])
        run(GIT + ["-C", str(temporary), "checkout", "--detach", service["commit"]])
        verify(service, temporary)
        temporary.rename(target)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def compose_config(service):
    source = verify(service)
    upstream = checked_path(source, service["upstream_compose"])
    override = checked_path(SPEC, service["override"])
    command = ["docker", "compose", "--project-name", service["project_name"],
               "--project-directory", str(upstream.parent)]
    environment = os.environ.copy()
    # Do not inherit COMPOSE_FILE, profiles or host DB_* overrides from a developer shell.
    for key in list(environment):
        if key.startswith("COMPOSE_") or key in ("DB_NAME", "DB_USER", "DB_PASS", "DEBUG", "SESSION_SECRET", "REACT_HOST", "API_HOST"):
            environment.pop(key)
    if service.get("environment_file"):
        env_file = checked_path(SPEC, service["environment_file"])
        environment["CTFM_REAL_BANK_ENV"] = str(env_file)
        command += ["--env-file", str(env_file)]
    command += ["-f", str(upstream), "-f", str(override), "config", "--format", "json"]
    rendered = json.loads(run(command, env=environment).stdout)
    return audit_config(service, rendered, source)


def audit_config(service, rendered, source):
    if rendered.get("name") != service["project_name"]:
        raise ValueError("Rendered project name does not match fixture")
    summary = {"id": service["id"], "project": rendered["name"], "status": "config_passed", "runtime": "not_run", "components": []}
    for name, component in sorted(rendered["services"].items()):
        if component.get("privileged") or component.get("network_mode") == "host" or component.get("pid") == "host" or component.get("ipc") == "host":
            raise ValueError(f"{name}: host privileges/namespaces are not allowed")
        if component.get("devices") or component.get("cap_add") or component.get("container_name"):
            raise ValueError(f"{name}: unexpected device/capability/container name")
        if component.get("ports") and any(p.get("host_ip") != "127.0.0.1" for p in component["ports"]):
            raise ValueError(f"{name}: all published ports must bind to 127.0.0.1")
        mounts = []
        for mount in component.get("volumes", []):
            if mount["type"] == "bind" and not Path(mount["source"]).resolve().is_relative_to(source.resolve()):
                raise ValueError(f"{name}: bind mount escapes pinned source checkout")
            if mount.get("target") in ("/var/run/docker.sock", "/run/docker.sock"):
                raise ValueError(f"{name}: Docker socket mount is prohibited")
            mounts.append({k: mount[k] for k in ("type", "source", "target", "read_only") if k in mount})
        summary["components"].append({"name": name, "image": component.get("image"), "build": bool(component.get("build")), "platform": component.get("platform"), "ports": component.get("ports", []), "mounts": mounts, "read_only": component.get("read_only", False)})
    if any(volume.get("external") for volume in rendered.get("volumes", {}).values()):
        raise ValueError("External volumes are prohibited in local fixtures")
    if any(network.get("external") for network in rendered.get("networks", {}).values()):
        raise ValueError("External networks are prohibited in local fixtures")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "verify", "config"))
    parser.add_argument("--id", choices=[x["id"] for x in read_lock()], help="Limit to one fixture")
    args = parser.parse_args()
    selected = [x for x in read_lock() if args.id is None or x["id"] == args.id]
    results = []
    for service in selected:
        if args.command == "fetch":
            fetch(service)
        elif args.command == "verify":
            verify(service)
        else:
            results.append(compose_config(service))
            continue
        results.append({"id": service["id"], "commit": service["commit"], "status": "verified"})
    print(json.dumps({"fixtures": results}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        # Do not print Compose stderr: it may contain rendered env/credentials.
        print(f"Fixture preparation failed ({type(error).__name__}).", file=sys.stderr)
        if isinstance(error, (ValueError, OSError)):
            print(str(error), file=sys.stderr)
        sys.exit(1)
