#!/usr/bin/env python3
"""Prepare Linux host directories and explicit mounts for the Compose installation.

This runs locally as root. It never invokes Docker or edits existing game projects.
Use --dry-run to inspect the generated configuration without writing anything.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


WEB_UID = IPC_GID = 10001
HOST_METRIC_FILES = {
    "stat": "/proc/stat",
    "meminfo": "/proc/meminfo",
    "loadavg": "/proc/loadavg",
    "uptime": "/proc/uptime",
    # /proc/net refers to the reader's network namespace. PID 1 explicitly
    # selects the Linux host namespace at the Docker daemon's bind source.
    "net-dev": "/proc/1/net/dev",
}


def canonical_path(value):
    if not value.startswith("/") or value == "/" or str(Path(value)) != value:
        raise ValueError(f"path must be canonical and absolute, other than /: {value!r}")
    # These paths also occur in Compose interpolation/env files. Refuse characters
    # with a second interpretation rather than relying on shell-style quoting.
    if re.search(r"[\x00-\x20\x7f$:'\"\\]", value) or any(part in (".", "..") for part in value.split("/")):
        raise ValueError(f"unsupported character or component in host path: {value!r}")
    return Path(value)


def overlaps(left, right):
    return left == right or left in right.parents or right in left.parents


def no_symlinks(path):
    for part in [*reversed(path.parents), path]:
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"symbolic-link path component is not allowed: {part}")


def private_directory(path, uid, gid, mode):
    no_symlinks(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        # Root's parent must already exist, so there is no recursive creation
        # through untrusted path components.
        os.mkdir(path, mode)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
    try:
        info = os.fstat(descriptor)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
            raise ValueError(f"existing directory has unexpected owner/mode; expected {uid}:{gid} {mode:04o}: {path}")
    finally:
        os.close(descriptor)


def atomic_config(path, value, replace):
    encoded = value.encode("utf-8")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        descriptor = None
    if descriptor is not None:
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError(f"existing config must be a root-owned regular 0600 file: {path}")
            if stream.read() == encoded:
                return
        if not replace:
            raise ValueError(f"configuration differs; review --dry-run and use --replace-config: {path}")
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def make_plan(root, discovery, workspaces, repository, socket, docker_storage_root="", host_metrics=False, max_builds=1, max_copies=1, max_switches=1):
    if any(type(value) is not int or value < 1 or value > 4 for value in (max_builds, max_copies, max_switches)):
        raise ValueError("scheduler limits must be integers 1..4")
    root = canonical_path(root)
    repository = canonical_path(repository)
    socket = canonical_path(socket)
    discovery = [canonical_path(value) for value in discovery] or [root / "services"]
    workspaces = [canonical_path(value) for value in workspaces] or [root / "workspaces"]
    protected = [root / name for name in ("config", "executor", "runtime", "dashboard")]
    system_roots = ("/bin", "/sbin", "/usr", "/etc", "/dev", "/proc", "/sys", "/run", "/var/run", "/tmp")
    if any(overlaps(root, Path(other)) for other in system_roots):
        raise ValueError("installation root must be outside container system paths")
    paths = discovery + workspaces
    for index, path in enumerate(paths):
        if any(overlaps(path, other) for other in protected + paths[:index]):
            raise ValueError(f"approved roots must be disjoint from private state and each other: {path}")
        # A service mounted at a container system path could hide the binary,
        # bootstrap or shared socket. Only dedicated host project roots are used.
        if any(overlaps(path, Path(other)) for other in system_roots):
            raise ValueError(f"approved root overlaps a container system path: {path}")
    configuration = {
        "state_directory": str(root / "executor"),
        "socket": "/run/ctf-manager/executor.sock",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_binary": "/usr/local/bin/docker",
        "compose_binary": "/usr/local/libexec/docker/cli-plugins/docker-compose",
        "discovery_roots": list(map(str, discovery)),
        "workspace_roots": list(map(str, workspaces)),
        "web_uid": WEB_UID,
        "scheduler": {"builds": max_builds, "copies": max_copies, "switches": max_switches},
        "development": False,
    }
    mounts = {
        "services": {
            "executor": {
                "volumes": [
                    {"type": "bind", "source": str(path), "target": str(path), "bind": {"create_host_path": False}}
                    for path in paths
                ]
            }
        }
    }
    if docker_storage_root:
        docker_root = canonical_path(docker_storage_root)
        if any(overlaps(docker_root, path) for path in [root, *paths]):
            raise ValueError("Docker storage root must not overlap installation, service or workspace roots")
        if any(overlaps(docker_root, Path(other)) for other in (*system_roots, "/root", "/boot", "/lib", "/lib64")):
            raise ValueError("Docker storage root must not hide or expose container system paths")
        if docker_root in (Path("/var/lib"), Path("/home"), Path("/opt"), Path("/mnt"), Path("/media")):
            raise ValueError("Docker storage root must be a dedicated data directory")
        configuration["docker_storage_directory"] = str(docker_root)
        mounts["services"]["executor"]["volumes"].append({
            "type": "bind", "source": str(docker_root), "target": str(docker_root),
            "read_only": True, "bind": {"create_host_path": False},
        })
    if host_metrics:
        configuration["host_metrics"] = True
        mounts["services"]["executor"]["volumes"].extend({
            "type": "bind", "source": source,
            "target": "/run/ctf-manager-host/" + name,
            "read_only": True, "bind": {"create_host_path": False},
        } for name, source in HOST_METRIC_FILES.items())
    environment = "\n".join((
        "# Generated by compose-bootstrap.py; load with docker compose --env-file.",
        f"COMPOSE_FILE={repository / 'compose.yaml'}:{root / 'config/compose.mounts.yaml'}",
        "COMPOSE_PROJECT_NAME=ctf-manager",
        f"CTFM_ROOT={root}",
        f"CTFM_DOCKER_SOCKET={socket}",
        "CTFM_BIND_ADDRESS=127.0.0.1",
        "CTFM_PORT=8765",
        "CTFM_ALLOWED_HOSTS=localhost:8765,127.0.0.1:8765",
        "CTFM_SECURE_COOKIES=false",
        "",
    ))
    return root, discovery, workspaces, configuration, mounts, environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/srv/ctf-manager", help="dedicated persistent host directory")
    parser.add_argument("--discovery-root", action="append", default=[], help="existing approved game-project root; repeatable")
    parser.add_argument("--workspace-root", action="append", default=[], help="existing approved source-workspace root; repeatable")
    parser.add_argument("--docker-socket", default="/var/run/docker.sock")
    parser.add_argument("--docker-storage-root", default="", help="explicit existing Docker daemon data root; optional read-only exact-path mount for physical free-space checks")
    parser.add_argument("--host-metrics", action="store_true", help="read host CPU/memory/load/uptime/network from five explicit read-only procfs file mounts on the Linux Docker host")
    parser.add_argument("--max-builds", type=int, choices=range(1, 5), default=1, help="maximum active build jobs, default 1")
    parser.add_argument("--max-copies", type=int, choices=range(1, 5), default=1, help="maximum active source/copy jobs, default 1")
    parser.add_argument("--max-switches", type=int, choices=range(1, 5), default=1, help="maximum active switching jobs, default 1; increase only after host acceptance")
    parser.add_argument("--dry-run", action="store_true", help="print the plan without changes or root privileges")
    parser.add_argument("--replace-config", action="store_true", help="replace reviewed root-owned configuration, keeping all state")
    args = parser.parse_args()
    try:
        repository = Path(__file__).resolve().parent.parent
        root, discovery, workspaces, configuration, mounts, environment = make_plan(args.root, args.discovery_root, args.workspace_root, str(repository), args.docker_socket, args.docker_storage_root, args.host_metrics, args.max_builds, args.max_copies, args.max_switches)
        if args.dry_run:
            print(json.dumps({"executor_config": configuration, "compose_override": mounts, "compose_environment": environment}, indent=2))
            return
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("production bootstrap must run locally as root on the Linux Docker host; use --dry-run to inspect")
        no_symlinks(root)
        parent = root.parent.stat()
        if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022 and not parent.st_mode & stat.S_ISVTX:
            raise ValueError("installation parent must be root-owned and not group/world writable (sticky root-owned /tmp is allowed)")
        socket = Path(args.docker_socket)
        if not stat.S_ISSOCK(socket.stat().st_mode):
            raise ValueError("--docker-socket must name an existing local Docker Unix socket")
        if args.docker_storage_root:
            docker_root = Path(args.docker_storage_root)
            no_symlinks(docker_root)
            if not docker_root.is_dir():
                raise ValueError("--docker-storage-root must be an existing Docker data directory")
        for path in discovery + workspaces:
            if path in (root / "services", root / "workspaces") and not path.exists():
                continue
            no_symlinks(path)
            if not path.is_dir():
                raise ValueError(f"approved root must be an existing directory: {path}")
        private_directory(root, 0, 0, 0o755)
        private_directory(root / "config", 0, 0, 0o700)
        private_directory(root / "executor", 0, 0, 0o700)
        private_directory(root / "runtime", 0, IPC_GID, 0o750)
        private_directory(root / "dashboard", WEB_UID, IPC_GID, 0o700)
        for path in discovery + workspaces:
            if path in (root / "services", root / "workspaces") and not path.exists():
                private_directory(path, 0, 0, 0o755)
        atomic_config(root / "config/executor.json", json.dumps(configuration, indent=2) + "\n", args.replace_config)
        atomic_config(root / "config/compose.mounts.yaml", json.dumps(mounts, indent=2) + "\n", args.replace_config)
        atomic_config(root / "config/compose.env", environment, args.replace_config)
        print(f"Prepared {root}; existing game-project files and Docker were not changed.")
        print(f"docker compose --env-file {root}/config/compose.env config --quiet")
        print(f"docker compose --env-file {root}/config/compose.env up -d --build")
    except (OSError, ValueError) as error:
        parser.exit(1, f"compose-bootstrap: {error}\n")


if __name__ == "__main__":
    main()
