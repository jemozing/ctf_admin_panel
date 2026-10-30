#!/usr/bin/env python3
"""Create a local, explicitly non-production bootstrap; never change Docker."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-host", help="explicit unix:/// Docker socket")
    parser.add_argument("--compose-binary", help="explicit installed Compose plugin binary")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker CLI is required")
    host = args.docker_host
    if not host:
        result = subprocess.run([docker, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], check=True, capture_output=True, text=True, timeout=10)
        host = json.loads(result.stdout)
    if not host.startswith("unix:///"):
        parser.error("development supports a local Unix socket only")
    compose_candidates = [args.compose_binary, str(Path.home()/".docker/cli-plugins/docker-compose"), shutil.which("docker-compose"), "/usr/local/lib/docker/cli-plugins/docker-compose", "/usr/libexec/docker/cli-plugins/docker-compose", "/usr/lib/docker/cli-plugins/docker-compose"]
    compose = next((str(Path(p).resolve()) for p in compose_candidates if p and Path(p).is_file() and os.access(p, os.X_OK)), None)
    if not compose:
        parser.error("provide --compose-binary with the installed Compose plugin path")
    for name in ["var/executor", "var/workspaces", "var/fixtures", "tests/fixtures/vendor"]:
        directory = root / name
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_uid != os.geteuid():
            parser.error(f"unsafe development directory: {directory}")
        if name == "var/executor":
            directory.chmod(0o700)
    configuration = {
        "state_directory": str(root / "var/executor"),
        "socket": str(root / "var/executor.sock"),
        "docker_host": host,
        "docker_binary": docker,
        "compose_binary": compose,
        "discovery_roots": [str(root / "tests/fixtures/vendor"), str(root / "var/fixtures")],
        "workspace_roots": [str(root / "var/workspaces")],
        "web_uid": os.geteuid(),
        "development": True,
    }
    path = root / "var/executor.dev.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(configuration, stream, indent=2)
        stream.write("\n")
    print(path)


if __name__ == "__main__":
    main()
