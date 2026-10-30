#!/usr/bin/env python3
"""Run the real mid-Apply EFBIG test in an isolated unprivileged Linux process."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from runtime_qualification import runtime_qualification

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ctf-manager-executor:local")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/apply-efbig-linux-2026-10-20.json")
    args = parser.parse_args()
    docker = shutil.which("docker")
    image = json.loads(subprocess.check_output([docker, "image", "inspect", args.image], text=True))[0]
    server = json.loads(subprocess.check_output([docker, "version", "--format", "{{json .Server}}"], text=True))
    qualification = runtime_qualification(server, image)
    platform = image["Os"] + "/" + image["Architecture"]
    if image["Os"] != "linux":
        raise RuntimeError("Linux runtime image required")
    binary = ROOT / ".cache/fault-multi" / ("filesystem-linux-" + image["Architecture"] + ".test")
    binary.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": image["Architecture"],
           "GOCACHE": str(ROOT / ".cache/go-build"), "GOMODCACHE": str(ROOT / ".cache/go-mod")}
    subprocess.run(["go", "test", "-c", "-o", str(binary), "./internal/filesystem"], cwd=ROOT, env=env, check=True)
    test = "TestApplyRealEFBIGAfterFirstReplacementCompensatesFromObservedTree"
    command = [docker, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
               "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
               "--mount", f"type=bind,src={binary},dst=/filesystem.test,readonly",
               "--entrypoint", "/filesystem.test", image["Id"], "-test.run", "^" + test + "$", "-test.v"]
    started = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    report = {"test": "real-kernel-efbig-mid-apply-and-observed-compensation", "status": "passed" if result.returncode == 0 else "failed",
              "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(), "platform": platform, "image_id": image["Id"],
              "test_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "test_source_sha256": hashlib.sha256((ROOT / "internal/filesystem/apply_error_linux_test.go").read_bytes()).hexdigest(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "exit_code": result.returncode,
              "runtime_qualification": qualification,
              "output": result.stdout + result.stderr,
              "isolation": {"network": "none", "uid_gid": "10001:10001", "capabilities": "all dropped", "docker_socket": False,
                            "root_filesystem": "read-only", "test_binary": "read-only", "temporary_files": "64MiB private tmpfs", "container": "--rm"},
              "checks": ["real RLIMIT_FSIZE=4096 in a subprocess causes EFBIG after first file replacement",
                         "earlier file changed; later file remains baseline; partial temporary file removed",
                         "immutable baseline and candidate preserved; unmanaged flag preserved",
                         "stale pre-switch manifest refused as ErrDrift",
                         "fresh observed partial tree permits exact baseline compensation"],
              "limitations": [qualification["scope_note"], "Real EFBIG is not ENOSPC, fsync EIO or power loss",
                              "Low-level filesystem Apply/compensation test; executor journal and Docker lifecycle covered by separate fault suite"]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
