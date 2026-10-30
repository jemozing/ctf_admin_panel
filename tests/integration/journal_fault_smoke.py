#!/usr/bin/env python3
"""Run real SQLite ENOSPC acceptance on a private, capability-free tmpfs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(arguments, **kwargs):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image", default="ctf-manager-executor:local")
    parser.add_argument("--report", type=Path, default=ROOT / "tests/integration/reports/journal-enospc-2026-10-20.json")
    args = parser.parse_args()
    report = {"test": "real-sqlite-journal-enospc", "status": "failed",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "test binary, no executor process or game project; isolated 2MiB tmpfs",
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "limitations": ["tmpfs ENOSPC, not physical power loss or fsync fault injection",
                              "metadata transaction acceptance, not full Deploy under filesystem exhaustion"]}
    try:
        server = json.loads(run(["docker", "version", "--format", "{{json .Server}} "]))
        architecture = {"arm64": "arm64", "amd64": "amd64"}.get(server["Arch"])
        if server["Os"] != "linux" or not architecture:
            raise RuntimeError("this test requires a Linux arm64 or amd64 daemon")
        image = json.loads(run(["docker", "image", "inspect", args.runtime_image]))[0]
        report["runtime"] = {"os": server["Os"], "architecture": architecture,
                             "docker_version": server["Version"], "image_id": image["Id"]}
        environment = {**os.environ, "GOCACHE": str(ROOT / ".cache/go-build"),
                       "GOMODCACHE": str(ROOT / ".cache/go-mod"),
                       "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": architecture}
        with tempfile.TemporaryDirectory(prefix="ctfm-journal-acceptance-") as temporary:
            binary = Path(temporary).resolve() / "store.test"
            run(["go", "test", "-c", "-o", str(binary), "./internal/store"], cwd=ROOT, env=environment)
            report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            output = run(["docker", "run", "--rm", "--read-only", "--network", "none", "--cap-drop", "ALL",
                          "--tmpfs", "/fault:rw,noexec,nosuid,size=2m",
                          "--tmpfs", "/tmp:rw,noexec,nosuid,size=4m",
                          "--mount", f"type=bind,source={binary},target=/acceptance.test,readonly",
                          "--env", "CTFM_TEST_JOURNAL_ENOSPC_ROOT=/fault",
                          "--entrypoint", "/acceptance.test", image["Id"],
                          "-test.run", "^TestJournalRealENOSPC", "-test.v"])
            report["output"] = output
            if "--- PASS: TestJournalRealENOSPCRetainsMutationIntentAndLocks" not in output or "SKIP" in output:
                raise RuntimeError("required real ENOSPC test did not execute")
        report["checks"] = {"actual_tmpfs_enospc_and_sqlite_full": True,
                            "failed_terminal_commit_not_published": True,
                            "durable_mutation_and_recovery_point_preserved": True,
                            "operation_locks_and_events_preserved": True,
                            "database_reopen_integrity_and_interrupted_reconciliation": True}
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.report), "checks": report["checks"]}))


if __name__ == "__main__":
    main()
