#!/usr/bin/env python3
"""Offline panel restore drill and application-consistent backup of this VM.

Runs as root on the explicitly selected Sibir review VM. It stops only the
panel, application targets and persistent MinIO; the volatile neuroLinks
dependency and both PostgreSQL servers remain running. Private artifacts never
leave the selected backup directory. No active state is restored or deleted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time
import uuid


def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, timeout=180, **kw).stdout


def inspect():
    ids = run(["docker", "ps", "-aq"]).decode().split()
    return json.loads(run(["docker", "inspect", *ids]))


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--destination", type=Path, required=True)
    a = p.parse_args()
    assert os.geteuid() == 0, "native root required"
    dest = a.destination
    assert dest.is_absolute() and dest.parent == Path("/srv/ctf-backups")
    dest.parent.mkdir(mode=0o700, exist_ok=True)
    assert not dest.parent.is_symlink() and not dest.exists()
    dest.mkdir(mode=0o700)
    os.umask(0o077)
    before = inspect()
    expected = {
        "ctf-manager-dashboard-1", "ctf-manager-executor-1",
        "ctfm-demo-sibir-bioguard-web-1", "ctfm-demo-sibir-ncdex-app-1",
        "ctfm-demo-sibir-ncdex-db-1", "ctfm-demo-sibir-bank-cyber-bank-api-1",
        "ctfm-demo-sibir-bank-cyber-bank-front-1", "ctfm-demo-sibir-bank-cyber-bank-postgres-1",
        "ctfm-demo-sibir-neli234-controller-1", "ctfm-demo-sibir-neli234-neurolink-1",
        "ctfm-demo-sibir-eyesee-eyesee-service-1", "ctfm-demo-sibir-eyesee-eyesee-storage-1",
    }
    byname = {c["Name"].lstrip("/"): c for c in before}
    assert set(byname) == expected and all(c["State"]["Running"] for c in before)
    assert all(c["State"].get("Health", {}).get("Status") == "healthy" for c in before)
    assert os.statvfs(dest).f_bavail * os.statvfs(dest).f_frsize > 4 * 1024**3
    save(dest / "protected-inventory-before.json", before)
    # These are read-only queries and never retain complete operation inputs.
    db = sqlite3.connect("file:/srv/ctf-manager/executor/executor.db?mode=ro", uri=True)
    active = [json.loads(r[0]) for r in db.execute("SELECT payload FROM operations")
              if json.loads(r[0]).get("state") not in ("succeeded", "failed", "cancelled", "interrupted", "requires_recovery")]
    db.close()
    assert not active, "pending operations; do not stop executor"
    binary = dest / "ctf-manager"
    run(["docker", "cp", "ctf-manager-executor-1:/usr/local/bin/ctf-manager", str(binary)])
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == "b3b385774a757763ee9b5ab88a6c4bf1a9545019ddb39b9fc532bb5d1f2ca637"
    passfile = dest / "passphrase"
    passfile.write_text(secrets.token_urlsafe(48) + "\n")
    passfile.chmod(0o600)
    panel = ["ctf-manager-dashboard-1", "ctf-manager-executor-1"]
    apps = [n for n in sorted(expected) if n not in panel and not n.endswith(("-db-1", "-postgres-1", "-neurolink-1"))]
    stopped = []
    report = {"test": "native-preacceptance-backup", "status": "running", "started_at_unix": time.time(),
              "destination": str(dest), "game_data_in_panel_archive": False,
              "volatile_neurolink_backed_up": False, "archives": {}, "panel_restore": {}}
    try:
        # Freeze writers before filesystem archives, leaving PostgreSQL available
        # for its native MVCC dump and preserving the neuroLinks RAM process.
        for name in apps + panel:
            run(["docker", "stop", "--time", "20", byname[name]["Id"]])
            stopped.append(name)
        for mode in ("metadata", "protected_full"):
            archive = dest / (mode + ".ctfmbak")
            cmd = [str(binary), "backup", "--executor-state", "/srv/ctf-manager/executor",
                   "--dashboard-state", "/srv/ctf-manager/dashboard", "--configuration", "/srv/ctf-manager/config/executor.json",
                   "--output", str(archive)]
            if mode == "protected_full":
                cmd += ["--passphrase-file", str(passfile)]
            saved = json.loads(run(cmd))
            restore = [str(binary), "restore", "--input", str(archive), "--destination", str(dest / ("restored-" + mode))]
            if mode == "protected_full":
                restore += ["--passphrase-file", str(passfile)]
            restored = json.loads(run(restore))
            assert restored["sessions_revoked"] and restored["queued_operations_disabled"]
            report["panel_restore"][mode] = {"files": saved["files"], "bytes": saved["bytes"],
                "sessions_revoked": restored["sessions_revoked"], "queued_operations_disabled": restored["queued_operations_disabled"],
                "requires_registration_review": restored["requires_registration_review"], "missing_count": len(restored.get("missing") or [])}
        for key, name in (("ncdex", "ctfm-demo-sibir-ncdex-db-1"), ("bank", "ctfm-demo-sibir-bank-cyber-bank-postgres-1")):
            out = dest / (key + ".pgdump")
            with out.open("xb") as f:
                subprocess.run(["docker", "exec", "-u", "postgres", byname[name]["Id"], "sh", "-c",
                    'exec pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"'], stdout=f, stderr=subprocess.PIPE, check=True, timeout=180)
            with out.open("rb") as f:
                subprocess.run(["docker", "exec", "-i", "-u", "postgres", byname[name]["Id"], "pg_restore", "--list"],
                               stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60)
        for name in ("ctfm-demo-sibir-bioguard-web-1", "ctfm-demo-sibir-neli234-controller-1"):
            mount = next(m for m in byname[name]["Mounts"] if m["Destination"] == "/data" and m["Type"] == "volume")
            files = []
            for f in Path(mount["Source"]).rglob("*"):
                if f.is_file() and not f.is_symlink():
                    with f.open("rb") as stream:
                        if stream.read(16) == b"SQLite format 3\x00": files.append(f)
            assert len(files) == 1, "expected one game SQLite database"
            src = sqlite3.connect("file:" + str(files[0]) + "?mode=ro", uri=True)
            target = sqlite3.connect(dest / ("bioguard.sqlite" if "bioguard" in name else "neli234.sqlite"))
            src.backup(target)
            assert target.execute("PRAGMA quick_check").fetchone() == ("ok",)
            src.close(); target.close()
        for name, target, filename in (("ctfm-demo-sibir-bank-cyber-bank-api-1", "/app/build/static/images", "bank-images.tar.gz"),
                                       ("ctfm-demo-sibir-eyesee-eyesee-storage-1", "/data", "eyesee-minio.tar.gz")):
            mount = next(m for m in byname[name]["Mounts"] if m["Destination"] == target and m["Type"] == "volume")
            run(["tar", "-czpf", str(dest / filename), "-C", mount["Source"], "."])
            run(["tar", "-tzf", str(dest / filename)])
        run(["tar", "-czpf", str(dest / "projects-config-workspaces.tar.gz"), "-C", "/srv/ctf-manager", "services", "config", "workspaces"])
        for f in sorted(dest.iterdir()):
            if f.is_file() and f.suffix in (".ctfmbak", ".pgdump", ".sqlite", ".gz"):
                h = hashlib.sha256()
                with f.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024*1024), b""): h.update(block)
                report["archives"][f.name] = {"bytes": f.stat().st_size, "sha256": h.hexdigest()}
        report["status"] = "passed"
    except Exception as e:
        report["status"] = "failed"
        # Subprocess output can contain configuration/credentials; retain only
        # bounded command identity and error type in the shareable result.
        report["error_type"] = type(e).__name__
        if not isinstance(e, subprocess.CalledProcessError): report["error"] = str(e)
        raise
    finally:
        restart_errors = []
        for name in reversed(stopped):
            try: run(["docker", "start", byname[name]["Id"]])
            except Exception as e: restart_errors.append({"container": name, "error_type": type(e).__name__})
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            after = inspect()
            if len(after) == 12 and all(c["State"]["Running"] and c["State"].get("Health", {}).get("Status") == "healthy" for c in after): break
            time.sleep(2)
        amap = {c["Name"].lstrip("/"): c for c in after}
        preserved = all(amap[n]["Id"] == byname[n]["Id"] and amap[n]["Image"] == byname[n]["Image"] and amap[n]["Mounts"] == byname[n]["Mounts"] for n in expected)
        untouched = [n for n in expected if n not in stopped]
        untouched_ok = all(amap[n]["State"]["StartedAt"] == byname[n]["State"]["StartedAt"] for n in untouched)
        healthy = all(c["State"]["Running"] and c["State"].get("Health", {}).get("Status") == "healthy" for c in after)
        report.update(finished_at_unix=time.time(), exact_container_ids_images_mounts_preserved=preserved,
                      untouched_dependencies_started_at_preserved=untouched_ok, all_12_healthy=healthy, restart_errors=restart_errors)
        if not (preserved and untouched_ok and healthy and not restart_errors): report["status"] = "failed"
        save(dest / "protected-inventory-after.json", after)
        save(dest / "report.json", report)
        print(json.dumps(report), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
