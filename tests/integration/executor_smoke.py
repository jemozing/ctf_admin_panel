#!/usr/bin/env python3
"""Check native executor/client wiring without mutating any Docker container."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def main():
    root = Path(__file__).resolve().parents[2]
    binary = root / "bin/ctf-manager"
    config_path = root / "var/executor.dev.json"
    config = json.loads(config_path.read_text())
    if not config.get("development"):
        raise SystemExit("this smoke uses an explicit development bootstrap only")
    socket_path = Path(config["socket"])
    if socket_path.exists():
        raise SystemExit("executor socket already exists; refusing to remove or replace it")
    process = subprocess.Popen([str(binary), "--config", str(config_path), "executor"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    report = {"test": "executor-cli", "docker_mutations": 0, "status": "failed"}
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("executor exited before binding its socket")
            if socket_path.exists():
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("executor did not become ready")
        status = subprocess.run([str(binary), "--config", str(config_path), "status"], check=True, capture_output=True, text=True, timeout=10)
        result = json.loads(status.stdout)
        assert result["status"] == "ok", result
        assert socket_path.stat().st_mode & 0o777 == 0o660
        # The server rejects an arbitrary command before any backend action.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(str(socket_path))
        body = b'{"command":"touch /unregistered-path"}'
        client.sendall(b"POST /v1/operations HTTP/1.1\r\nHost: executor\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while chunk := client.recv(8192):
            data += chunk
        client.close()
        assert data.startswith(b"HTTP/1.1 400"), data[:100]
        report.update(status="passed", health=result, socket_mode="0660", arbitrary_command_rejected=True)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        report["clean_shutdown"] = process.returncode == 0 and not socket_path.exists()
        if report["status"] == "passed":
            assert report["clean_shutdown"], (stdout, stderr)
        destination = root / "tests/integration/reports/executor-cli-2026-10-19.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
