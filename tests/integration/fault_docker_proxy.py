#!/usr/bin/env python3
"""Fixture-scoped Unix Docker API gates; never runs in product images.

The caller mounts only its unique fixture root and an existing Docker socket.
Only the SDK traffic of that isolated executor uses this proxy; Compose uses the
real socket. A gate may suppress a real response, but never invents a successful
Docker response. Normal forwarding intentionally supports bounded HTTP API calls
only, not builds, attach, upgrades or long-lived streams.
"""

import http.client
import http.server
import json
from pathlib import Path
import socket
import socketserver
import sqlite3
import sys
import threading
import time

root = Path(sys.argv[1])
upstream = sys.argv[2]
socket_path = root / "config/docker-proxy.sock"
mode_path = root / "config/proxy-mode"
log_path = root / "config/proxy-events.jsonl"
mutex = threading.Lock()


def mode():
    try:
        return mode_path.read_text().strip()
    except FileNotFoundError:
        return ""


def record(**value):
    with mutex:
        with log_path.open("a") as handle:
            handle.write(json.dumps({"at": time.time(), **value}) + "\n")


class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(25)
        self.sock.connect(upstream)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def reply_error(self):
        body = b'{"message":"fixture-injected Docker API unavailable"}'
        try:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def handle_api(self):
        selected = mode()
        stop = self.command == "POST" and "/containers/" in self.path and "/stop" in self.path
        warmup = False
        if selected == "before_warmup" and self.command == "GET" and "/containers/json" in self.path:
            operation_id = (root / "config/operation-id").read_text().strip()
            with sqlite3.connect("file:" + str(root / "executor/executor.db") + "?mode=ro", uri=True) as db:
                row = db.execute("SELECT payload FROM operations WHERE id=?", (operation_id,)).fetchone()
                warmup = row is not None and json.loads(row[0])["stage"] == "warmup"
        before = (selected == "before_stop" and stop or selected == "before_budget" and "/system/df" in self.path
                  or warmup)
        if selected == "unavailable" or before:
            if before:
                (root / "config/proxy-reached").write_text(selected)
                record(method=self.command, path=self.path, gate=selected, forwarded=False)
                while mode() == selected:
                    time.sleep(.02)
            self.reply_error()
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Upgrade"):
            raise RuntimeError("fixture proxy does not support streaming requests")
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1 << 20:
            raise RuntimeError("fixture request is too large")
        body = self.rfile.read(length) if length else None
        connection = Connection("docker", timeout=25)
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in ("connection", "host")}
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(32 << 20)
            if response.read(1):
                raise RuntimeError("fixture Docker response is too large")
            record(method=self.command, path=self.path, status=response.status,
                   gate=selected, forwarded=True)
            if stop and selected in ("after_stop", "lose_stop_response"):
                if selected == "lose_stop_response":
                    mode_path.unlink(missing_ok=True)
                (root / "config/proxy-reached").write_text(selected)
                while selected == "after_stop" and mode() == selected:
                    time.sleep(.02)
                # The daemon really acknowledged Stop. Its response is discarded,
                # so the executor must reconcile an unknown effect, never success.
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ("connection", "content-length", "transfer-encoding"):
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        finally:
            connection.close()

    do_GET = handle_api
    do_POST = handle_api
    do_HEAD = handle_api
    do_DELETE = handle_api
    do_PUT = handle_api


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


socket_path.unlink(missing_ok=True)
with Server(str(socket_path), Handler) as server:
    socket_path.chmod(0o660)
    server.serve_forever(poll_interval=.1)
