"""Small, dependency-free state service for CTF Manager integration fixtures.

This is test infrastructure. It binds inside its container; Compose exposes it
only on a dynamically allocated host loopback port.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


MAX_BODY = 4096
MAX_VALUE = 2048
KEY = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")


@dataclass(frozen=True)
class Config:
    storage: str = "sqlite"
    database: Path = Path("/data/state.sqlite3")
    backend_url: str = "http://database:8080"
    version_file: Path = Path("/app/VERSION")
    role: str = "app"

    @classmethod
    def from_environment(cls) -> Config:
        return cls(
            storage=os.getenv("FIXTURE_STORAGE", "sqlite"),
            database=Path(os.getenv("FIXTURE_DB_PATH", "/data/state.sqlite3")),
            backend_url=os.getenv("FIXTURE_BACKEND_URL", "http://database:8080").rstrip("/"),
            version_file=Path(os.getenv("FIXTURE_VERSION_PATH", "/app/VERSION")),
            role=os.getenv("FIXTURE_ROLE", "app"),
        )


class StorageUnavailable(Exception):
    pass


class Store:
    def __init__(self, config: Config):
        self.config = config
        if config.storage not in {"sqlite", "remote"}:
            raise ValueError("FIXTURE_STORAGE must be sqlite or remote")
        if config.storage == "sqlite":
            config.database.parent.mkdir(parents=True, exist_ok=True)
            with self.connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS entries ("
                    "namespace TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, "
                    "PRIMARY KEY (namespace, key))"
                )

    def connect(self):
        return sqlite3.connect(self.config.database, timeout=5)

    def proxy(self, method: str, path: str, value: str | None = None):
        body = None if value is None else json.dumps({"value": value}).encode()
        request = Request(
            self.config.backend_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            try:
                return error.code, json.load(error)
            except (ValueError, OSError) as cause:
                raise StorageUnavailable from cause
        except (URLError, OSError, ValueError) as cause:
            raise StorageUnavailable from cause

    def healthy(self):
        if self.config.storage == "remote":
            status, _ = self.proxy("GET", "/health")
            if status != 200:
                raise StorageUnavailable
        else:
            with self.connect() as connection:
                connection.execute("SELECT 1").fetchone()

    def entry(self, method: str, namespace: str, key: str, value: str | None = None):
        if self.config.storage == "remote":
            return self.proxy(method, f"/{namespace}/{key}", value)
        with self.connect() as connection:
            if method == "PUT":
                connection.execute(
                    "INSERT INTO entries(namespace, key, value) VALUES (?, ?, ?) "
                    "ON CONFLICT(namespace, key) DO UPDATE SET value=excluded.value",
                    (namespace, key, value),
                )
                return 200, {"key": key, "value": value}
            if method == "DELETE":
                connection.execute(
                    "DELETE FROM entries WHERE namespace=? AND key=?", (namespace, key)
                )
                return 200, {"key": key, "deleted": True}
            row = connection.execute(
                "SELECT value FROM entries WHERE namespace=? AND key=?", (namespace, key)
            ).fetchone()
            if row is None:
                return 404, {"error": "not_found"}
            return 200, {"key": key, "value": row[0]}


def make_server(config: Config, host: str = "0.0.0.0", port: int = 8080):
    store = Store(config)

    class Handler(BaseHTTPRequestHandler):
        server_version = "CTFMFixture/1"

        def respond(self, status: int, payload: dict):
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.dispatch("GET")

        def do_PUT(self):
            self.dispatch("PUT")

        def do_DELETE(self):
            self.dispatch("DELETE")

        def read_value(self):
            if self.headers.get_content_type() != "application/json":
                self.respond(415, {"error": "json_required"})
                return None
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self.respond(413, {"error": "invalid_body_size"})
                return None
            try:
                payload = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeError):
                self.respond(400, {"error": "invalid_json"})
                return None
            if not isinstance(payload, dict) or set(payload) != {"value"}:
                self.respond(400, {"error": "value_required"})
                return None
            value = payload["value"]
            if not isinstance(value, str) or len(value) > MAX_VALUE:
                self.respond(400, {"error": "invalid_value"})
                return None
            return value

        def dispatch(self, method: str):
            path = urlsplit(self.path).path
            try:
                if path == "/health" and method == "GET":
                    store.healthy()
                    self.respond(200, {
                        "status": "ok", "role": config.role, "storage": config.storage
                    })
                    return
                if path == "/version" and method == "GET":
                    self.respond(200, {
                        "version": config.version_file.read_text().strip(), "role": config.role
                    })
                    return
                parts = path.split("/")
                if (len(parts) != 3 or parts[1] not in {"flags", "state"}
                        or KEY.fullmatch(parts[2]) is None):
                    self.respond(404, {"error": "not_found"})
                    return
                value = self.read_value() if method == "PUT" else None
                if method == "PUT" and value is None:
                    return
                status, payload = store.entry(method, parts[1], parts[2], value)
                self.respond(status, payload)
            except StorageUnavailable:
                self.respond(503, {"error": "storage_unavailable"})
            except (sqlite3.Error, OSError):
                self.respond(503, {"error": "local_storage_unavailable"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    make_server(Config.from_environment(), port=int(os.getenv("FIXTURE_PORT", "8080"))).serve_forever()
