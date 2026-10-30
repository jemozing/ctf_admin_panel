#!/usr/bin/env python3
"""Normal synthetic player writes/reads for five already-running SibirCTF apps.

Import is inert. The controller explicitly calls prepare(), write_after_deploy()
and verify(). Only new UUID players/records are written; no deletes, checker,
exploit, Docker, SSH, service restart or application configuration is used.
Opaque credentials, payloads and RAM keys are kept only in private checkpoints.
"""
import argparse
import fcntl
import hashlib
import html
from html.parser import HTMLParser
import http.cookiejar
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PORTS = {"bioguard": 18011, "ncdex": 18012, "bank": 18013, "neli234": 18014, "eyesee": 18015}


class ProbeError(RuntimeError):
    """Safe diagnostics: never attach response bodies, cookies or credentials."""


class AuthenticationFailed(ProbeError):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def digest(value):
    if not isinstance(value, bytes):
        value = str(value).encode()
    return hashlib.sha256(value).hexdigest()


def private_read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.geteuid() and info.st_nlink == 1,
                "probe checkpoint must be a private owned 0600 regular file")
        return json.load(source)


def private_write(path, value):
    require(not path.is_symlink(), "refuse symlink probe checkpoint")
    if path.exists():
        private_read(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w") as target:
        json.dump(value, target, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    temporary.replace(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, request, response, code, message, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme + "://" + parsed.netloc == self.origin, "cross-origin application redirect refused")
        return super().redirect_request(request, response, code, message, headers, newurl)


class HTTPClient:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(SameOriginRedirect(base), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, value=None, *, form=False):
        require(path.startswith("/") and not path.startswith("//") and "\r" not in path and "\n" not in path,
                "application request must remain on its known origin")
        headers = {"Cache-Control": "no-cache"}
        data = None
        if value is not None:
            data = urllib.parse.urlencode(value).encode() if form else json.dumps(value).encode()
            headers.update({"Content-Type": "application/x-www-form-urlencoded" if form else "application/json",
                            "Origin": self.base, "Referer": self.base + path})
        request = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            with self.opener.open(request, timeout=20) as response:
                body = response.read(8 * 1024 * 1024 + 1)
                require(len(body) <= 8 * 1024 * 1024, "application response exceeded bounded probe limit")
                return response.geturl(), body
        except urllib.error.HTTPError as error:
            if error.code == 401:
                raise AuthenticationFailed("application rejected authentication") from None
            raise ProbeError("application HTTP request failed: " + str(error.code)) from None
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            raise ProbeError("application HTTP transport failed; no automatic write replay") from None

    def text(self, path, value=None, *, form=False):
        destination, body = self.request(path, value, form=form)
        try:
            return destination, body.decode("utf-8")
        except UnicodeDecodeError:
            raise ProbeError("application returned invalid UTF-8") from None

    def json(self, path, value=None):
        _, body = self.request(path, value)
        try:
            return json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise ProbeError("application returned invalid JSON") from None


class CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("name") == "csrfmiddlewaretoken":
            self.token = values.get("value")


class DjangoClient(HTTPClient):
    def form(self, path, values):
        _, page = self.text(path)
        parser = CSRFParser()
        parser.feed(page)
        require(parser.token, "BioGuard form omitted CSRF token")
        return self.text(path, {**values, "csrfmiddlewaretoken": parser.token}, form=True)


class NeuroClient:
    def __init__(self, host, port):
        self.connection = socket.create_connection((host, port), timeout=15)
        self.buffer = b""
        try:
            self.until(b"2. Login\n")
        except BaseException:
            self.connection.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_unused):
        self.connection.close()

    def receive(self, deadline):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "neuroLinks response deadline exceeded")
        self.connection.settimeout(min(15, remaining))
        try:
            piece = self.connection.recv(4096)
        except OSError:
            raise ProbeError("neuroLinks transport failed; no automatic write replay") from None
        require(piece, "neuroLinks unexpectedly closed the connection")
        self.buffer += piece
        require(len(self.buffer) <= 16384, "neuroLinks reply exceeded bounded probe limit")

    def until(self, token):
        deadline = time.monotonic() + 20
        while token not in self.buffer:
            self.receive(deadline)
        index = self.buffer.index(token) + len(token)
        result, self.buffer = self.buffer[:index], self.buffer[index:]
        return result

    def exact(self, length):
        deadline = time.monotonic() + 20
        while len(self.buffer) < length:
            self.receive(deadline)
        result, self.buffer = self.buffer[:length], self.buffer[length:]
        return result

    def send(self, line):
        require("\n" not in line and "\r" not in line and "\x00" not in line, "unsafe neuroLinks line")
        try:
            self.connection.sendall((line + "\n").encode())
        except OSError:
            raise ProbeError("neuroLinks send failed; no automatic write replay") from None

    def login(self, record):
        self.send("2")
        self.until(b"Username: ")
        self.send(record["username"])
        self.until(b"Password: ")
        self.send(record["password"])
        if b"Login successful!\n" not in self.until(b"\n"):
            raise AuthenticationFailed("neuroLinks rejected synthetic player authentication")

    def register(self, record):
        self.send("1")
        self.until(b"Enter username: ")
        self.send(record["username"])
        self.until(b"Enter password: ")
        self.send(record["password"])
        require(b"Registration successful!" in self.until(b"2. Login\n"), "neuroLinks player registration failed")

    def command_line(self, command):
        self.send(command)
        return self.until(b"\n").rstrip(b"\r\n\x00").decode("ascii")

    def internalize(self, record):
        self.send("internalize " + record["concept"] + "=" + record["solution"])
        # The pinned application returns its opaque MD5-shaped key without a
        # newline. Read the exact 32 hexadecimal bytes, including TCP fragments.
        prefix = b"Internalized: "
        result = self.exact(len(prefix) + 32)
        require(result.startswith(prefix) and re.fullmatch(rb"[0-9a-fA-F]{32}", result[len(prefix):]),
                "neuroLinks did not return a complete opaque concept key")
        return result[len(prefix):].decode("ascii")

    def read_concept(self, record):
        require(re.fullmatch(r"[0-9a-fA-F]{32}", record["concept_key"]), "invalid saved opaque RAM key")
        expected = ("Ejected: " + record["concept"] + "=" + record["solution"]).encode()
        self.send("eject " + record["concept_key"])
        require(self.exact(len(expected)) == expected, "neuroLinks own RAM concept was not preserved")


class ProbeAdapter:
    def __init__(self, root, checkpoint_dir, *, host="127.0.0.1", ports=None, vendor_root=None, namespace=None,
                 eyesee_empty_store_proof=None):
        self.root = str(root)
        self.directory = Path(checkpoint_dir).absolute()
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                "probe checkpoint directory must be a private owned 0700 directory")
        require(host in ("127.0.0.1", "localhost"), "probe apps only through VM loopback or explicit local tunnels")
        self.host = host
        self.ports = {**DEFAULT_PORTS, **(ports or {})}
        require(all(type(port) is int and 1 <= port <= 65535 for port in self.ports.values()), "invalid service port")
        self.vendor = Path(vendor_root) if vendor_root else ROOT / "tests/fixtures/vendor"
        identity = self.directory / "identity.json"
        if identity.exists():
            saved = private_read(identity)
            require(saved["root"] == self.root and saved["host"] == host and saved["ports"] == self.ports,
                    "probe checkpoints belong to different apps/endpoints")
            require(namespace is None or namespace == saved["namespace"], "probe run namespace changed")
            self.namespace = saved["namespace"]
        else:
            self.namespace = namespace or uuid.uuid4().hex
            require(isinstance(self.namespace, str) and re.fullmatch(r"[A-Za-z0-9_-]{8,96}", self.namespace), "invalid probe run namespace")
            private_write(identity, {"root": self.root, "host": host, "ports": self.ports, "namespace": self.namespace})
        self.pb = None
        self.eyesee_empty_store_proof = eyesee_empty_store_proof

    def _base(self, key):
        return f"http://{self.host}:{self.ports[key]}"

    def _lock(self, key):
        require(key in DEFAULT_PORTS, "unknown SibirCTF probe key")
        descriptor = os.open(self.directory / (key + ".lock"), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(descriptor)
        if not (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid() and info.st_nlink == 1):
            os.close(descriptor)
            raise ProbeError("unsafe probe lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(descriptor)
            raise
        return os.fdopen(descriptor, "a")

    def _load(self, key):
        path = self.directory / (key + ".json")
        state = private_read(path) if path.exists() else {"service": key, "namespace": self.namespace, "records": {}}
        require(state["service"] == key and state["namespace"] == self.namespace, "probe checkpoint identity changed")
        return path, state

    def _new_record(self, key, phase):
        token = digest(self.namespace + ":" + key + ":" + phase)[:12]
        marker = "CTFM_NATIVE_" + token + "_" + secrets.token_hex(12)
        return {"phase": phase, "username": "ctfm_" + token, "password": secrets.token_urlsafe(24),
                "email": "ctfm_" + token + "@example.invalid", "diagnosis": marker,
                "title": "CTFM native " + token, "description": "CTFM native record " + token,
                "exploit": "CTFM_NONEXECUTABLE_DATA_" + secrets.token_hex(16),
                "content": marker, "comment": "CTFM native comment " + token,
                "thought": "ctfm_thought_" + token, "ad": marker,
                "concept": "ctfm_concept_" + token, "solution": "CTFM_RAM_" + secrets.token_hex(16),
                "patient_id": str(uuid.uuid4()), "patient_name": "CTFM native " + token,
                "doctor_name": "Synthetic doctor", "modifications": ["CTFM native " + token],
                "features": [str(uuid.uuid4())], "completed": False}

    def prepare(self, key):
        return self.seed(key, "before")

    def write_after_deploy(self, key):
        if key == "eyesee":
            return {"service": key, "status": "skipped_upstream_uuid_collision_risk",
                    "new_after_deploy_data_created": False,
                    "reason": "pinned upstream process restarts its deterministic UUID stream; a new AddPrescription may overwrite an existing MinIO object",
                    "existing_before_data": self.verify(key)}
        return self.seed(key, "after")

    def seed(self, key, phase="before"):
        require(phase in ("before", "after"), "probe phase must be before or after")
        require(key != "eyesee" or phase == "before", "EyeSee after-Deploy write is unsafe with the pinned upstream deterministic UUID stream")
        with self._lock(key):
            path, state = self._load(key)
            require(phase == "before" or state["records"].get("before", {}).get("completed"), "before-Deploy data must be verified first")
            if phase not in state["records"]:
                state["records"][phase] = self._new_record(key, phase)
                private_write(path, state)  # Intent/credentials precede every write.
            record = state["records"][phase]
            save = lambda: private_write(path, state)
            self._record(key, record, not record["completed"], save)
            record["completed"] = True
            save()
            return self._verify_state(key, state)

    def verify(self, key):
        with self._lock(key):
            _path, state = self._load(key)
            return self._verify_state(key, state)

    def _verify_state(self, key, state):
        require(state["records"].get("before", {}).get("completed"), "no completed before-Deploy probe exists")
        results = []
        for phase in ("before", "after"):
            if phase not in state["records"]:
                continue
            record = state["records"][phase]
            require(record["completed"], "a probe write has an unresolved partial result")
            value = self._record(key, record, False, lambda: None)
            results.append({"phase": phase, **value})
        return {"service": key, "status": "passed", "namespace": self.namespace,
                "record_count": len(results), "records": results,
                "ordinary_application_operations": True, "raw_payloads_or_credentials_exported": False,
                "ram_state_scope": "only while the unchanged neurolink process stays alive; host/daemon restart excluded" if key == "neli234" else "not_applicable"}

    def _attempt(self, record, name, save):
        require(not record.get(name + "_attempted"), "ambiguous prior " + name + " write; refusing blind replay")
        record[name + "_attempted"] = True
        save()

    def _record(self, key, record, write, save):
        try:
            return getattr(self, "_" + key)(record, write, save)
        except ProbeError:
            raise
        except Exception as error:
            raise ProbeError(key + " application probe failed (" + type(error).__name__ + "); private checkpoint retained") from None

    def _bioguard(self, record, write, save):
        def login():
            client = DjangoClient(self._base("bioguard"))
            destination, _ = client.form("/login", {"username": record["username"], "password": record["password"]})
            if urllib.parse.urlsplit(destination).path != "/profile":
                raise AuthenticationFailed("BioGuard synthetic patient login failed")
            return client
        try:
            client = login()
        except AuthenticationFailed:
            require(write and not record.get("account_confirmed"), "BioGuard previously confirmed patient is missing")
            self._attempt(record, "account_create", save)
            client = DjangoClient(self._base("bioguard"))
            destination, _ = client.form("/register", {"username": record["username"], "password1": record["password"], "password2": record["password"],
                "first_name": "CTFM", "last_name": "Native", "email": record["email"], "birth_year": "2000", "diagnosis": record["diagnosis"], "appointments": "", "vip": "false"})
            require(urllib.parse.urlsplit(destination).path == "/login", "BioGuard registration did not finish normally")
            client = login()
        if write and not record.get("account_confirmed"):
            record["account_confirmed"] = True
            save()
        destination, page = client.text("/profile")
        require(urllib.parse.urlsplit(destination).path == "/profile" and html.escape(record["diagnosis"]) in page,
                "BioGuard diagnosis was not preserved for its authenticated patient")
        return {"fresh_login": True, "sqlite_diagnosis_preserved": True, "diagnosis_sha256": digest(record["diagnosis"])}

    def _ncdex(self, record, write, save):
        def login():
            client = HTTPClient(self._base("ncdex"))
            client.text("/users/login", {"email": record["email"], "password": record["password"]}, form=True)
            destination, page = client.text("/users/profile")
            if urllib.parse.urlsplit(destination).path != "/users/profile" or html.escape(record["username"]) not in page:
                raise AuthenticationFailed("ncdex synthetic player login failed")
            return client, page
        try:
            client, profile = login()
        except AuthenticationFailed:
            require(write and not record.get("account_confirmed"), "ncdex previously confirmed player is missing")
            self._attempt(record, "account_create", save)
            client = HTTPClient(self._base("ncdex"))
            destination, _ = client.text("/users/register", {key: record[key] for key in ("username", "email", "password")}, form=True)
            require(urllib.parse.urlsplit(destination).path == "/users/profile", "ncdex registration did not finish normally")
            client, profile = login()
        if write and not record.get("account_confirmed"):
            record["account_confirmed"] = True
            save()
        if "record_id" not in record:
            require(write, "ncdex record identity was never pinned")
            ids = set(re.findall(r'href=["\']/vulnerabilities/([0-9]+)["\']', profile))
            require(len(ids) <= 512, "synthetic ncdex profile has too many records")
            found = []
            for identity in ids:
                _, page = client.text("/vulnerabilities/" + identity)
                if all(html.escape(record[key]) in page for key in ("title", "description", "exploit")):
                    found.append(int(identity))
            require(len(found) <= 1, "ncdex synthetic record is duplicated")
            if found:
                record["record_id"] = found[0]
            else:
                self._attempt(record, "record_create", save)
                destination, page = client.text("/vulnerabilities", {**{key: record[key] for key in ("title", "description", "exploit")}, "exploit_type": "rce", "platform": "linux", "price": "100"}, form=True)
                match = re.fullmatch(r"/vulnerabilities/([0-9]+)", urllib.parse.urlsplit(destination).path)
                require(match and all(html.escape(record[key]) in page for key in ("title", "description", "exploit")), "ncdex normal record creation was not confirmed")
                record["record_id"] = int(match[1])
            save()
        client, _ = login()
        destination, page = client.text("/vulnerabilities/" + str(int(record["record_id"])))
        require(urllib.parse.urlsplit(destination).path == "/vulnerabilities/" + str(record["record_id"])
                and all(html.escape(record[key]) in page for key in ("title", "description", "exploit")), "ncdex PostgreSQL record was not preserved")
        return {"fresh_login": True, "postgres_record_preserved": True, "record_id": record["record_id"],
                "payload_sha256": digest(json.dumps({key: record[key] for key in ("title", "description", "exploit")}, sort_keys=True))}

    def _bank(self, record, write, save):
        def login():
            client = HTTPClient(self._base("bank"))
            client.json("/api/login", {"username": record["username"], "password": record["password"]})
            user = client.json("/api/user")
            if not isinstance(user, dict) or user.get("name") != record["username"]:
                raise AuthenticationFailed("CyberBank synthetic player login failed")
            return client, user
        try:
            client, user = login()
        except AuthenticationFailed:
            require(write and not record.get("account_confirmed"), "CyberBank previously confirmed player is missing")
            self._attempt(record, "account_create", save)
            HTTPClient(self._base("bank")).json("/api/register", {"username": record["username"], "password": record["password"]})
            client, user = login()
        if write and not record.get("account_confirmed"):
            record["account_confirmed"] = True
            save()
        if "product_id" not in record:
            require(write, "CyberBank product identity was never pinned")
            products = client.json("/api/products")
            require(isinstance(products, list), "CyberBank product list is invalid")
            found = [item for item in products if item.get("description") == record["description"]]
            require(len(found) <= 1, "CyberBank synthetic product duplicated")
            if not found:
                self._attempt(record, "product_create", save)
                product = client.json("/api/products/create", {"description": record["description"], "content": record["content"], "price": 17})
            else:
                product = found[0]
            record["product_id"] = int(product["id"])
            save()
        path = "/api/products/" + str(int(record["product_id"]))
        product = client.json(path)
        matching = [item for item in product.get("comments", []) if item.get("content") == record["comment"]]
        if not matching and write:
            self._attempt(record, "comment_create", save)
            client.json(path + "/comment", {"content": record["comment"]})
            product = client.json(path)
            matching = [item for item in product.get("comments", []) if item.get("content") == record["comment"]]
        require(len(matching) == 1 and product.get("description") == record["description"]
                and product.get("content") == record["content"] and product.get("price") == 17,
                "CyberBank PostgreSQL product/comment was not preserved")
        image_path = product.get("image_path", "")
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,180}", image_path) and ".." not in image_path, "unsafe CyberBank generated image path")
        _, image = client.request("/api/public/images/" + image_path)
        require(image.startswith(b"\x89PNG\r\n\x1a\n"), "CyberBank generated PNG cannot be read")
        pin = {"product_id": product["id"], "user_id": user["id"], "image_path": image_path, "image_sha256": digest(image)}
        if "pin" not in record:
            require(write, "CyberBank data/PNG identity was never pinned")
            record["pin"] = pin
            save()
        require(pin == record["pin"], "CyberBank persistent product/user/PNG identity changed")
        return {"fresh_login": True, "postgres_product_and_comment_preserved": True, "generated_png_preserved": True,
                "product_id": product["id"], "user_id": user["id"], "image_sha256": pin["image_sha256"],
                "content_sha256": digest(record["content"]), "comment_sha256": digest(record["comment"])}

    def _neli234(self, record, write, save):
        def login():
            client = NeuroClient(self.host, self.ports["neli234"])
            try:
                client.login(record)
                return client
            except BaseException:
                client.connection.close()
                raise
        try:
            client = login()
        except AuthenticationFailed:
            require(write and not record.get("account_confirmed"), "neuroLinks previously confirmed player is missing")
            self._attempt(record, "account_create", save)
            with NeuroClient(self.host, self.ports["neli234"]) as registration:
                registration.register(record)
            client = login()
        with client:
            if write and not record.get("account_confirmed"):
                record["account_confirmed"] = True
                save()
            thought = client.command_line("impulseintrusive " + record["thought"])
            if thought == "Not found" and write and not record.get("thought_confirmed"):
                self._attempt(record, "thought_create", save)
                require(client.command_line("intrusivethought " + record["thought"] + ":" + record["ad"]) == "Added successfully", "neuroLinks normal SQLite write failed")
                thought = client.command_line("impulseintrusive " + record["thought"])
            require(thought == "Found: " + record["ad"], "neuroLinks own SQLite thought was not preserved")
            if write and not record.get("thought_confirmed"):
                record["thought_confirmed"] = True
                save()
            if "concept_key" not in record:
                require(write, "neuroLinks opaque own RAM key was never pinned")
                self._attempt(record, "concept_create", save)
                record["concept_key"] = client.internalize(record)
                save()
        # The pinned upstream forwards the auxiliary's response bytes without
        # framing/normalizing them. A complete key may have a trailing delimiter
        # left behind on this write connection. Its key is already durably
        # saved; close it and authenticate a fresh reader instead of replaying
        # internalize or letting those bytes prefix the next response.
        with login() as reader:
            require(reader.command_line("impulseintrusive " + record["thought"]) == "Found: " + record["ad"],
                    "neuroLinks own SQLite thought was not preserved after fresh login")
            reader.read_concept(record)
        return {"fresh_login": True, "sqlite_thought_preserved": True, "own_ram_concept_preserved": True,
                "thought_sha256": digest(record["ad"]), "concept_sha256": digest(record["solution"]),
                "opaque_key_sha256": digest(record["concept_key"])}

    def _messages(self):
        if self.pb is None:
            source = self.vendor / "2025-cybersibir-service-eyesee/checker_eyesee/proto/service_pb2.py"
            require(source.is_file(), "EyeSee generated protobuf definitions are unavailable")
            specification = importlib.util.spec_from_file_location("ctfm_native_eyesee_pb2", source)
            module = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(module)
            self.pb = module
        return self.pb

    def _rpc(self, method, request, response_type):
        require(method in ("ServiceHealthCheck", "AddPrescription", "GetPrescriptionIDs", "CheckPrescription"), "unreviewed EyeSee RPC method")
        try:
            import grpc
        except ImportError:
            raise ProbeError("EyeSee full data probe requires existing grpcio and protobuf modules") from None
        try:
            with grpc.insecure_channel(f"{self.host}:{self.ports['eyesee']}") as channel:
                call = channel.unary_unary("/service.proto.EyeSeeService/" + method, request_serializer=type(request).SerializeToString,
                                          response_deserializer=response_type.FromString)
                return call(request, timeout=20)
        except grpc.RpcError as error:
            raise ProbeError("EyeSee normal RPC " + method + " failed: " + error.code().name) from None

    def _eyesee(self, record, write, save):
        pb = self._messages()
        health = self._rpc("ServiceHealthCheck", pb.ServiceHealthCheckRequest(), pb.ServiceHealthCheckResponse)
        require(health.status == "OK", "EyeSee RPC health is not OK")
        fields = ("patient_id", "patient_name", "doctor_name", "modifications", "features")
        ids = self._rpc("GetPrescriptionIDs", pb.GetPrescriptionIDsRequest(patient_id=record["patient_id"]), pb.GetPrescriptionIDsResponse)
        require(len(ids.ids) <= 512, "synthetic EyeSee patient has too many prescriptions")
        if "prescription_id" not in record:
            require(write, "EyeSee prescription identity was never pinned")
            found = []
            for identity in ids.ids:
                uuid.UUID(identity)
                current = self._rpc("CheckPrescription", pb.CheckPrescriptionRequest(id=identity), pb.CheckPrescriptionResponse)
                if all((list(getattr(current, key)) if key in ("modifications", "features") else getattr(current, key)) == record[key] for key in fields):
                    found.append(identity)
            require(len(found) <= 1, "EyeSee synthetic prescription duplicated")
            if found:
                record["prescription_id"] = found[0]
            else:
                require(callable(self.eyesee_empty_store_proof), "EyeSee first AddPrescription requires a fresh read-only empty MinIO game-bucket proof")
                proof = self.eyesee_empty_store_proof()
                require(isinstance(proof, dict)
                        and type(proof.get("prescription_objects")) is int and proof["prescription_objects"] == 0
                        and type(proof.get("relation_objects")) is int and proof["relation_objects"] == 0
                        and re.fullmatch(r"[0-9a-f]{64}", str(proof.get("storage_id", "")))
                        and type(proof.get("observed_at_unix")) in (int, float)
                        and 0 <= time.time() - proof["observed_at_unix"] <= 15,
                        "EyeSee MinIO proof must freshly confirm both game buckets empty on the inspected storage container")
                record["empty_store_proof"] = {key: proof[key] for key in ("prescription_objects", "relation_objects", "storage_id", "observed_at_unix")}
                save()
                self._attempt(record, "prescription_create", save)
                created = self._rpc("AddPrescription", pb.AddPrescriptionRequest(**{key: record[key] for key in fields},
                    od_spf=1.5, od_cyl=0.5, od_ax=90, os_spf=1.5, os_cyl=0.5, os_ax=90), pb.AddPrescriptionResponse)
                uuid.UUID(created.id)
                record["prescription_id"] = created.id
            save()
        result = self._rpc("CheckPrescription", pb.CheckPrescriptionRequest(id=record["prescription_id"]), pb.CheckPrescriptionResponse)
        require(all((list(getattr(result, key)) if key in ("modifications", "features") else getattr(result, key)) == record[key] for key in fields),
                "EyeSee own prescription data was not preserved")
        require(all(getattr(result, key) == value for key, value in {"od_spf": 1.5, "od_cyl": .5, "od_ax": 90, "os_spf": 1.5, "os_cyl": .5, "os_ax": 90}.items()), "EyeSee prescription numeric fields changed")
        ids = self._rpc("GetPrescriptionIDs", pb.GetPrescriptionIDsRequest(patient_id=record["patient_id"]), pb.GetPrescriptionIDsResponse)
        require(record["prescription_id"] in ids.ids, "EyeSee patient/prescription MinIO relation was not preserved")
        encoded = result.SerializeToString(deterministic=True)
        if "prescription_sha256" not in record:
            require(write, "EyeSee immutable prescription bytes were never pinned")
            record["prescription_sha256"] = digest(encoded)
            save()
        require(record["prescription_sha256"] == digest(encoded), "EyeSee prescription representation changed")
        return {"grpc_health": "OK", "minio_prescription_and_relation_preserved": True,
                "prescription_id": record["prescription_id"], "prescription_sha256": digest(encoded)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/srv/ctf-manager"))
    parser.add_argument("--checkpoints", type=Path, required=True)
    parser.add_argument("--services", default=",".join(DEFAULT_PORTS))
    parser.add_argument("--action", choices=("prepare", "after", "verify"), default="verify")
    parser.add_argument("--namespace")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--vendor-root", type=Path)
    parser.add_argument("--eyesee-empty-proof", type=Path, help="private fresh read-only game-bucket proof JSON; required only before first EyeSee Add")
    args = parser.parse_args()
    keys = args.services.split(",")
    require(keys and len(keys) == len(set(keys)) and all(key in DEFAULT_PORTS for key in keys), "invalid/duplicate service keys")
    proof = (lambda: private_read(args.eyesee_empty_proof)) if args.eyesee_empty_proof else None
    adapter = ProbeAdapter(args.root, args.checkpoints, host=args.host, vendor_root=args.vendor_root,
                           namespace=args.namespace, eyesee_empty_store_proof=proof)
    result = {}
    for key in keys:
        try:
            method = {"prepare": adapter.prepare, "after": adapter.write_after_deploy, "verify": adapter.verify}[args.action]
            result[key] = method(key)
        except ProbeError as error:
            result[key] = {"service": key, "status": "failed", "error": str(error)}
    print(json.dumps(result, indent=2))
    return 1 if any(value["status"] == "failed" for value in result.values()) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        raise SystemExit(1)
