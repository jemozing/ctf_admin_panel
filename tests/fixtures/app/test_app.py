import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app import Config, make_server


class FixtureAppTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.version = self.root / "VERSION"
        self.version.write_text("v1\n")
        self.servers = []
        self.url = self.start(Config(database=self.root / "data/state.db", version_file=self.version))

    def tearDown(self):
        for server, thread in self.servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.temporary.cleanup()

    def start(self, config):
        server = make_server(config, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}"

    def request(self, method, path, payload=None, url=None, raw=None, content_type="application/json"):
        body = raw if raw is not None else None if payload is None else json.dumps(payload).encode()
        request = Request((url or self.url) + path, data=body, method=method,
                          headers={"Content-Type": content_type})
        try:
            response = urlopen(request, timeout=2)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def test_health_and_live_version_file(self):
        self.assertEqual(self.request("GET", "/health")[1]["status"], "ok")
        self.assertEqual(self.request("GET", "/version")[1]["version"], "v1")
        self.version.write_text("v2\n")
        self.assertEqual(self.request("GET", "/version")[1]["version"], "v2")

    def test_persistence_and_namespaces(self):
        for namespace, value in (("flags", "CTFM_TEST_FLAG_тест"), ("state", "2")):
            status, _ = self.request("PUT", f"/{namespace}/round_1", {"value": value})
            self.assertEqual(status, 200)
        second = self.start(Config(database=self.root / "data/state.db", version_file=self.version))
        self.assertEqual(self.request("GET", "/flags/round_1", url=second)[1]["value"],
                         "CTFM_TEST_FLAG_тест")
        self.assertEqual(self.request("GET", "/state/round_1", url=second)[1]["value"], "2")
        self.assertEqual(self.request("DELETE", "/flags/round_1")[0], 200)
        self.assertEqual(self.request("GET", "/flags/round_1")[0], 404)
        self.assertEqual(self.request("GET", "/state/round_1")[0], 200)

    def test_remote_database_and_failure_health(self):
        remote = self.start(Config(storage="remote", backend_url=self.url, version_file=self.version))
        self.assertEqual(self.request("PUT", "/flags/remote", {"value": "CTFM_TEST"}, url=remote)[0], 200)
        self.assertEqual(self.request("GET", "/flags/remote")[1]["value"], "CTFM_TEST")
        self.assertEqual(self.request("GET", "/health", url=remote)[0], 200)
        backend, thread = self.servers.pop(0)
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=2)
        self.assertEqual(self.request("GET", "/health", url=remote)[0], 503)

    def test_invalid_requests_are_bounded(self):
        cases = [
            ({"other": "x"}, None, "application/json", 400),
            ({"value": 1}, None, "application/json", 400),
            ({"value": "x" * 2049}, None, "application/json", 400),
            (None, b"{bad", "application/json", 400),
            (None, b"x" * 4097, "application/json", 413),
            ({"value": "x"}, None, "text/plain", 415),
        ]
        for payload, raw, content_type, status in cases:
            with self.subTest(status=status, content_type=content_type):
                self.assertEqual(self.request("PUT", "/flags/test", payload, raw=raw,
                                              content_type=content_type)[0], status)
        self.assertEqual(self.request("GET", "/flags/../other")[0], 404)
        self.assertEqual(self.request("GET", "/flags/unknown")[0], 404)
        self.assertEqual(self.request("PUT", "/flags/empty", {"value": ""})[0], 200)


if __name__ == "__main__":
    unittest.main()
