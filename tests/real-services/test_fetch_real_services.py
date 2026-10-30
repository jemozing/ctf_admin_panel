"""Offline regression checks for fixture isolation and locked-source boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("real_fixture_tool", ROOT / "scripts/fetch-real-services.py")
fixture_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture_tool)


class IsolationPolicyTest(unittest.TestCase):
    def setUp(self):
        self.fixture = {"id": "sample", "project_name": "ctfm-real-sample"}
        self.config = {
            "name": "ctfm-real-sample",
            "services": {"app": {"ports": [{"host_ip": "127.0.0.1", "target": 8080, "published": "28080"}]}},
        }

    def audit(self, changed):
        return fixture_tool.audit_config(self.fixture, changed, Path("/tmp/ctfm-pinned-source"))

    def test_loopback_config_is_accepted_without_daemon(self):
        result = self.audit(self.config)
        self.assertEqual(result["status"], "config_passed")
        self.assertEqual(result["runtime"], "not_run")

    def test_upstream_wildcard_port_cannot_survive_merge(self):
        for host in ("0.0.0.0", "::", None):
            with self.subTest(host=host):
                config = copy.deepcopy(self.config)
                config["services"]["app"]["ports"].append({"host_ip": host, "target": 8080})
                with self.assertRaises(ValueError):
                    self.audit(config)

    def test_host_privileges_are_rejected(self):
        for key, value in (("privileged", True), ("network_mode", "host"), ("pid", "host"), ("ipc", "host"), ("cap_add", ["SYS_ADMIN"]), ("devices", ["/dev/kvm"]), ("container_name", "global-name")):
            with self.subTest(key=key):
                config = copy.deepcopy(self.config)
                config["services"]["app"][key] = value
                with self.assertRaises(ValueError):
                    self.audit(config)

    def test_socket_and_outside_bind_mounts_are_rejected(self):
        for source, target in (("/var/run/docker.sock", "/var/run/docker.sock"), ("/etc", "/data"), ("/tmp/ctfm-pinned-source/config", "/run/docker.sock")):
            with self.subTest(source=source):
                config = copy.deepcopy(self.config)
                config["services"]["app"]["volumes"] = [{"type": "bind", "source": source, "target": target}]
                with self.assertRaises(ValueError):
                    self.audit(config)

    def test_shared_external_resources_are_rejected(self):
        for resource in ("volumes", "networks"):
            config = copy.deepcopy(self.config)
            config[resource] = {"existing-game-data": {"external": True}}
            with self.assertRaises(ValueError):
                self.audit(config)

    def test_project_identity_must_match(self):
        config = copy.deepcopy(self.config)
        config["name"] = "production-vulnbox"
        with self.assertRaises(ValueError):
            self.audit(config)


class SourceBoundaryTest(unittest.TestCase):
    def test_traversal_and_symlinks_cannot_escape_source(self):
        with tempfile.TemporaryDirectory(prefix="ctfm-fixture-test-") as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                fixture_tool.checked_path(root, "../outside")
            (root / "escape").symlink_to(root.parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                fixture_tool.checked_path(root, "escape/outside")

    def test_exactly_five_licensed_pins_have_matching_maps_and_config_results(self):
        locked = fixture_tool.read_lock()
        maps = json.loads((ROOT / "tests/real-services/service-maps.json").read_text())["maps"]
        results = json.loads((ROOT / "tests/real-services/reports/config-results.json").read_text())["fixtures"]
        self.assertEqual(len(locked), 5)
        self.assertEqual({x["id"] for x in locked}, {x["id"] for x in maps})
        self.assertEqual({x["id"] for x in locked}, {x["id"] for x in results})
        for service in locked:
            self.assertEqual(service["license"]["spdx"], "MIT")
            self.assertIn("LICENSE", service["reviewed_files_sha256"])
            self.assertTrue(service["linux_source_template"].startswith("/srv/ctfm/real-services/tests/fixtures/vendor/"))
        for result in results:
            self.assertEqual(result["status"], "config_passed")
            self.assertEqual(result["runtime"], "not_run")


if __name__ == "__main__":
    unittest.main()
