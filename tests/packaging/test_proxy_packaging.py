"""Opt-in proxy packaging and bootstrap boundaries; no Docker or UID changes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("proxy_bootstrap", ROOT / "scripts/proxy-bootstrap.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class ProxyPackagingTests(unittest.TestCase):
    def test_separate_project_has_no_privileged_panel_or_game_mounts(self):
        model = json.loads((ROOT / "compose.proxy.yaml").read_text())
        self.assertEqual(set(model["services"]), {"traffic-proxy", "traffic-store"})
        self.assertEqual(model["name"], "ctfm-traffic")
        self.assertEqual(model["services"]["traffic-proxy"]["network_mode"], "host")
        self.assertNotIn("network_mode", model["services"]["traffic-store"])
        for name, service in model["services"].items():
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("privileged", service)
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertLessEqual(service["pids_limit"], 128)
            self.assertEqual(service["mem_limit"], "256m")
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"]["create_host_path"])
                self.assertNotIn("docker.sock", mount["source"])
                self.assertNotIn("ctf-manager", mount["target"])
                self.assertNotIn("/services", mount["source"])
                if "secrets/" in mount["source"]:
                    self.assertTrue(mount["read_only"])
        ports = model["services"]["traffic-store"]["ports"]
        self.assertEqual(ports, [{"target": 9802, "published": "9802", "host_ip": "127.0.0.1", "protocol": "tcp"}])
        self.assertIn("--minimum-free-bytes=1073741824", model["services"]["traffic-store"]["command"])

    def test_scoped_credentials_are_not_shared_beyond_their_roles(self):
        model = json.loads((ROOT / "compose.proxy.yaml").read_text())
        sources = {name: {Path(item["source"]).name for item in value["volumes"] if "secrets/" in item["source"]}
                   for name, value in model["services"].items()}
        self.assertEqual(sources["traffic-proxy"], {"proxy-control", "proxy-ingest"})
        self.assertEqual(sources["traffic-store"], {"recorder-ingest", "recorder-read"})
        dockerfile = (ROOT / "Dockerfile.proxy").read_text()
        self.assertIn("USER 10002:10002", dockerfile)
        self.assertIn("USER 10003:10003", dockerfile)
        self.assertNotIn("docker-cli", dockerfile)
        self.assertNotIn("/out/ctf-manager ", dockerfile)

    def test_bootstrap_prepares_empty_policy_and_private_per_uid_copies_only(self):
        previous_umask = os.umask(0o077)
        os.umask(previous_umask)
        self.addCleanup(os.umask, previous_umask)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proxy"
            output = io.StringIO()
            with patch.object(BOOTSTRAP.sys, "platform", "linux"), patch.object(BOOTSTRAP.os, "geteuid", return_value=0), \
                    patch.object(BOOTSTRAP, "validate_root"), patch.object(BOOTSTRAP.os, "chown"), \
                    patch.object(BOOTSTRAP.os, "fchown"), patch.object(sys, "argv", ["proxy-bootstrap", "--root", str(root)]), contextlib.redirect_stdout(output):
                self.assertEqual(BOOTSTRAP.main(), 0)
            policy = json.loads((root / "policy/policy.json").read_text())
            self.assertEqual(policy, {"schema_version": 1, "revision": 0, "routes": []})
            self.assertEqual(stat.S_IMODE((root / "policy").stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE((root / "policy/.control-lock").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "tls").stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            token = {p.name: p.read_text() for p in (root / "secrets").iterdir()}
            self.assertEqual(set(token), {"proxy-control", "executor-control", "proxy-ingest", "recorder-ingest", "recorder-read", "executor-read"})
            self.assertEqual(token["proxy-control"], token["executor-control"])
            self.assertEqual(token["proxy-ingest"], token["recorder-ingest"])
            self.assertEqual(token["recorder-read"], token["executor-read"])
            self.assertEqual(len(set(token.values())), 3)
            for path in (root / "secrets").iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(path.read_text().strip(), output.getvalue())
            fragment = json.loads((root / "executor-proxy.json").read_text())["proxy"]
            self.assertTrue(fragment["control_url"].startswith("unix:///"))
            self.assertTrue(fragment["traffic_url"].startswith("unix:///"))
            self.assertEqual((fragment["backend_port_min"],fragment["backend_port_max"]),(29080,29111))
            override = json.loads((root / "executor-proxy.override.yaml").read_text())
            executor = override["services"]["executor"]
            self.assertNotIn("network_mode", executor)
            self.assertEqual(len(executor["volumes"]), 5)
            self.assertEqual([m["read_only"] for m in executor["volumes"]], [False, True, True, True, True])
            self.assertFalse(json.loads(output.getvalue())["containers_started"])

    def test_bootstrap_refuses_existing_or_system_root(self):
        for root in (Path("/"), Path("/srv"), Path("/etc/new-proxy")):
            with self.subTest(root=root), self.assertRaises(RuntimeError):
                BOOTSTRAP.validate_root(root)


if __name__ == "__main__":
    unittest.main()
