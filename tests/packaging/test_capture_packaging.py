"""Passive capture packaging boundaries; never starts Docker or changes UIDs."""
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
SPEC = importlib.util.spec_from_file_location("capture_bootstrap", ROOT / "scripts/capture-bootstrap.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class CapturePackagingTests(unittest.TestCase):
    def test_capture_has_only_raw_capability_and_no_sensitive_mounts(self):
        model = json.loads((ROOT / "compose.capture.yaml").read_text())
        self.assertEqual(model["name"], "ctfm-packets")
        self.assertEqual(set(model["services"]), {"packet-capture", "packet-store"})
        capture, store = model["services"]["packet-capture"], model["services"]["packet-store"]
        self.assertEqual(capture["network_mode"], "host")
        self.assertEqual(capture["user"], "0:0")
        self.assertEqual(capture["cap_add"], ["NET_RAW"])
        self.assertNotIn("network_mode", store)
        self.assertNotIn("cap_add", store)
        self.assertEqual(store["user"], "10005:10005")
        self.assertTrue(model["networks"]["packets-private"]["internal"])
        self.assertEqual(store["ports"], [{"target": 9804, "published": "9804", "host_ip": "127.0.0.1", "protocol": "tcp"}])
        for service in model["services"].values():
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("privileged", service)
            self.assertNotIn("pid", service)
            self.assertNotIn("devices", service)
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertLessEqual(service["pids_limit"], 128)
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"]["create_host_path"])
                for forbidden in ("docker.sock", "/services", "ctf-manager", "executor.sock"):
                    self.assertNotIn(forbidden, mount["source"])
                    self.assertNotIn(forbidden, mount["target"])
                if "secrets/" in mount["source"]:
                    self.assertTrue(mount["read_only"])
        self.assertIn("--minimum-free-bytes=1073741824", store["command"])
        self.assertIn("--quota-bytes=268435456", store["command"])
        self.assertIn("--per-service-bytes=67108864", store["command"])

    def test_credentials_and_executor_mounts_are_scoped(self):
        model = json.loads((ROOT / "compose.capture.yaml").read_text())
        sources = {name: {Path(m["source"]).name for m in value["volumes"] if "secrets/" in m["source"]}
                   for name, value in model["services"].items()}
        self.assertEqual(sources["packet-capture"], {"capture-control", "capture-ingest"})
        self.assertEqual(sources["packet-store"], {"packets-ingest", "packets-read"})
        overlay = json.loads((ROOT / "compose.capture.executor.yaml").read_text())
        self.assertEqual(set(overlay["services"]), {"executor"})
        executor = overlay["services"]["executor"]
        self.assertNotIn("network_mode", executor)
        self.assertNotIn("cap_add", executor)
        self.assertEqual([m["read_only"] for m in executor["volumes"]], [False, True, True, True, True])
        self.assertTrue(all(m["source"] == m["target"] for m in executor["volumes"]))
        dockerfile = (ROOT / "Dockerfile.capture").read_text()
        self.assertIn("USER 10005:10005", dockerfile)
        self.assertNotIn("docker-cli", dockerfile)
        self.assertNotIn("/out/ctf-manager ", dockerfile)
        self.assertTrue(all("NET_ADMIN" not in service.get("cap_add", [])
                            for service in model["services"].values()))

    def test_bootstrap_prepares_disabled_policy_and_does_not_edit_panel(self):
        previous_umask = os.umask(0o077)
        os.umask(previous_umask)
        self.addCleanup(os.umask, previous_umask)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "capture"
            output = io.StringIO()
            arguments = ["capture-bootstrap", "--root", str(root), "--interface", "br-game", "--interface", "docker0"]
            with patch.object(BOOTSTRAP.sys, "platform", "linux"), patch.object(BOOTSTRAP.os, "geteuid", return_value=0), \
                    patch.object(BOOTSTRAP, "validate_root"), patch.object(BOOTSTRAP.os, "chown") as chown, \
                    patch.object(BOOTSTRAP.os, "fchown") as fchown, patch.object(sys, "argv", arguments), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(BOOTSTRAP.main(), 0)
            policy = json.loads((root / "policy/policy.json").read_text())
            self.assertEqual(policy, {"schema_version": 1, "revision": 1, "enabled": False,
                                      "snaplen": 0, "max_packets_per_second": 1000, "interfaces": []})
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            for name in ("policy", "capture-control", "packets-control", "packets-state", "secrets"):
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "policy/.control-lock").stat().st_mode), 0o700)
            tokens = {p.name: p.read_text() for p in (root / "secrets").iterdir()}
            self.assertEqual(set(tokens), {"capture-control", "executor-control", "capture-ingest", "packets-ingest", "packets-read", "executor-read"})
            self.assertEqual(tokens["capture-control"], tokens["executor-control"])
            self.assertEqual(tokens["capture-ingest"], tokens["packets-ingest"])
            self.assertEqual(tokens["packets-read"], tokens["executor-read"])
            self.assertEqual(len(set(tokens.values())), 3)
            for path in (root / "secrets").iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(path.read_text().strip(), output.getvalue())
            self.assertIn((root / "packets-state", 10005, 10005), [c.args for c in chown.call_args_list])
            self.assertTrue(any(c.args[1:] == (10005, 10005) for c in fchown.call_args_list))
            fragment = json.loads((root / "executor_capture_patch.json").read_text())["capture"]
            self.assertEqual(fragment["allowed_interfaces"], ["br-game", "docker0"])
            self.assertTrue(fragment["enabled"])
            self.assertTrue(fragment["control_url"].startswith("unix:///"))
            self.assertTrue(fragment["packets_url"].startswith("unix:///"))
            override = json.loads((root / "executor-capture.override.yaml").read_text())
            self.assertEqual([m["read_only"] for m in override["services"]["executor"]["volumes"]], [False, True, True, True, True])
            result = json.loads(output.getvalue())
            self.assertFalse(result["containers_started"])
            self.assertFalse(result["capture_enabled"])
            self.assertFalse(result["main_panel_config_modified"])

    def test_bootstrap_refuses_broad_interface_scope_or_existing_roots(self):
        for values in ([], ["br-*"], ["eth0", "eth0"], ["x" * 16], ["../eth0"], ["br-a"] * 9):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                BOOTSTRAP.validate_interfaces(values)
        self.assertEqual(BOOTSTRAP.validate_interfaces(["lo","eth0","veth123"]),["eth0","lo","veth123"])
        for root in (Path("/"), Path("/srv"), Path("/etc/new-capture")):
            with self.subTest(root=root), self.assertRaises(RuntimeError):
                BOOTSTRAP.validate_root(root)


if __name__ == "__main__":
    unittest.main()
