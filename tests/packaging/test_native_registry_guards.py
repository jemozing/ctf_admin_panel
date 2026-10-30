"""Registry-only guards: no Docker, network, root or firewall execution."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parents[1] / "integration"
sys.path.insert(0, str(DIRECTORY))
SPEC = importlib.util.spec_from_file_location("native_registry_offline", DIRECTORY / "native_registry_offline.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NONCE = "0123456789ab"


def protected_container():
    return {"Id": "protected-id", "Name": "/bank", "Image": "sha256:protected",
            "Config": {"Env": ["PASSWORD=not-for-report"], "Labels": {"com.docker.compose.project": "bank"}},
            "HostConfig": {"NetworkMode": "bank_default"},
            "State": {"Pid": 123, "StartedAt": "original", "Running": True, "Status": "running", "OOMKilled": False},
            "RestartCount": 0, "Mounts": [{"Type": "volume", "Name": "bank-data", "Destination": "/data"}],
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18013"}]},
                                "Networks": {"bank_default": {"NetworkID": "network", "EndpointID": "endpoint",
                                                               "IPAddress": "172.21.0.5", "GlobalIPv6Address": "fd00::5"}}}}


class RulesTests(unittest.TestCase):
    def test_inventory_contains_metadata_hashes_without_environment_values(self):
        value = MODULE.container_view(protected_container())
        self.assertNotIn("not-for-report", json.dumps(value))
        self.assertNotIn("PASSWORD", json.dumps(value))
        self.assertEqual(value["pid"], 123)
        self.assertEqual(value["ports"]["80/tcp"][0]["HostPort"], "18013")

    def test_exact_destinations_and_per_family_rules(self):
        destinations = MODULE.protected_destinations({"id": MODULE.container_view(protected_container())})
        self.assertEqual(destinations, {4: ["172.21.0.5"], 6: ["fd00::5"]})
        with patch.object(MODULE.shutil, "which", side_effect=lambda name: name):
            block = MODULE.ProtectedRegistryBlock(NONCE, 22, destinations)
        ipv4, ipv6 = block.rules_by_backend["iptables"], block.rules_by_backend["ip6tables"]
        self.assertIn("172.21.0.5/32", ipv4[1])
        self.assertIn("fd00::5/128", ipv6[1])
        self.assertNotIn("172.21.0.5", str(ipv6))
        self.assertNotIn("fd00::5", str(ipv4))
        self.assertEqual(ipv4[0][2:4], ["--sport", "22"])
        self.assertIn("REJECT", ipv4[-1])
        self.assertNotIn("ESTABLISHED", str(ipv4))

    def test_wide_cidr_and_wrong_family_are_refused(self):
        common = MODULE.destination_rules([["ssh"], ["reject"]], [], 4, "comment")
        for address in ("172.16.0.0/12", "fd00::1", "0.0.0.0/0"):
            with self.subTest(address=address), self.assertRaises((ValueError, RuntimeError)):
                MODULE.destination_rules(common, [address], 4, "comment")

    def test_duplicate_endpoint_across_protected_containers_is_ambiguous(self):
        value = MODULE.container_view(protected_container())
        with self.assertRaises(RuntimeError):
            MODULE.protected_destinations({"one": value, "two": value})

    def test_loopback_unspecified_multicast_and_wrong_family_refused(self):
        for address in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "::1"):
            value = MODULE.container_view(protected_container())
            value["networks"]["bank_default"]["IPAddress"] = address
            with self.subTest(address=address), self.assertRaises(RuntimeError):
                MODULE.protected_destinations({"id": value})

    def test_dnat_http_control_must_match_exact_protected_publication(self):
        protected = {"containers": {"id": MODULE.container_view(protected_container())}}
        self.assertEqual(MODULE.validate_http_control("http://127.0.0.1:18013/", protected), "id")
        for url in ("http://example.com:18013/", "http://127.0.0.1:18012/", "http://user:secret@127.0.0.1:18013/",
                    "http://127.0.0.1:18013/?token=secret", "https://127.0.0.1:18013/"):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                MODULE.validate_http_control(url, protected)

    def test_bank_nonstandard_internal_1337_port_is_allowed_by_exact_publication(self):
        container = MODULE.container_view(protected_container())
        container["ports"]["1337/tcp"] = container["ports"].pop("80/tcp")
        self.assertEqual(MODULE.validate_http_control("http://127.0.0.1:18013/", {"containers": {"bank": container}}), "bank")

    def test_ip_change_pid_restart_mount_or_original_tag_change_fails_guard(self):
        class Host:
            def __init__(self):
                self.items = {"protected-id": protected_container()}
                self.image = {"Id": "sha256:protected", "Os": "linux", "Architecture": "amd64",
                              "RootFS": {"Layers": ["one"]}, "RepoTags": ["bank:original"]}
                self.info = {"ID": "daemon"}
            def identity(self):
                return {"pid": 99}
            def containers(self):
                return self.items
            def json(self, *parts):
                return self.info if parts[0] == "info" else [self.image]
        host = Host()
        protected = {"schema_version": 1, "test": "protected-native-registry-inventory", "expected_container_count": 1,
                     "daemon": host.identity(), "host": host.info,
                     "containers": {"protected-id": MODULE.container_view(host.items["protected-id"])},
                     "images": {"sha256:protected": MODULE.image_view(host.image)}, "volumes": {}, "networks": {}}
        with patch.object(MODULE, "inspect_objects", return_value=[]):
            MODULE.assert_protected(host, protected)
            for mutate in (
                    lambda: host.items["protected-id"]["State"].update(Pid=124),
                    lambda: host.items["protected-id"]["State"].update(StartedAt="changed"),
                    lambda: host.items["protected-id"]["Mounts"][0].update(Name="other-volume"),
                    lambda: host.items["protected-id"]["NetworkSettings"]["Networks"]["bank_default"].update(IPAddress="172.21.0.6"),
                    lambda: host.image.update(RepoTags=[])):
                host.items = {"protected-id": protected_container()}
                host.image["RepoTags"] = ["bank:original"]
                mutate()
                with self.assertRaises(RuntimeError):
                    MODULE.assert_protected(host, protected)

    def test_no_preexisting_container_can_be_adopted_by_name_or_prefix(self):
        class Host:
            def identity(self): return {"pid": 99}
            def json(self, *_): return {"ID": "daemon"}
            def containers(self):
                return {"foreign": {"Name": "/ctfm-registry-offline-" + NONCE + "-app-1",
                                    "Config": {"Labels": {MODULE.OWNER_LABEL: "other"}}}}
        value = {"schema_version": 1, "test": "protected-native-registry-inventory", "expected_container_count": 0,
                 "containers": {}, "daemon": {"pid": 99}, "host": {"ID": "daemon"}, "images": {}, "volumes": {}, "networks": {}}
        with self.assertRaises(RuntimeError):
            MODULE.assert_protected(Host(), value, NONCE, "ctfm-registry-offline-" + NONCE)


class CleanupTests(unittest.TestCase):
    def test_watchdog_removes_only_family_specific_exact_rules_and_keeps_foreign_content(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(MODULE.shutil, "which", side_effect=lambda name: name):
            block = MODULE.ProtectedRegistryBlock(NONCE, 22, {4: ["172.21.0.5"], 6: ["fd00::5"]})
            jump = ["-m", "comment", "--comment", block.comment, "-j", block.chain]
            foreign = ["-s", "192.0.2.1", "-j", "RETURN"]
            tables = {binary: {"OUTPUT": [copy.deepcopy(jump), ["-j", "UNCHANGED"]],
                               block.chain: copy.deepcopy(rules) + [foreign]}
                      for binary, rules in block.rules_by_backend.items()}
            commands = []
            def fake_run(arguments, **_):
                commands.append(arguments)
                binary, wait, seconds, action, chain, *rule = arguments
                self.assertEqual((wait, seconds), ("-w", "5"))
                self.assertNotIn(action, ("-F", "-P"))
                table = tables[binary]
                if action == "-C":
                    code = 0 if rule in table.get(chain, []) else 1
                elif action == "-S":
                    code = 0 if chain in table else 1
                elif action == "-D":
                    table[chain].remove(rule)
                    code = 0
                elif action == "-X":
                    self.assertEqual(chain, block.chain)
                    code = 1 if table[chain] else 0
                    if not code: del table[chain]
                else:
                    self.fail("unexpected cleanup operation")
                return subprocess.CompletedProcess(arguments, code, "", "")
            marker = Path(temporary) / "fired"
            program = MODULE.family_cleanup_program(block.rules_by_backend, block.chain, block.comment, marker)
            with patch.object(subprocess, "run", side_effect=fake_run), patch.object(sys, "argv", ["cleanup", "--watchdog"]), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                exec(compile(program, "cleanup", "exec"), {"__name__": "__main__"})
            self.assertEqual(stopped.exception.code, 1)  # Foreign rule retained.
            self.assertTrue(marker.exists())
            for table in tables.values():
                self.assertEqual(table, {"OUTPUT": [["-j", "UNCHANGED"]], block.chain: [foreign]})
            self.assertFalse(any("fd00::5/128" in command for command in commands if command[0] == "iptables"))
            self.assertFalse(any("172.21.0.5/32" in command for command in commands if command[0] == "ip6tables"))


if __name__ == "__main__":
    unittest.main()
