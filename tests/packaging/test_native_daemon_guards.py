"""Safety guards and exact cleanup are testable without Docker/root/network."""
import contextlib
import copy
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "integration/native_daemon_smoke.py"
SPEC = importlib.util.spec_from_file_location("native_daemon_smoke", MODULE)
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
NONCE = "0123456789ab"
CHAIN = "CTFMND_" + NONCE
COMMENT = "ctfm-native-" + NONCE


class NativeGuardsTests(unittest.TestCase):
    def test_default_empty_host_is_accepted(self):
        NATIVE.require_empty_host({}, [{"Name": name} for name in ("bridge", "host", "none")], [])

    def test_every_preexisting_container_including_stopped_or_lookalike_is_refused(self):
        for name, state in (("/game", "running"), ("/game", "exited"), ("/ctfm-native-daemon-" + NONCE + "-app-1", "exited")):
            with self.subTest(name=name, state=state), self.assertRaises(RuntimeError):
                NATIVE.require_empty_host({"foreign": {"Name": name, "State": {"Status": state}}}, [], [])

    def test_preexisting_network_and_compose_volumes_are_refused(self):
        for networks, volumes in (([{"Name": "other_default"}], []), ([], ["old_game_db"])):
            with self.subTest(networks=networks), self.assertRaises(RuntimeError):
                NATIVE.require_empty_host({}, networks, volumes)

    def test_host_wide_action_requires_exact_ids_names_images_and_nonce(self):
        owned = {"id": {"Name": "/synthetic", "Image": "sha256:image", "Config": {"Labels": {NATIVE.OWNER_LABEL: NONCE}}}}
        NATIVE.require_owned_containers(owned, owned, NONCE)
        changes = [({}, "missing"), ({**owned, "foreign": owned["id"]}, "foreign")]
        for field, value in (("Name", "/other"), ("Image", "sha256:changed"), ("Config", {"Labels": {NATIVE.OWNER_LABEL: "other"}})):
            changed = copy.deepcopy(owned)
            changed["id"][field] = value
            changes.append((changed, field))
        for changed, label in changes:
            with self.subTest(change=label), self.assertRaises(RuntimeError):
                NATIVE.require_owned_containers(changed, owned, NONCE)

    def test_native_profile_refuses_proxy_mirror_rootless_swarm_live_restore(self):
        profile = {"OSType": "linux", "Architecture": "amd64", "KernelVersion": "kernel"}
        NATIVE.require_daemon_profile(profile, "kernel")
        for key, value in (("HTTPProxy", "http://proxy:3128"), ("HTTPSProxy", "http://proxy:3128"),
                           ("RegistryConfig", {"Mirrors": ["http://mirror"]}),
                           ("SecurityOptions", ["name=rootless"]), ("SecurityOptions", ["name=userns"]),
                           ("Swarm", {"LocalNodeState": "active"}), ("LiveRestoreEnabled", True),
                           ("KernelVersion", "other"), ("Architecture", "arm64"), ("OSType", "windows")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                NATIVE.require_daemon_profile({**profile, key: value}, "kernel")

    def test_daemon_socket_must_be_held_by_main_pid(self):
        NATIVE.require_socket_owner({"99"}, {"socket:[99]"})
        for inodes, descriptors in ((set(), {"socket:[99]"}), ({"99"}, {"socket:[100]"}), ({"99"}, {"/run/docker.sock"})):
            with self.subTest(inodes=inodes), self.assertRaises(RuntimeError):
                NATIVE.require_socket_owner(inodes, descriptors)

    def test_no_dedicated_consent_or_non_linux_refused_before_docker(self):
        with patch.object(NATIVE, "run") as command:
            with self.assertRaises(RuntimeError):
                NATIVE.NativeHost(False)
            with patch.object(NATIVE.platform, "system", return_value="Darwin"), self.assertRaises(RuntimeError):
                NATIVE.NativeHost(True)
            command.assert_not_called()

    def test_non_root_and_non_systemd_refused_before_docker(self):
        with patch.object(NATIVE, "run") as command, patch.object(NATIVE.platform, "system", return_value="Linux"), patch.object(NATIVE.platform, "machine", return_value="x86_64"):
            with patch.object(NATIVE.os, "geteuid", return_value=1000), self.assertRaises(RuntimeError):
                NATIVE.NativeHost(True)
            with patch.object(NATIVE.os, "geteuid", return_value=0), patch.object(NATIVE.Path, "is_dir", return_value=False), self.assertRaises(RuntimeError):
                NATIVE.NativeHost(True)
            command.assert_not_called()

    def test_firewall_identity_cannot_select_default_or_foreign_chain(self):
        NATIVE.validate_firewall_identity(CHAIN, COMMENT, 22)
        for chain, comment, port in (("OUTPUT", COMMENT, 22), (CHAIN, "other", 22),
                                     (CHAIN, COMMENT, 0), (CHAIN, COMMENT, True), (CHAIN, COMMENT, 65536)):
            with self.subTest(chain=chain, port=port), self.assertRaises(RuntimeError):
                NATIVE.validate_firewall_identity(chain, comment, port)

    def test_rule_preserves_guest_ssh_responses_without_established_bypass(self):
        rules = NATIVE.firewall_rules(CHAIN, COMMENT, 22)
        self.assertEqual(rules[0], ["-p", "tcp", "--sport", "22", "-m", "comment", "--comment", COMMENT, "-j", "RETURN"])
        self.assertIn("80,443", rules[1])
        self.assertIn("REJECT", rules[1])
        self.assertNotIn("ESTABLISHED", str(rules))

    def test_packet_proof_counts_rejects_only(self):
        text = "Chain test (1 references)\n pkts bytes target prot opt\n 3 160 RETURN tcp --\n 7 420 REJECT tcp --\n"
        self.assertEqual(NATIVE.rejected_packets(text), 7)

    def test_guest_ssh_port_is_derived_and_wrong_forwarded_port_refused(self):
        connection = "192.0.2.10 53000 192.0.2.20 22"
        self.assertEqual(NATIVE.ssh_server_port(None, connection), 22)
        self.assertEqual(NATIVE.ssh_server_port(22, connection), 22)
        self.assertEqual(NATIVE.ssh_server_port(None, None), 22)
        with self.assertRaises(RuntimeError):
            NATIVE.ssh_server_port(2222, connection)
        with self.assertRaises(RuntimeError):
            NATIVE.ssh_server_port(None, "malformed")

    def test_host_lock_refuses_symlink_hardlink_wrong_owner_and_writable_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid"
            with NATIVE.safe_host_lock(valid, owner_uid=os.geteuid()):
                self.assertEqual(valid.stat().st_mode & 0o777, 0o600)
            alias = root / "alias"
            alias.symlink_to(valid)
            with self.assertRaises(OSError):
                NATIVE.safe_host_lock(alias, owner_uid=os.geteuid())
            os.link(valid, root / "hardlink")
            with self.assertRaises(RuntimeError):
                NATIVE.safe_host_lock(valid, owner_uid=os.geteuid())
            other = root / "other"
            other.touch(mode=0o644)
            with self.assertRaises(RuntimeError):
                NATIVE.safe_host_lock(other, owner_uid=os.geteuid())
            other.chmod(0o600)
            with self.assertRaises(RuntimeError):
                NATIVE.safe_host_lock(other, owner_uid=os.geteuid() + 1)


class FakeFirewall:
    def __init__(self, foreign=False):
        self.jump = ["-m", "comment", "--comment", COMMENT, "-j", CHAIN]
        self.own_rules = NATIVE.firewall_rules(CHAIN, COMMENT, 22)
        self.foreign_rule = ["-s", "192.0.2.1", "-j", "RETURN"]
        self.state = {binary: {"OUTPUT": [self.jump, ["-j", "UNCHANGED"]], CHAIN: copy.deepcopy(self.own_rules)}
                      for binary in ("fake-ipv4", "fake-ipv6")}
        if foreign:
            for table in self.state.values():
                table[CHAIN].append(self.foreign_rule)
        self.commands = []

    def __call__(self, arguments, **_):
        self.commands.append(arguments)
        binary, wait, seconds, action, chain, *rule = arguments
        assert wait == "-w" and seconds == "5"
        assert action in ("-C", "-D", "-S", "-X"), "unexpected global mutation"
        table = self.state[binary]
        result = 0
        if action == "-C":
            result = 0 if rule in table.get(chain, []) else 1
        elif action == "-S":
            result = 0 if chain in table else 1
        elif action == "-D":
            table[chain].remove(rule)
        elif action == "-X":
            assert chain == CHAIN, "foreign chain deletion"
            if table.get(chain):
                result = 1
            else:
                table.pop(chain, None)
        return subprocess.CompletedProcess(arguments, result, "", "")


class CleanupTests(unittest.TestCase):
    def cleanup(self, fake, *, watchdog=False):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "fired"
            program = NATIVE.cleanup_program(list(fake.state), CHAIN, COMMENT, fake.own_rules, marker)
            with patch.object(subprocess, "run", side_effect=fake), patch.object(sys, "argv", ["cleanup", *( ["--watchdog"] if watchdog else [])]), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                exec(compile(program, "cleanup.py", "exec"), {"__name__": "__main__"})
            return stopped.exception.code, marker.exists()

    def test_cleanup_detaches_exact_own_rules_for_both_families(self):
        fake = FakeFirewall()
        exit_code, marker = self.cleanup(fake)
        self.assertEqual(exit_code, 0)
        self.assertFalse(marker)
        for table in fake.state.values():
            self.assertEqual(table, {"OUTPUT": [["-j", "UNCHANGED"]]})
        # Jump is detached before rules are removed, for each backend.
        for binary in fake.state:
            deletes = [cmd for cmd in fake.commands if cmd[0] == binary and cmd[3] == "-D"]
            self.assertEqual(deletes[0][4], "OUTPUT")

    def test_cleanup_never_flushes_foreign_chain_content(self):
        fake = FakeFirewall(foreign=True)
        exit_code, _ = self.cleanup(fake)
        self.assertEqual(exit_code, 1)
        for table in fake.state.values():
            self.assertEqual(table["OUTPUT"], [["-j", "UNCHANGED"]])
            self.assertEqual(table[CHAIN], [fake.foreign_rule])
        self.assertFalse(any("-F" in cmd for cmd in fake.commands))

    def test_watchdog_marks_expired_window_and_restores_network(self):
        fake = FakeFirewall()
        exit_code, marker = self.cleanup(fake, watchdog=True)
        self.assertEqual(exit_code, 0)
        self.assertTrue(marker)
        self.assertTrue(all(CHAIN not in table for table in fake.state.values()))

    def test_registry_block_requires_both_ip_families(self):
        with patch.object(NATIVE.shutil, "which", side_effect=["iptables", None]), self.assertRaises(RuntimeError):
            NATIVE.RegistryBlock(NONCE, 22)

    def test_watchdog_expiry_cannot_be_reported_as_offline_success(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(NATIVE.shutil, "which", side_effect=lambda name: name):
            block = NATIVE.RegistryBlock(NONCE, 22, run_command=lambda *_a, **_k: self.fail("expired block must fail before tools"))
            block.marker = Path(temporary) / "expired"
            block.marker.touch()
            block.active = True
            with self.assertRaises(RuntimeError):
                block.assert_active()

    def test_watchdog_is_independent_and_waiting_before_any_firewall_mutation(self):
        commands = []

        def fake_run(arguments, **_):
            commands.append(list(map(str, arguments)))
            return subprocess.CompletedProcess(arguments, 0, "waiting\n" if "show" in arguments else "active\n", "")

        with patch.object(NATIVE.shutil, "which", side_effect=lambda name: name):
            block = NATIVE.RegistryBlock(NONCE, 22, run_command=fake_run)
            block.arm_watchdog()
        self.assertTrue(block.armed)
        self.assertFalse(block.active)
        self.assertEqual(commands[0][0], "systemd-run")
        self.assertIn("--on-active=180s", commands[0])
        self.assertIn("--watchdog", commands[0])
        self.assertTrue(any("SubState" in " ".join(command) for command in commands))
        self.assertFalse(any(command[0] in ("iptables", "ip6tables") for command in commands))

    def test_uncertain_output_query_keeps_watchdog_armed(self):
        for code in (0, 4):
            commands = []

            def fake_run(arguments, **_):
                commands.append(list(map(str, arguments)))
                return subprocess.CompletedProcess(arguments, code if "-C" in arguments else 0, "", "")

            with self.subTest(code=code), patch.object(NATIVE.shutil, "which", side_effect=lambda name: name):
                block = NATIVE.RegistryBlock(NONCE, 22, run_command=fake_run)
                block.armed = True
                with self.assertRaises(RuntimeError):
                    block.restore()
                self.assertTrue(block.armed)
                self.assertFalse(any(command[:2] == ["systemctl", "stop"] for command in commands))


if __name__ == "__main__":
    unittest.main()
