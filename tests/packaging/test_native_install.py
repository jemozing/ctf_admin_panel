import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ctfm_native_install", ROOT / "packaging/native/install.py")
INSTALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALL
SPEC.loader.exec_module(INSTALL)


def elf(arch="amd64", suffix=b""):
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    data[18:20] = (62 if arch == "amd64" else 183).to_bytes(2, "little")
    return bytes(data) + suffix


class NativeInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ctfm-native-install-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def package(self, name="release", arch="amd64", version="v0.1.0", suffix=b""):
        source = self.root / name
        source.mkdir()
        values = {"install.py": b"# reviewed installer fixture\n", "config/executor.example.json": b"{}\n"}
        for unit in INSTALL.UNITS:
            values["systemd/" + unit] = (ROOT / "packaging/native/systemd" / unit).read_bytes()
        records = {}
        for binary in INSTALL.BINARIES:
            data = elf(arch, suffix)
            path = "bin/" + binary
            values[path] = data
            records[binary] = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        values["release.json"] = (json.dumps({"schema_version": 1, "name": "ctf-manager", "version": version,
                                              "goos": "linux", "goarch": arch, "binaries": records}) + "\n").encode()
        for relative, data in values.items():
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.checksums(source)
        return source

    def checksums(self, source):
        lines = []
        for path in sorted(source.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(source)))
        (source / "SHA256SUMS").write_text("\n".join(lines) + "\n")

    def config(self):
        return INSTALL.native_config([Path("/srv/game-services")], [Path("/srv/ctf-workspaces")],
                                     "/usr/bin/docker", "/var/run/docker.sock", "/var/lib/docker", 999)

    def mapped(self, value):
        return self.root / "host" / value.lstrip("/")

    def prepare_targets(self, files):
        for name in [*files, str(INSTALL.CONFIG), str(INSTALL.MANIFEST)]:
            self.mapped(name).parent.mkdir(parents=True, exist_ok=True)

    def test_release_validation_accepts_both_architectures_without_executing_binaries(self):
        for arch in ("amd64", "arm64"):
            package = self.package(name=arch, arch=arch)
            with patch.object(INSTALL.subprocess, "run", side_effect=AssertionError("must not execute payload")):
                bundle = INSTALL.load_bundle(package)
            self.assertEqual(bundle.arch, arch)
            self.assertEqual(bundle.version, "v0.1.0")
            self.assertEqual(bundle.files["bin/ctf-manager"], elf(arch))

    def test_release_checksum_and_binary_architecture_are_enforced(self):
        source = self.package()
        (source / "bin/ctf-manager").write_bytes(elf(suffix=b"changed"))
        with self.assertRaisesRegex(ValueError, "checksum"):
            INSTALL.load_bundle(source)
        (source / "bin/ctf-manager").write_bytes(elf("arm64"))
        manifest = json.loads((source / "release.json").read_text())
        manifest["binaries"]["ctf-manager"]["sha256"] = hashlib.sha256(elf("arm64")).hexdigest()
        (source / "release.json").write_text(json.dumps(manifest))
        self.checksums(source)
        with self.assertRaisesRegex(ValueError, "architecture"):
            INSTALL.load_bundle(source)

    def test_release_rejects_symlinks_hardlinks_traversal_and_missing_coverage(self):
        source = self.package()
        target = source / "bin/ctfm-proxy"
        target.unlink()
        target.symlink_to(source / "bin/ctf-manager")
        with self.assertRaisesRegex(ValueError, "symbolic"):
            INSTALL.load_bundle(source)
        target.unlink()
        os.link(source / "bin/ctf-manager", target)
        with self.assertRaisesRegex(ValueError, "without links"):
            INSTALL.load_bundle(source)
        target.unlink()
        target.write_bytes(elf())
        (source / "SHA256SUMS").write_text("a" * 64 + "  ../outside\n")
        with self.assertRaises(ValueError):
            INSTALL.load_bundle(source)
        self.checksums(source)
        with (source / "SHA256SUMS").open("a") as stream:
            stream.write("a" * 64 + "  ../outside\n")
        with self.assertRaisesRegex(ValueError, "relative"):
            INSTALL.load_bundle(source)

    def test_dry_run_is_cross_platform_and_performs_no_host_commands_or_writes(self):
        source = self.package(arch="amd64")
        before = {str(path.relative_to(source)): path.read_bytes() for path in source.rglob("*") if path.is_file()}
        output = io.StringIO()
        with patch.object(INSTALL.sys, "platform", "darwin"), patch.object(INSTALL.os, "geteuid", return_value=501), \
                patch.object(INSTALL.subprocess, "run", side_effect=AssertionError("host command")), \
                patch.object(INSTALL, "ensure_identity", side_effect=AssertionError("account mutation")), contextlib.redirect_stdout(output):
            self.assertEqual(INSTALL.main(["--source-dir", str(source), "--dry-run"]), 0)
        plan = json.loads(output.getvalue())
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["starts_services"])
        self.assertFalse(plan["prerequisites_checked"])
        self.assertEqual(before, {str(path.relative_to(source)): path.read_bytes() for path in source.rglob("*") if path.is_file()})

    def test_roots_refuse_system_paths_aliases_overlap_and_systemd_specifiers(self):
        for path in ("/", "/etc/game", "/home", "/srv", "/var/lib", "/var/lib/docker/game", "/var/lib/ctf-manager", "/srv/../private",
                     "/srv/game/", "/srv/game space", "/srv/%n", "/srv/$ROOT", "/srv/game:other", "/srv/game\\other"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                INSTALL.validated_roots([path], [])
        with self.assertRaises(ValueError):
            INSTALL.validated_roots(["/srv/games"], ["/srv/games/work"])
        self.assertEqual(INSTALL.validated_roots([], []), ([Path("/srv/game-services")], [Path("/srv/ctf-workspaces")]))

    def test_untrusted_parent_diagnostic_identifies_path_uid_and_mode_without_repair(self):
        inspected = []
        def info(path):
            inspected.append(str(path))
            if path == Path("/srv/shared"):
                return SimpleNamespace(st_uid=1001, st_mode=stat.S_IFDIR | 0o777)
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with patch.object(INSTALL, "no_symlinks"), patch.object(Path, "lstat", info), \
                patch.object(INSTALL.os, "chmod", side_effect=AssertionError("must not repair host permissions")), \
                patch.object(INSTALL.os, "chown", side_effect=AssertionError("must not repair host ownership")), \
                self.assertRaisesRegex(ValueError, r"untrusted installation parent /srv/shared \(uid=1001, mode=0777\)"):
            INSTALL.stable_parents(Path("/srv/shared/services"))
        self.assertEqual(inspected, ["/", "/srv", "/srv/shared"])

    def test_units_keep_ipc_across_executor_stop_and_isolate_dashboard(self):
        executor = (ROOT / "packaging/native/systemd/ctfm-executor.service").read_text()
        dashboard = (ROOT / "packaging/native/systemd/ctfm-dashboard.service").read_text()
        self.assertIn("RuntimeDirectoryPreserve=yes", executor)
        self.assertIn("PrivateTmp=no", executor)
        self.assertIn("ReadWritePaths=/var/lib/ctf-manager/executor /run/ctf-manager /run/ctf-manager-host /tmp", executor)
        self.assertEqual(executor.count("BindReadOnlyPaths=/proc/"), 5)
        self.assertIn("/proc/1/net/dev:/run/ctf-manager-host/net-dev", executor)
        self.assertIn("ReadOnlyPaths=-/run/ctf-manager", dashboard)
        self.assertNotIn("Requires=", dashboard)
        self.assertNotIn("BindsTo=", dashboard)
        files = INSTALL.target_files(INSTALL.load_bundle(self.package()), self.config())
        self.assertIn("InaccessiblePaths=/srv/game-services /srv/ctf-workspaces /var/lib/docker", files[str(INSTALL.WEB_DROPIN)][0].decode())

    def test_resource_limits_match_the_existing_compose_budget(self):
        compose = (ROOT / "compose.yaml").read_text()
        for service in ("executor", "dashboard"):
            block = re.search(r"^  " + service + r":\n(.*?)(?=^  [^\s]+:\n|\Z)", compose, re.M | re.S)[1]
            memory = next(line.split(":", 1)[1].strip() for line in block.splitlines() if line.strip().startswith("mem_limit:"))
            tasks = next(line.split(":", 1)[1].strip() for line in block.splitlines() if line.strip().startswith("pids_limit:"))
            unit = (ROOT / "packaging/native/systemd" / ("ctfm-" + service + ".service")).read_text()
            self.assertIn("MemoryMax=" + memory.upper() + "\n", unit)
            self.assertIn("TasksMax=" + tasks + "\n", unit)

    def test_fresh_install_and_upgrade_preserve_exact_configuration_and_game_data(self):
        bundle = INSTALL.load_bundle(self.package())
        config = self.config()
        files = INSTALL.target_files(bundle, config)
        self.prepare_targets(files)
        reloads = []
        INSTALL.preflight_files(files, False, self.mapped, require_root=False)
        INSTALL.install_files(bundle, config, files, None, lambda: reloads.append(True), self.mapped, os.geteuid())
        saved = b'{"custom_policy":"fixture-only", "whitespace":"preserved"}\n'
        self.mapped(str(INSTALL.CONFIG)).write_bytes(saved)
        game = self.mapped("/srv/game-services/live-state.txt")
        game.parent.mkdir(parents=True)
        game.write_text("new game state must survive\n")
        account = self.mapped("/var/lib/ctf-manager/dashboard/account.txt")
        account.parent.mkdir(parents=True)
        account.write_text("fixture administrator\n")
        replacement = INSTALL.load_bundle(self.package(name="updated", version="v0.1.1", suffix=b"updated"))
        new_files = INSTALL.target_files(replacement, config)
        old = INSTALL.preflight_files(new_files, True, self.mapped, require_root=False, expected_owner=os.geteuid())
        INSTALL.install_files(replacement, config, new_files, old, lambda: reloads.append(True), self.mapped, os.geteuid())
        self.assertEqual(self.mapped(str(INSTALL.CONFIG)).read_bytes(), saved)
        self.assertEqual(game.read_text(), "new game state must survive\n")
        self.assertEqual(account.read_text(), "fixture administrator\n")
        self.assertEqual(self.mapped("/usr/local/bin/ctf-manager").read_bytes(), elf(suffix=b"updated"))
        self.assertEqual(json.loads(self.mapped(str(INSTALL.MANIFEST)).read_text())["version"], "v0.1.1")
        self.assertEqual(len(reloads), 2)

    def test_fresh_failure_rolls_back_config_payload_and_manifest(self):
        bundle = INSTALL.load_bundle(self.package())
        files = INSTALL.target_files(bundle, self.config())
        self.prepare_targets(files)
        with self.assertRaisesRegex(RuntimeError, "reload failed"):
            INSTALL.install_files(bundle, self.config(), files, None, lambda: (_ for _ in ()).throw(RuntimeError("reload failed")), self.mapped, os.geteuid())
        self.assertFalse(self.mapped(str(INSTALL.CONFIG)).exists())
        self.assertFalse(self.mapped(str(INSTALL.MANIFEST)).exists())
        self.assertTrue(all(not self.mapped(path).exists() for path in files))

    def test_upgrade_refuses_changed_files_and_rolls_back_failed_publication(self):
        bundle = INSTALL.load_bundle(self.package())
        config = self.config()
        files = INSTALL.target_files(bundle, config)
        self.prepare_targets(files)
        INSTALL.install_files(bundle, config, files, None, lambda: None, self.mapped, os.geteuid())
        binary = self.mapped("/usr/local/bin/ctf-manager")
        binary.write_bytes(elf(suffix=b"external-change"))
        with self.assertRaisesRegex(ValueError, "changed outside"):
            INSTALL.preflight_files(files, True, self.mapped, require_root=False, expected_owner=os.geteuid())
        binary.write_bytes(bundle.files["bin/ctf-manager"])
        old = INSTALL.preflight_files(files, True, self.mapped, require_root=False, expected_owner=os.geteuid())
        before = {name: self.mapped(name).read_bytes() for name in [*files, str(INSTALL.CONFIG), str(INSTALL.MANIFEST)]}
        new = INSTALL.load_bundle(self.package(name="updated", version="v0.1.1", suffix=b"replacement"))
        with self.assertRaises(RuntimeError):
            INSTALL.install_files(new, config, INSTALL.target_files(new, config), old, lambda: (_ for _ in ()).throw(RuntimeError()), self.mapped, os.geteuid())
        self.assertEqual(before, {name: self.mapped(name).read_bytes() for name in before})

    def test_failure_after_atomic_replace_is_still_included_in_rollback(self):
        bundle = INSTALL.load_bundle(self.package())
        files = INSTALL.target_files(bundle, self.config())
        self.prepare_targets(files)
        original = INSTALL.atomic_write
        calls = []
        def write_then_fail(path, data, mode):
            original(path, data, mode)
            calls.append(path)
            if len(calls) == 1:
                raise OSError("fixture fsync failure after replacement")
        with patch.object(INSTALL, "atomic_write", side_effect=write_then_fail), self.assertRaisesRegex(OSError, "fsync"):
            INSTALL.install_files(bundle, self.config(), files, None, lambda: None, self.mapped, os.geteuid())
        self.assertTrue(calls)
        self.assertTrue(all(not self.mapped(path).exists() for path in files))
        self.assertFalse(self.mapped(str(INSTALL.CONFIG)).exists())
        self.assertFalse(self.mapped(str(INSTALL.MANIFEST)).exists())

    def test_preflight_refuses_foreign_binary_and_symbolic_link_target(self):
        bundle = INSTALL.load_bundle(self.package())
        files = INSTALL.target_files(bundle, self.config())
        self.prepare_targets(files)
        binary = self.mapped("/usr/local/bin/ctf-manager")
        binary.write_text("foreign installation\n")
        with self.assertRaisesRegex(ValueError, "existing binary"):
            INSTALL.preflight_files(files, False, self.mapped, require_root=False)
        binary.unlink()
        binary.symlink_to(self.root / "foreign")
        with self.assertRaises(ValueError):
            INSTALL.preflight_files(files, False, self.mapped, require_root=False)

    def test_upgrade_inherits_custom_docker_endpoint_before_prerequisite_checks(self):
        source = self.package()
        saved = {"docker_binary": "/usr/local/bin/docker", "docker_host": "unix:///run/custom/docker.sock"}
        calls = []
        def check(args, _):
            calls.append((args.docker_binary, args.docker_socket))
            raise ValueError("test prerequisite stop")
        with patch.object(INSTALL.sys, "platform", "linux"), patch.object(INSTALL.os, "geteuid", return_value=0), \
                patch.object(INSTALL, "private_json", return_value=(b"{}", saved)), patch.object(INSTALL, "prerequisites", side_effect=check), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(INSTALL.main(["--source-dir", str(source), "--upgrade"]), 1)
            self.assertEqual(calls, [("/usr/local/bin/docker", "/run/custom/docker.sock")])
            calls.clear()
            self.assertEqual(INSTALL.main(["--source-dir", str(source), "--upgrade", "--docker-socket", "/run/other.sock"]), 1)
            self.assertEqual(calls, [])

    def test_saved_configuration_cannot_silently_fall_back_to_default_roots(self):
        config = self.config()
        config["discovery_roots"] = []
        with self.assertRaisesRegex(ValueError, "non-empty"):
            INSTALL.validate_saved_config(config, 999)

    def test_unit_stop_check_rejects_transitional_states_and_live_pids(self):
        def result(active, pid="0", load="loaded", returncode=0):
            return SimpleNamespace(returncode=returncode, stdout=f"ActiveState={active}\nMainPID={pid}\nLoadState={load}\n")
        for value in (result("inactive"), result("failed"), result("inactive", load="not-found", returncode=1)):
            with patch.object(INSTALL, "command", return_value=value):
                INSTALL.require_stopped_units("/usr/bin/systemctl")
        for value in (result("activating"), result("deactivating"), result("active", pid="42"),
                      result("inactive", pid="42"), result("inactive", pid=""), result("unknown", load="not-found", returncode=1),
                      result("inactive", returncode=1)):
            with self.subTest(state=value.stdout), patch.object(INSTALL, "command", return_value=value), self.assertRaisesRegex(ValueError, "fully"):
                INSTALL.require_stopped_units("/usr/bin/systemctl")

    def test_port_probe_rejects_an_active_reusable_loopback_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with self.assertRaisesRegex(ValueError, "occupied"):
                INSTALL.ensure_port_available(port=port)

    def test_port_probe_allows_immediate_rebind_after_closed_tcp_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.settimeout(3)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(("127.0.0.1", port))
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    # The server sends FIN first, so its endpoint enters
                    # TIME_WAIT when the peer finishes the close handshake.
                    connection.shutdown(socket.SHUT_WR)
                    self.assertEqual(client.recv(1), b"")
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(connection.recv(1), b"")
        # A plain bind still reproduces the original installer failure. The
        # reusable probe must accept the very same port without a sleep/retry.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plain:
            with self.assertRaises(OSError):
                plain.bind(("127.0.0.1", port))
        INSTALL.ensure_port_available(port=port)

    def test_existing_service_identity_cannot_be_root_login_or_docker_group_member(self):
        good = SimpleNamespace(pw_uid=999, pw_gid=998, pw_shell="/usr/sbin/nologin")
        with patch.object(INSTALL.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=998)), \
                patch.object(INSTALL.pwd, "getpwnam", return_value=good), patch.object(INSTALL.os, "getgrouplist", return_value=[998]):
            self.assertEqual(INSTALL.existing_identity()[0], good)
            for bad in (SimpleNamespace(pw_uid=0, pw_gid=998, pw_shell="/usr/sbin/nologin"), SimpleNamespace(pw_uid=999, pw_gid=998, pw_shell="/bin/bash")):
                with patch.object(INSTALL.pwd, "getpwnam", return_value=bad), self.assertRaises(ValueError):
                    INSTALL.existing_identity()
            with patch.object(INSTALL.os, "getgrouplist", return_value=[998, 997]), self.assertRaisesRegex(ValueError, "supplementary"):
                INSTALL.existing_identity()


if __name__ == "__main__":
    unittest.main()
