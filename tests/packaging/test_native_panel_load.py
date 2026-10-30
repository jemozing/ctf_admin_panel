"""Pure guards/protocol doubles; no Docker, apps, proc writes or real sockets."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import stat
import sys
import threading
import time
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
SPEC = importlib.util.spec_from_file_location("native_panel_load", Path(__file__).resolve().parents[1] / "integration/native_panel_load.py")
LOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOAD)


class LoadGuardsTests(unittest.TestCase):
    def test_exact_atomic_line_size_and_namespace_sequence_marker(self):
        for key in LOAD.KEYS:
            line = LOAD.synthetic_line("abcdefabcd", key, 123, 987654321)
            self.assertEqual(len(line), 1024)
            self.assertTrue(line.endswith(b"\n"))
            self.assertIn(("seq=" + LOAD.encode_integer(123, 12) + " t=" + LOAD.encode_integer(987654321, 20) + " ").encode(), line)
            self.assertEqual(line.count(b"\n"), 1)
            self.assertFalse(any(character.isdigit() for character in line.decode()))

    def test_public_numeric_flag_redaction_cannot_destroy_synthetic_signature(self):
        stop = threading.Event()
        for key in LOAD.KEYS:
            line = LOAD.synthetic_line("abcdefabcd", key, 111111, 1111111111111111)
            displayed = line.replace(b"1", b"[REDACTED]")
            self.assertEqual(displayed, line)
            stream = LOAD.Stream(None, key, "service-id", "app", "abcdefabcd", 1, stop, lambda _error: None)
            match = stream.pattern.match(displayed.decode())
            self.assertTrue(match)
            self.assertEqual(LOAD.decode_integer(match[1]), 111111)
            self.assertEqual(LOAD.decode_integer(match[2]), 1111111111111111)

    def test_sampler_discontinuity_fails_even_if_aggregate_hour_could_pass(self):
        self.assertEqual(LOAD.check_sampler_gap(1, 2.1), 1.1)
        for current in (6.01, 31.84, 0):
            with self.subTest(current=current), self.assertRaisesRegex(RuntimeError, "timing interval invalid"):
                LOAD.check_sampler_gap(1, current)

    def test_inventory_rejects_restart_mount_image_or_id_changes(self):
        original = {"id": {key: key for key in ("id", "name", "image_id", "pid", "started_at", "restart_count", "mounts", "project", "component")}}
        LOAD.preserved(original, original)
        for field in original["id"]:
            changed = {"id": {**original["id"], field: "changed"}}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                LOAD.preserved(original, changed)
        with self.assertRaises(RuntimeError):
            LOAD.preserved(original, {})

    def test_resource_guard_refuses_memory_disk_and_inode_pressure(self):
        capacity = types.SimpleNamespace(f_bavail=2048, f_frsize=1024**2, f_favail=5000)
        with patch.object(LOAD.Path, "read_text", return_value="MemAvailable: 1048576 kB\nMemTotal: 4194304 kB\nSwapFree: 0 kB\n"), patch.object(LOAD.os, "statvfs", return_value=capacity):
            LOAD.resource_guard(Path("/test"), 512 * 1024**2, 1024 * 1024**2)
            with self.assertRaises(RuntimeError):
                LOAD.resource_guard(Path("/test"), 2 * 1024**3, 1024**3)
            capacity.f_bavail = 100
            with self.assertRaises(RuntimeError):
                LOAD.resource_guard(Path("/test"), 512 * 1024**2, 1024**3)
            capacity.f_bavail, capacity.f_favail = 2048, 10
            with self.assertRaises(RuntimeError):
                LOAD.resource_guard(Path("/test"), 512 * 1024**2, 1024**3)

    def test_declared_retention_does_not_fake_a_real_hour_of_history(self):
        beginning = datetime(2026, 10, 29, tzinfo=timezone.utc)
        value = {"available": True, "stale": False, "retention_seconds": 3600,
                 "history": [{"at": (beginning + timedelta(seconds=offset)).isoformat()} for offset in (0, 5)]}
        self.assertEqual(LOAD.history_summary(value)["span_seconds"], 5)
        value["history"] = [{"at": (beginning + timedelta(seconds=offset)).isoformat()} for offset in range(0, 3601, 5)]
        self.assertEqual(LOAD.history_summary(value)["span_seconds"], 3600)
        value["stale"] = True
        with self.assertRaises(RuntimeError):
            LOAD.history_summary(value)

    def test_stdout_regular_file_refused_before_open_for_write(self):
        identity = "a" * 64
        container = {"pid": 555, "id": identity, "pid_mode": "", "tty": False, "log_driver": "json-file"}
        metadata = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=1, st_ino=7)
        with patch.object(LOAD, "process_identity", return_value="ticks"), patch.object(LOAD.os, "pidfd_open", return_value=77, create=True), patch.object(LOAD.os, "close"), patch.object(LOAD.Path, "read_text", return_value="0::/system.slice/docker-" + identity + ".scope\n"), patch.object(LOAD.Path, "is_file", return_value=True), patch.object(LOAD.Path, "stat", return_value=metadata), patch.object(LOAD.os, "open") as opened:
            with self.assertRaisesRegex(RuntimeError, "not a FIFO"):
                LOAD.PinnedProcess(container, stdout=True)
            opened.assert_not_called()

    def test_stdout_fifo_is_nonblocking_and_tied_to_pidfd_identity(self):
        identity = "a" * 64
        container = {"pid": 555, "id": identity, "pid_mode": "", "tty": False, "log_driver": "json-file"}
        metadata = types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_dev=1, st_ino=7)
        with patch.object(LOAD, "process_identity", return_value="ticks"), patch.object(LOAD.os, "pidfd_open", return_value=77, create=True), patch.object(LOAD.os, "close"), patch.object(LOAD.Path, "read_text", return_value="0::/system.slice/docker-" + identity + ".scope\n"), patch.object(LOAD.Path, "is_file", return_value=True), patch.object(LOAD.Path, "stat", return_value=metadata), patch.object(LOAD.os, "open", return_value=88) as opened, patch.object(LOAD.os, "fstat", return_value=metadata), patch.object(LOAD.os, "fpathconf", return_value=4096), patch.object(LOAD.select, "select", return_value=([], [], [])):
            pinned = LOAD.PinnedProcess(container, stdout=True)
            self.assertTrue(opened.call_args.args[1] & LOAD.os.O_NONBLOCK)
            self.assertEqual(pinned.pipe_identity, (1, 7))
            with patch.object(LOAD.select, "select", return_value=([77], [], [])), self.assertRaises(RuntimeError):
                pinned.assert_alive()
            pinned.close()

    def test_backpressure_is_counted_as_drop_not_delivered_line(self):
        stop, go = threading.Event(), threading.Event()
        go.set()
        pinned = types.SimpleNamespace(pidfd=77, stdout_fd=88, assert_alive=lambda: None)
        failures = []
        injector = LOAD.Injector(pinned, "bank", "abcdef", 100, [time.monotonic()], go, stop, failures.append)
        def blocked(_descriptor, _line):
            stop.set()
            raise BlockingIOError()
        with patch.object(LOAD.select, "select", return_value=([], [], [])), patch.object(LOAD.os, "write", side_effect=blocked):
            injector.run()
        self.assertEqual(injector.stats["written_lines"], 0)
        self.assertEqual(injector.stats["backpressure_dropped_lines"], 1)
        self.assertEqual(sum(injector.written), 0)
        self.assertEqual(failures, [])

    def test_dead_pinned_process_is_never_written(self):
        stop, go = threading.Event(), threading.Event()
        go.set()
        pinned = types.SimpleNamespace(pidfd=77, stdout_fd=88, assert_alive=lambda: None)
        failures = []
        injector = LOAD.Injector(pinned, "bank", "abcdef", 100, [time.monotonic()], go, stop, failures.append)
        with patch.object(LOAD.select, "select", return_value=([77], [], [])), patch.object(LOAD.os, "write") as write:
            injector.run()
        write.assert_not_called()
        self.assertEqual(len(failures), 1)

    def test_api_rejects_credentials_and_disables_environment_proxy(self):
        with self.assertRaises(RuntimeError):
            LOAD.API("http://user:password@127.0.0.1:8765")
        with patch.object(LOAD.urllib.request, "build_opener") as builder:
            LOAD.API("http://127.0.0.1:8765")
            handler = builder.call_args.args[0]
            self.assertIsInstance(handler, LOAD.urllib.request.ProxyHandler)
            self.assertEqual(handler.proxies, {})


if __name__ == "__main__":
    unittest.main()
