"""Failure-preservation policy and secret-safe metadata without Docker access."""

import importlib.util
import json
from pathlib import Path
import subprocess
import stat
import sys
import unittest


MODULE = Path(__file__).resolve().parents[1] / "integration/mvp_workflows_smoke.py"
sys.path.insert(0, str(MODULE.parent))
try:
    SPEC = importlib.util.spec_from_file_location("mvp_workflows_debug", MODULE)
    WORKFLOW = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(WORKFLOW)
finally:
    sys.path.pop(0)


class WorkflowDebugTests(unittest.TestCase):
    def test_failure_preservation_requires_explicit_flag(self):
        self.assertFalse(WORKFLOW.should_preserve_fixture(False, "failed"))
        self.assertTrue(WORKFLOW.should_preserve_fixture(True, "failed"))

    def test_success_always_cleans_up_even_with_debug_flag(self):
        for requested in (False, True):
            with self.subTest(requested=requested):
                self.assertFalse(WORKFLOW.should_preserve_fixture(requested, "passed"))

    def test_only_boolean_opt_in_can_preserve(self):
        for requested in (None, "true", "false", 1):
            with self.subTest(requested=requested):
                self.assertFalse(WORKFLOW.should_preserve_fixture(requested, "failed"))

    def test_timeout_metadata_omits_argv_payload_and_process_output(self):
        private = "SYNTHETIC_PRIVATE_PAYLOAD_FOR_TEST"
        error = subprocess.TimeoutExpired(["/usr/local/bin/docker", "run", private], 60,
                                          output=private.encode(), stderr=private.encode())
        metadata = WORKFLOW.exception_metadata(error)
        self.assertEqual(metadata["type"], "TimeoutExpired")
        self.assertEqual(metadata["timeout_seconds"], 60)
        self.assertEqual(metadata["executable"], "docker")
        self.assertNotIn(private, json.dumps(metadata))

    def test_string_command_and_other_exception_messages_are_not_dumped(self):
        private = "SYNTHETIC_PRIVATE_PAYLOAD_FOR_TEST"
        for error in (subprocess.TimeoutExpired("sh -c " + private, 20), RuntimeError(private)):
            with self.subTest(error=type(error).__name__):
                self.assertNotIn(private, json.dumps(WORKFLOW.exception_metadata(error)))

    def test_rpc_trace_records_only_routes_and_monotonic_duration(self):
        report = {}
        ticks = iter((20.0, 20.125))
        with WORKFLOW.trace_rpc(report, "GET", "/v1/services/private-id/checks?token=private-query", clock=lambda: next(ticks)):
            self.assertEqual(report["last_rpc"]["phase"], "running")
            self.assertFalse(report["last_rpc"]["completed"])
        entry = report["last_rpc"]
        self.assertEqual(entry["path"], "/v1/services/:service_id/checks")
        self.assertEqual(entry["elapsed_seconds"], 0.125)
        self.assertEqual(entry["phase"], "completed")
        self.assertTrue(entry["completed"])
        self.assertIsNone(entry["error_type"])
        self.assertNotIn("private", json.dumps(report))

    def test_rpc_trace_retains_error_type_and_reraises_without_private_text(self):
        report = {}
        ticks = iter((3.0, 8.0))
        with self.assertRaisesRegex(RuntimeError, "private payload"):
            with WORKFLOW.trace_rpc(report, "POST", "/v1/operations/private-id/cancel", clock=lambda: next(ticks)):
                raise RuntimeError("private payload")
        self.assertEqual(report["last_rpc"]["error_type"], "RuntimeError")
        self.assertEqual(report["last_rpc"]["phase"], "error")
        self.assertFalse(report["last_rpc"]["completed"])
        self.assertEqual(report["last_rpc"]["elapsed_seconds"], 5.0)
        self.assertNotIn("private", json.dumps(report))

    def test_rpc_trace_history_is_bounded_and_unknown_paths_are_not_copied(self):
        report = {}
        for index in range(20):
            ticks = iter((float(index), float(index) + 0.25))
            with WORKFLOW.trace_rpc(report, "GET", "/v1/operations", clock=lambda: next(ticks)):
                pass
        self.assertEqual(len(report["rpc_durations"]), 16)
        self.assertEqual(WORKFLOW.safe_rpc_path("/v1/services/private/private-suffix"), "unrecognized_route")
        self.assertEqual(WORKFLOW.safe_rpc_path("/private-url"), "unrecognized_route")


class NativeLocalHelperGuardTests(unittest.TestCase):
    def evidence(self, endpoint="unix:///var/run/docker.sock", docker_info=None, **overrides):
        inputs = {"local_platform": "linux", "local_kernel": "6.8.0-test",
                  "effective_uid": 0, "socket_mode": stat.S_IFSOCK | 0o600}
        inputs.update(overrides)
        if docker_info is None:
            docker_info = {"OSType": "linux", "KernelVersion": "6.8.0-test"}
        return WORKFLOW.native_local_helper_evidence(endpoint, docker_info, **inputs)

    def test_same_linux_kernel_root_and_real_unix_socket_are_recorded(self):
        evidence = self.evidence(docker_info={"OSType": "linux", "KernelVersion": "6.8.0-test",
                                              "irrelevant_private_data": "do-not-copy"})
        self.assertTrue(evidence["same_kernel_verified"])
        self.assertTrue(evidence["unix_socket_verified"])
        self.assertEqual(evidence["effective_uid"], 0)
        self.assertNotIn("do-not-copy", json.dumps(evidence))

    def test_other_platform_unprivileged_user_and_non_socket_are_rejected(self):
        for overrides in ({"local_platform": "darwin"}, {"effective_uid": 1000},
                          {"socket_mode": stat.S_IFREG | 0o600}):
            with self.subTest(overrides=overrides), self.assertRaises(RuntimeError):
                self.evidence(**overrides)

    def test_remote_relative_or_query_endpoints_are_rejected(self):
        for endpoint in ("ssh://test.invalid", "tcp://127.0.0.1:2375", "unix://relative.sock",
                         "unix:///var/run/docker.sock?private", "unix:///var/run/docker.sock#private"):
            with self.subTest(endpoint=endpoint), self.assertRaises(RuntimeError):
                self.evidence(endpoint=endpoint)

    def test_kernel_mismatch_or_unknown_daemon_metadata_are_rejected(self):
        for info in ({"OSType": "linux", "KernelVersion": "6.8.0-other"},
                     {"OSType": "linux"}, {"OSType": "windows", "KernelVersion": "6.8.0-test"}, {}):
            with self.subTest(info=info), self.assertRaises(RuntimeError):
                self.evidence(docker_info=info)
        with self.assertRaises(RuntimeError):
            self.evidence(docker_info={"OSType": "linux", "KernelVersion": ""}, local_kernel="")


if __name__ == "__main__":
    unittest.main()
