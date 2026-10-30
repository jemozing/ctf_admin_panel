"""Runtime report qualifiers use observed metadata, not a fixed developer VM."""

import importlib.util
from pathlib import Path
import unittest


MODULE = Path(__file__).resolve().parents[1] / "integration/runtime_qualification.py"
SPEC = importlib.util.spec_from_file_location("runtime_qualification", MODULE)
QUALIFIERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFIERS)


class RuntimeQualificationTests(unittest.TestCase):
    def qualify(self, *, daemon="amd64", image="amd64", binary="linux/amd64", client_os="Linux", client_arch="x86_64"):
        return QUALIFIERS.runtime_qualification({"Os": "linux", "Arch": daemon},
                                               {"Os": "linux", "Architecture": image},
                                               binary_platform=binary, client_system=client_os,
                                               client_machine=client_arch)

    def test_native_guest_amd64_does_not_report_orbstack_arm64(self):
        value = self.qualify()
        self.assertEqual(value["daemon_platform"], "linux/amd64")
        self.assertEqual(value["client_platform"], "linux/amd64")
        self.assertTrue(value["image_matches_daemon"])
        self.assertTrue(value["executor_matches_daemon"])
        self.assertEqual(value["guest_executor_execution"], "matching_guest_architecture")
        self.assertNotIn("OrbStack", value["scope_note"])
        self.assertNotIn("arm64", value["scope_note"])

    def test_matching_guest_architecture_does_not_attest_physical_host(self):
        value = self.qualify()
        for field in ("physical_host_architecture_verified", "hypervisor_verified",
                      "dedicated_host_verified", "physical_nvme_verified"):
            self.assertFalse(value[field], field)

    def test_mac_client_and_arm_daemon_are_qualified_independently(self):
        value = self.qualify(daemon="arm64", image="arm64", binary="linux/arm64", client_os="Darwin", client_arch="arm64")
        self.assertEqual(value["client_platform"], "darwin/arm64")
        self.assertEqual(value["daemon_platform"], "linux/arm64")
        self.assertTrue(value["executor_matches_daemon"])

    def test_amd64_binary_on_arm_daemon_is_different_guest_execution(self):
        value = self.qualify(daemon="arm64", image="amd64")
        self.assertFalse(value["image_matches_daemon"])
        self.assertFalse(value["executor_matches_daemon"])
        self.assertEqual(value["guest_executor_execution"], "different_guest_architecture")

    def test_actual_binary_can_differ_from_image_label(self):
        value = self.qualify(image="arm64")
        self.assertFalse(value["image_matches_daemon"])
        self.assertTrue(value["executor_matches_daemon"])

    def test_aliases_do_not_falsely_report_cross_architecture(self):
        value = self.qualify(daemon="aarch64", image="arm64", binary="linux/aarch64", client_arch="aarch64")
        self.assertTrue(value["image_matches_daemon"])
        self.assertTrue(value["executor_matches_daemon"])

    def test_image_metadata_without_binary_probe_is_not_execution_proof(self):
        value = self.qualify(binary=None)
        self.assertTrue(value["image_matches_daemon"])
        self.assertIsNone(value["executor_matches_daemon"])
        self.assertEqual(value["guest_executor_execution"], "not_probed")

    def test_missing_metadata_remains_unknown(self):
        value = QUALIFIERS.runtime_qualification({}, {}, client_system="", client_machine="")
        self.assertIsNone(value["daemon_platform"])
        self.assertIsNone(value["image_matches_daemon"])
        self.assertEqual(value["architecture_metadata_state"], "unknown")
        self.assertEqual(value["guest_executor_execution"], "not_probed")

    def test_malformed_binary_probe_does_not_claim_execution(self):
        for binary in ("linux/", "not-a-platform", "linux/amd64/extra"):
            with self.subTest(binary=binary):
                self.assertIsNone(self.qualify(binary=binary)["executor_matches_daemon"])

    def test_os_mismatch_is_not_hidden_by_matching_architecture(self):
        value = QUALIFIERS.runtime_qualification({"Os": "windows", "Arch": "amd64"},
                                                {"Os": "linux", "Architecture": "amd64"},
                                                binary_platform="linux/amd64", client_system="Linux", client_machine="amd64")
        self.assertFalse(value["image_matches_daemon"])
        self.assertFalse(value["executor_matches_daemon"])


if __name__ == "__main__":
    unittest.main()
