"""Competition/reference acceptance scope without Docker or remote access."""

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[1] / "integration/resource_profiles.py"
SPEC = importlib.util.spec_from_file_location("resource_profiles", MODULE)
PROFILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILES)
sys.path.insert(0, str(MODULE.parent))
try:
    OBSERVATION_SPEC = importlib.util.spec_from_file_location("observation_load", MODULE.with_name("observation_load.py"))
    OBSERVATION = importlib.util.module_from_spec(OBSERVATION_SPEC)
    OBSERVATION_SPEC.loader.exec_module(OBSERVATION)
finally:
    sys.path.pop(0)
GIB = 1024**3


class ResourceProfileTests(unittest.TestCase):
    def host(self, memory=4 * GIB, **changes):
        info = {"NCPU": 4, "MemTotal": memory, "OSType": "linux",
                "Architecture": "x86_64", "OperatingSystem": "Ubuntu"}
        return {**info, **changes}

    def capacity(self, total=25_000_000_000):
        return {"path": "/srv/ctfm-test", "total_bytes": total,
                "available_bytes": 12_000_000_000,
                "source": "statvfs_approved_daemon_side_fixture_root"}

    def competition(self, info=None, **changes):
        arguments = {"dedicated_host_attested": True, "configured_disk_gb": 40,
                     "filesystem_capacity": self.capacity()}
        return PROFILES.assess_resource_profile(self.host() if info is None else info,
                                               "competition-4g", **{**arguments, **changes})

    def test_default_profile_remains_legacy_eight_gib(self):
        observation = PROFILES.assess_resource_profile(self.host(8 * GIB), dedicated_host_attested=True)
        self.assertEqual(observation["id"], "legacy-8g")
        self.assertTrue(observation["host_match"])
        fields = PROFILES.acceptance_fields(observation, "passed")
        self.assertEqual(fields["reference_acceptance"], "passed")
        self.assertEqual(fields["competition_acceptance"], "not_claimed")

    def test_four_gib_cannot_pass_legacy_reference(self):
        observation = PROFILES.assess_resource_profile(self.host(), dedicated_host_attested=True)
        self.assertFalse(PROFILES.hardware_matches(self.host()))
        self.assertFalse(observation["host_match"])
        self.assertIn("ram", observation["mismatches"])
        self.assertEqual(PROFILES.acceptance_fields(observation, "passed")["reference_acceptance"], "not_claimed")

    def test_explicit_competition_pass_never_becomes_legacy_pass(self):
        observation = self.competition()
        self.assertTrue(observation["host_match"])
        self.assertTrue(PROFILES.hardware_matches(self.host(), "competition-4g"))
        self.assertEqual(PROFILES.acceptance_fields(observation, "passed"),
                         {"resource_profile_acceptance": "passed", "reference_acceptance": "not_claimed",
                          "competition_acceptance": "passed"})

    def test_eight_gib_does_not_pass_selected_competition(self):
        observation = self.competition(self.host(8 * GIB))
        self.assertFalse(observation["host_match"])
        self.assertEqual(PROFILES.acceptance_fields(observation, "passed")["competition_acceptance"], "not_claimed")

    def test_both_amd64_architecture_names_are_accepted(self):
        for architecture in ("amd64", "x86_64"):
            with self.subTest(architecture=architecture):
                self.assertTrue(self.competition(self.host(Architecture=architecture))["host_match"])

    def test_arm_and_non_linux_cannot_pass_either_target(self):
        for profile, memory in (("legacy-8g", 8 * GIB), ("competition-4g", 4 * GIB)):
            for changes in ({"Architecture": "arm64"}, {"Architecture": "aarch64"}, {"OSType": "windows"}):
                with self.subTest(profile=profile, changes=changes):
                    observation = PROFILES.assess_resource_profile(self.host(memory, **changes), profile,
                                                                  dedicated_host_attested=True, configured_disk_gb=40,
                                                                  filesystem_capacity=self.capacity())
                    self.assertIn("linux_amd64", observation["mismatches"])
                    self.assertFalse(observation["host_match"])

    def test_missing_architecture_is_unknown(self):
        observation = self.competition(self.host(Architecture=None))
        self.assertEqual(observation["checks"]["linux_amd64"], "unknown")
        self.assertEqual(observation["state"], "unknown")

    def test_competition_memory_band_is_inclusive_and_exact(self):
        for memory in (int(3.5 * GIB), int(4.5 * GIB)):
            with self.subTest(memory=memory):
                self.assertTrue(self.competition(self.host(memory))["host_match"])
        for memory in (int(3.5 * GIB) - 1, int(4.5 * GIB) + 1):
            with self.subTest(memory=memory):
                self.assertFalse(self.competition(self.host(memory))["host_match"])

    def test_cpu_count_is_four_not_at_least_four(self):
        for count in (2, 6, 8):
            with self.subTest(count=count):
                self.assertIn("cpu", self.competition(self.host(NCPU=count))["mismatches"])

    def test_unknown_memory_and_cpu_are_not_zero_usage_or_a_pass(self):
        for changes in ({"MemTotal": None}, {"MemTotal": 0}, {"NCPU": None}, {"NCPU": True}):
            with self.subTest(changes=changes):
                observation = self.competition(self.host(**changes))
                self.assertEqual(observation["state"], "unknown")
                self.assertFalse(observation["host_match"])

    def test_dedicated_host_attestation_is_required(self):
        observation = self.competition(dedicated_host_attested=False)
        self.assertIn("dedicated_host", observation["unknown"])
        self.assertFalse(observation["host_match"])

    def test_desktop_daemon_is_not_accepted_as_native_reference(self):
        for name in ("OrbStack", "Docker Desktop"):
            with self.subTest(name=name):
                observation = self.competition(self.host(OperatingSystem=name))
                self.assertIn("native_docker_host", observation["mismatches"])

    def test_virtual_disk_declaration_required_only_for_competition(self):
        self.assertIn("configured_virtual_disk", self.competition(configured_disk_gb=None)["unknown"])
        self.assertIn("configured_virtual_disk", self.competition(configured_disk_gb=80)["mismatches"])
        observation = PROFILES.assess_resource_profile(self.host(8 * GIB), dedicated_host_attested=True)
        self.assertTrue(observation["host_match"])

    def test_filesystem_measurement_does_not_prove_virtual_disk_or_nvme(self):
        observation = self.competition()
        self.assertEqual(observation["configured_virtual_disk_gb"], 40)
        self.assertEqual(observation["filesystem_capacity"]["total_bytes"], 25_000_000_000)
        self.assertFalse(observation["filesystem_capacity_is_virtual_disk_size"])
        self.assertFalse(observation["physical_nvme_verified"])

    def test_competition_requires_valid_recorded_filesystem_capacity(self):
        for capacity in (None, {}, [], True, {"path": "/srv/x", "total_bytes": 0, "available_bytes": 0},
                         {"path": "/srv/x", "total_bytes": 10, "available_bytes": 11}):
            with self.subTest(capacity=capacity):
                self.assertIn("filesystem_capacity_recorded", self.competition(filesystem_capacity=capacity)["unknown"])

    def test_failed_run_never_receives_either_acceptance(self):
        for profile, memory in (("legacy-8g", 8 * GIB), ("competition-4g", 4 * GIB)):
            observation = PROFILES.assess_resource_profile(self.host(memory), profile, dedicated_host_attested=True,
                                                          configured_disk_gb=40, filesystem_capacity=self.capacity())
            for status in ("failed", "thresholds_not_met", "running", "cleanup_failed"):
                with self.subTest(profile=profile, status=status):
                    self.assertEqual(set(PROFILES.acceptance_fields(observation, status).values()), {"not_claimed"})

    def test_invalid_explicit_profile_or_disk_is_rejected(self):
        with self.assertRaises(ValueError):
            PROFILES.assess_resource_profile(self.host(), "unknown")
        with self.assertRaises(ValueError):
            PROFILES.hardware_matches(self.host(), "unknown")
        for size in (0, -1, True, "40"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.competition(configured_disk_gb=size)

    def online_ranges(self):
        return {"memory": [
            {"range": "0x0000000000000000-0x00000000dfffffff", "size": 3758096384, "state": "online"},
            {"range": "0x0000000100000000-0x000000011fffffff", "size": 536870912, "state": "online"},
        ]}

    def test_lsmem_online_ranges_preserve_holes_and_ignore_offline(self):
        payload = self.online_ranges()
        payload["memory"].append({"range": "0x0000000200000000-0x000000021fffffff", "size": 536870912, "state": "offline"})
        self.assertEqual(PROFILES.online_memory_from_lsmem(payload), 4 * GIB)

    def test_invalid_or_duplicate_online_ranges_cannot_inflate_physical_ram(self):
        valid = self.online_ranges()
        for payload in ([], {}, {"memory": []}, {"memory": ["bad"]},
                        {"memory": [valid["memory"][0], valid["memory"][0]]},
                        {"memory": [{**valid["memory"][0], "size": 4 * GIB}]},
                        {"memory": [{"range": "bad", "size": GIB, "state": "online"}]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                PROFILES.online_memory_from_lsmem(payload)

    def test_actual_four_gib_vm_with_reserved_memory_matches_explicit_basis(self):
        observation = self.competition(self.host(3563139072), physical_memory_bytes=4 * GIB,
                                       physical_memory_source=PROFILES.HOST_ONLINE_MEMORY_SOURCE)
        self.assertTrue(observation["host_match"])
        self.assertEqual(observation["memory_basis"], "host_online_physical_with_usable_guard")
        self.assertEqual(observation["observed"]["memory_total_bytes"], 3563139072)
        self.assertEqual(observation["observed"]["physical_online_memory_bytes"], 4 * GIB)
        self.assertEqual(observation["online_minus_memtotal_bytes"], 4 * GIB - 3563139072)

    def test_missing_or_unverified_physical_evidence_cannot_relax_memtotal_band(self):
        for source in (None, "operator_guess", "container_sysfs"):
            with self.subTest(source=source):
                observation = self.competition(self.host(3563139072), physical_memory_bytes=4 * GIB,
                                               physical_memory_source=source)
                self.assertFalse(observation["host_match"])
                self.assertEqual(observation["memory_basis"], "docker_usable_memory")

    def test_eight_gib_physical_host_cannot_pass_four_gib_by_reserved_memtotal(self):
        observation = self.competition(self.host(4 * GIB), physical_memory_bytes=8 * GIB,
                                       physical_memory_source=PROFILES.HOST_ONLINE_MEMORY_SOURCE)
        self.assertFalse(observation["host_match"])

    def test_physical_evidence_requires_usable_floor_and_coherent_total(self):
        for usable, physical in ((3 * GIB - 1, 4 * GIB), (4 * GIB + 1, 4 * GIB), (3 * GIB, 3 * GIB)):
            with self.subTest(usable=usable, physical=physical):
                self.assertFalse(self.competition(self.host(usable), physical_memory_bytes=physical,
                                                  physical_memory_source=PROFILES.HOST_ONLINE_MEMORY_SOURCE)["host_match"])
        self.assertTrue(self.competition(self.host(3 * GIB), physical_memory_bytes=4 * GIB,
                                        physical_memory_source=PROFILES.HOST_ONLINE_MEMORY_SOURCE)["host_match"])

    def test_physical_evidence_does_not_change_legacy_usable_memory_contract(self):
        observation = PROFILES.assess_resource_profile(self.host(7 * GIB), dedicated_host_attested=True,
                                                      physical_memory_bytes=8 * GIB,
                                                      physical_memory_source=PROFILES.HOST_ONLINE_MEMORY_SOURCE)
        self.assertFalse(observation["host_match"])
        self.assertEqual(observation["memory_basis"], "docker_usable_memory")

    def test_online_memory_probe_scopes_local_host_to_docker_kernel(self):
        result = SimpleNamespace(returncode=0, stdout=json.dumps(self.online_ranges()))
        with mock.patch.object(OBSERVATION.sys, "platform", "linux"), \
             mock.patch.object(OBSERVATION.platform, "release", return_value="test-kernel"), \
             mock.patch.object(OBSERVATION.subprocess, "run", return_value=result) as command:
            evidence = OBSERVATION.read_host_online_memory({"OSType": "linux", "KernelVersion": "test-kernel"})
        self.assertEqual(evidence["physical_memory_bytes"], 4 * GIB)
        self.assertEqual(evidence["source"], PROFILES.HOST_ONLINE_MEMORY_SOURCE)
        self.assertEqual(command.call_args.args[0], ["lsmem", "--json", "--bytes", "--output", "RANGE,SIZE,STATE"])
        self.assertEqual(command.call_args.kwargs["env"]["LC_ALL"], "C")

    def test_online_memory_probe_never_reads_mac_or_a_different_host_kernel(self):
        for local_os, docker_kernel in (("darwin", "test-kernel"), ("linux", "other-kernel")):
            with self.subTest(local_os=local_os), \
                 mock.patch.object(OBSERVATION.sys, "platform", local_os), \
                 mock.patch.object(OBSERVATION.platform, "release", return_value="test-kernel"), \
                 mock.patch.object(OBSERVATION.subprocess, "run") as command:
                evidence = OBSERVATION.read_host_online_memory({"OSType": "linux", "KernelVersion": docker_kernel})
                self.assertIsNone(evidence["physical_memory_bytes"])
                command.assert_not_called()

    def test_bad_lsmem_output_records_unknown_without_changing_fallback(self):
        for output in ("not-json", "[]", '{"memory":[]}'):
            with self.subTest(output=output), \
                 mock.patch.object(OBSERVATION.sys, "platform", "linux"), \
                 mock.patch.object(OBSERVATION.platform, "release", return_value="test-kernel"), \
                 mock.patch.object(OBSERVATION.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)):
                evidence = OBSERVATION.read_host_online_memory({"OSType": "linux", "KernelVersion": "test-kernel"})
                self.assertEqual(evidence["source"], "unavailable")
                self.assertIn("strict MemTotal fallback", evidence["reason"])


if __name__ == "__main__":
    unittest.main()
