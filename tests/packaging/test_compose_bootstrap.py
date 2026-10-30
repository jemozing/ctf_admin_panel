"""Bootstrap path policy and generated mount isolation, without root or Docker."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts/compose-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("compose_bootstrap", MODULE_PATH)
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class BootstrapPolicyTests(unittest.TestCase):
    def plan(self, discovery=None, workspaces=None, docker_storage_root="", host_metrics=False):
        return BOOTSTRAP.make_plan("/srv/ctf-manager", discovery or [], workspaces or [], "/opt/ctf-manager", "/var/run/docker.sock", docker_storage_root, host_metrics)

    def test_scheduler_limits_are_bounded_and_independent(self):
        config = BOOTSTRAP.make_plan("/srv/ctf-manager", [], [], "/opt/ctf-manager", "/var/run/docker.sock", max_builds=3, max_copies=2, max_switches=1)[3]
        self.assertEqual(config["scheduler"], {"builds": 3, "copies": 2, "switches": 1})
        for value in (0, 5, True):
            with self.assertRaises(ValueError):
                BOOTSTRAP.make_plan("/srv/ctf-manager", [], [], "/opt/ctf-manager", "/var/run/docker.sock", max_builds=value)

    def test_host_metrics_have_only_five_read_only_executor_files(self):
        _, _, _, config, mounts, _ = BOOTSTRAP.make_plan("/srv/ctf-manager", [], [], "/opt/ctf-manager", "/var/run/docker.sock", host_metrics=True)
        self.assertTrue(config["host_metrics"])
        self.assertEqual(set(mounts["services"]), {"executor"})
        metrics = [item for item in mounts["services"]["executor"]["volumes"] if item["target"].startswith("/run/ctf-manager-host/")]
        self.assertEqual(len(metrics), 5)
        self.assertEqual({item["source"] for item in metrics}, {"/proc/stat", "/proc/meminfo", "/proc/loadavg", "/proc/uptime", "/proc/1/net/dev"})
        for item in metrics:
            self.assertTrue(item["read_only"])
            self.assertFalse(item["bind"]["create_host_path"])
        self.assertNotIn("host_metrics", self.plan()[3])

    def test_mounts_preserve_host_paths_and_exclude_dashboard(self):
        _, _, _, config, mounts, _ = self.plan(["/srv/games", "/home/team/games"], ["/srv/sources"])
        self.assertFalse(config["development"])
        self.assertEqual(config["web_uid"], 10001)
        self.assertEqual(config["state_directory"], "/srv/ctf-manager/executor")
        self.assertEqual(set(mounts["services"]), {"executor"})
        volumes = mounts["services"]["executor"]["volumes"]
        self.assertEqual([item["source"] for item in volumes], ["/srv/games", "/home/team/games", "/srv/sources"])
        for item in volumes:
            self.assertEqual(item["source"], item["target"])
            self.assertFalse(item["bind"]["create_host_path"])

    def test_rejects_expansion_symlinks_and_noncanonical_paths(self):
        for value in ("/", "relative", "/srv/../etc", "/srv/./games", "/srv/games/", "/srv/$HOME", "/srv/line\nbreak", "/srv/a:b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan([value])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "target").mkdir()
            (root / "alias").symlink_to(root / "target", target_is_directory=True)
            with self.assertRaises(ValueError):
                BOOTSTRAP.no_symlinks(root / "alias" / "child")

    def test_private_state_and_ancestor_roots_cannot_be_exported(self):
        for path in ("/srv/ctf-manager", "/srv/ctf-manager/executor", "/srv/ctf-manager/config/sub", "/srv/ctf-manager/dashboard", "/srv", "/run", "/usr/local", "/var", "/tmp/games"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.plan([path])

    def test_source_roots_cannot_overlap(self):
        for discovery, workspaces in ((["/srv/games"], ["/srv/games/sources"]), (["/srv/games", "/srv/games"], [])):
            with self.subTest(discovery=discovery), self.assertRaises(ValueError):
                self.plan(discovery, workspaces)

    def test_default_roots_and_compose_environment(self):
        _, discovery, workspaces, config, mounts, environment = self.plan()
        self.assertEqual(discovery, [Path("/srv/ctf-manager/services")])
        self.assertEqual(workspaces, [Path("/srv/ctf-manager/workspaces")])
        self.assertIn("COMPOSE_FILE=/opt/ctf-manager/compose.yaml:/srv/ctf-manager/config/compose.mounts.yaml\n", environment)
        self.assertIn("CTFM_BIND_ADDRESS=127.0.0.1\n", environment)
        self.assertEqual(json.loads(json.dumps(mounts)), mounts)
        self.assertNotIn("docker_storage_directory", config)
        self.assertEqual(len(mounts["services"]["executor"]["volumes"]), 2)

    def test_explicit_docker_root_adds_only_read_only_executor_mount(self):
        for path in ("/var/lib/docker", "/mnt/docker-data", "/srv/docker-data"):
            with self.subTest(path=path):
                _, _, _, config, mounts, _ = self.plan(docker_storage_root=path)
                self.assertEqual(config["docker_storage_directory"], path)
                self.assertEqual(set(mounts["services"]), {"executor"})
                docker = mounts["services"]["executor"]["volumes"][-1]
                self.assertEqual(docker, {"type": "bind", "source": path, "target": path,
                                        "read_only": True, "bind": {"create_host_path": False}})

    def test_docker_root_refuses_expansion_system_paths_and_overlap(self):
        for path in ("/", "/var", "/var/lib", "/etc/docker", "/run/docker", "/usr/docker", "/root/docker",
                     "/mnt", "/home", "/srv", "/srv/ctf-manager/executor", "/srv/ctf-manager/services", "/srv/ctf-manager/workspaces",
                     "/srv/$DOCKER", "/srv/../var/lib/docker", "/srv/docker/"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.plan(docker_storage_root=path)
        with self.assertRaises(ValueError):
            self.plan(["/mnt/docker-data/services"], ["/srv/source"], "/mnt/docker-data")

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is not installed")
    def test_generated_environment_loads_both_compose_files(self):
        repository = MODULE_PATH.parents[1]
        # The temporary root must not overlap /tmp inside executor. The project
        # checkout is an allowed location for this read-only config validation.
        scratch = repository / "var"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="compose-config-", dir=scratch) as folder:
            root = Path(folder).resolve()
            (_, _, _, _, mounts, environment) = BOOTSTRAP.make_plan(str(root), [], [], str(repository), "/var/run/docker.sock", "/var/lib/docker", host_metrics=True)
            config = root / "config"
            config.mkdir()
            (config / "compose.mounts.yaml").write_text(json.dumps(mounts))
            env_file = config / "compose.env"
            env_file.write_text(environment)
            result = subprocess.run(["docker", "compose", "--env-file", str(env_file), "config", "--format", "json"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            model = json.loads(result.stdout)["services"]
            self.assertEqual(set(model), {"dashboard", "executor"})
            web = model["dashboard"]
            self.assertEqual(web["user"], "10001:10001")
            self.assertTrue(web["read_only"])
            self.assertEqual(web["cap_drop"], ["ALL"])
            self.assertEqual({item["target"] for item in web["volumes"]}, {"/var/lib/ctf-manager", "/run/ctf-manager"})
            self.assertTrue(next(item for item in web["volumes"] if item["target"] == "/run/ctf-manager")["read_only"])
            executor_volumes = model["executor"]["volumes"]
            for relative in ("executor", "services", "workspaces"):
                value = str(root / relative)
                self.assertTrue(any(item["source"] == value and item["target"] == value for item in executor_volumes))
            self.assertTrue(any(item["target"] == "/var/run/docker.sock" for item in executor_volumes))
            docker_data = next(item for item in executor_volumes if item["target"] == "/var/lib/docker")
            self.assertEqual(docker_data["source"], "/var/lib/docker")
            self.assertTrue(docker_data["read_only"])
            self.assertFalse(docker_data["bind"]["create_host_path"])
            metrics = [item for item in executor_volumes if item["target"].startswith("/run/ctf-manager-host/")]
            self.assertEqual(len(metrics), 5)
            self.assertTrue(all(item["read_only"] and not item["bind"]["create_host_path"] for item in metrics))
            self.assertNotIn("pid", model["executor"])
            self.assertNotEqual(model["executor"].get("network_mode"), "host")


if __name__ == "__main__":
    unittest.main()
