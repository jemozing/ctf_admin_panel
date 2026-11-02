"""Native bundles must be portable, deterministic and limited to public inputs."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts/build-native-release.py"
SPEC = importlib.util.spec_from_file_location("native_release", MODULE_PATH)
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


def elf_bytes(architecture="amd64", program_type=1):
    header = bytearray(64)
    header[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<HHI", header, 16, 2, RELEASE.ARCHITECTURES[architecture], 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, 1)
    program = bytearray(56)
    struct.pack_into("<I", program, 0, program_type)
    return bytes(header + program) + b"synthetic native test binary\n"


class NativeReleaseTests(unittest.TestCase):
    def test_systemd_smoke_entrypoint_parses_and_requires_explicit_opt_in(self):
        script = MODULE_PATH.parents[1] / "tests/integration/native_systemd_smoke.py"
        help_result = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--allow-system-install", help_result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "must-not-exist.json"
            result = subprocess.run([sys.executable, str(script), "--package-dir", directory, "--report", str(report)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(report.exists())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ctfm-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repository"
        self.repository.mkdir()
        self.binaries = self.base / "compiled"
        self.binaries.mkdir()
        self.output = self.base / "staging"
        self.output.mkdir()
        for source, target in RELEASE.PUBLIC_INPUTS.items():
            file = self.repository / source
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("public input for " + target + "\n")
        for name in RELEASE.BINARIES:
            (self.binaries / name).write_bytes(elf_bytes())

    def bundle(self, version="v1.2.3"):
        return RELEASE.make_bundle(self.repository, self.output, self.binaries, version,
                                   "amd64", {"commit": "a" * 40, "dirty": False, "epoch": 1234567890},
                                   "go version go1.26.0 linux/amd64")

    def test_version_cannot_expand_paths_or_linker_arguments(self):
        for value in ("v1.2.3", "0.1.0-dev", "v2.0.0-rc.1", "1.2.3+build.7", "dev-" + "a" * 12):
            self.assertEqual(RELEASE.validate_version(value), value)
        for value in ("", ".", "../version", "v1", "v01.2.3", "1.2.3\nother", "v1.2.3 extra",
                      "v1.2.3;cmd", "v1.2.3/../../file", "$(command)", "-Xmain.other=oops", "dev-commit", "a" * 81):
            with self.subTest(value=value), self.assertRaises(ValueError):
                RELEASE.validate_version(value)
        with self.assertRaises(ValueError):
            RELEASE.package_name("v1.2.3", "x86_64")

    def test_manifest_matches_exact_binaries_and_internal_checksum_inventory(self):
        bundle = self.bundle()
        manifest = json.loads((bundle / "release.json").read_text())
        self.assertEqual((manifest["schema_version"], manifest["name"], manifest["version"], manifest["goos"], manifest["goarch"]),
                         (1, "ctf-manager", "v1.2.3", "linux", "amd64"))
        self.assertFalse(manifest["build"]["cgo_enabled"])
        self.assertEqual(set(manifest["binaries"]), set(RELEASE.BINARIES))
        for name, entry in manifest["binaries"].items():
            path = bundle / entry["path"]
            self.assertEqual(entry["path"], "bin/" + name)
            self.assertEqual(entry["size"], path.stat().st_size)
            self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        entries = {}
        for line in (bundle / "SHA256SUMS").read_text().splitlines():
            digest, relative = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((bundle / relative).read_bytes()).hexdigest())
            entries[relative] = digest
        expected = set(RELEASE.PUBLIC_INPUTS.values()) | {"bin/" + name for name in RELEASE.BINARIES} | {"release.json"}
        self.assertEqual(set(entries), expected)

    def test_private_and_generated_trees_never_enter_bundle(self):
        for relative in ("var/secrets/token", ".env", ".git/config", "web/node_modules/dependency.js",
                         ".cache/large-file", "tests/fixtures/vendor/game/main.go", "docs/private-untracked.txt"):
            file = self.repository / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("not a release input\n")
        bundle = self.bundle()
        all_files = {file.relative_to(bundle).as_posix() for file in bundle.rglob("*") if file.is_file()}
        self.assertEqual(all_files, set(RELEASE.PUBLIC_INPUTS.values()) | {"bin/" + name for name in RELEASE.BINARIES} | {"release.json", "SHA256SUMS"})

    def test_symlink_and_hardlink_public_inputs_are_rejected(self):
        readme = self.repository / "README.md"
        outside = self.base / "outside"
        outside.write_text("outside bytes")
        readme.unlink()
        readme.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.bundle()
        readme.unlink()
        os.link(outside, readme)
        with self.assertRaises(ValueError):
            RELEASE.regular_input(self.repository, "README.md")

    def test_symlink_parent_in_an_allowlisted_path_is_rejected(self):
        docs = self.repository / "docs"
        docs.rename(self.repository / "moved-docs")
        docs.symlink_to(self.repository / "moved-docs", target_is_directory=True)
        with self.assertRaises(ValueError):
            RELEASE.regular_input(self.repository, "docs/native-install.md")

    def test_elf_machine_and_dynamic_loader_must_match_static_linux_contract(self):
        binary = self.binaries / "ctf-manager"
        RELEASE.check_linux_elf(binary, "amd64")
        for data, architecture in ((elf_bytes("arm64"), "amd64"),
                                   (elf_bytes(program_type=2), "amd64"),
                                   (elf_bytes(program_type=3), "amd64"),
                                   (b"not an ELF executable", "amd64")):
            with self.subTest(architecture=architecture, header=data[:20]):
                binary.write_bytes(data)
                with self.assertRaises(ValueError):
                    RELEASE.check_linux_elf(binary, architecture)
        binary.write_bytes(elf_bytes("arm64"))
        RELEASE.check_linux_elf(binary, "arm64")

    def test_invalid_program_header_bounds_are_rejected(self):
        binary = self.binaries / "ctf-manager"
        malformed = bytearray(elf_bytes())
        struct.pack_into("<Q", malformed, 32, 1 << 60)
        binary.write_bytes(malformed)
        with self.assertRaises(ValueError):
            RELEASE.check_linux_elf(binary, "amd64")

    def test_reproducible_tar_has_no_host_identity_paths_or_special_members(self):
        bundle = self.bundle()
        first, second = self.base / "first.tar.gz", self.base / "second.tar.gz"
        RELEASE.write_archive(bundle, first, 1234567890)
        for path in bundle.rglob("*"):
            os.utime(path, (1700000000, 1700000000))
        RELEASE.write_archive(bundle, second, 1234567890)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            members = archive.getmembers()
            self.assertTrue(members)
            for member in members:
                self.assertTrue(member.name == bundle.name or member.name.startswith(bundle.name + "/"))
                self.assertFalse(member.name.startswith("/"))
                self.assertNotIn("..", Path(member.name).parts)
                self.assertTrue(member.isfile() or member.isdir())
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime),
                                 (0, 0, "root", "root", 1234567890))
            archive.extractall(self.base / "extracted", filter="data")
        self.assertEqual((self.base / "extracted" / bundle.name / "release.json").read_bytes(), (bundle / "release.json").read_bytes())

    def test_archive_rejects_new_symlinks_before_including_them(self):
        bundle = self.bundle()
        (bundle / "unexpected-link").symlink_to(self.repository / "README.md")
        with self.assertRaises(ValueError):
            RELEASE.write_archive(bundle, self.base / "refused.tar.gz", 0)

    def test_existing_output_is_not_overwritten_or_built_into(self):
        output = self.base / "release-output"
        output.mkdir()
        previous = output / "prior-archive.tar.gz"
        previous.write_bytes(b"keep this artifact")
        args = argparse.Namespace(version="v1.2.3", arch=["amd64"], output_dir=str(output), skip_frontend=True)
        with mock.patch.object(RELEASE, "ROOT", self.repository), mock.patch.object(RELEASE.subprocess, "run") as process:
            with self.assertRaisesRegex(ValueError, "output directory must be empty"):
                RELEASE.build(args)
            process.assert_not_called()
        self.assertEqual(previous.read_bytes(), b"keep this artifact")

    def test_invalid_epoch_is_rejected_without_becoming_tar_metadata(self):
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "not-a-timestamp"}):
            with self.assertRaisesRegex(ValueError, "SOURCE_DATE_EPOCH"):
                RELEASE.source_info(self.repository)

    def notice_sources(self):
        toolchain, cache = self.base / "toolchain", self.base / "module-cache"
        toolchain.mkdir()
        cache.mkdir()
        (toolchain / "LICENSE").write_text("Go standard-library notice\n")
        module = cache / "example.org/module@v1.2.3"
        module.mkdir(parents=True)
        (module / "LICENSE").write_text("Go dependency notice\n")
        (module / "NOTICE.txt").write_text("Additional Go dependency attribution\n")
        (module / "source.go").write_text("not a notice\n")
        nested = module / "LICENSES"
        nested.mkdir()
        (nested / "private-source.go").write_text("do not recurse\n")
        package = self.repository / "web/node_modules/@example/widget"
        package.mkdir(parents=True)
        (package / "package.json").write_text(json.dumps({"name": "@example/widget", "version": "2.3.4"}))
        (package / "LICENSE-MIT").write_text("npm dependency notice\n")
        (package / "main.js").write_text("not a notice\n")
        lock = {"packages": {"": {"name": "our-project"}, "node_modules/@example/widget": {"version": "2.3.4"},
                              "node_modules/optional-other-platform": {"version": "1.0.0", "optional": True}}}
        (self.repository / "web/package-lock.json").write_text(json.dumps(lock))
        modules = [{"Path": "example.org/our-project", "Main": True, "Dir": str(self.repository)},
                   {"Path": "example.org/module", "Version": "v1.2.3", "Dir": str(module)},
                   {"Path": "example.org/test-only", "Version": "v0.1.0"}]
        return toolchain, cache, module, package, modules

    def test_dependency_notices_include_cached_roots_and_origins_without_host_paths(self):
        toolchain, cache, module, package, modules = self.notice_sources()
        payloads = RELEASE.collect_licenses_from_sources(self.repository, modules, toolchain, cache, "go1.26.0")
        self.assertEqual(set(payloads), {"licenses/go/stdlib@go1.26.0/LICENSE", "licenses/go/example.org/module@v1.2.3/LICENSE",
                                        "licenses/go/example.org/module@v1.2.3/NOTICE.txt", "licenses/npm/@example/widget@2.3.4/LICENSE-MIT", "THIRD_PARTY_NOTICES.md"})
        index = payloads["THIRD_PARTY_NOTICES.md"].decode()
        self.assertIn("https://pkg.go.dev/example.org/module@v1.2.3", index)
        self.assertIn("https://www.npmjs.com/package/@example/widget/v/2.3.4", index)
        self.assertIn("Source not downloaded; no notice copied", index)
        self.assertNotIn(str(self.base), index)
        bundle = RELEASE.make_bundle(self.repository, self.output, self.binaries, "v1.2.3", "amd64",
                                     {"commit": "a" * 40, "dirty": False, "epoch": 0}, "go version fixture", payloads)
        checksum_inventory = (bundle / "SHA256SUMS").read_text()
        for relative, data in payloads.items():
            self.assertEqual((bundle / relative).read_bytes(), data)
            self.assertIn(hashlib.sha256(data).hexdigest() + "  " + relative, checksum_inventory)

    def test_dependency_notice_collection_is_bounded_and_rejects_links(self):
        toolchain, cache, module, package, modules = self.notice_sources()
        for option in ("MAX_LICENSE_FILES", "MAX_LICENSE_FILE_BYTES", "MAX_LICENSE_TOTAL_BYTES"):
            with self.subTest(option=option), mock.patch.object(RELEASE, option, 1):
                with self.assertRaisesRegex(ValueError, "notices exceed"):
                    RELEASE.collect_licenses_from_sources(self.repository, modules, toolchain, cache, "go1.26.0")
        (package / "LICENSE-MIT").unlink()
        (package / "LICENSE-MIT").symlink_to(module / "LICENSE")
        with self.assertRaises(ValueError):
            RELEASE.collect_licenses_from_sources(self.repository, modules, toolchain, cache, "go1.26.0")

    def test_installed_npm_notice_version_must_match_lockfile(self):
        toolchain, cache, module, package, modules = self.notice_sources()
        (package / "package.json").write_text(json.dumps({"name": "@example/widget", "version": "9.9.9"}))
        with self.assertRaisesRegex(ValueError, "locked version"):
            RELEASE.collect_licenses_from_sources(self.repository, modules, toolchain, cache, "go1.26.0")

    def test_notice_metadata_probe_explicitly_disables_network_downloads(self):
        toolchain, cache, module, package, modules = self.notice_sources()
        metadata = "\n".join(json.dumps(value) for value in modules)
        settings = json.dumps({"GOROOT": str(toolchain), "GOMODCACHE": str(cache), "GOVERSION": "go1.26.0"})
        results = [argparse.Namespace(stdout=metadata), argparse.Namespace(stdout=settings)]
        with mock.patch.object(RELEASE, "run", side_effect=results) as process:
            payloads = RELEASE.collect_license_payloads(self.repository)
        self.assertIn("THIRD_PARTY_NOTICES.md", payloads)
        for call in process.call_args_list:
            self.assertEqual(call.kwargs["env"]["GOPROXY"], "off")
            self.assertEqual(call.kwargs["env"]["GONOPROXY"], "none")
        self.assertEqual(RELEASE.json_objects(metadata), modules)

    def test_homebrew_toolchain_license_can_live_beside_libexec(self):
        toolchain, cache, module, package, modules = self.notice_sources()
        libexec = toolchain / "libexec"
        libexec.mkdir()
        payloads = RELEASE.collect_licenses_from_sources(self.repository, modules, libexec, cache, "go1.26.0")
        self.assertEqual(payloads["licenses/go/stdlib@go1.26.0/LICENSE"], (toolchain / "LICENSE").read_bytes())


if __name__ == "__main__":
    unittest.main()
