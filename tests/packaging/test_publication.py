"""Publication checks reject local state and inspect the staged snapshot."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check-publication.py"
SPEC = importlib.util.spec_from_file_location("publication_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class PublicationAuditTests(unittest.TestCase):
    def types(self, files):
        return {item["type"] for item in CHECK.audit(files)}

    def test_public_sources_and_explicit_synthetic_env_are_allowed(self):
        files = {
            "README.md": b"Use /Users/user/project and host 192.0.2.10.\n",
            ".env.example": b"API_TOKEN=<your-token>\nPASSWORD=replace-me\n",
            CHECK.PUBLIC_ENV_FIXTURE: b"DB_PASS=test-only\nSESSION_SECRET=fixture-only\n",
            "tests/integration/reports/README.md": b"Local evidence is excluded.\n",
            "tests/integration/reports/public-summary.json": b'{"status":"deferred"}',
            "internal/proxy/proxy_test.go": b'host := "' + b"192.168." + b"50.10" + b'"',
        }
        self.assertEqual(CHECK.audit(files), [])

    def test_private_paths_cannot_hide_in_arbitrary_extensions(self):
        paths = ["var/state.json", ".cache/data.txt", ".code-review-graph/graph.db", "web/node_modules/x/a.js",
                 "tests/fixtures/vendor/upstream/main.go", "tests/fixtures/runtime/a.json",
                 "bin/app", "dist/app.js", "backup/data.txt", "trace.pcapng", "state.sqlite-wal",
                 "secrets/deploy.key", ".env", "project.env", ".env.local", ".ssh/config",
                 "tests/integration/reports/raw.json", "web/tsconfig.tsbuildinfo"]
        for path in paths:
            with self.subTest(path=path):
                self.assertIn("private-or-generated-path", self.types({path: b"safe"}))

    def test_templates_do_not_exempt_real_secrets(self):
        self.assertIn("non-placeholder-env-secret", self.types({".env.example": b"API_TOKEN=opaque-value\n"}))
        self.assertIn("non-placeholder-env-secret", self.types({CHECK.PUBLIC_ENV_FIXTURE: b"DB_PASS=opaque-value\n"}))

    def test_key_markers_alone_are_not_key_material(self):
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertEqual(CHECK.audit({"test.py": ("assert " + repr(marker) + " not in output").encode()}), [])
        pem = marker + "\n" + "M" * 64 + "\n-----END " + "PRIVATE KEY-----\n"
        issues = CHECK.audit({"accident.txt": ("safe\n" + pem).encode()})
        self.assertEqual(issues, [{"type": "private-key-block", "path": "accident.txt", "line": 2}])
        self.assertNotIn("M" * 64, json.dumps(issues))

    def test_provider_tokens_are_reported_without_their_values(self):
        tokens = ["ghp_" + "a" * 36, "github_pat_" + "b" * 50,
                  "glpat-" + "c" * 20, "AKIA" + "A" * 16]
        for token in tokens:
            issues = CHECK.audit({"settings.txt": ("safe\nvalue=" + token).encode()})
            self.assertEqual(issues, [{"type": "provider-token", "path": "settings.txt", "line": 2}])
            self.assertNotIn(token, json.dumps(issues))

    def test_personal_paths_and_operational_lan_hosts_are_redacted(self):
        personal = "/Users/" + "actual-owner/project"
        endpoint = "192.168." + "50.200"
        issues = CHECK.audit({"docs/local.md": (personal + "\nssh owner@" + endpoint).encode()})
        self.assertEqual({item["type"] for item in issues}, {"personal-home-path", "private-lan-endpoint"})
        self.assertNotIn(personal, json.dumps(issues))
        self.assertNotIn(endpoint, json.dumps(issues))

    def test_size_count_and_nonregular_limits(self):
        self.assertIn("file-size-limit", self.types({"large.txt": b"x" * (CHECK.MAX_FILE_BYTES + 1)}))
        files = [CHECK.PublicationFile("a", mode="120000"), CHECK.PublicationFile("b", mode="160000"),
                 CHECK.PublicationFile("c", stage=2)]
        self.assertEqual(self.types(files), {"non-regular-file", "submodule", "unmerged-index-entry"})
        many = [CHECK.PublicationFile(str(i)) for i in range(CHECK.MAX_FILES + 1)]
        self.assertEqual(self.types(many), {"file-count-limit"})
        total = [CHECK.PublicationFile("large", size=CHECK.MAX_TOTAL_BYTES + 1)]
        self.assertEqual(self.types(total), {"total-size-limit", "file-size-limit"})


@unittest.skipUnless(shutil.which("git"), "local Git is required")
class PublicationIndexTests(unittest.TestCase):
    def run_git(self, root, *args):
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def test_exact_index_blob_not_unstaged_worktree(self):
        with tempfile.TemporaryDirectory(prefix="ctfm-publication-") as directory:
            root = Path(directory)
            self.run_git(root, "init", "-q")
            file = root / "README.md"
            file.write_text("public\n")
            self.run_git(root, "add", "README.md")
            token = "glpat-" + "z" * 24
            file.write_text(token)
            self.assertEqual(CHECK.audit(CHECK.index_files(root)), [])
            self.run_git(root, "add", "README.md")
            file.write_text("public again\n")
            self.assertEqual({i["type"] for i in CHECK.audit(CHECK.index_files(root))}, {"provider-token"})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = CHECK.main(["--repository", str(root)])
            self.assertEqual(code, 1)
            self.assertNotIn(token, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["scope"], "git-index-blobs")

    def test_staged_symlink_is_rejected_without_following_it(self):
        with tempfile.TemporaryDirectory(prefix="ctfm-publication-") as directory:
            root = Path(directory)
            self.run_git(root, "init", "-q")
            (root / "link").symlink_to("missing-private-target")
            self.run_git(root, "add", "link")
            self.assertEqual(CHECK.audit(CHECK.index_files(root)), [{"type": "non-regular-file", "path": "link"}])

    def test_empty_index_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="ctfm-publication-") as directory:
            root = Path(directory)
            self.run_git(root, "init", "-q")
            with self.assertRaisesRegex(ValueError, "empty-index"):
                CHECK.index_files(root)


if __name__ == "__main__":
    unittest.main()
