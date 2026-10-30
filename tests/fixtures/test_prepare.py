from pathlib import Path
import tempfile
import unittest

from prepare import PROFILES, prepare_fixture


class PrepareTests(unittest.TestCase):
    def test_generated_projects_are_independent_of_canonical_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for profile in PROFILES:
                project = prepare_fixture(profile, root / profile)
                self.assertTrue((project / "code/app.py").is_file())
                self.assertTrue((project / "code/Dockerfile").is_file())
                self.assertIn("build: ./code", (project / "compose.yaml").read_text())
            (root / "bind-mount/code/VERSION").write_text("patched\n")
            self.assertEqual((root / "named-volume/code/VERSION").read_text(), "v1\n")

    def test_repeated_preparation_cannot_overwrite_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bind-mount"
            prepare_fixture("bind-mount", destination)
            sentinel = destination / "data/keep-this"
            sentinel.write_text("CTFM_TEST_FLAG")
            with self.assertRaises(FileExistsError):
                prepare_fixture("bind-mount", destination)
            self.assertEqual(sentinel.read_text(), "CTFM_TEST_FLAG")


if __name__ == "__main__":
    unittest.main()
