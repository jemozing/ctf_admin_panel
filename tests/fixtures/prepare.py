#!/usr/bin/env python3
"""Materialize independent fixture projects from their shared canonical app."""

import argparse
from pathlib import Path
import os
import shutil


ROOT = Path(__file__).resolve().parent
PROFILES = ("named-volume", "bind-mount", "writable-layer")


def prepare_fixture(profile: str, destination: Path):
    if profile not in PROFILES:
        raise ValueError("unknown fixture profile")
    # Never overwrite existing source or bind data, including on repeated runs.
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copy2(ROOT / profile / "compose.yaml", destination / "compose.yaml")
    shutil.copytree(ROOT / "app", destination / "code",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "test_app.py"))
    if profile == "bind-mount":
        (destination / "data").mkdir()
        (destination / ".env").write_text(
            f"CTFM_FIXTURE_UID={os.getuid()}\nCTFM_FIXTURE_GID={os.getgid()}\n"
        )
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True,
                        help="new directory for generated projects; never overwritten")
    parser.add_argument("--fixture", choices=["all", *PROFILES], default="all")
    arguments = parser.parse_args()
    arguments.destination.mkdir(parents=True, exist_ok=False)
    selected = PROFILES if arguments.fixture == "all" else [arguments.fixture]
    for profile in selected:
        path = prepare_fixture(profile, arguments.destination / profile)
        print(path)


if __name__ == "__main__":
    main()
