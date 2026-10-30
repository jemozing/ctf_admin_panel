#!/usr/bin/env python3
"""Audit exact Git index blobs before publication; never print matched values.

Uses only Python's standard library and the local Git executable. The complete
index is checked, including tracked files that have no staged modification.
``audit({"README.md": b"text"})`` also supports isolated, pure fixture checks.
"""

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
import subprocess
import sys


MAX_FILES = 10000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
PUBLIC_REPORTS = {
    "tests/integration/reports/README.md",
    "tests/integration/reports/public-summary.json",
}
PUBLIC_ENV_FIXTURE = "tests/real-services/bank.env"
# Deliberately public synthetic credentials, reviewed with the real-service
# fixture. A changed file must use placeholder values or be reviewed again.
PUBLIC_ENV_FIXTURE_SHA256 = "ba0b51bf3cf2d349ae1f05b91a74657cd30a3c74528cc7d0a5c23e2aec106b44"
CACHE_COMPONENTS = {
    ".git", ".cache", ".code-review-graph", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "__pycache__", "node_modules", ".venv", "venv", ".ssh", ".aws",
}
PRIVATE_SUFFIXES = {
    ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".kdbx",
    ".pcap", ".pcapng", ".db", ".sqlite", ".sqlite3", ".dump",
    ".bak", ".backup", ".tar", ".tgz", ".zip", ".7z", ".gz", ".pyc",
}
PRIVATE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts",
    "authorized_keys", "credentials", "admin-password", "keylog",
    "sslkeylogfile", ".ds_store",
}
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----"
    r"\s+[A-Za-z0-9+/=\s]{32,}?-----END (?P=kind)-----"
)
PROVIDER_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{12,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9_])"
)
PERSONAL_PATH = re.compile(r"/Users/([A-Za-z0-9_.-]+)(?:/|\b)")
GENERIC_USERS = {"user", "username", "example", "your-user", "your-username", "shared"}
LAN_ADDRESS = re.compile(r"\b192[.]168[.]\d{1,3}[.]\d{1,3}\b")
SECRET_FIELD = re.compile(r"password|passwd|(?:^|_)pass(?:_|$)|token|secret|private_key|access_key|api_key|credential", re.I)
ENV_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


@dataclass(frozen=True)
class PublicationFile:
    path: str
    data: bytes = b""
    mode: str = "100644"
    size: int | None = None
    stage: int = 0


def finding(kind, path="<index>", line=None):
    value = {"type": kind, "path": path}
    if line is not None:
        value["line"] = line
    return value


def env_template(path):
    return PurePosixPath(path).name == ".env.example" or path.endswith(".env.example")


def private_path(path):
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or ".." in parts or "\\" in path:
        return True
    if any(part.lower() in CACHE_COMPONENTS for part in parts):
        return True
    if parts[0] in {"var", "bin", "dist", "backups", "backup"}:
        return True
    if path.startswith(("tests/fixtures/runtime/", "tests/fixtures/vendor/", "web/dist/")):
        return True
    if path.startswith("tests/integration/reports/") and path not in PUBLIC_REPORTS:
        return True
    name = parts[-1].lower()
    if name in PRIVATE_NAMES or PurePosixPath(name).suffix in PRIVATE_SUFFIXES:
        return True
    if name.endswith(("-wal", "-shm", ".tsbuildinfo", "~")):
        return True
    if (name == ".env" or name.endswith(".env") or name.startswith(".env.")):
        return path != PUBLIC_ENV_FIXTURE and not env_template(path)
    return False


def placeholder(value):
    value = value.strip().strip("\"'").lower()
    return not value or bool(re.fullmatch(
        r"(?:<[^>]+>|\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}|"
        r"(?:replace|change)[-_ ]?me(?:[-_ ].*)?|your[-_ ].+|"
        r"(?:example|test|demo|fixture|development|dev|local)(?:[-_ ].*)?)", value
    ))


def audit(files):
    """Return redacted findings for a mapping of paths to bytes or file records."""
    if isinstance(files, dict):
        files = [PublicationFile(path, data) for path, data in files.items()]
    files = list(files)
    if len(files) > MAX_FILES:
        return [finding("file-count-limit")]
    sizes = [item.size if item.size is not None else len(item.data) for item in files]
    results = []
    if sum(sizes) > MAX_TOTAL_BYTES:
        results.append(finding("total-size-limit"))
    for item, size in zip(files, sizes):
        path = item.path
        if item.stage != 0:
            results.append(finding("unmerged-index-entry", path))
        if item.mode not in {"100644", "100755"}:
            results.append(finding("submodule" if item.mode == "160000" else "non-regular-file", path))
        if private_path(path):
            results.append(finding("private-or-generated-path", path))
        if size > MAX_FILE_BYTES:
            results.append(finding("file-size-limit", path))
        if size > MAX_FILE_BYTES or item.mode not in {"100644", "100755"}:
            continue
        text = item.data.decode("utf-8", errors="replace")
        for kind, pattern in (("private-key-block", PRIVATE_KEY), ("provider-token", PROVIDER_TOKEN)):
            for match in pattern.finditer(text):
                results.append(finding(kind, path, text.count("\n", 0, match.start()) + 1))
        for match in PERSONAL_PATH.finditer(text):
            if match.group(1).lower() not in GENERIC_USERS:
                results.append(finding("personal-home-path", path, text.count("\n", 0, match.start()) + 1))
        # Private LAN literals are permitted in unit-test fixtures. Operational
        # scripts and documentation should use supplied hosts or RFC 5737 data.
        if not (path.endswith("_test.go") or PurePosixPath(path).name.startswith("test_")):
            for match in LAN_ADDRESS.finditer(text):
                results.append(finding("private-lan-endpoint", path, text.count("\n", 0, match.start()) + 1))
        known_fixture = (path == PUBLIC_ENV_FIXTURE and
                         hashlib.sha256(item.data).hexdigest() == PUBLIC_ENV_FIXTURE_SHA256)
        if env_template(path) or (path == PUBLIC_ENV_FIXTURE and not known_fixture):
            for number, line in enumerate(text.splitlines(), 1):
                match = ENV_ASSIGNMENT.match(line)
                if match and SECRET_FIELD.search(match.group(1)) and not placeholder(match.group(2)):
                    results.append(finding("non-placeholder-env-secret", path, number))
    # One finding per location is sufficient, regardless of how many tokens occur.
    return sorted({json.dumps(item, sort_keys=True): item for item in results}.values(),
                  key=lambda item: (item["path"], item.get("line", 0), item["type"]))


def git(repository, arguments, payload=None):
    result = subprocess.run(["git", "-C", str(repository), *arguments], input=payload,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Git errors can include user-supplied content; do not echo stderr.
        raise ValueError("git-index-read-failed")
    return result.stdout


def index_files(repository):
    table = git(repository, ["ls-files", "--stage", "-z"])
    entries = []
    for record in table.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        if not re.fullmatch(r"[0-9a-f]{40,64}", oid):
            raise ValueError("invalid-index-object")
        entries.append((mode, oid, int(stage), path.decode("utf-8", errors="surrogateescape")))
        if len(entries) > MAX_FILES:
            raise ValueError("file-count-limit")
    if not entries:
        raise ValueError("empty-index")
    # Inspect sizes before loading blobs. Submodules reference commits and are
    # rejected from metadata without requiring those objects to exist locally.
    regular = [entry for entry in entries if entry[0] in {"100644", "100755"}]
    objects = list(dict.fromkeys(entry[1] for entry in regular))
    metadata = git(repository, ["cat-file", "--batch-check"],
                   "".join(oid + "\n" for oid in objects).encode("ascii")) if objects else b""
    sizes = {}
    for oid, line in zip(objects, metadata.splitlines(), strict=True):
        values = line.decode("ascii").split()
        if len(values) != 3 or values[0] != oid or values[1] != "blob":
            raise ValueError("invalid-index-object")
        sizes[oid] = int(values[2])
    if sum(sizes[entry[1]] for entry in regular) > MAX_TOTAL_BYTES:
        raise ValueError("total-size-limit")
    selected = [oid for oid in objects if sizes[oid] <= MAX_FILE_BYTES]
    content = git(repository, ["cat-file", "--batch"],
                  "".join(oid + "\n" for oid in selected).encode("ascii")) if selected else b""
    offset, blobs = 0, {}
    for oid in selected:
        end = content.find(b"\n", offset)
        expected = f"{oid} blob {sizes[oid]}".encode("ascii")
        if end < 0 or content[offset:end] != expected:
            raise ValueError("invalid-index-object")
        offset = end + 1
        blobs[oid] = content[offset:offset + sizes[oid]]
        offset += sizes[oid]
        if content[offset:offset + 1] != b"\n":
            raise ValueError("invalid-index-object")
        offset += 1
    if offset != len(content):
        raise ValueError("invalid-index-object")
    return [PublicationFile(path, blobs.get(oid, b""), mode, sizes.get(oid, 0), stage)
            for mode, oid, stage, path in entries]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".", help="local Git working tree (default: current directory)")
    args = parser.parse_args(argv)
    try:
        files = index_files(args.repository)
        issues = audit(files)
        result = {"ok": not issues, "scope": "git-index-blobs", "files": len(files),
                  "bytes": sum(item.size for item in files), "findings": issues}
    except (OSError, ValueError, UnicodeError) as error:
        allowed = {"git-index-read-failed", "invalid-index-object", "empty-index",
                   "file-count-limit", "total-size-limit"}
        kind = str(error) if str(error) in allowed else "index-audit-failed"
        result = {"ok": False, "scope": "git-index-blobs", "findings": [finding(kind)]}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
