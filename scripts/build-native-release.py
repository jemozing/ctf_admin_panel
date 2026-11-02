#!/usr/bin/env python3
"""Build checksummed Linux/systemd bundles from a fixed set of public inputs.

Requires Go, Node.js and npm only on the build machine. Runtime dependencies
are checked by the bundled installer. No host installation or Docker commands
are performed by this builder.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURES = {"amd64": 62, "arm64": 183}
BINARIES = ("ctf-manager", "ctfm-proxy", "ctfm-traffic", "ctfm-capture", "ctfm-packets")
# No recursive repository copies: runtime state, third-party games, captures,
# local reports and credentials can never enter an archive through a glob.
PUBLIC_INPUTS = {
    "packaging/native/install.py": "install.py",
    "packaging/native/systemd/ctfm-executor.service": "systemd/ctfm-executor.service",
    "packaging/native/systemd/ctfm-dashboard.service": "systemd/ctfm-dashboard.service",
    "packaging/native/executor.example.json": "config/executor.example.json",
    "README.md": "README.md",
    "LICENSE": "LICENSE",
    "docs/native-install.md": "docs/native-install.md",
    "docs/native-release.md": "docs/native-release.md",
}
VERSION = re.compile(r"(?:v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?|dev-[0-9a-f]{7,40})")
LICENSE_NAME = re.compile(r"(?:LICENSE|LICENCE|COPYING|NOTICE)[A-Za-z0-9._-]*", re.IGNORECASE)
MAX_LICENSE_FILES = 256
MAX_LICENSE_FILE_BYTES = 4 * 1024 * 1024
MAX_LICENSE_TOTAL_BYTES = 16 * 1024 * 1024


def validate_version(value):
    if not isinstance(value, str) or len(value) > 80 or not VERSION.fullmatch(value):
        raise ValueError("version must be a semantic version or dev-<7..40 lowercase hex characters>")
    return value


def package_name(version, architecture):
    validate_version(version)
    if architecture not in ARCHITECTURES:
        raise ValueError("architecture must be amd64 or arm64")
    return f"ctf-manager_{version}_linux_{architecture}"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular_input(root, relative):
    path = root / relative
    if not path.is_file() or path.is_symlink() or path.resolve() != path:
        raise ValueError(f"required public input must be a real regular file: {relative}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"hard-linked or special package input is not allowed: {relative}")
    return path


def check_linux_elf(path, architecture):
    """Verify ELF64 little-endian architecture and absence of dynamic loaders."""
    if architecture not in ARCHITECTURES:
        raise ValueError("unsupported ELF architecture")
    size = Path(path).stat().st_size
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3):
            raise ValueError("binary must be a Linux-compatible ELF64 executable")
        kind, machine, version = struct.unpack_from("<HHI", header, 16)
        offset = struct.unpack_from("<Q", header, 32)[0]
        entry_size, count = struct.unpack_from("<HH", header, 54)
        if kind not in (2, 3) or machine != ARCHITECTURES[architecture] or version != 1:
            raise ValueError("ELF architecture or executable type does not match the package")
        if not count or entry_size != 56 or offset < 64 or offset + entry_size * count > size:
            raise ValueError("ELF program headers are invalid")
        stream.seek(offset)
        for _ in range(count):
            program = stream.read(entry_size)
            if struct.unpack_from("<I", program)[0] in (2, 3):
                raise ValueError("release binaries must be static, without PT_DYNAMIC or PT_INTERP")


def run(command, root, **kwargs):
    return subprocess.run(command, cwd=root, check=True, **kwargs)


def source_info(root):
    def git(*arguments):
        result = subprocess.run(["git", *arguments], cwd=root, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=normal")
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        epoch = git("show", "-s", "--format=%ct", "HEAD") or "0"
    if not re.fullmatch(r"[0-9]+", epoch) or not 0 <= int(epoch) <= 0xFFFFFFFF:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer between 0 and 4294967295")
    if commit is not None and not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("invalid source commit")
    return {"commit": commit, "dirty": status != "", "epoch": int(epoch)}


def write_checksums(root):
    paths = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    data = "".join(f"{sha256(path)}  {path.relative_to(root).as_posix()}\n" for path in paths)
    (root / "SHA256SUMS").write_text(data, encoding="utf-8")


def json_objects(data):
    decoder = json.JSONDecoder()
    result, offset = [], 0
    while offset < len(data):
        while offset < len(data) and data[offset].isspace():
            offset += 1
        if offset == len(data):
            break
        value, offset = decoder.raw_decode(data, offset)
        if not isinstance(value, dict) or len(result) >= 2048:
            raise ValueError("Go module metadata exceeds supported bounds")
        result.append(value)
    return result


def collect_licenses_from_sources(root, modules, go_root, go_cache, go_version):
    """Copy installed, locked dependency notices; never perform license lookups."""
    payloads, rows = {}, []
    total = 0

    def add_payload(relative, data):
        nonlocal total
        if relative in payloads:
            if payloads[relative] != data:
                raise ValueError("conflicting notices for the same dependency version")
            return
        if len(payloads) >= MAX_LICENSE_FILES or len(data) > MAX_LICENSE_FILE_BYTES or total + len(data) > MAX_LICENSE_TOTAL_BYTES:
            raise ValueError("third-party notices exceed file count or byte limits")
        payloads[relative] = data
        total += len(data)

    def notices(directory, ecosystem, name, version, origin, only_license=False):
        if not re.fullmatch(r"[A-Za-z0-9@][A-Za-z0-9@._~/-]{0,199}", name) or any(part in ("", ".", "..") for part in name.split("/")) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}", version):
            raise ValueError("invalid dependency name or version in notice metadata")
        paths = []
        if directory is not None:
            directory = Path(directory).resolve(strict=True)
            for candidate in sorted(directory.iterdir()):
                if not LICENSE_NAME.fullmatch(candidate.name) or only_license and candidate.name != "LICENSE":
                    continue
                if candidate.is_dir() and not candidate.is_symlink():
                    continue  # Root-level files only; no recursive source copies.
                source = regular_input(directory, candidate.name)
                with source.open("rb") as stream:
                    data = stream.read(MAX_LICENSE_FILE_BYTES + 1)
                relative = f"licenses/{ecosystem}/{name}@{version}/{candidate.name}"
                add_payload(relative, data)
                paths.append(relative)
        state = ", ".join(f"[{Path(path).name}]({path})" for path in paths)
        if not state:
            state = "Source not downloaded; no notice copied" if directory is None else "No top-level notice file found"
        rows.append((ecosystem, name, version, origin, state))

    go_root, go_cache = Path(go_root).resolve(strict=True), Path(go_cache).resolve(strict=True)
    # Homebrew places the unmodified Go SDK in libexec and its LICENSE in the
    # formula prefix; official Go distributions keep LICENSE directly in GOROOT.
    toolchain_notices = go_root
    if not (go_root / "LICENSE").is_file() and go_root.name == "libexec" and (go_root.parent / "LICENSE").is_file():
        toolchain_notices = go_root.parent
    notices(toolchain_notices, "go", "stdlib", go_version, "https://go.dev/LICENSE", only_license=True)
    for record in sorted(modules, key=lambda value: value.get("Path", "")):
        if record.get("Main"):
            continue
        module = record.get("Replace", record)
        name, version = module.get("Path"), module.get("Version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("native releases do not support local Go module replacements")
        directory = module.get("Dir")
        if directory:
            directory = Path(directory)
            if directory.is_symlink() or directory.resolve(strict=True) != directory or not directory.resolve(strict=True).is_relative_to(go_cache):
                raise ValueError("Go notices must come from the installed module cache")
        notices(directory, "go", name, version, f"https://pkg.go.dev/{name}@{version}")
    lock = json.loads(regular_input(root, "web/package-lock.json").read_text(encoding="utf-8"))
    for relative, record in sorted(lock.get("packages", {}).items()):
        if not relative:
            continue
        parts = Path(relative).parts
        if not parts or parts[0] != "node_modules" or any(part in (".", "..") for part in parts) or Path(relative).is_absolute() or "\\" in relative or record.get("link"):
            raise ValueError("npm notices require installed registry package paths")
        package = root / "web" / relative
        if not package.exists():
            continue  # Optional packages for another build platform are not installed.
        if package.is_symlink() or package.resolve() != package:
            raise ValueError("linked npm package paths cannot supply release notices")
        metadata_path = regular_input(package, "package.json")
        if metadata_path.stat().st_size > MAX_LICENSE_FILE_BYTES:
            raise ValueError("npm package metadata exceeds notice limits")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        name, version = metadata.get("name"), metadata.get("version")
        if version != record.get("version") or not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("installed npm package does not match its locked version")
        notices(package, "npm", name, version, f"https://www.npmjs.com/package/{name}/v/{version}")
    text = ["# Third-party notices", "", "These are copies of top-level notices from the Go toolchain, cached Go modules and installed locked npm packages used by the build.",
            "Build-time and test-only dependencies may be listed. Modules whose source was not downloaded are marked explicitly; no extra downloads or license classification are performed.",
            "Dependencies retain their own licenses.", "", "| Ecosystem | Package | Version | Copied notices |", "|---|---|---|---|"]
    for ecosystem, name, version, origin, state in sorted(rows):
        text.append(f"| {ecosystem} | [{name}]({origin}) | {version} | {state} |")
    add_payload("THIRD_PARTY_NOTICES.md", ("\n".join(text) + "\n").encode())
    return payloads


def collect_license_payloads(root):
    # Read only existing module metadata/source copies. In particular, license
    # collection must not silently fetch a dependency absent from this build.
    environment = {**os.environ, "GOPROXY": "off", "GONOPROXY": "none", "GOPRIVATE": "", "GOSUMDB": "off", "GOWORK": "off"}
    data = run(["go", "list", "-e", "-mod=readonly", "-m", "-json", "all"], root,
               env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    settings = json.loads(run(["go", "env", "-json", "GOROOT", "GOMODCACHE", "GOVERSION"], root,
                              env=environment, stdout=subprocess.PIPE, text=True).stdout)
    return collect_licenses_from_sources(root, json_objects(data), settings["GOROOT"], settings["GOMODCACHE"], settings["GOVERSION"])


def make_bundle(root, destination, binary_directory, version, architecture, source, go_version, license_payloads=None):
    """Stage only reviewed input files and verified binaries; return its directory."""
    root = Path(root).resolve()
    bundle = Path(destination) / package_name(version, architecture)
    bundle.mkdir()
    for relative, target in PUBLIC_INPUTS.items():
        source_file = regular_input(root, relative)
        output = bundle / target
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, output)
        output.chmod(0o755 if target == "install.py" else 0o644)
    binaries = {}
    for name in BINARIES:
        binary = regular_input(Path(binary_directory).resolve(), name)
        check_linux_elf(binary, architecture)
        output = bundle / "bin" / name
        output.parent.mkdir(exist_ok=True)
        shutil.copyfile(binary, output)
        output.chmod(0o755)
        binaries[name] = {"path": f"bin/{name}", "sha256": sha256(output), "size": output.stat().st_size}
    for relative, data in sorted((license_payloads or {}).items()):
        if relative != "THIRD_PARTY_NOTICES.md" and (not relative.startswith("licenses/") or ".." in Path(relative).parts or Path(relative).is_absolute()):
            raise ValueError("invalid third-party notice destination")
        output = bundle / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        output.chmod(0o644)
    manifest = {"schema_version": 1, "name": "ctf-manager", "version": validate_version(version),
                "goos": "linux", "goarch": architecture, "source": source,
                "build": {"go_version": go_version, "cgo_enabled": False}, "binaries": binaries}
    (bundle / "release.json").write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    write_checksums(bundle)
    return bundle


def write_archive(bundle, output, epoch):
    """Emit reproducible tar metadata and gzip header, with no links or devices."""
    with Path(output).open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(mode="w|", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for path in [bundle, *sorted(bundle.rglob("*"))]:
                    info = path.lstat()
                    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or path.is_symlink():
                        raise ValueError("archives may contain only real directories and regular files")
                    relative = path.relative_to(bundle.parent).as_posix()
                    member = tarfile.TarInfo(relative)
                    member.uid = member.gid = 0
                    member.uname = member.gname = "root"
                    member.mtime = epoch
                    if path.is_dir():
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o755
                        archive.addfile(member)
                    else:
                        member.mode = 0o755 if relative.startswith(bundle.name + "/bin/") or path.name == "install.py" else 0o644
                        member.size = info.st_size
                        with path.open("rb") as content:
                            archive.addfile(member, content)


def build(args):
    version = validate_version(args.version)
    architectures = list(dict.fromkeys(args.arch or ARCHITECTURES))
    for architecture in architectures:
        package_name(version, architecture)
    root = ROOT.resolve()
    for relative in PUBLIC_INPUTS:
        regular_input(root, relative)
    output = Path(args.output_dir).absolute()
    if output.exists() and (output.is_symlink() or any(output.iterdir())):
        raise ValueError("output directory must be empty; choose a new --output-dir for another build")
    output.mkdir(parents=True, exist_ok=True)
    if args.skip_frontend:
        regular_input(root, "web/dist/index.html")
    else:
        if not (root / "web/node_modules/.package-lock.json").is_file():
            run(["npm", "ci"], root / "web")
        run(["npm", "run", "build"], root / "web")
    source = source_info(root)
    go_version = run(["go", "version"], root, stdout=subprocess.PIPE, text=True).stdout.strip()
    archives = []
    with tempfile.TemporaryDirectory(prefix="ctfm-native-build-") as temporary:
        temporary = Path(temporary).resolve()
        compiled = []
        for architecture in architectures:
            binaries = temporary / ("binaries-" + architecture)
            binaries.mkdir()
            environment = {**os.environ, "GOOS": "linux", "GOARCH": architecture, "CGO_ENABLED": "0", "GOWORK": "off"}
            for name in BINARIES:
                flags = "-s -w" + (f" -X main.version={version}" if name == "ctf-manager" else "")
                run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", flags,
                     "-o", str(binaries / name), "./cmd/" + name], root, env=environment)
            compiled.append((architecture, binaries))
        license_payloads = collect_license_payloads(root)
        for architecture, binaries in compiled:
            bundle = make_bundle(root, temporary, binaries, version, architecture, source, go_version, license_payloads)
            archive = temporary / (bundle.name + ".tar.gz")
            write_archive(bundle, archive, source["epoch"])
            archives.append(archive)
        # No partial release is promoted if a later architecture failed.
        for archive in archives:
            shutil.copyfile(archive, output / archive.name)
    checksums = "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(output.glob("*.tar.gz")))
    (output / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    return {"version": version, "architectures": architectures, "archives": [path.name for path in archives],
            "source_commit": source["commit"], "source_dirty": source["dirty"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="semantic version (v prefix optional), or dev-<commit>")
    parser.add_argument("--arch", action="append", choices=tuple(ARCHITECTURES), help="repeatable; default: both architectures")
    parser.add_argument("--output-dir", default="dist", help="empty output directory (default: dist)")
    parser.add_argument("--skip-frontend", action="store_true", help="use a frontend already built from this checkout")
    args = parser.parse_args(argv)
    try:
        result = build(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"native-release: {error}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
