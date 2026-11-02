#!/usr/bin/env python3
"""Install a verified native CTF Service Manager release on a Linux systemd host.

No package downloads, game-container changes, recursive ownership fixes or
automatic service starts are performed. --dry-run validates the bundle and
prints the installation plan without root privileges or host changes.
"""

import argparse
from dataclasses import dataclass
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys


BINARIES = ("ctf-manager", "ctfm-proxy", "ctfm-traffic", "ctfm-capture", "ctfm-packets")
UNITS = ("ctfm-executor.service", "ctfm-dashboard.service")
USER = "ctfm-web"
GROUP = "ctfm-ipc"
CONFIG = Path("/etc/ctf-manager/executor.json")
STATE = Path("/var/lib/ctf-manager")
MANIFEST = STATE / "install.json"
UNIT_ROOT = Path("/etc/systemd/system")
DROPIN = UNIT_ROOT / "ctfm-executor.service.d/10-storage.conf"
WEB_DROPIN = UNIT_ROOT / "ctfm-dashboard.service.d/10-isolation.conf"
BIN_ROOT = Path("/usr/local/bin")
DEFAULT_DISCOVERY = "/srv/game-services"
DEFAULT_WORKSPACE = "/srv/ctf-workspaces"
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_BUNDLE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class Bundle:
    version: str
    arch: str
    files: dict[str, bytes]


def canonical_path(value):
    if not isinstance(value, str) or not value.startswith("/") or value == "/" or str(Path(value)) != value:
        raise ValueError("paths must be canonical absolute paths other than /")
    if re.search(r"[\x00-\x20\x7f$%:'\"\\]", value) or any(part in (".", "..") for part in value.split("/")):
        raise ValueError("host paths cannot contain whitespace, shell/systemd specifiers or aliases")
    return Path(value)


def overlaps(left, right):
    return left == right or left in right.parents or right in left.parents


def validated_roots(discovery, workspaces):
    discovery = [canonical_path(value) for value in discovery] or [Path(DEFAULT_DISCOVERY)]
    workspaces = [canonical_path(value) for value in workspaces] or [Path(DEFAULT_WORKSPACE)]
    roots = discovery + workspaces
    protected = ("/bin", "/sbin", "/usr", "/etc", "/dev", "/proc", "/sys", "/run", "/var/run", "/var/lib/ctf-manager", "/var/lib/docker", "/var/lib/containerd", "/root", "/boot", "/tmp", "/lib", "/lib64")
    broad = ("/home", "/srv", "/var", "/var/lib", "/opt", "/mnt", "/media")
    for index, path in enumerate(roots):
        if str(path) in broad or any(overlaps(path, Path(item)) for item in protected) or any(overlaps(path, other) for other in roots[:index]):
            raise ValueError("service/workspace roots must be dedicated, disjoint and outside private/system data")
    return discovery, workspaces


def no_symlinks(path):
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symbolic links in installation or approved-root paths are not allowed")


def stable_parents(path):
    """Check the host hierarchy; callers never repair an existing directory."""
    no_symlinks(path)
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"untrusted installation parent {item} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o}); expected a root-owned directory without group/world write")


def bundle_file(source, relative, limit=MAX_FILE_BYTES):
    if not relative or relative.startswith("/") or "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
        raise ValueError("release contains an invalid relative path")
    path = source / relative
    no_symlinks(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError("release payload must contain bounded regular files without links")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("release payload exceeds its size bound")
    return data


def load_bundle(source):
    source = Path(source).absolute()
    no_symlinks(source)
    checksum_text = bundle_file(source, "SHA256SUMS", 128 * 1024).decode("utf-8")
    checksums = {}
    for line in checksum_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00-\x1f\x7f]+)", line)
        if not match or match[2] in checksums or match[2] == "SHA256SUMS":
            raise ValueError("invalid or duplicate release checksum entry")
        checksums[match[2]] = match[1]
    required = {"release.json", "install.py", "config/executor.example.json", *["systemd/" + name for name in UNITS], *["bin/" + name for name in BINARIES]}
    if not required <= checksums.keys() or len(checksums) > 512:
        raise ValueError("release checksums do not cover the required native files")
    files, total = {}, 0
    for relative, digest in checksums.items():
        data = bundle_file(source, relative)
        total += len(data)
        if total > MAX_BUNDLE_BYTES or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("release payload checksum or size verification failed")
        files[relative] = data
    release = json.loads(files["release.json"])
    if not isinstance(release, dict) or release.get("schema_version") != 1 or release.get("name") != "ctf-manager" or release.get("goos") != "linux" or release.get("goarch") not in ("amd64", "arm64") or not isinstance(release.get("binaries"), dict):
        raise ValueError("unsupported native release manifest")
    version = release.get("version", "")
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}", version):
        raise ValueError("invalid native release version")
    for name in BINARIES:
        record = release.get("binaries", {}).get(name, {})
        data = files["bin/" + name]
        expected_machine = 62 if release["goarch"] == "amd64" else 183
        if not isinstance(record, dict) or record.get("path") != "bin/" + name or record.get("size") != len(data) or record.get("sha256") != hashlib.sha256(data).hexdigest():
            raise ValueError("native binary metadata does not match verified payload")
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or int.from_bytes(data[18:20], "little") != expected_machine:
            raise ValueError("native binary is not the expected 64-bit Linux ELF architecture")
    return Bundle(version, release["goarch"], files)


def command(arguments, check=True):
    result = subprocess.run(arguments, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, text=True)
    if check and result.returncode:
        raise ValueError("host prerequisite command failed: " + Path(arguments[0]).name)
    return result


def trusted_binary(name, explicit=None):
    selected = explicit or shutil.which(name)
    if not selected:
        raise ValueError("required host command is unavailable: " + name)
    path = Path(selected).resolve(strict=True)
    stable_parents(path.parent)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("host command is not a regular file: " + name)
    if info.st_uid != 0 or info.st_mode & 0o022 or not os.access(path, os.X_OK):
        raise ValueError("host command must be root-owned and executable without group/world write: " + name)
    return str(path)


def require_stopped_units(systemctl):
    for unit in UNITS:
        result = command([systemctl, "show", "--property=ActiveState", "--property=MainPID", "--property=LoadState", unit], check=False)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        not_found = values.get("LoadState") == "not-found"
        if (result.returncode != 0 and not not_found or values.get("ActiveState") not in ("inactive", "failed")
                or values.get("MainPID") != "0"):
            raise ValueError("stop native services fully before installation or upgrade; transitional states and live PIDs are not accepted")


def prerequisites(args, bundle):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("native installation requires root on Linux; --dry-run is available without installation")
    host_arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if host_arch != bundle.arch:
        raise ValueError("release architecture does not match this Linux host")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("a running systemd system manager is required")
    commands = {name: trusted_binary(name, args.docker_binary if name == "docker" else None)
                for name in ("docker", "git", "systemctl", "groupadd", "useradd", "runuser", "nologin")}
    systemd = command([commands["systemctl"], "--version"]).stdout
    match = re.match(r"systemd\s+(\d+)\b", systemd)
    if not match or int(match[1]) < 247:
        raise ValueError("systemd 247 or newer is required by the native unit profile")
    git = command([commands["git"], "--version"]).stdout
    match = re.match(r"git version\s+(\d+)\.(\d+)(?:\.|\b)", git)
    if not match or tuple(map(int, match.groups())) < (2, 40):
        raise ValueError("Git 2.40 or newer is required for pinned HTTPS sources")
    if not any(path.is_file() for path in map(Path, ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"))):
        raise ValueError("host CA certificates are required for Git HTTPS sources")
    docker_socket = canonical_path(args.docker_socket)
    socket_info = docker_socket.stat()
    if not stat.S_ISSOCK(socket_info.st_mode):
        raise ValueError("--docker-socket must name an existing local Docker socket")
    docker = [commands["docker"], "--host", "unix://" + str(docker_socket)]
    version = command([commands["docker"], "compose", "version", "--short"]).stdout.strip()
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version)
    if not match or tuple(map(int, match.groups())) < (5, 5, 0):
        raise ValueError("Docker Compose v5.5.0 or newer is required by the native compatibility profile")
    docker_root = command(docker + ["info", "--format", "{{.DockerRootDir}}"]).stdout.strip()
    docker_root = str(canonical_path(docker_root))
    stable_parents(Path(docker_root))
    if not Path(docker_root).is_dir():
        raise ValueError("Docker data root must be an existing trusted local directory")
    if command(docker + ["ps", "--filter", "label=com.docker.compose.project=ctf-manager", "--format", "{{.ID}}" ]).stdout.strip():
        raise ValueError("the Compose panel is running; native setup does not migrate or stop it")
    require_stopped_units(commands["systemctl"])
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 8765))
        except OSError:
            raise ValueError("127.0.0.1:8765 is occupied; native setup does not stop other applications") from None
    return commands, docker_root


def existing_identity():
    try:
        group = grp.getgrnam(GROUP)
    except KeyError:
        group = None
    try:
        user = pwd.getpwnam(USER)
    except KeyError:
        user = None
    if group and group.gr_gid == 0:
        raise ValueError("the IPC group must be distinct from root")
    if user:
        if not group or user.pw_uid == 0 or user.pw_gid != group.gr_gid or Path(user.pw_shell).name not in ("nologin", "false"):
            raise ValueError("existing ctfm-web account has unexpected UID, primary group or login shell")
        if set(os.getgrouplist(USER, user.pw_gid)) != {user.pw_gid}:
            raise ValueError("existing ctfm-web account must not have supplementary groups")
    return user, group


def ensure_identity(commands):
    user, group = existing_identity()
    if not group:
        command([commands["groupadd"], "--system", GROUP])
    if not user:
        command([commands["useradd"], "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", commands["nologin"], "--gid", GROUP, "--password", "!", USER])
    user, group = existing_identity()
    return user.pw_uid, group.gr_gid


def private_json(path, expected_owner=0):
    no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise ValueError("native config and manifest must be root-owned private regular 0600 files")
        raw = stream.read(1024 * 1024 + 1)
    return raw, json.loads(raw)


def target_files(bundle, config):
    files = {str(BIN_ROOT / name): (bundle.files["bin/" + name], 0o755) for name in BINARIES}
    for name in UNITS:
        files[str(UNIT_ROOT / name)] = (bundle.files["systemd/" + name], 0o644)
    roots = config["discovery_roots"] + config["workspace_roots"]
    dropin = "# Generated by install.py; approved roots remain administrator-owned.\n[Service]\nReadWritePaths=" + " ".join(roots) + "\n"
    files[str(DROPIN)] = (dropin.encode(), 0o644)
    hidden = roots + [config["docker_storage_directory"]] if config.get("docker_storage_directory") else roots
    isolation = "# Generated by install.py; the web process does not read game roots.\n[Service]\nInaccessiblePaths=" + " ".join(hidden) + "\n"
    files[str(WEB_DROPIN)] = (isolation.encode(), 0o644)
    return files


def native_config(discovery, workspaces, docker_binary, docker_socket, docker_root, web_uid):
    return {
        "state_directory": str(STATE / "executor"), "socket": "/run/ctf-manager/executor.sock",
        "docker_host": "unix://" + str(docker_socket), "docker_binary": docker_binary,
        "docker_storage_directory": docker_root,
        "discovery_roots": list(map(str, discovery)), "workspace_roots": list(map(str, workspaces)),
        "web_uid": web_uid, "host_metrics": True, "development": False,
    }


def validate_saved_config(config, web_uid):
    if not isinstance(config, dict) or config.get("state_directory") != str(STATE / "executor") or config.get("socket") != "/run/ctf-manager/executor.sock" or config.get("web_uid") != web_uid or config.get("development") is not False:
        raise ValueError("existing native config does not match the systemd paths and web identity")
    if any(not isinstance(config.get(name), list) or not config[name] for name in ("discovery_roots", "workspace_roots")):
        raise ValueError("existing approved roots must be explicit non-empty lists")
    return validated_roots(config.get("discovery_roots", []), config.get("workspace_roots", []))


def verify_existing_file(path, mode, digest=None, expected_owner=0):
    no_symlinks(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
            raise ValueError("existing native files have unexpected ownership, type or permissions")
        raw = stream.read(MAX_FILE_BYTES + 1)
    if digest and hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("an installed binary/unit was changed outside native installation; review it before upgrading")
    return raw


def preflight_files(files, upgrade, mapped=lambda path: Path(path), require_root=True, expected_owner=0):
    old_manifest = None
    manifest_path = mapped(str(MANIFEST))
    if upgrade:
        _, old_manifest = private_json(manifest_path, expected_owner)
        if not isinstance(old_manifest, dict) or old_manifest.get("schema_version") != 1 or not isinstance(old_manifest.get("files"), dict) or set(old_manifest["files"]) != set(files) or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in old_manifest["files"].values()):
            raise ValueError("existing native installation manifest does not match this package layout")
    elif manifest_path.exists() or manifest_path.is_symlink():
        raise ValueError("native installation exists; stop services and use --upgrade")
    for name, (_, mode) in files.items():
        path = mapped(name)
        if require_root:
            stable_parents(path.parent)
        else:
            no_symlinks(path)
        if upgrade:
            verify_existing_file(path, mode, old_manifest["files"][name], expected_owner)
        elif path.exists() or path.is_symlink():
            raise ValueError("refusing to replace an existing binary/unit on a fresh installation")
    return old_manifest


def ensure_directory(path, uid, gid, mode):
    no_symlinks(path)
    created = False
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        os.mkdir(path, mode)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        created = True
    try:
        info = os.fstat(descriptor)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
            raise ValueError("existing native directory has unexpected owner/group/mode; it was not repaired")
    finally:
        os.close(descriptor)
    return created


def check_directory(path, uid, gid, mode):
    no_symlinks(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
        raise ValueError("existing native directory has unexpected owner/group/mode; it was not repaired")


def atomic_write(path, data, mode):
    no_symlinks(path)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def install_files(bundle, config, files, old_manifest, reload_systemd, mapped=lambda path: Path(path), expected_owner=0):
    """Publish the verified in-memory bytes, with rollback while services stop."""
    backups, changed = {}, []
    publishing = dict(files)
    if old_manifest is None:
        publishing[str(CONFIG)] = ((json.dumps(config, indent=2) + "\n").encode(), 0o600)
    for name in [*publishing, str(MANIFEST)]:
        path = mapped(name)
        if path.exists():
            mode = stat.S_IMODE(path.stat().st_mode)
            backups[name] = (verify_existing_file(path, mode, expected_owner=expected_owner), mode)
        else:
            backups[name] = None
    try:
        for name, (data, mode) in publishing.items():
            changed.append(name)
            atomic_write(mapped(name), data, mode)
        manifest = {"schema_version": 1, "version": bundle.version,
                    "files": {name: hashlib.sha256(data).hexdigest() for name, (data, _) in files.items()}}
        changed.append(str(MANIFEST))
        atomic_write(mapped(str(MANIFEST)), (json.dumps(manifest, indent=2) + "\n").encode(), 0o600)
        reload_systemd()
    except BaseException:
        rollback_errors = []
        for name in reversed(changed):
            try:
                previous = backups[name]
                if previous is None:
                    mapped(name).unlink(missing_ok=True)
                else:
                    atomic_write(mapped(name), *previous)
            except OSError:
                rollback_errors.append(name)
        if rollback_errors:
            raise ValueError("native publication failed and rollback was incomplete; keep services stopped and inspect the installation") from None
        raise


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path(__file__).absolute().parent)
    parser.add_argument("--discovery-root", action="append", default=[])
    parser.add_argument("--workspace-root", action="append", default=[])
    parser.add_argument("--docker-binary")
    parser.add_argument("--docker-socket", help="local Docker socket (default /var/run/docker.sock; upgrades inherit saved config)")
    parser.add_argument("--dry-run", action="store_true", help="verify release and show a plan without root, Linux or host writes")
    parser.add_argument("--upgrade", action="store_true", help="replace verified installed binaries/units, preserving config and all state; services must be stopped")
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        bundle = load_bundle(args.source_dir)
        discovery, workspaces = validated_roots(args.discovery_root, args.workspace_root)
        requested_socket = args.docker_socket
        if args.docker_socket is not None:
            canonical_path(args.docker_socket)
        if args.dry_run:
            print(json.dumps({"mode": "upgrade" if args.upgrade else "install", "version": bundle.version,
                              "platform": "linux/" + bundle.arch, "binaries": [str(BIN_ROOT / name) for name in BINARIES],
                              "services": list(UNITS), "config": str(CONFIG), "state": str(STATE),
                              "discovery_roots": list(map(str, discovery)) if not args.upgrade or args.discovery_root else None,
                              "workspace_roots": list(map(str, workspaces)) if not args.upgrade or args.workspace_root else None,
                              "upgrade_preserves_config_and_state": True, "starts_services": False,
                              "prerequisites_checked": False, "dry_run": True}, indent=2))
            return 0
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("native installation requires root on Linux; --dry-run is available without installation")
        config = None
        if args.upgrade:
            _, config = private_json(CONFIG)
            if not isinstance(config, dict) or not isinstance(config.get("docker_host"), str) or not config["docker_host"].startswith("unix:///") or not isinstance(config.get("docker_binary"), str):
                raise ValueError("existing native Docker endpoint is invalid")
            saved_socket = config["docker_host"][len("unix://"):]
            canonical_path(saved_socket)
            if requested_socket is not None and requested_socket != saved_socket:
                raise ValueError("--upgrade preserves the configured Docker socket")
            saved_binary = config["docker_binary"]
            if args.docker_binary and Path(args.docker_binary).resolve() != Path(saved_binary).resolve():
                raise ValueError("--upgrade preserves the configured Docker binary")
            args.docker_binary, args.docker_socket = saved_binary, saved_socket
        else:
            args.docker_socket = requested_socket or "/var/run/docker.sock"
        commands, docker_root = prerequisites(args, bundle)
        user, group = existing_identity()
        if args.upgrade:
            if not user:
                raise ValueError("native service account is missing; automatic identity migration is not supported")
            saved_discovery, saved_workspaces = validate_saved_config(config, user.pw_uid)
            if config.get("docker_storage_directory") and config["docker_storage_directory"] != docker_root:
                raise ValueError("Docker data root differs from the preserved native configuration")
            if args.discovery_root and discovery != saved_discovery or args.workspace_root and workspaces != saved_workspaces:
                raise ValueError("--upgrade preserves configured roots; do not pass different root arguments")
            discovery, workspaces = saved_discovery, saved_workspaces
        else:
            if CONFIG.exists() or CONFIG.is_symlink():
                raise ValueError("executor configuration already exists; native setup does not migrate other installations")
            for path in (CONFIG.parent, STATE):
                stable_parents(path)
                if path.exists() and any(path.iterdir()):
                    raise ValueError("private native directories are not empty; automatic migration is not supported")
            config = native_config(discovery, workspaces, commands["docker"], args.docker_socket, docker_root, user.pw_uid if user else -1)
        for path in discovery + workspaces:
            stable_parents(path)
            if not path.is_dir() and str(path) not in (DEFAULT_DISCOVERY, DEFAULT_WORKSPACE):
                raise ValueError("custom approved roots must already exist; native setup does not create or repair game projects")
            if overlaps(path, Path(docker_root)):
                raise ValueError("approved roots must not overlap Docker storage")
        files = target_files(bundle, config)
        old_manifest = preflight_files(files, args.upgrade)
        for path, uid, gid, mode in ((CONFIG.parent, 0, 0, 0o700), (STATE, 0, 0, 0o755),
                                     (STATE / "executor", 0, 0, 0o700), (DROPIN.parent, 0, 0, 0o755),
                                     (WEB_DROPIN.parent, 0, 0, 0o755)):
            check_directory(path, uid, gid, mode)
        if user:
            check_directory(STATE / "dashboard", user.pw_uid, group.gr_gid, 0o700)
        if group:
            for path in (Path("/run/ctf-manager"), Path("/run/ctf-manager-host")):
                check_directory(path, 0, group.gr_gid, 0o750)
        elif any(path.exists() or path.is_symlink() for path in (Path("/run/ctf-manager"), Path("/run/ctf-manager-host"))):
            raise ValueError("runtime directories exist without the native IPC group; review the previous installation")
        web_uid, ipc_gid = ensure_identity(commands)
        if not args.upgrade:
            config["web_uid"] = web_uid
        created = []
        directories = [(CONFIG.parent, 0, 0, 0o700), (STATE, 0, 0, 0o755),
                       (STATE / "executor", 0, 0, 0o700), (STATE / "dashboard", web_uid, ipc_gid, 0o700),
                       (DROPIN.parent, 0, 0, 0o755), (WEB_DROPIN.parent, 0, 0, 0o755),
                       (Path("/run/ctf-manager"), 0, ipc_gid, 0o750),
                       (Path("/run/ctf-manager-host"), 0, ipc_gid, 0o750)]
        if not BIN_ROOT.exists():
            directories.append((BIN_ROOT, 0, 0, 0o755))
        directories += [(path, 0, 0, 0o755) for path in discovery + workspaces if not path.exists()]
        try:
            for path, uid, gid, mode in directories:
                if ensure_directory(path, uid, gid, mode):
                    created.append(path)
            install_files(bundle, config, files, old_manifest, lambda: command([commands["systemctl"], "daemon-reload"]))
        except BaseException:
            for path in reversed(created):
                try:
                    path.rmdir()
                except OSError:
                    pass
            raise
        print("Native binaries and systemd units installed. Services were not started.")
        if not args.upgrade:
            print("Create the first administrator in Bash or Zsh; read waits for a hidden password and Enter:")
            print("sudo -v")
            print("read -r -s CTFM_INITIAL_PASSWORD")
            print("printf '\\n'")
            print("printf '%s\\n' \"$CTFM_INITIAL_PASSWORD\" | sudo runuser -u ctfm-web -g ctfm-ipc -- /usr/local/bin/ctf-manager init-admin --state /var/lib/ctf-manager/dashboard --username admin")
            print("unset CTFM_INITIAL_PASSWORD")
        print("sudo systemctl enable --now ctfm-executor ctfm-dashboard")
        print("sudo systemctl status ctfm-executor ctfm-dashboard")
        print("Dashboard: http://127.0.0.1:8765/ (use an SSH tunnel from another machine)")
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        print("native-install: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
