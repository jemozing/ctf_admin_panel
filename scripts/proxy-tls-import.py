#!/usr/bin/env python3
"""Import an immutable TLS certificate profile without exposing the private key.

Run on the Linux proxy host as root. Certificate provisioning and renewal are
external; use a new profile ID for every rotation, then review it in the panel.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import sys
import tempfile


MAX_CERTIFICATE_BYTES = 128 * 1024
MAX_PRIVATE_KEY_BYTES = 32 * 1024
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_input(path, maximum, private):
    """Freeze input bytes once; SSL validates only our private staging copies."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
                "TLS input must be one bounded regular file")
        require(not info.st_mode & (0o077 if private else 0o022),
                "private key must have mode 0600 or stricter; certificate must not be writable by others")
        data = stream.read(maximum + 1)
        require(0 < len(data) <= maximum, "TLS input exceeds its size budget")
        return data


def trusted_directory(path, uid, gid=None):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022,
            "TLS profile directory must be owned by the installer and not writable by others")
    if gid is not None:
        require(info.st_gid == gid and info.st_mode & 0o007 == 0,
                "TLS directory must use the dedicated proxy group and exclude other users")


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def import_profile(directory, profile_id, certificate_path, private_key_path, gid):
    require(IDENTIFIER.fullmatch(profile_id) is not None, "invalid TLS certificate profile ID")
    require(directory.is_absolute() and str(directory) == os.path.normpath(str(directory)) and directory != Path('/'),
            "canonical absolute TLS directory required")
    uid = os.geteuid()
    trusted_directory(directory, uid, gid)
    # All ancestors must remain trusted; neither proxy nor a game may redirect
    # this host-side write through a symlink or group-writable directory.
    parent = directory.parent
    while True:
        trusted_directory(parent, uid)
        if parent == parent.parent:
            break
        parent = parent.parent
    certificate = read_input(certificate_path, MAX_CERTIFICATE_BYTES, False)
    key = read_input(private_key_path, MAX_PRIVATE_KEY_BYTES, True)
    lock_fd = os.open(directory / '.import.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    staging = None
    try:
        info = os.fstat(lock_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1 and not info.st_mode & 0o077,
                "TLS import lock must be a private regular installer-owned file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        target = directory / profile_id
        require(not target.exists() and not target.is_symlink(), "certificate profile already exists; rotate using a new ID")
        staging = Path(tempfile.mkdtemp(prefix='.import-', dir=directory))
        write_private(staging / 'certificate.pem', certificate)
        write_private(staging / 'private-key.pem', key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Reject password-protected keys without prompting or printing inputs.
        context.load_cert_chain(staging / 'certificate.pem', staging / 'private-key.pem', password=lambda: b'')
        for name in ['certificate.pem', 'private-key.pem']:
            os.chown(staging / name, uid, gid)
            os.chmod(staging / name, 0o640)
        os.chown(staging, uid, gid)
        os.chmod(staging, 0o750)
        fsync_directory(staging)
        os.rename(staging, target)
        staging = None
        fsync_directory(directory)
        return {'status': 'imported', 'certificate_id': profile_id,
                'certificate_chain_sha256': hashlib.sha256(certificate).hexdigest(),
                'key_pair_validated': True, 'hostname_expiry_checked_by_proxy_preflight': True,
                'private_key_printed': False, 'policy_modified': False}
    finally:
        if staging is not None:
            shutil.rmtree(staging)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('/srv/ctfm-proxy/tls'))
    parser.add_argument('--id', required=True)
    parser.add_argument('--certificate', type=Path, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--proxy-gid', type=int, default=10002)
    args = parser.parse_args()
    require(sys.platform.startswith('linux') and os.geteuid() == 0, 'run as root on the Linux proxy host')
    require(args.proxy_gid > 0, 'a dedicated non-root proxy group is required')
    print(json.dumps(import_profile(args.directory, args.id, args.certificate, args.private_key, args.proxy_gid)))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, ssl.SSLError):
        # Neither OpenSSL diagnostics nor input values are emitted: they may
        # contain private material or sensitive file paths.
        print('TLS import refused: check private files, key pair, directory permissions and use a new certificate ID.', file=sys.stderr)
        raise SystemExit(1)
