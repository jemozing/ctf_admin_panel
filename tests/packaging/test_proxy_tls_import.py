"""TLS file boundaries/transaction safety. No installed files, Docker or VM."""
import importlib.util
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('tls_import', ROOT / 'scripts/proxy-tls-import.py')
TLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TLS)


class TLSImportTests(unittest.TestCase):
    def test_private_input_rejects_links_public_modes_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / 'key'
            key.write_bytes(b'private-material')
            key.chmod(0o600)
            self.assertEqual(TLS.read_input(key, 64, True), b'private-material')
            key.chmod(0o640)
            with self.assertRaises(RuntimeError): TLS.read_input(key, 64, True)
            key.chmod(0o600)
            with self.assertRaises(RuntimeError): TLS.read_input(key, 1, True)
            link = root / 'link'
            link.symlink_to(key)
            with self.assertRaises(OSError): TLS.read_input(link, 64, True)
            hardlink = root / 'hardlink'
            os.link(key, hardlink)
            with self.assertRaises(RuntimeError): TLS.read_input(key, 64, True)
            fifo = root / 'fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(RuntimeError): TLS.read_input(fifo, 64, True)

    def test_real_directory_boundary_rejects_symlink_and_writable_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tls'
            directory.mkdir(mode=0o750)
            TLS.trusted_directory(directory, os.geteuid(), os.getegid())
            directory.chmod(0o770)
            with self.assertRaises(RuntimeError): TLS.trusted_directory(directory, os.geteuid())
            link = root / 'link'
            link.symlink_to(directory)
            with self.assertRaises(RuntimeError): TLS.trusted_directory(link, os.geteuid())

    def test_bad_pair_keeps_no_profile_and_never_overwrites_old_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tls'
            directory.mkdir(mode=0o750)
            certificate, key = root / 'certificate', root / 'key'
            certificate.write_bytes(b'not-a-certificate')
            key.write_bytes(b'not-a-private-key')
            key.chmod(0o600)
            # The host-only /srv ancestor requirement is covered separately;
            # this test keeps all transaction writes inside a private fixture.
            with patch.object(TLS, 'trusted_directory'):
                with self.assertRaises(ssl.SSLError):
                    TLS.import_profile(directory, 'bad', certificate, key, os.getegid())
                self.assertFalse((directory / 'bad').exists())
                self.assertFalse(list(directory.glob('.import-*')))
                old = directory / 'existing'
                old.mkdir()
                (old / 'marker').write_bytes(b'keep')
                with self.assertRaises(RuntimeError):
                    TLS.import_profile(directory, 'existing', certificate, key, os.getegid())
                self.assertEqual((old / 'marker').read_bytes(), b'keep')
                for bad in ('../escape', '/absolute', '.hidden', 'name/key'):
                    with self.assertRaises(RuntimeError):
                        TLS.import_profile(directory, bad, certificate, key, os.getegid())

    def test_only_proxy_gets_readonly_tls_mount(self):
        import json
        model = json.loads((ROOT / 'compose.proxy.yaml').read_text())
        proxy, recorder = model['services']['traffic-proxy'], model['services']['traffic-store']
        self.assertIn('--tls-directory=/etc/ctfm-tls', proxy['command'])
        tls = [v for v in proxy['volumes'] if v['target'] == '/etc/ctfm-tls']
        self.assertEqual(len(tls), 1)
        self.assertTrue(tls[0]['read_only'])
        self.assertFalse(tls[0]['bind']['create_host_path'])
        self.assertFalse(any(v['target'] == '/etc/ctfm-tls' for v in recorder['volumes']))
