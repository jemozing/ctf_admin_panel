"""Pure local doubles: never contact apps, Docker, SSH or a real game store."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch
import urllib.request
import uuid

SPEC = importlib.util.spec_from_file_location("native_sibir_probes", Path(__file__).resolve().parents[1] / "integration/native_sibir_probes.py")
PROBES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBES)


class PhaseTests(unittest.TestCase):
    def test_seed_reuses_private_records_and_verifies_both_phases_without_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = PROBES.ProbeAdapter("/srv/ctf-manager", Path(temporary) / "probes", namespace="test_run_012345")
            writes = []
            def record(_key, value, write, _save):
                if write:
                    writes.append(value["phase"])
                return {"preserved": True, "payload_sha256": PROBES.digest(value["content"])}
            with patch.object(adapter, "_record", side_effect=record):
                before = adapter.prepare("bank")
                saved = PROBES.private_read(adapter.directory / "bank.json")
                adapter.prepare("bank")
                after = adapter.write_after_deploy("bank")
                adapter.verify("bank")
            self.assertEqual(writes, ["before", "after"])
            self.assertEqual(before["record_count"], 1)
            self.assertEqual(after["record_count"], 2)
            self.assertEqual((adapter.directory / "bank.json").stat().st_mode & 0o777, 0o600)
            public = json.dumps([before, after])
            for field in ("username", "password", "content", "comment", "solution"):
                self.assertNotIn(saved["records"]["before"][field], public)
            resumed = PROBES.ProbeAdapter("/srv/ctf-manager", adapter.directory, namespace="test_run_012345")
            self.assertEqual(resumed.namespace, adapter.namespace)

    def test_partial_seed_never_becomes_verified_and_ambiguous_write_is_not_repeated(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = PROBES.ProbeAdapter("/srv/ctf-manager", Path(temporary) / "probes")
            def partial(_key, record, _write, save):
                adapter._attempt(record, "product_create", save)
                raise PROBES.ProbeError("ambiguous response")
            with patch.object(adapter, "_record", side_effect=partial):
                with self.assertRaises(PROBES.ProbeError):
                    adapter.prepare("bank")
                with self.assertRaisesRegex(PROBES.ProbeError, "blind replay"):
                    adapter.prepare("bank")
            with self.assertRaises(PROBES.ProbeError):
                adapter.verify("bank")

    def test_after_phase_requires_verified_before_phase_and_identity_is_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probes"
            adapter = PROBES.ProbeAdapter("/srv/ctf-manager", path, namespace="test_run_012345")
            with self.assertRaises(PROBES.ProbeError):
                adapter.write_after_deploy("ncdex")
            with self.assertRaises(PROBES.ProbeError):
                PROBES.ProbeAdapter("/srv/other", path, namespace="test_run_012345")
            with self.assertRaises(PROBES.ProbeError):
                PROBES.ProbeAdapter("/srv/ctf-manager", path, namespace="different_run_012345")

    def test_http_redirect_never_sends_player_session_cross_origin(self):
        handler = PROBES.SameOriginRedirect("http://127.0.0.1:18011")
        request = urllib.request.Request("http://127.0.0.1:18011/login")
        with self.assertRaises(PROBES.ProbeError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://example.org/collect")
        result = handler.redirect_request(request, None, 302, "Found", {}, "http://127.0.0.1:18011/profile")
        self.assertEqual(result.full_url, "http://127.0.0.1:18011/profile")


class Message:
    def __init__(self, **values):
        self.__dict__.update(values)
    def SerializeToString(self, deterministic=False):
        return json.dumps(self.__dict__, sort_keys=deterministic).encode()


class EyeRPC:
    def __init__(self):
        self.objects = {}
        self.calls = []
    def __call__(self, method, request, _response):
        self.calls.append(method)
        if method == "ServiceHealthCheck":
            return Message(status="OK")
        if method == "GetPrescriptionIDs":
            return Message(ids=[identity for identity, value in self.objects.items() if value.patient_id == request.patient_id])
        if method == "CheckPrescription":
            return self.objects[request.id]
        if method == "AddPrescription":
            identity = str(uuid.uuid4())
            self.objects[identity] = Message(**request.__dict__)
            return Message(id=identity)
        raise AssertionError("unexpected RPC")


class EyeSafetyTests(unittest.TestCase):
    def setup_adapter(self, temporary, proof=None):
        adapter = PROBES.ProbeAdapter("/srv/ctf-manager", Path(temporary) / "probes", eyesee_empty_store_proof=proof)
        adapter.pb = types.SimpleNamespace(**{name: Message for name in ("ServiceHealthCheckRequest", "ServiceHealthCheckResponse", "GetPrescriptionIDsRequest", "GetPrescriptionIDsResponse", "CheckPrescriptionRequest", "CheckPrescriptionResponse", "AddPrescriptionRequest", "AddPrescriptionResponse")})
        return adapter

    def proof(self):
        return {"prescription_objects": 0, "relation_objects": 0, "storage_id": "a" * 64, "observed_at_unix": time.time()}

    def test_initial_prescription_requires_fresh_empty_both_buckets_and_after_write_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = self.setup_adapter(temporary, self.proof)
            rpc = EyeRPC()
            with patch.object(adapter, "_rpc", side_effect=rpc):
                before = adapter.prepare("eyesee")
                first_objects = copy.deepcopy(rpc.objects)
                after = adapter.write_after_deploy("eyesee")
                adapter.verify("eyesee")
            self.assertEqual(before["record_count"], 1)
            self.assertEqual(after["status"], "skipped_upstream_uuid_collision_risk")
            self.assertFalse(after["new_after_deploy_data_created"])
            self.assertEqual(rpc.calls.count("AddPrescription"), 1)
            self.assertEqual({key: value.__dict__ for key, value in rpc.objects.items()}, {key: value.__dict__ for key, value in first_objects.items()})

    def test_missing_nonempty_stale_or_wrong_storage_proof_never_calls_add(self):
        for kind in ("missing", "prescriptions", "relations", "stale", "identity"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                value = self.proof()
                if kind == "prescriptions": value["prescription_objects"] = 1
                if kind == "relations": value["relation_objects"] = 1
                if kind == "stale": value["observed_at_unix"] -= 30
                if kind == "identity": value["storage_id"] = "wrong"
                adapter = self.setup_adapter(temporary, None if kind == "missing" else lambda: value)
                rpc = EyeRPC()
                with patch.object(adapter, "_rpc", side_effect=rpc), self.assertRaises(PROBES.ProbeError):
                    adapter.prepare("eyesee")
                self.assertNotIn("AddPrescription", rpc.calls)

    def test_lost_add_reply_is_discovered_by_own_patient_relation_without_second_add(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = self.setup_adapter(temporary, self.proof)
            rpc = EyeRPC()
            def lost_reply(method, request, response):
                value = rpc(method, request, response)
                if method == "AddPrescription":
                    raise PROBES.ProbeError("simulated lost response")
                return value
            with patch.object(adapter, "_rpc", side_effect=lost_reply), self.assertRaises(PROBES.ProbeError):
                adapter.prepare("eyesee")
            adapter.eyesee_empty_store_proof = lambda: self.fail("resume must discover own stored object")
            with patch.object(adapter, "_rpc", side_effect=rpc):
                self.assertEqual(adapter.prepare("eyesee")["status"], "passed")
            self.assertEqual(rpc.calls.count("AddPrescription"), 1)


class NeuroFramingTests(unittest.TestCase):
    def test_internalize_trailing_delimiter_is_discarded_with_write_connection_and_not_replayed(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = PROBES.ProbeAdapter("/srv/ctf-manager", Path(temporary) / "probes")
            record = adapter._new_record("neli234", "after")
            record.update(account_confirmed=True, thought_confirmed=True)
            key = "a" * 32
            menu = b"Choose an option:\n1. Register\n2. Login\n"
            login = [menu, b"Username: ", b"Password: ", b"Login successful!\n"]
            found = ("Found: " + record["ad"] + "\n").encode()
            ejected = ("Ejected: " + record["concept"] + "=" + record["solution"]).encode()
            writer, reader = MagicMock(), MagicMock()
            writer.recv.side_effect = [*login, found, b"Internalized: " + key.encode() + b"\n"]
            reader.recv.side_effect = [*login, found, ejected]
            sockets, saved = [], []
            def connect(_address, **_kwargs):
                if sockets:
                    self.assertTrue(writer.close.called, "write connection must close before fresh read login")
                value = writer if not sockets else reader
                sockets.append(value)
                return value
            with patch.object(PROBES.socket, "create_connection", side_effect=connect):
                evidence = adapter._neli234(record, True, lambda: saved.append(copy.deepcopy(record)))
            self.assertEqual(record["concept_key"], key)
            self.assertTrue(any(item.get("concept_key") == key for item in saved))
            self.assertTrue(evidence["own_ram_concept_preserved"])
            writer_commands = [call.args[0] for call in writer.sendall.call_args_list]
            reader_commands = [call.args[0] for call in reader.sendall.call_args_list]
            self.assertEqual(sum(value.startswith(b"internalize ") for value in writer_commands + reader_commands), 1)
            self.assertFalse(any(value.startswith(b"eject ") for value in writer_commands))
            self.assertEqual(sum(value.startswith(b"eject ") for value in reader_commands), 1)
            self.assertTrue(reader.close.called)

    def test_saved_concept_key_resume_reads_on_fresh_connection_without_new_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter = PROBES.ProbeAdapter("/srv/ctf-manager", Path(temporary) / "probes")
            record = adapter._new_record("neli234", "after")
            record.update(account_confirmed=True, thought_confirmed=True,
                          concept_create_attempted=True, concept_key="a" * 32)
            clients = []
            def create(_host, _port):
                if clients:
                    self.assertTrue(clients[-1].connection.close.called)
                client = MagicMock()
                client.__enter__.return_value = client
                client.__exit__.side_effect = lambda *_args: client.connection.close()
                client.command_line.return_value = "Found: " + record["ad"]
                clients.append(client)
                return client
            with patch.object(PROBES, "NeuroClient", side_effect=create):
                adapter._neli234(record, True, lambda: self.fail("saved verified inputs must not be rewritten"))
            self.assertEqual(len(clients), 2)
            for client in clients:
                client.internalize.assert_not_called()
                client.register.assert_not_called()
            clients[0].read_concept.assert_not_called()
            clients[1].read_concept.assert_called_once_with(record)

    def test_opaque_key_and_own_concept_reads_handle_fragments_without_guessing(self):
        client = object.__new__(PROBES.NeuroClient)
        client.buffer = b""
        client.connection = MagicMock()
        key = "a" * 32
        client.connection.recv.side_effect = [b"Internali", b"zed: " + key[:8].encode(), key[8:].encode()]
        record = {"concept": "synthetic_concept", "solution": "synthetic_solution"}
        self.assertEqual(client.internalize(record), key)
        self.assertEqual(client.connection.sendall.call_args.args[0], b"internalize synthetic_concept=synthetic_solution\n")
        record["concept_key"] = key
        client.connection.recv.side_effect = [b"Ejected: synthetic_", b"concept=synthetic_solution"]
        client.read_concept(record)
        self.assertEqual(client.connection.sendall.call_args.args[0], ("eject " + key + "\n").encode())
        with self.assertRaises(PROBES.ProbeError):
            client.send("unsafe\nline")


if __name__ == "__main__":
    unittest.main()
