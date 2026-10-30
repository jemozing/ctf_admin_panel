"""Cycle-controller guards and resume semantics; no Docker/network access."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'integration/native_sibir_cycles.py'
SPEC = importlib.util.spec_from_file_location('native_cycles_test', MODULE)
CYCLES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CYCLES)


class FakeAPI:
    def __init__(self, checkpoint):
        self.path = checkpoint
        self.previews = 0
        self.submissions = []
        self.jobs = {}
        self.ambiguous_once = True

    def request(self, path, payload=None, expected=200):
        if path == '/api/preview':
            self.previews += 1
            return {'plan_digest': 'sha256:' + '1' * 64, 'policy_revision': 1,
                    'current_tree_digest': 'sha256:' + '2' * 64}
        if path == '/api/operations':
            stored = CYCLES.private_read(self.path)['services']['ncdex']['operations']['fetch_source']['request']
            assert stored == payload  # Checkpoint exists before a possibly ambiguous write.
            self.submissions.append(copy.deepcopy(payload))
            key = payload['idempotency_key']
            job = self.jobs.setdefault(key, {'spec': {'id': 'op-one', 'kind': 'fetch_source',
                'service_id': payload['service_id'], 'idempotency_key': key}, 'state': 'succeeded'})
            if self.ambiguous_once:
                self.ambiguous_once = False
                raise OSError('private transport detail must not become a new request')
            return job
        if path == '/api/operations/op-one':
            return next(iter(self.jobs.values()))
        raise AssertionError('Unexpected API request')


def runtime(identity, image, started):
    return {'id': identity, 'image_id': image, 'started_at': started, 'state': 'running',
            'health': 'healthy', 'oom_killed': False,
            'mounts': [{'Type': 'volume', 'Name': 'game-data', 'Source': '/data', 'Destination': '/data', 'RW': True}]}


class ControllerTests(unittest.TestCase):
    def test_successful_subset_does_not_claim_all_five_cycles_complete(self):
        keys = ['bioguard', 'ncdex', 'bank', 'neli234']
        state = {'run_id': 'subset-test-123', 'started_at': 'now', 'selected_service_keys': ['neli234'],
                 'services': {key: {'status': 'passed'} for key in keys}}
        report = CYCLES.public_report(state, 'passed')
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['selected_service_keys'], ['neli234'])
        self.assertIn('requested service subset', report['status_scope'])
        self.assertFalse(report['all_five_service_cycles_complete'])
        state['services']['eyesee'] = {'status': 'passed'}
        self.assertTrue(CYCLES.public_report(state, 'passed')['all_five_service_cycles_complete'])
        self.assertFalse(CYCLES.public_report(state, 'failed')['all_five_service_cycles_complete'])
        state['services']['bank']['status'] = 'running'
        self.assertFalse(CYCLES.public_report(state, 'passed')['all_five_service_cycles_complete'])

    def test_owned_probe_error_messages_survive_but_untrusted_and_namesake_errors_do_not(self):
        source = MODULE.with_name('native_sibir_probes.py')
        specification = importlib.util.spec_from_file_location('native_probe_error_test', source)
        probes = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(probes)
        reason = 'neuroLinks own RAM concept was not preserved'
        self.assertEqual(CYCLES.owned_error_message(probes.ProbeError(reason), probes.ProbeError), reason)
        self.assertEqual(CYCLES.owned_error_message(CYCLES.ControllerError('known controller reason'), probes.ProbeError),
                         'known controller reason')
        namesake = type('ProbeError', (RuntimeError,), {})
        for error in (RuntimeError('PRIVATE_BODY'), OSError('PRIVATE_PATH'), namesake('PRIVATE_LOOKALIKE')):
            with self.subTest(error=type(error).__name__):
                self.assertIsNone(CYCLES.owned_error_message(error, probes.ProbeError))
        self.assertIsNone(CYCLES.owned_error_message(RuntimeError('PRIVATE_IMPORT_FAILURE')))

    def test_functional_get_retries_transient_gateway_errors_with_public_counters(self):
        client = CYCLES.Client('http://127.0.0.1:8765')
        class Response(io.BytesIO):
            status = 200
        failures = [urllib.error.HTTPError('http://127.0.0.1:8765/api/services', code, 'private gateway detail', {},
                    io.BytesIO(b'{"code":"executor_unavailable","message":"PRIVATE_RESPONSE"}')) for code in (502, 503, 504)]
        with patch.object(client.opener, 'open', side_effect=failures + [Response(b'{"ok":true}')]) as opened, \
             patch.object(CYCLES.time, 'sleep') as sleep:
            self.assertEqual(client.request('/api/services'), {'ok': True})
        self.assertEqual(opened.call_count, 4)
        self.assertEqual(sleep.call_count, 3)
        self.assertTrue(all(call.args == (2,) for call in sleep.call_args_list))
        summary = client.read_retry_summary()
        self.assertEqual(summary['read_request_count'], 4)
        self.assertEqual(summary['read_retry_count'], 3)
        self.assertEqual(summary['retry_reasons'], {'HTTP_502': 1, 'HTTP_503': 1, 'HTTP_504': 1})
        self.assertNotIn('PRIVATE_RESPONSE', json.dumps(summary))
        state = {'run_id': 'counter-test-123', 'started_at': 'now', 'services': {}, 'api_read_retries': summary}
        self.assertEqual(CYCLES.public_report(state, 'passed')['api_read_retries'], summary)

    def test_gateway_get_retry_stops_after_six_attempts(self):
        client = CYCLES.Client('http://127.0.0.1:8765')
        failures = [urllib.error.HTTPError('http://127.0.0.1:8765/api/services', 502, 'unavailable', {},
                    io.BytesIO(b'{"code":"executor_unavailable"}')) for _ in range(6)]
        with patch.object(client.opener, 'open', side_effect=failures) as opened, patch.object(CYCLES.time, 'sleep') as sleep:
            with self.assertRaises(CYCLES.ControllerError):client.request('/api/services')
        self.assertEqual(opened.call_count, 6)
        self.assertEqual(sleep.call_count, 5)
        self.assertEqual(client.read_retry_summary()['read_retry_count'], 5)

    def test_posts_and_nontransient_get_errors_never_retry(self):
        for payload, status in [({'private': 'PRIVATE_PAYLOAD'}, 502), (None, 401), (None, 403), (None, 404)]:
            with self.subTest(payload=payload is not None, status=status):
                client = CYCLES.Client('http://127.0.0.1:8765')
                failure = urllib.error.HTTPError('http://127.0.0.1:8765/api/operations', status, 'private reason', {},
                    io.BytesIO(b'{"code":"executor_unavailable"}'))
                with patch.object(client.opener, 'open', side_effect=failure) as opened, patch.object(CYCLES.time, 'sleep') as sleep:
                    with self.assertRaises(CYCLES.ControllerError) as error:
                        client.request('/api/operations', payload)
                self.assertEqual(opened.call_count, 1)
                sleep.assert_not_called()
                self.assertEqual(client.read_retry_summary()['read_retry_count'], 0)
                self.assertNotIn('PRIVATE_PAYLOAD', str(error.exception))
        client = CYCLES.Client('http://127.0.0.1:8765')
        with patch.object(client.opener, 'open', side_effect=OSError('PRIVATE_TRANSPORT')) as opened, patch.object(CYCLES.time, 'sleep') as sleep:
            with self.assertRaises(CYCLES.ControllerError):client.request('/api/operations', {'key': 'PRIVATE_PAYLOAD'})
        self.assertEqual(opened.call_count, 1)
        sleep.assert_not_called()

    def test_new_attempt_clears_stale_safe_error_and_counters_preserving_history(self):
        previous = {'status': 'failed', 'api_read_retries': {'read_retry_count': 5}}
        state = {'safe_error': 'old failure', 'api_read_retries': {'read_retry_count': 5}, 'attempts': [copy.deepcopy(previous)]}
        current = CYCLES.start_attempt(state)
        self.assertNotIn('safe_error', state)
        self.assertNotIn('api_read_retries', state)
        self.assertEqual(state['attempts'][0], previous)
        self.assertIs(state['attempts'][1], current)
        self.assertEqual(current['status'], 'running')

    def retry_fixture(self, directory, state_name='failed', mutation=False):
        root = Path(directory)
        baseline_runtime = {'app': runtime('app-id', 'image-app', 'time1')}
        old = {'id': 'op-failed', 'request': {'service_id': 'service-one', 'action': 'fetch_source',
               'idempotency_key': 'original-key', 'plan_digest': 'old-plan'}, 'result': {'state': 'failed'}}
        saved = {'service_id': 'service-one', 'targets': ['app'], 'before_data_written': True,
                 'baseline': {'release': {'id': 'baseline'}, 'runtime': baseline_runtime, 'code': {'hash': 'baseline'}, 'known_release_ids': ['baseline']},
                 'operations': {'fetch_source': copy.deepcopy(old)}}
        state = {'run_id': 'retry-test-123', 'services': {'ncdex': saved}}
        job = {'spec': {'id': 'op-failed', 'service_id': 'service-one', 'kind': 'fetch_source',
                       'idempotency_key': 'original-key'}, 'state': state_name, 'mutation_started': mutation,
               'outcome': {'reason': 'PRIVATE_OLD_FAILURE_DETAIL'}}
        class API:
            def request(self, path, payload=None, expected=200):
                if path == '/api/operations/op-failed':return job
                raise AssertionError('Retry validation must never POST')
        controller = CYCLES.Cycles(API(), root, root / 'checkpoint.json', state, None)
        detail = {'service': {'id': 'service-one', 'project_directory': str(root / 'services/sibir-ncdex'),
                  'compose_project': 'ctfm-demo-sibir-ncdex', 'managed_paths': [{'path': 'vuln-service', 'kind': 'code'}], 'targets': ['app']}, 'releases': []}
        controller.details = lambda *_args: detail
        return controller, saved, old, job, baseline_runtime

    def test_explicit_failed_retry_archives_exact_old_step_before_clearing_and_uses_new_attempt_key(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, saved, old, job, observed = self.retry_fixture(directory)
            snapshots = []
            original_save = controller.save
            def capture_save():
                original_save()
                snapshots.append(CYCLES.private_read(controller.path))
            controller.save = capture_save
            with patch.object(CYCLES, 'runtime_observation', return_value=observed), \
                 patch.object(CYCLES, 'verify_snapshot', return_value={'hash': 'baseline'}), \
                 patch.object(controller, 'guarded_probe', return_value={'own_before_data_preserved': True}) as probe:
                controller.retry_failed_pre_mutation('ncdex', 'fetch_source')
            self.assertEqual(probe.call_args.args, ('ncdex', saved, 'verify'))
            history = saved['retry_history'][0]
            self.assertEqual(history['step'], old)
            self.assertEqual(history['api_job'], job)
            self.assertTrue(any(item['services']['ncdex'].get('retry_history')
                                and item['services']['ncdex']['operations']['fetch_source'] == old for item in snapshots))
            replacement = saved['operations']['fetch_source']
            self.assertEqual(replacement['attempt'], 2)
            self.assertEqual(replacement['retry_of'], 'op-failed')
            self.assertNotIn('request', replacement)
            api = FakeAPI(controller.path)
            api.ambiguous_once = False
            controller.client = api
            controller.operation('ncdex', 'fetch_source', saved)
            self.assertTrue(api.submissions[0]['idempotency_key'].endswith('-attempt-2'))
            self.assertNotEqual(api.submissions[0]['plan_digest'], old['request']['plan_digest'])
            self.assertNotIn('PRIVATE_OLD_FAILURE_DETAIL', json.dumps(CYCLES.public_report(
                {**controller.state, 'started_at': 'now'}, 'passed')))

    def test_retry_refuses_nonfailed_or_mutated_job_without_clearing_history(self):
        for state_name, mutation in [('running', False), ('queued', False), ('succeeded', False),
                                     ('requires_recovery', True), ('failed', True)]:
            with self.subTest(state=state_name, mutation=mutation), tempfile.TemporaryDirectory() as directory:
                controller, saved, old, _job, _observed = self.retry_fixture(directory, state_name, mutation)
                with self.assertRaises(CYCLES.ControllerError):controller.retry_failed_pre_mutation('ncdex', 'fetch_source')
                self.assertEqual(saved['operations']['fetch_source'], old)
                self.assertFalse(saved.get('retry_history'))

    def test_retry_refuses_unknown_ambiguous_original_and_deploy_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, saved, _old, _job, _observed = self.retry_fixture(directory)
            del saved['operations']['fetch_source']['id']
            with self.assertRaises(CYCLES.ControllerError):controller.retry_failed_pre_mutation('ncdex', 'fetch_source')
            for action in ('deploy', 'rollback', 'recover'):
                with self.subTest(action=action), self.assertRaises(CYCLES.ControllerError):controller.retry_failed_pre_mutation('ncdex', action)
            self.assertFalse(saved.get('retry_history'))

    def test_retry_refuses_baseline_runtime_or_code_drift_before_replacing_step(self):
        for drift in ('runtime', 'code', 'probe'):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                controller, saved, old, _job, observed = self.retry_fixture(directory)
                observed = copy.deepcopy(observed)
                if drift == 'runtime':observed['app']['started_at'] = 'restarted'
                code = {'hash': 'changed' if drift == 'code' else 'baseline'}
                with patch.object(CYCLES, 'runtime_observation', return_value=observed), \
                     patch.object(CYCLES, 'verify_snapshot', return_value=code), \
                     patch.object(controller, 'guarded_probe', side_effect=RuntimeError('probe failed') if drift == 'probe' else None):
                    with self.assertRaises(RuntimeError):controller.retry_failed_pre_mutation('ncdex', 'fetch_source')
                self.assertEqual(saved['operations']['fetch_source'], old)
                self.assertFalse(saved.get('retry_history'))

    def test_ambiguous_submission_resumes_exact_checkpoint_key_without_new_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checkpoint.json'
            state = {'run_id': 'resume-test-123', 'services': {'ncdex': {'service_id': 'service-one'}}}
            api = FakeAPI(path)
            controller = CYCLES.Cycles(api, Path(directory), path, state, None)
            saved = state['services']['ncdex']
            with self.assertRaises(OSError):
                controller.operation('ncdex', 'fetch_source', saved)
            controller.operation('ncdex', 'fetch_source', saved)
            self.assertEqual(api.previews, 1)
            self.assertEqual(len(api.jobs), 1)
            self.assertEqual(api.submissions[0], api.submissions[1])
            self.assertEqual(saved['operations']['fetch_source']['id'], 'op-one')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_auxiliary_restart_is_rejected_before_saved_ram_key_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            before = {'controller': runtime('app', 'image-app', 'time1'), 'neurolink': runtime('aux', 'image-aux', 'time1')}
            after = copy.deepcopy(before)
            after['neurolink']['started_at'] = 'time2'
            saved = {'service_id': 'service-neli', 'targets': ['controller'], 'baseline': {'runtime': before}}
            state = {'run_id': 'guard-test-123', 'services': {'neli234': saved}}
            class Probes:
                called = False
                def verify(self, key):
                    self.called = True
            probes = Probes()
            controller = CYCLES.Cycles(None, Path(directory), Path(directory) / 'state.json', state, probes)
            controller.details = lambda _identity: {}
            with patch.object(CYCLES, 'runtime_observation', return_value=after):
                with self.assertRaises(CYCLES.ControllerError):
                    controller.guarded_probe('neli234', saved, 'verify')
            self.assertFalse(probes.called)

    def test_target_can_recreate_but_volume_and_auxiliary_identity_must_match(self):
        before = {'app': runtime('a', 'i1', 't1'), 'db': runtime('d', 'db1', 't1')}
        after = copy.deepcopy(before)
        after['app'].update(id='b', image_id='i2', started_at='t2')
        CYCLES.assert_preserved(before, after, ['app'])
        with self.assertRaises(CYCLES.ControllerError):
            CYCLES.assert_preserved(before, after, ['app'], all_components=True)
        after['app']['mounts'][0]['Name'] = 'new-empty-volume'
        with self.assertRaises(CYCLES.ControllerError):
            CYCLES.assert_preserved(before, after, ['app'])

    def test_code_content_noop_is_distinct_from_exact_metadata_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'code').mkdir()
            file = root / 'code/main.py'
            file.write_text('print("test")\n')
            file.chmod(0o644)
            first = CYCLES.code_summary(CYCLES.code_entries(root, [{'path': 'code', 'kind': 'code'}]))
            file.chmod(0o600)
            second = CYCLES.code_summary(CYCLES.code_entries(root, [{'path': 'code', 'kind': 'code'}]))
            self.assertEqual(first['content_sha256'], second['content_sha256'])
            self.assertNotEqual(first['metadata_sha256'], second['metadata_sha256'])

    def test_snapshot_verification_detects_managed_bytes_and_metadata_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            game = root / 'game';(game / 'code').mkdir(parents=True)
            (game / 'code/main').write_text('known-code')
            service = {'id': 'service-one', 'project_directory': str(game), 'managed_paths': [{'path': 'code', 'kind': 'code'}]}
            entries = CYCLES.code_entries(game, service['managed_paths'])
            metadata = root / 'executor/snapshots/snap-one';metadata.mkdir(parents=True)
            release = {'snapshot_id': 'snap-one', 'tree_digest': 'sha256:' + '1' * 64}
            (metadata / 'snapshot.json').write_text(json.dumps({'id': 'snap-one', 'service_id': service['id'],
                'state': 'complete', 'manifest_digest': release['tree_digest'], 'manifest': {'entries': entries}}))
            CYCLES.verify_snapshot(root, service, release)
            (game / 'code/main').write_text('different-code')
            with self.assertRaises(CYCLES.ControllerError):
                CYCLES.verify_snapshot(root, service, release)

    def test_private_checkpoints_reject_permissive_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'state.json';file.write_text('{}');file.chmod(0o644)
            with self.assertRaises(CYCLES.ControllerError):CYCLES.private_read(file)
            file.chmod(0o600)
            link = root / 'link.json';link.symlink_to(file)
            with self.assertRaises(OSError):CYCLES.private_read(link)

    def test_report_omits_operation_request_payload_and_documents_eyesee_limit(self):
        secret = 'PRIVATE_REQUEST_VALUE'
        state = {'run_id': 'report-test-123', 'started_at': 'now', 'services': {'ncdex': {
            'operations': {'fetch_source': {'request': {'private': secret}, 'result': {'state': 'succeeded'}}}}}}
        result = CYCLES.public_report(state, 'passed')
        self.assertNotIn(secret, json.dumps(result))
        self.assertIn('EyeSee after-Deploy Add', ' '.join(result['limitations']))

    def test_client_rejects_nonlocal_or_credential_origins(self):
        for origin in ('http://external.invalid', 'http://user:private@127.0.0.1:8765', 'http://127.0.0.1/path'):
            with self.subTest(origin=origin), self.assertRaises(CYCLES.ControllerError):
                CYCLES.Client(origin)


if __name__ == '__main__':
    unittest.main()
