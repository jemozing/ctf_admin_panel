"""Registration negative harness contracts, with no Docker/network access."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'integration/web_registration_git_smoke.py'
SPEC = importlib.util.spec_from_file_location('registration_negatives_test', SOURCE)
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def draft(identity='service-one'):
    return {'id': identity, 'name': 'fixture', 'project_directory': '/native/services/game',
            'source_directory': '/native/workspaces/' + identity, 'managed_paths': [],
            'data_paths': [{'kind': 'named_volume', 'significant': True},
                           {'kind': 'writable_layer', 'significant': False, 'loss_accepted': False}]}


class RefusalAPI:
    def __init__(self):
        self.mode = 'original'
        self.calls = []

    def request(self, path, payload=None, csrf=None):
        self.calls.append((path, copy.deepcopy(payload)))
        if path in ('/api/services', '/api/operations'):
            return 200, []
        if path == '/api/registration/inspect':
            if self.mode == 'external_env' or payload['project_directory'] == '/etc':
                return 400, {'code': 'invalid_registration'}
            return 200, {'service': draft('service-' + self.mode)}
        value = payload['service']
        message = 'identity changed'
        if value['project_directory'] == '/native/services/game' and value['source_directory'].startswith('/native/workspaces/'):
            kinds = [item['kind'] for item in value['data_paths']]
            if 'named_volume' not in kinds:message = 'unclassified_runtime_mount'
            elif 'writable_layer' not in kinds:message = 'unclassified_writable_layer'
            elif any(item['kind'] == 'writable_layer' and item.get('significant') for item in value['data_paths']):message = 'blocks recreation'
            elif self.mode == 'privileged':message = 'unsupported_privilege'
            elif self.mode == 'host_network':message = 'unsupported_network_mode'
        return 400, {'code': 'invalid_registration', 'message': message}


class NegativeHarnessTests(unittest.TestCase):
    def test_classification_is_a_copy_and_acknowledges_only_disposable_layers(self):
        original = draft()
        value = HARNESS.classified_draft(original)
        self.assertFalse(original['data_paths'][1]['loss_accepted'])
        self.assertTrue(value['data_paths'][1]['loss_accepted'])
        self.assertTrue(value['data_paths'][0]['significant'])
        self.assertEqual(value['managed_paths'], [{'path': 'LICENSE', 'kind': 'code'}])

    def test_negative_cases_use_http_refusals_and_restore_profile(self):
        api = RefusalAPI()
        modes, observed, identities = [], [], set()
        def patch_profile(mode):
            modes.append(mode);api.mode = mode
        cases = HARNESS.registration_negatives_before_approval(api.request, None, 'csrf', draft(), '/native',
            patch_profile, lambda: observed.append(True), identities)
        self.assertEqual(len(cases), 9)
        self.assertEqual(len(observed), 9)
        self.assertEqual(modes[-1], 'restore')
        self.assertEqual(identities, {'service-privileged', 'service-host_network'})
        self.assertTrue(all(item['status'] == 400 for item in cases))
        self.assertFalse(any(path in ('/api/preview', '/api/operations') and payload is not None for path, payload in api.calls))

    def test_unsupported_profile_is_restored_when_refusal_check_fails(self):
        api = RefusalAPI();modes = []
        def patch_profile(mode):
            modes.append(mode);api.mode = mode
        def runtime_check():
            if api.mode == 'privileged':raise RuntimeError('observation failed')
        with self.assertRaises(RuntimeError):
            HARNESS.registration_negatives_before_approval(api.request, None, 'csrf', draft(), '/native',
                patch_profile, runtime_check, set())
        self.assertEqual(modes[-1], 'restore')

    def test_rejection_requires_expected_reason_and_no_registry_or_job_mutation(self):
        api = RefusalAPI()
        with self.assertRaises(AssertionError):
            HARNESS.assert_rejected_registration(api.request, 'csrf', 'wrong-reason', '/api/registration/proposals',
                {'service': draft()}, message_contains='different reason')
        count = {'read': 0}
        def mutating_response(path, payload=None, csrf=None):
            if path == '/api/services':
                count['read'] += 1
                return 200, [] if count['read'] == 1 else [{'id': 'unexpected'}]
            if path == '/api/operations':return 200, []
            return 400, {'code': 'invalid_registration'}
        with self.assertRaises(AssertionError):
            HARNESS.assert_rejected_registration(mutating_response, 'csrf', 'side-effect', '/api/registration/proposals', {})

    def test_conflict_cases_reach_approval_with_distinct_drafts(self):
        inspections, proposals, observed = [], [], []
        def expect(path, payload, csrf):
            if path == '/api/registration/inspect':
                inspections.append(payload['project_directory'])
                return {'service': draft('service-new-' + str(len(inspections)))}
            proposals.append(payload['service'])
            return {'id': 'proposal-' + str(len(proposals)), 'digest': 'digest', 'service': payload['service']}
        def request(path, payload=None, csrf=None):
            if payload is None:return 200, [{'existing': True}]
            self.assertEqual(path, '/api/registration/approve')
            return 409, {'code': 'conflict'}
        cases = HARNESS.registration_conflicts_after_approval(request, expect, 'csrf', '/native', 'service-original',
            lambda: observed.append(True), set())
        self.assertEqual(inspections, ['/native/services/game', '/native/services/game/overlap'])
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(item['distinct_service_id'] and item['valid_proposal_reached_approve'] for item in cases))

    def test_real_embedded_profile_patch_preserves_exact_original_on_restore(self):
        module = ast.parse(SOURCE.read_text())
        function = next(node for node in ast.walk(module) if isinstance(node, ast.FunctionDef) and node.name == 'patch_profile')
        code = next(node.value.value for node in function.body if isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Constant))
        compile(code, '<profile-patch-helper>', 'exec')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);(root / 'services/game').mkdir(parents=True);(root / 'config').mkdir()
            original = 'services:\n  app:\n    image: fixture\n  database:\n    image: fixture\n'
            (root / '.negative-compose.original').write_text(original)
            path = root / 'services/game/compose.yaml';path.write_text(original)
            for mode, needle in [('privileged', '    privileged: true\n'), ('host_network', '    network_mode: host\n'),
                                 ('external_env', '    env_file: ["')]:
                subprocess.run([sys.executable, '-c', code, str(root), '/unused-repo', mode], check=True)
                self.assertIn(needle, path.read_text())
            subprocess.run([sys.executable, '-c', code, str(root), '/unused-repo', 'restore'], check=True)
            self.assertEqual(path.read_text(), original)

    def test_protected_observation_whitelists_identity_without_config_secrets(self):
        row = {'id': 'known', 'image': 'image', 'started_at': 'time', 'state': 'running', 'pid': 1,
               'mounts': [{'Type': 'volume', 'Source': '/owned', 'Destination': '/data', 'RW': True, 'Name': 'data', 'Unknown': 'omit'}]}
        with patch.object(HARNESS, 'command', return_value=json.dumps(row)) as command:
            observed = HARNESS.protected_inventory('/docker', ['known'])
        template = command.call_args.args[0][3]
        self.assertNotIn('.Config', template)
        self.assertNotIn('Unknown', observed['known']['mounts'][0])


if __name__ == '__main__':
    unittest.main()
