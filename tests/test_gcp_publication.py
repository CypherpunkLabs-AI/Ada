import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_release import assets, COMMIT, REPOSITORY

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gcp_publisher', ROOT / 'scripts/publish-gcp-images.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class GcpPublication(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        assets(self.root / 'dist')
        path = self.root / 'dist/deployment.json'
        self.deployment = json.loads(path.read_text())
        self.deployment.update(guest_os_features=['TDX_CAPABLE', 'UEFI_COMPATIBLE', 'GVNIC'],
                               licenses=['https://example.test/ubuntu-license'])
        path.write_text(json.dumps(self.deployment))
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        env = patch.dict(os.environ, {'GCP_PROJECT_ID': 'cypherpunklabs', 'GCP_IMAGE_BUCKET': 'images-test',
                         'GITHUB_SHA': COMMIT, 'WORKFLOW_COMMIT': COMMIT, 'GITHUB_REPOSITORY': REPOSITORY,
                         'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': '10', 'GITHUB_RUN_ATTEMPT': '2',
                         'GITHUB_STEP_SUMMARY': str(self.root / 'summary')})
        env.start()
        self.addCleanup(env.stop)

    def test_both_images_registered_only_after_verification(self):
        events = []
        def run(*args, **kwargs):
            events.append(args)
        def verify(*args):
            events.append(('verified-deployment',))
        def describe(command):
            name = command[4]
            return json.dumps({'id': '123', 'selfLink': 'https://example.test/' + name, 'status': 'READY',
                               'guestOsFeatures': [{'type': x} for x in self.deployment['guest_os_features']],
                               'licenses': self.deployment['licenses']}).encode()
        with patch.object(publisher, 'run', side_effect=run), \
                patch.object(publisher, 'verify_deployment', side_effect=verify), \
                patch.object(publisher.subprocess, 'check_output', side_effect=describe):
            publisher.main()
        create = [event for event in events if event[:4] == ('gcloud', 'compute', 'images', 'create')]
        self.assertEqual(len(create), 2)
        self.assertLess(events.index(('verified-deployment',)), events.index(create[0]))
        self.assertIn('--source-uri=gs://images-test/ada-proxy/' + COMMIT + '/10-2/deployment-gcp.tar.gz', create[0])
        self.assertIn('--source-uri=gs://images-test/ada-proxy/' + COMMIT + '/10-2/workload-disk.tar.gz', create[1])
        self.assertTrue(any(arg.startswith('--guest-os-features=') for arg in create[0]))
        self.assertFalse(any(arg.startswith('--guest-os-features=') for arg in create[1]))
        upload = [event for event in events if event[:3] == ('gcloud', 'storage', 'cp')]
        self.assertTrue(all('--if-generation-match=0' in event for event in upload))
        record = json.loads(Path('dist/gcp-images.json').read_text())
        self.assertEqual(set(record['images']), {'boot', 'workload'})
        self.assertFalse(record['hardware_boot_verified'])

    def test_failed_signature_performs_no_google_mutation(self):
        with patch.object(publisher, 'run', side_effect=ValueError('signature rejected')) as run:
            with self.assertRaisesRegex(ValueError, 'signature rejected'):
                publisher.main()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], 'gh')

    def test_missing_boot_features_never_returns_ready_deployment(self):
        Path('dist/gcp-images.json').unlink()
        response = {'id': '123', 'selfLink': 'https://example.test/image', 'status': 'READY',
                    'guestOsFeatures': [], 'licenses': []}
        with patch.object(publisher, 'run'), patch.object(publisher, 'verify_deployment'), \
                patch.object(publisher.subprocess, 'check_output', return_value=json.dumps(response).encode()):
            with self.assertRaisesRegex(ValueError, 'boot image features missing'):
                publisher.main()
        self.assertFalse(Path('dist/gcp-images.json').exists())


if __name__ == '__main__':
    unittest.main()
