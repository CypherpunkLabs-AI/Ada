import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import deployment
import release
from deployment_fixture import sign_fixture
from test_release import assets


class Deployment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dist = self.root / 'dist'
        self.entry = assets(self.dist)

    def test_full_deployment_hash_chain_and_os_signing_identity(self):
        with patch.object(deployment, 'run') as run:
            deployment.verify_deployment(self.dist, self.entry)
        command = run.call_args.args
        self.assertIn(deployment.OS_REPOSITORY + '/.github/workflows/image.yml', command)
        self.assertIn('refs/tags/v0.1.0', command)
        self.assertIn('--deny-self-hosted-runners', command)

    def test_modified_workload_disk_boot_disk_or_os_proof_is_rejected(self):
        with patch.object(deployment, 'run'):
            for name in deployment.DEPLOYMENT_FILES:
                with self.subTest(name=name):
                    path = self.dist / name
                    raw = path.read_bytes()
                    path.write_bytes(raw + b'tampered')
                    with self.assertRaisesRegex(ValueError, 'artifact mismatch'):
                        deployment.verify_deployment(self.dist, self.entry)
                    path.write_bytes(raw)

    def test_signed_but_inconsistent_os_or_workload_selection_is_rejected(self):
        with patch.object(deployment, 'run'):
            for field, value in [('workload_sha256', 'f' * 64), ('os_release_manifest', '{}'),
                                 ('expected_measurements', {})]:
                with self.subTest(field=field):
                    path = self.dist / 'image-release.json'
                    original = path.read_bytes()
                    image = json.loads(original)
                    image[field] = value
                    deployment.write_json(path, image)
                    sign_fixture(self.dist)
                    with self.assertRaises(ValueError):
                        deployment.verify_deployment(self.dist, self.entry)
                    path.write_bytes(original)
                    sign_fixture(self.dist)

    def test_public_proofs_never_include_secrets(self):
        (self.dist / 'secrets.env').write_text('NEARAI_API_KEY=not-public')
        deployment.package_proof(self.dist)
        with tarfile.open(self.dist / 'release-proof.tar.gz') as archive:
            self.assertEqual(archive.getnames(), ['release-proof/' + name for name in deployment.PROOFS])
        for name in deployment.PROOFS:
            path = self.dist / name
            raw = path.read_bytes()
            path.unlink()
            path.symlink_to(self.dist / 'secrets.env')
            with self.assertRaises(OSError):
                deployment.package_proof(self.dist)
            path.unlink()
            path.write_bytes(raw)

    def test_tools_reject_symlinks_and_path_traversal(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('scripts/tool', tarfile.SYMTYPE)]:
            with self.subTest(name=name):
                archive_path = self.root / 'tools.tar.gz'
                with tarfile.open(archive_path, 'w:gz') as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                    archive.addfile(member)
                with self.assertRaisesRegex(ValueError, 'unsafe OS tools'):
                    deployment.unpack_tools(archive_path, self.root / 'tools')

    def test_os_tools_are_not_extracted_when_signature_fails(self):
        (self.root / 'image-version').write_text('v0.1.0\n')
        def download(*args, **kwargs):
            if args[1:3] == ('release', 'download'):
                shutil.copyfile(self.dist / 'os-release.json', self.root / 'os/os-release.json')
            else:
                raise ValueError('invalid OS signature')
        with patch.object(deployment, 'run', side_effect=download), patch.object(deployment, 'unpack_tools') as unpack:
            with self.assertRaisesRegex(ValueError, 'invalid OS signature'):
                deployment.select_os(self.root / 'os', self.root / 'tools', self.root)
            unpack.assert_not_called()

    def test_workload_packages_only_proxy_and_measured_launcher(self):
        checkout = self.root / 'checkout'
        checkout.mkdir()
        shutil.copytree(ROOT / 'deployment', checkout / 'deployment')
        (checkout / 'image-version').write_text('v0.1.0\n')
        (checkout / '.env').write_text('SECRET=never-package')
        reference = self.entry['image'] + '@' + self.entry['digest']
        image = {'Architecture': 'amd64', 'Os': 'linux', 'RepoDigests': [reference], 'Id': 'sha256:' + '9' * 64}
        def docker(*args, **kwargs):
            if args[:2] == ('docker', 'save'):
                self.assertEqual(args[4], image['Id'])
                Path(args[3]).write_bytes(b'docker save fixture')
        with patch.object(deployment, 'run', side_effect=docker), \
                patch.object(deployment.subprocess, 'check_output', return_value=json.dumps([image]).encode()):
            deployment.build_workload(self.dist, self.root / 'staging', checkout)
        with tarfile.open(self.dist / 'workload.tar') as archive:
            self.assertEqual(set(archive.getnames()), {'proxy.tar', 'proxy-image-id', 'compose.yaml',
                             'images.lock.json', 'release.json', 'assets.json', 'start', 'launch.py', 'release_proof.py'})
            compose = json.load(archive.extractfile('compose.yaml'))
            self.assertEqual(set(compose['services']), {'hiro-proxy'})
            service = compose['services']['hiro-proxy']
            self.assertEqual(service['ports'], ['443:8443'])
            self.assertEqual(service['environment']['HIRO_SOURCE_COMMIT'], self.entry['source_commit'])
            self.assertEqual(service['env_file'][0]['path'], '/mnt/config/secrets.env')
            self.assertEqual(service['image'], reference)
            self.assertIsNone(service['environment']['DOCUMENT_ROUTER_SOCKET'])
            self.assertNotIn('SECRET', service['environment'])
            self.assertTrue(archive.extractfile('start').read().startswith(b'#!/bin/sh'))

    def test_unversioned_os_selection_rejected(self):
        for value in ('latest', 'main', '../v0.1.0', 'v0.1.0\nv0.2.0'):
            (self.root / 'image-version').write_text(value)
            with self.assertRaises(ValueError):
                deployment.selected_version(self.root)


class GuestQuote(unittest.TestCase):
    def test_guest_rejects_debug_stale_and_unsupported_quotes(self):
        spec = importlib.util.spec_from_file_location('launcher', ROOT / 'deployment/launch.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            raw = bytearray(632)
            raw[:2], raw[4:8], raw[568:632] = b'\x04\x00', b'\x81\x00\x00\x00', b'n' * 64
            with patch.object(launcher, 'REPORT', report), patch.object(launcher.os, 'urandom', return_value=b'n' * 64):
                (report / 'outblob').write_bytes(raw)
                self.assertEqual(launcher.quote(), bytes(48))
                for offset, value in [(168, 1), (568, 0), (0, 5)]:
                    changed = raw.copy()
                    changed[offset] = value
                    (report / 'outblob').write_bytes(changed)
                    with self.assertRaises(ValueError):
                        launcher.quote()


if __name__ == '__main__':
    unittest.main()
