"""Small unsigned fixtures; signature verification is mocked explicitly by callers."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment


def sign_fixture(root):
    statement = {'subject': [{'name': name, 'digest': {'sha256': deployment.digest(root / name)}}
                            for name in ('release.json', 'image-release.json', 'deployment.json')]}
    deployment.write_json(root / 'release.sigstore.json', {
        'verificationMaterial': {'test': 'not a trusted certificate'},
        'dsseEnvelope': {'payloadType': 'application/vnd.in-toto+json',
                         'payload': base64.b64encode(json.dumps(statement).encode()).decode(),
                         'signatures': [{'sig': 'test-only'}]}})
    deployment.package_proof(root)


def deployment_assets(root, entry):
    write = deployment.write_json
    digest = deployment.digest
    reference = entry['image'] + '@' + entry['digest']
    (root / 'compose.yaml').write_text(json.dumps({'services': {'ada-proxy': {'image': reference}}}))
    write(root / 'release.json', {'schema': 1, 'profile': 'ada.gcp-tdx.v1', 'tag': entry['release_tag'],
                                 'source_commit': entry['source_commit'], 'os_version': 'v0.1.0',
                                 'containers': {'ada-proxy': reference},
                                 'compose_sha256': digest(root / 'compose.yaml'),
                                 'image_lock_sha256': digest(root / 'images.lock.json')})
    with tarfile.open(root / 'workload.tar', 'w') as archive:
        for name in ('release.json', 'compose.yaml', 'images.lock.json'):
            archive.add(root / name, arcname=name)
        start = b'#!/bin/sh\nexit 0\n'
        info = tarfile.TarInfo('start')
        info.size = len(start)
        archive.addfile(info, io.BytesIO(start))
    for name in ('deployment-gcp.tar.gz', 'deployment.efi', 'workload-disk.tar.gz'):
        (root / name).write_bytes(b'test ' + name.encode())
    write(root / deployment.PROFILE, {'test': 'qualified platform fixture'})
    base = {'kind': 'ada-image.os-release.v1', 'tag': 'v0.1.0', 'source_repository': deployment.OS_REPOSITORY,
            'source_ref': 'refs/tags/v0.1.0', 'build_workflow': '.github/workflows/image.yml',
            'source_commit': 'd' * 40, 'workflow_commit': 'd' * 40,
            'files': {deployment.PROFILE: {'sha256': digest(root / deployment.PROFILE)}}}
    write(root / 'os-release.json', base)
    (root / 'os-release.sigstore.json').write_text('mocked OS attestation')
    workload_hash = digest(root / 'workload.tar')
    cmdline = 'roothash=' + 'e' * 64 + ' ada-image.workload_sha256=' + workload_hash
    (root / 'cmdline').write_text(cmdline)
    app = {'status': 'included', 'profile_sha256': digest(root / deployment.PROFILE),
           'expected_boot': {'mrtd': 'f' * 96, 'rtmr0': '0' * 96, 'rtmr1': '1' * 96,
                             'rtmr2': '2' * 96, 'rtmr3': '0' * 96}, 'launch': {'machine_type': 'c3-standard-4'}}
    write(root / 'deployment.json', {'kind': 'ada-image.deployment.v1',
                                    'os': {'repository': deployment.OS_REPOSITORY, 'tag': 'v0.1.0',
                                           'source_commit': base['source_commit'],
                                           'manifest_sha256': digest(root / 'os-release.json')},
                                    'workload_sha256': workload_hash,
                                    'boot': {'kernel_command_line': cmdline, 'dm_verity_root_hash': 'e' * 64},
                                    'platform_appraisal': app,
                                    'files': {name: digest(root / name) for name in deployment.DEPLOYMENT_FILES}})
    deployment.finalize(root, 'v0.1.0')
    sign_fixture(root)
    images = {kind: {'status': 'READY', 'archive_sha256': digest(root / name),
                     'image_id': '123', 'self_link': 'https://example.test/' + kind}
              for kind, name in [('boot', 'deployment-gcp.tar.gz'), ('workload', 'workload-disk.tar.gz')]}
    write(root / 'gcp-images.json', {'source_commit': entry['source_commit'],
                                   'deployment_sha256': digest(root / 'deployment.json'), 'images': images})
    (root / 'gcp-images.sigstore.json').write_text('mocked GCP attestation')
