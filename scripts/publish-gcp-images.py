#!/usr/bin/env python3
"""Register the signed deployment's boot and workload disks; never create a VM."""
import json
import os
from pathlib import Path
import re
import subprocess
from deployment import digest, require, run, verify_deployment, write_json


def main():
    directory = Path('dist')
    project, bucket = os.environ['GCP_PROJECT_ID'], os.environ['GCP_IMAGE_BUCKET']
    require(re.fullmatch('[a-z][a-z0-9-]{4,61}[a-z0-9]', project), 'invalid GCP project')
    require(re.fullmatch('[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]', bucket), 'invalid bucket name')
    entry = json.loads((directory / 'images.lock.json').read_text())['services']['hiro-proxy']
    commit, repository = os.environ['GITHUB_SHA'], os.environ['GITHUB_REPOSITORY']
    require(entry['source_commit'] == commit == os.environ['WORKFLOW_COMMIT']
            and entry['source_repository'] == repository and os.environ['GITHUB_REF'] == 'refs/heads/main',
            'publication must belong to this main workflow')
    for name in ('release.json', 'image-release.json', 'deployment.json'):
        run('gh', 'attestation', 'verify', directory / name, '--bundle', directory / 'release.sigstore.json',
            '--repo', repository, '--signer-workflow', repository + '/.github/workflows/ci.yml',
            '--signer-digest', commit, '--source-digest', commit, '--source-ref', 'refs/heads/main',
            '--predicate-type', 'https://slsa.dev/provenance/v1', '--deny-self-hosted-runners')
    verify_deployment(directory, entry)
    deployment = json.loads((directory / 'deployment.json').read_text())
    attempt = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    require(re.fullmatch('[0-9]+-[0-9]+', attempt), 'invalid workflow run/attempt')
    prefix = f'gs://{bucket}/hiro-proxy/{commit}/{attempt}'
    images = {}
    for kind, archive in [('boot', 'deployment-gcp.tar.gz'), ('workload', 'workload-disk.tar.gz')]:
        name = f'hiro-proxy-{kind}-{commit[:12]}-{attempt}'
        require(len(name) <= 63, 'GCP image name too long')
        uri = prefix + '/' + archive
        run('gcloud', 'storage', 'cp', '--if-generation-match=0', directory / archive, uri)
        flags = []
        if kind == 'boot':
            flags = ['--guest-os-features=' + ','.join(deployment['guest_os_features']),
                     '--licenses=' + ','.join(deployment['licenses'])]
        run('gcloud', 'compute', 'images', 'create', name, '--project=' + project,
            '--source-uri=' + uri, '--architecture=X86_64', '--storage-location=us', *flags,
            '--description=Hiro proxy ' + entry['release_tag'] + ' ' + kind,
            '--labels=application=hiro-proxy,source-commit=' + commit, '--quiet')
        result = json.loads(subprocess.check_output([
            'gcloud', 'compute', 'images', 'describe', name, '--project=' + project, '--format=json']))
        require(result['status'] == 'READY', kind + ' image is not READY')
        if kind == 'boot':
            require(set(deployment['guest_os_features']) <= {x['type'] for x in result['guestOsFeatures']}
                    and set(deployment['licenses']) <= set(result.get('licenses', [])), 'boot image features missing')
        images[kind] = {'name': name, 'image_id': result['id'], 'self_link': result['selfLink'],
                        'status': result['status'], 'archive_uri': uri, 'archive_sha256': digest(directory / archive)}
    record = {'schema': 1, 'project': project, 'source_commit': commit, 'release_tag': entry['release_tag'],
              'deployment_sha256': digest(directory / 'deployment.json'), 'images': images,
              'hardware_boot_verified': False}
    write_json(directory / 'gcp-images.json', record)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write('\nRegistered GCP images (boot and workload must be deployed together):\n\n')
        for kind, image in images.items():
            summary.write(f'- {kind}: `{image["name"]}`\n')


if __name__ == '__main__':
    main()
