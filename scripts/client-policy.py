#!/usr/bin/env python3
"""Authenticate selected Hiro releases and publish client authorization metadata.

All approvals originate in reviewed client-policy/production.json. Downloads
never add approvals. No secrets or private signing keys are stored here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def download(repository, version, directory, names):
    require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version), 'explicit version required')
    directory.mkdir(parents=True, exist_ok=True)
    if all((directory / n).is_file() for n in names):
        return
    command = ['gh', 'release', 'download', version, '--repo', repository, '--dir', directory, '--clobber']
    for name in names:
        command += ['--pattern', name]
    run(*command)


def authenticate(artifact, bundle, publisher, commit, ref):
    require(re.fullmatch('[0-9a-f]{40}', commit), 'invalid source commit')
    result = run('gh', 'attestation', 'verify', artifact, '--bundle', bundle,
        '--repo', publisher['repository'], '--signer-workflow', publisher['repository'] + '/' + publisher['workflow'],
        '--signer-digest', commit, '--source-digest', commit, '--source-ref', ref,
        '--predicate-type', 'https://slsa.dev/provenance/v1', '--deny-self-hosted-runners',
        '--custom-trusted-root', ROOT / 'client-policy/trusted-root.json', '--format', 'json',
        stdout=subprocess.PIPE, text=True)
    # gh checks signatures, repository/workflow/source and log proofs. The client
    # additionally pins numeric source-repository identities and checkpoint origin.
    require(bool(json.loads(result.stdout)), 'empty verification result')


def qualification(directory, manifest, profile):
    archive = directory / 'platform-evidence.tar.gz'
    expected = manifest['files']['platform-evidence.tar.gz']
    require(sha(archive) == expected['sha256'] and archive.stat().st_size == expected['size'],
            'qualification archive differs from signed OS manifest')
    contents = {}
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            name = Path(member.name).name
            if name not in ('intel-quote-verification.json', 'intel-collateral.json'):
                continue
            require(member.isfile() and member.size <= 1024 * 1024 and name not in contents,
                    'invalid qualification evidence')
            contents[name] = tar.extractfile(member).read()
    for name, data in contents.items():
        require(hashlib.sha256(data).hexdigest() == profile['evidence']['files'][name],
                'qualification evidence differs from qualified profile')
    verified = json.loads(contents['intel-quote-verification.json'])
    require(verified['status'] == 'UpToDate' and not verified['advisory_ids'], 'unapproved reference TCB')
    collateral = json.loads(contents['intel-collateral.json'])
    return verified['report']['TD10'], min(json.loads(collateral['tcb_info'])['tcbEvaluationDataNumber'],
                                         json.loads(collateral['qe_identity'])['tcbEvaluationDataNumber'])


def prepare(args):
    config = read(args.approvals)
    require(os.environ['GITHUB_REPOSITORY'] == config['policy_repository'], 'wrong policy repository')
    workflow_commit = os.environ['GITHUB_WORKFLOW_SHA']
    policy_ref = os.environ['GITHUB_REF']
    require(re.fullmatch('[0-9a-f]{40}', workflow_commit) and policy_ref.startswith(('refs/heads/', 'refs/tags/')),
            'policy must have an authenticated workflow revision/ref')
    publishers = config['publishers']
    approved = []
    release_publisher = os_publisher = None
    for item in config['approved_releases']:
        directory = args.work / item['tag']
        download(publishers['hiro']['repository'], item['tag'], directory,
                 ['release.json', 'image-release.json', 'release.sigstore.json'])
        require(sha(directory / 'release.json') == item['release_sha256']
                and sha(directory / 'image-release.json') == item['image_release_sha256'],
                'release is not the reviewed approval')
        release = read(directory / 'release.json')
        image = read(directory / 'image-release.json')
        require(release['source_commit'] == item['source_commit'] and release['tag'] == item['tag'],
                'approved release source/version mismatch')
        for name in ('release.json', 'image-release.json'):
            authenticate(directory / name, directory / 'release.sigstore.json', publishers['hiro'],
                         item['source_commit'], 'refs/heads/main')
        require(image['workload_release_sha256'] == item['release_sha256']
                and image['source_commit'] == item['source_commit'], 'workload/boot image mismatch')
        os_directory = args.work / ('os-' + release['os_version'])
        download(publishers['hiro-image']['repository'], release['os_version'], os_directory,
                 ['os-release.json', 'os-release.sigstore.json', 'gcp-tdx-platform-profile.json', 'platform-evidence.tar.gz'])
        os_manifest = read(os_directory / 'os-release.json')
        authenticate(os_directory / 'os-release.json', os_directory / 'os-release.sigstore.json',
                     publishers['hiro-image'], os_manifest['source_commit'], 'refs/tags/' + release['os_version'])
        require(image['os_release_manifest'].encode() == (os_directory / 'os-release.json').read_bytes(),
                'application selected a different OS release')
        profile_path = os_directory / 'gcp-tdx-platform-profile.json'
        require(sha(profile_path) == os_manifest['files'][profile_path.name]['sha256'], 'OS profile digest mismatch')
        profile = read(profile_path)
        appraisal = image['deployment']['platform_appraisal']
        require(appraisal['status'] == 'included' and appraisal['profile_sha256'] == sha(profile_path)
                and appraisal['quote_requirements'] == profile['quote_requirements'], 'unqualified deployment profile')
        report, evaluation = qualification(os_directory, os_manifest, profile)
        platform = {name: image['expected_measurements'][name] for name in ('mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3')}
        for name in ('mr_seam', 'mr_signer_seam', 'mr_config_id', 'mr_owner', 'mr_owner_config',
                     'td_attributes', 'seam_attributes', 'xfam'):
            platform[name] = report[name]
        platform.update(minimum_tee_tcb_svn=report['tee_tcb_svn'], minimum_tcb_evaluation=evaluation,
                        allowed_advisories=profile['quote_requirements']['allowed_advisory_ids'])
        for name in ('allow_smt', 'allow_dynamic_platform', 'allow_cached_keys'):
            require(type(item[name]) is bool, 'explicit platform flag decision required')
            platform[name] = item[name]
        approved.append({'release_sha256': item['release_sha256'], 'image_release_sha256': item['image_release_sha256'],
                         'release_workflow_commit': item['source_commit'],
                         'os_workflow_commit': os_manifest['workflow_commit'],
                         'sequence': item['sequence'], 'platform': platform})
        rp = dict(publishers['hiro'], workflow_commit=item['source_commit'])
        op = dict(publishers['hiro-image'], workflow_commit=os_manifest['workflow_commit'])
        # The bootstrap fixes publisher identities. Each signed approval pins
        # its own exact revisions, allowing reviewed upgrades without changing
        # the client's policy authority or trusting a server-selected revision.
        if release_publisher is None:
            release_publisher, os_publisher = rp, op
    require(approved, 'retain the release descriptors when revoking; revocation wins over approval')
    revoked = list(config['revoked_releases'])
    now = int(time.time())
    sequence = int(os.environ['GITHUB_RUN_NUMBER']) * 1000 + int(os.environ['GITHUB_RUN_ATTEMPT'])
    policy = {'schema': 1, 'policy_id': config['policy_id'], 'sequence': sequence,
              'issued_at': now, 'expires_at': now + 48 * 3600,
              'minimum_release_sequence': config['minimum_release_sequence'],
              'approved_releases': [a['release_sha256'] for a in approved], 'revoked_releases': sorted(set(revoked)),
              'platforms': [], 'kms': [], 'gcp_releases': approved}
    publisher = dict(publishers['hiro'], workflow=config['policy_workflow'], workflow_commit=workflow_commit)
    trust = {name: config[name] for name in ('policy_id', 'service', 'workload_subject', 'max_policy_age_seconds',
                                            'max_challenge_age_seconds', 'max_recipient_age_seconds')}
    trust.update(schema=1, recipient='oak-session-v1-ed25519', trust_root_sha256=sha(ROOT / 'client-policy/trusted-root.json'),
                 minimum_policy_sequence=sequence, minimum_release_sequence=policy['minimum_release_sequence'],
                 not_before=now, not_after=now + 365 * 86400, policy_ref=policy_ref,
                 policy_publisher=publisher, release_publisher=release_publisher,
                 checkpoint_origins=read(ROOT / 'client-policy/checkpoint-origins.json'),
                 gcp={'release_ref': 'refs/heads/main', 'os_publisher': os_publisher})
    args.output.mkdir(parents=True, exist_ok=True)
    write(args.output / 'policy.json', policy)
    write(args.output / 'trust-config.json', trust)
    shutil.copyfile(ROOT / 'client-policy/trusted-root.json', args.output / 'trusted-root.json')
    write(args.output / 'client-bootstrap.json', {'endpoint': config['endpoint'],
        'policy_url': config['endpoint'].replace('wss:', 'https:').replace('/v1/session', '/v1/verification-policy'),
        'trusted_config': trust, 'trusted_roots': (args.output / 'trusted-root.json').read_text()})


def seal(args):
    config = read(args.output / 'trust-config.json')
    publisher = config['policy_publisher']
    bundle = Path(os.environ['POLICY_BUNDLE'])
    for name in ('policy.json', 'client-bootstrap.json'):
        authenticate(args.output / name, bundle, publisher, publisher['workflow_commit'], config['policy_ref'])
    shutil.copyfile(bundle, args.output / 'policy.sigstore.json')
    write(args.output / 'policy-envelope.json', {'artifact': (args.output / 'policy.json').read_text(),
                                               'bundle': bundle.read_text()})
    print('Authenticated policy and client bootstrap prepared in ' + str(args.output))


def select(args):
    """Prepare a reviewable approval change; never sign or publish it here."""
    require(args.release and args.sequence and args.sequence > 0,
            'select requires --release vX.Y.Z and a positive --sequence')
    config = read(args.approvals)
    publisher = config['publishers']['hiro']
    directory = args.work / args.release
    download(publisher['repository'], args.release, directory,
             ['release.json', 'image-release.json', 'release.sigstore.json'])
    release = read(directory / 'release.json')
    image = read(directory / 'image-release.json')
    commit = release['source_commit']
    require(release['tag'] == args.release, 'release version mismatch')
    # Resolve the explicitly selected tag, including annotated tags, and require
    # its commit to match both the signed source and signed workflow revision.
    resolved = run('gh', 'api', 'repos/' + publisher['repository'] + '/commits/' + args.release,
                   '--jq', '.sha', stdout=subprocess.PIPE, text=True).stdout.strip()
    require(commit == resolved, 'release tag/source mismatch')
    for name in ('release.json', 'image-release.json'):
        authenticate(directory / name, directory / 'release.sigstore.json', publisher,
                     commit, 'refs/heads/main')
    require(image['workload_release_sha256'] == sha(directory / 'release.json')
            and image['source_commit'] == commit, 'release/boot manifest mismatch')
    require(sha(directory / 'release.json') not in config['revoked_releases'],
            'cannot reapprove a revoked release')
    require(args.sequence >= config['minimum_release_sequence'], 'release below rollback floor')
    require(args.sequence > max((item['sequence'] for item in config['approved_releases']), default=0),
            'new release sequence must increase')
    require(all(item['tag'] != args.release and item['sequence'] != args.sequence
                for item in config['approved_releases']), 'version or sequence already selected')
    # Retain old approvals for an overlap during deployment. Raise the minimum
    # sequence or add old digests to revoked_releases in the same reviewed file.
    config['approved_releases'].append({
        'tag': args.release, 'sequence': args.sequence, 'source_commit': commit,
        'release_sha256': sha(directory / 'release.json'),
        'image_release_sha256': sha(directory / 'image-release.json'),
        'allow_smt': True, 'allow_dynamic_platform': False, 'allow_cached_keys': False,
    })
    write(args.approvals, config)
    print('Updated ' + str(args.approvals) + '; review and commit before running Client release approval.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'seal', 'select'])
    parser.add_argument('--release', help='Explicit published application version for select')
    parser.add_argument('--sequence', type=int, help='Increasing application release sequence for select')
    parser.add_argument('--approvals', type=Path, default=ROOT / 'client-policy/production.json')
    parser.add_argument('--work', type=Path, default=Path('policy-work'))
    parser.add_argument('--output', type=Path, default=Path('policy-dist'))
    args = parser.parse_args()
    {'prepare': prepare, 'seal': seal, 'select': select}[args.command](args)
