#!/usr/bin/python3
"""Start the proxy workload authenticated by the selected OS loader."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from release_proof import stage_release_proof

ROOT = Path(__file__).resolve().parent
EXTEND = '/usr/lib/ada-image/tdx-extend'
REPORT = Path('/sys/kernel/config/tsm/report/ada-proxy')


def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)


def quote():
    challenge = os.urandom(64)
    (REPORT / 'inblob').write_bytes(challenge)
    raw = (REPORT / 'outblob').read_bytes()
    # TDX quote v4, TDREPORT10. Unsupported formats fail closed.
    if len(raw) < 632 or raw[:2] != b'\x04\x00' or raw[4:8] != b'\x81\x00\x00\x00':
        raise ValueError('unsupported TDX quote')
    if raw[568:632] != challenge:
        raise ValueError('TDX startup challenge mismatch')
    if raw[168] & 1:
        raise ValueError('debug TDX guest')
    return raw[520:568]


def main():
    run('swapoff', '--all')
    if any(line.strip() for line in Path('/proc/swaps').read_text().splitlines()[1:]):
        raise ValueError('swap must be disabled before starting Ada')
    release_bytes = (ROOT / 'release.json').read_bytes()
    release = json.loads(release_bytes)
    for file, key in [('compose.yaml', 'compose_sha256'), ('images.lock.json', 'image_lock_sha256')]:
        if hashlib.sha256((ROOT / file).read_bytes()).hexdigest() != release[key]:
            raise ValueError('embedded release mismatch: ' + file)
    assets = json.loads((ROOT / 'assets.json').read_text())
    for name, expected in assets.items():
        h = hashlib.sha256()
        with (ROOT / name).open('rb') as f:
            for block in iter(lambda: f.read(1024 * 1024), b''):
                h.update(block)
        if h.hexdigest() != expected:
            raise ValueError('embedded asset mismatch: ' + name)
    run(EXTEND, '-help', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('TDX measurement helper executable verified', flush=True)
    run('modprobe', 'configfs')
    if not os.path.ismount('/sys/kernel/config'):
        run('mount', '-t', 'configfs', 'configfs', '/sys/kernel/config')
    subprocess.run(['modprobe', 'tdx_guest'], check=False)
    evidence = Path('/run/ada/attestation')
    evidence.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(evidence.parent, 0o755)
    os.chmod(evidence, 0o755)
    # Host tmpfs survives container restarts; VM shutdown destroys all TLS state.
    # noswap also prevents tmpfs private-key pages from reaching a swap device.
    tls_cache = evidence.parent / 'tls'
    tls_cache.mkdir(exist_ok=True, mode=0o700)
    if not os.path.ismount(tls_cache):
        run('mount', '-t', 'tmpfs', '-o',
            'noswap,nosuid,nodev,noexec,size=4M,mode=0700,uid=65532,gid=65532',
            'tmpfs', str(tls_cache))
    report_mount = evidence.parent / 'tdx-report'
    report_mount.mkdir(exist_ok=True, mode=0o755)
    proof = stage_release_proof('/mnt/config/release-proof', evidence, release_bytes)
    image_release = json.loads(proof['image-release.json'])
    root_parameter = 'roothash=' + image_release['boot']['dm_verity_root_hash']
    if root_parameter not in Path('/proc/cmdline').read_text().split():
        raise ValueError('release proof does not match the booted root filesystem')
    workload_parameter = 'ada-image.workload_sha256=' + image_release['workload_sha256']
    if (workload_parameter not in Path('/proc/cmdline').read_text().split()
            or image_release['workload_sha256'] != os.environ['ADA_IMAGE_WORKLOAD_SHA256']):
        raise ValueError('release proof does not match the measured workload archive')
    print('Public release proofs matched to measured workload and boot root', flush=True)
    if Path('/sys/firmware/acpi/tables/CCEL').exists():
        REPORT.mkdir(exist_ok=True)
        if (REPORT / 'provider').read_text().strip() != 'tdx_guest':
            raise ValueError('TDX provider unavailable')
        event = b'ada.release.v1\0' + release_bytes
        expected = hashlib.sha384(bytes(48) + hashlib.sha384(event).digest()).digest()
        current = quote()
        if current == bytes(48):
            run(EXTEND, '-rtmr=3', input=event)
        elif current != expected:
            raise ValueError('RTMR3 already contains a different release; boot a new VM')
        if quote() != expected:
            raise ValueError('RTMR3 extension failed')
        shutil.copyfile('/sys/firmware/acpi/tables/data/CCEL', evidence / 'ccel.bin')
        os.chmod(evidence / 'ccel.bin', 0o444)
        for name in ['inblob', 'outblob', 'generation', 'provider']:
            os.chown(REPORT / name, 65532, 65532)
        os.chmod(REPORT, 0o755)
        if not os.path.ismount(report_mount):
            run('mount', '--bind', str(REPORT), str(report_mount))
    else:
        raise ValueError('TDX CCEL required before starting the proxy')
    run('docker', 'load', '--input', str(ROOT / 'proxy.tar'))
    image_id = (ROOT / 'proxy-image-id').read_text().strip()
    config = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image_id]))[0]
    if config['Id'] != image_id:
        raise ValueError('loaded container identity mismatch')
    # docker save/load does not preserve registry RepoDigests. Use the exact
    # content-addressed config ID recorded at build time, never a tag or pull.
    override = {'services': {'ada-proxy': {'image': image_id, 'pull_policy': 'never'}}}
    (evidence.parent / 'container.json').write_text(json.dumps(override))
    # The service env_file reads /mnt/config/secrets.env. Disable automatic
    # .env loading so deployment secrets never participate in YAML interpolation.
    run('docker', 'compose', '--project-name', 'ada', '--env-file', '/dev/null',
        '-f', str(ROOT / 'compose.yaml'), '-f', str(evidence.parent / 'container.json'),
        'up', '-d', '--pull', 'never', '--no-build')
    print('Ada proxy release started', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Ada startup failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
