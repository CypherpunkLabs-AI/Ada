"""Load public release proofs without treating supplied signatures as trusted.

CI and independent clients authenticate Sigstore signatures. These checks bind
the supplied files to each other and to the workload embedded in the boot image.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIMITS = {'release.json': 256 * 1024, 'image-release.json': 512 * 1024,
          'release.sigstore.json': 256 * 1024}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_release_proof(directory, expected_release=None):
    files = {}
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, limit in LIMITS.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            with os.fdopen(fd, 'rb') as source:
                require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), name + ' must be a regular file')
                raw = source.read(limit + 1)
            require(0 < len(raw) <= limit, name + ' is empty or exceeds its size limit')
            # All evidence is sent as exact UTF-8 strings, never reserialized.
            raw.decode('utf-8')
            files[name] = raw
    finally:
        os.close(directory_fd)

    release_bytes = files['release.json']
    if expected_release is not None:
        require(release_bytes == expected_release, 'release proof does not match the embedded workload')
    release = json.loads(release_bytes)
    image = json.loads(files['image-release.json'])
    require(release['schema'] == 1 and release['profile'] == 'hiro.gcp-tdx.v1', 'unsupported workload proof')
    require(image['schema'] == 1 and image['profile'] == 'hiro.gcp-tdx.boot.v1', 'unsupported image proof')
    commit = release['source_commit']
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit)
            and image['source_commit'] == commit, 'release proof source commit mismatch')
    require(image['workload_release_sha256'] == hashlib.sha256(release_bytes).hexdigest(),
            'image proof does not identify the exact workload bytes')
    event = hashlib.sha384(b'hiro.release.v1\0' + release_bytes).digest()
    require(image['application_rtmr3'] == hashlib.sha384(bytes(48) + event).hexdigest(),
            'image proof application measurement mismatch')

    bundle = json.loads(files['release.sigstore.json'])
    envelope = bundle['dsseEnvelope']
    require(envelope['payloadType'] == 'application/vnd.in-toto+json', 'unsupported Sigstore payload')
    require(isinstance(envelope['signatures'], list) and envelope['signatures']
            and isinstance(bundle['verificationMaterial'], dict) and bundle['verificationMaterial'],
            'missing Sigstore verification material')
    statement = json.loads(base64.b64decode(envelope['payload'], validate=True))
    for name in ('release.json', 'image-release.json'):
        matching = [subject for subject in statement['subject'] if subject['name'] == name]
        require(len(matching) == 1 and matching[0]['digest']['sha256'] == hashlib.sha256(files[name]).hexdigest(),
                'Sigstore subject mismatch: ' + name)
    return files


def stage_release_proof(directory, destination, expected_release):
    """Copy only the allowlisted public files to the guest's volatile evidence mount."""
    files = load_release_proof(directory, expected_release)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o755)
    for name, raw in files.items():
        temporary = destination / (name + '.tmp')
        # A previous service start may have left immutable-permission files.
        temporary.unlink(missing_ok=True)
        with temporary.open('xb') as output:
            output.write(raw)
        temporary.chmod(0o444)
        temporary.replace(destination / name)
    return files
