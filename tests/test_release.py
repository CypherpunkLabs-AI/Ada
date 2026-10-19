import copy
from deployment_fixture import deployment_assets
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import release

spec = importlib.util.spec_from_file_location("metadata", SCRIPTS / "write-image-metadata.py")
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)

REPOSITORY = "Example/Proxy"
COMMIT = "a" * 40
TAG = "v2.7.9"
DIGEST = "sha256:" + "b" * 64


def cargo_files(root, version="2.7.9", locked=None):
    (root / "Cargo.toml").write_text(f'[package]\nname = "ada-proxy"\nversion = "{version}"\n')
    (root / "Cargo.lock").write_text(
        f'[[package]]\nname = "ada-proxy"\nversion = "{version if locked is None else locked}"\n')


def assets(root, tag=TAG, commit=COMMIT):
    root.mkdir(exist_ok=True)
    entry = {
        "release_tag": tag, "source_commit": commit, "workflow_commit": commit,
        "source_repository": REPOSITORY, "source_ref": "refs/heads/main",
        "build_workflow": ".github/workflows/ci.yml", "runtime_profile": "ada.gcp-tdx.v1",
        "image": "ghcr.io/example/proxy", "digest": DIGEST,
    }
    (root / "images.lock.json").write_text(json.dumps({"schema": 1, "services": {"ada-proxy": entry}}))
    for name in ["image.sigstore.json", "images.lock.sigstore.json"]:
        (root / name).write_text("test signature bundle")
    (root / "image-ref.txt").write_text(entry["image"] + "@" + DIGEST + "\n")
    (root / "image-digest.txt").write_text(DIGEST + "\n")
    (root / "release-notes.md").write_text("Example release\n")
    deployment_assets(root, entry)
    (root / "SHA256SUMS").write_text(release.checksums(root))
    return entry


class FakeGitHub:
    repository = REPOSITORY

    def __init__(self, source):
        self.source = source
        self.target = None
        self.record = None
        self.events = []
        self.corrupt_download = False

    def release(self, tag):
        return copy.deepcopy(self.record)

    def tag_commit(self, tag):
        return self.target

    def download(self, tag, directory):
        self.events.append("download")
        for name in release.ASSETS:
            shutil.copyfile(self.source / name, directory / name)
        if self.corrupt_download:
            (directory / "image-digest.txt").write_text("corrupt")

    def api(self, method, path, data=None, **kwargs):
        self.events.append((method, path))
        if (method, path) == ("POST", "git/refs"):
            if self.target is not None:
                raise RuntimeError("tag already exists")
            self.target = data["sha"]
            return {}
        if (method, path) == ("POST", "releases"):
            self.record = dict(data, id=1)
            return copy.deepcopy(self.record)
        if (method, path) == ("GET", "releases/1"):
            return copy.deepcopy(self.record)
        if (method, path) == ("PATCH", "releases/1"):
            self.record.update(data)
            return copy.deepcopy(self.record)
        raise AssertionError((method, path, data))


class Versions(unittest.TestCase):
    def test_uses_manual_version_without_incrementing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ["2.7.9", "0.3.0", "3.0.0-rc.1"]:
                with self.subTest(version=version):
                    cargo_files(root, version)
                    self.assertEqual(release.version_tag(root), "v" + version)

    def test_rejects_mismatched_cargo_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            cargo_files(Path(directory), "2.7.9", "2.7.8")
            with self.assertRaisesRegex(ValueError, "Cargo.lock"):
                release.version_tag(Path(directory))

    def test_rejects_invalid_release_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            for version in ["02.7.9", "2.7", "2.7.9-01", "2.7.9+build"]:
                with self.subTest(version=version):
                    cargo_files(Path(directory), version)
                    with self.assertRaises(ValueError):
                        release.version_tag(Path(directory))


class GitHubAPI(unittest.TestCase):
    def test_only_404_is_treated_as_a_missing_tag(self):
        github = release.GitHub(REPOSITORY)
        with patch.dict(os.environ, {"GH_TOKEN": "unit-test-token"}):
            for status in [401, 403, 404, 500]:
                with self.subTest(status=status):
                    error = HTTPError("https://api.github.com/test", status, "test error", {}, None)
                    with patch.object(release, "urlopen", side_effect=error):
                        if status == 404:
                            self.assertIsNone(github.tag_commit(TAG))
                        else:
                            with self.assertRaises(RuntimeError):
                                github.tag_commit(TAG)

    def test_resolves_annotated_tag_to_commit(self):
        github = release.GitHub(REPOSITORY)
        with patch.object(github, "api", side_effect=[
            {"object": {"type": "tag", "sha": "c" * 40}},
            {"object": {"type": "commit", "sha": COMMIT}},
        ]):
            self.assertEqual(github.tag_commit(TAG), COMMIT)

    def test_release_discovery_includes_paginated_drafts(self):
        github = release.GitHub(REPOSITORY)
        draft = {"tag_name": TAG, "draft": True}
        with patch.object(github, "api", side_effect=[
            [{"tag_name": "v1.0.0", "draft": False}] * 100, [draft],
        ]) as api:
            self.assertEqual(github.release(TAG), draft)
            self.assertEqual(api.call_args_list[1].args, ("GET", "releases?per_page=100&page=2"))


class Publication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        assets(self.dist)
        self.github = FakeGitHub(self.dist)
        self.environment = patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(self.root / "summary")})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.runner = patch.object(release.subprocess, "run")
        self.run = self.runner.start()
        self.addCleanup(self.runner.stop)

    def test_first_release_tags_tested_commit_and_publishes_after_upload_verification(self):
        self.assertTrue(release.should_publish(self.github, TAG, COMMIT))
        release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertEqual(self.github.target, COMMIT)
        self.assertFalse(self.github.record["draft"])
        self.assertLess(self.github.events.index("download"), self.github.events.index(("PATCH", "releases/1")))
        sums = (self.dist / "SHA256SUMS").read_text()
        self.assertIn("images.lock.sigstore.json", sums)
        self.assertIn("image.sigstore.json", sums)
        commands = [call.args[0] for call in self.run.call_args_list]
        verifications = [command for command in commands if command[1:3] == ["attestation", "verify"]]
        self.assertEqual(len(verifications), 7)
        for command in verifications[:-1]:
            self.assertEqual(command[command.index("--source-ref") + 1], "refs/heads/main")
            self.assertEqual(command[command.index("--source-digest") + 1], COMMIT)
            self.assertIn("--deny-self-hosted-runners", command)

    def test_published_version_is_verified_and_skipped_for_later_main_commit(self):
        self.github.target = COMMIT
        self.github.record = {"id": 1, "draft": False, "tag_name": TAG, "target_commitish": COMMIT}
        self.assertFalse(release.should_publish(self.github, TAG, "c" * 40))
        self.assertFalse(any(isinstance(event, tuple) for event in self.github.events))
        self.assertEqual(len(self.run.call_args_list), 7)

    def test_retry_never_overwrites_published_release(self):
        release.publish(self.github, TAG, COMMIT, self.dist)
        self.github.events.clear()
        self.run.reset_mock()
        release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertFalse(any(isinstance(event, tuple) for event in self.github.events))
        self.assertFalse(any(call.args[0][1:3] == ["release", "upload"] for call in self.run.call_args_list))

    def test_interrupted_upload_keeps_draft_and_retry_reuses_tag(self):
        def fail_upload(command, **kwargs):
            if command[1:3] == ["release", "upload"]:
                raise subprocess.CalledProcessError(1, command)
        self.run.side_effect = fail_upload
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertTrue(self.github.record["draft"])
        self.run.side_effect = None
        release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertFalse(self.github.record["draft"])
        self.assertEqual(self.github.events.count(("POST", "git/refs")), 1)
        self.assertEqual(self.github.events.count(("POST", "releases")), 1)

    def test_conflicting_tag_fails_without_mutation(self):
        self.github.target = "c" * 40
        with self.assertRaisesRegex(ValueError, "another commit"):
            release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertEqual(self.github.events, [])

    def test_failed_signature_prevents_tag_creation(self):
        self.run.side_effect = subprocess.CalledProcessError(1, ["gh", "attestation", "verify"])
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertIsNone(self.github.target)
        self.assertIsNone(self.github.record)

    def test_corrupt_upload_does_not_publish_draft(self):
        self.github.corrupt_download = True
        with self.assertRaisesRegex(ValueError, "Uploaded release asset differs"):
            release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertTrue(self.github.record["draft"])

    def test_signed_metadata_must_bind_the_selected_version(self):
        assets(self.dist, tag="v9.0.0")
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            release.publish(self.github, TAG, COMMIT, self.dist)
        self.assertIsNone(self.github.target)

    def test_prerelease_uses_declared_version(self):
        tag = "v3.0.0-rc.2"
        assets(self.dist, tag=tag)
        release.publish(self.github, tag, COMMIT, self.dist)
        self.assertEqual(self.github.record["tag_name"], tag)
        self.assertTrue(self.github.record["prerelease"])

    def test_metadata_writer_binds_manual_version_and_current_build(self):
        cargo_files(self.root)
        bundle = self.root / "bundle.json"
        bundle.write_text("test bundle")
        environment = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": COMMIT,
                       "GITHUB_REF": "refs/heads/main", "WORKFLOW_COMMIT": COMMIT,
                       "IMAGE": "ghcr.io/example/proxy", "DIGEST": DIGEST, "RELEASE_TAG": TAG,
                       "PROVENANCE_BUNDLE": str(bundle)}
        original = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.dict(os.environ, environment):
                metadata.main()
        finally:
            os.chdir(original)
        document = json.loads((self.dist / "images.lock.json").read_text())
        self.assertEqual(document["services"]["ada-proxy"]["release_tag"], TAG)
        self.assertEqual(document["services"]["ada-proxy"]["digest"], DIGEST)


if __name__ == "__main__":
    unittest.main()
