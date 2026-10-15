#!/usr/bin/env python3
"""Publish the manually declared Cargo version from its successful main build."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
from deployment import DEPLOYMENT_FILES, digest, verify_deployment


NUMBER = r"(?:0|[1-9][0-9]*)"
IDENTIFIER = rf"(?:{NUMBER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION = rf"{NUMBER}\.{NUMBER}\.{NUMBER}(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?"
ASSETS = (
    "images.lock.json", "images.lock.sigstore.json", "image.sigstore.json",
    "image-ref.txt", "image-digest.txt", "release-notes.md", "SHA256SUMS",
    *DEPLOYMENT_FILES, "compose.yaml", "release.json", "image-release.json",
    "deployment.json", "release.sigstore.json", "release-proof.tar.gz",
    "gcp-images.json", "gcp-images.sigstore.json",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version_tag(root=Path(".")):
    package = tomllib.loads((root / "Cargo.toml").read_text())["package"]
    version = package["version"]
    require(isinstance(version, str) and re.fullmatch(VERSION, version),
            "Release version must be major.minor.patch with an optional SemVer prerelease")
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    locked = [p["version"] for p in packages if p["name"] == package["name"] and "source" not in p]
    require(locked == [version], "Update the package version in Cargo.lock to match Cargo.toml")
    return "v" + version


class GitHub:
    def __init__(self, repository):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository")
        self.repository = repository

    def api(self, method, path, data=None, missing_ok=False):
        request = Request(
            f"https://api.github.com/repos/{self.repository}/{path}",
            data=None if data is None else json.dumps(data).encode(), method=method,
            headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                     "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        try:
            with urlopen(request, timeout=60) as response:
                return json.load(response)
        except HTTPError as error:
            error.close()
            if missing_ok and error.code == 404:
                return None
            raise RuntimeError(f"GitHub {method} {path} failed (HTTP {error.code})") from error

    def release(self, tag):
        # The collection includes drafts, which must be resumed rather than duplicated.
        page = 1
        while True:
            releases = self.api("GET", f"releases?per_page=100&page={page}")
            for release in releases:
                if release["tag_name"] == tag:
                    return release
            if len(releases) < 100:
                return None
            page += 1

    def tag_commit(self, tag):
        ref = self.api("GET", "git/ref/tags/" + quote(tag, safe=""), missing_ok=True)
        if ref is None:
            return None
        obj = ref["object"]
        for _ in range(10):
            if obj["type"] == "commit":
                require(re.fullmatch(r"[0-9a-f]{40}", obj["sha"]), "Invalid tag commit")
                return obj["sha"]
            require(obj["type"] == "tag", "Release tag must point to a commit")
            obj = self.api("GET", "git/tags/" + obj["sha"])["object"]
        raise ValueError("Too many nested annotated tags")

    def download(self, tag, directory):
        command = ["gh", "release", "download", tag, "--repo", self.repository, "--dir", str(directory)]
        for name in ASSETS:
            command.extend(["--pattern", name])
        subprocess.run(command, check=True)


def verify_assets(directory, repository, tag, commit):
    for name in ASSETS:
        require((directory / name).is_file() and not (directory / name).is_symlink(),
                f"Missing release asset: {name}")
    document = json.loads((directory / "images.lock.json").read_text())
    require(document.get("schema") == 1 and set(document["services"]) == {"hiro-proxy"},
            "Unexpected image metadata")
    entry = document["services"]["hiro-proxy"]
    require(entry["release_tag"] == tag and entry["source_commit"] == commit
            and entry["workflow_commit"] == commit and entry["source_repository"] == repository
            and entry["source_ref"] == "refs/heads/main"
            and entry["build_workflow"] == ".github/workflows/ci.yml"
            and entry["runtime_profile"] == "hiro.gcp-tdx.v1", "Release/build identity mismatch")
    require(entry["image"] == "ghcr.io/" + repository.lower()
            and re.fullmatch(r"sha256:[0-9a-f]{64}", entry["digest"]), "Invalid image identity")
    reference = entry["image"] + "@" + entry["digest"]
    require((directory / "image-ref.txt").read_text() == reference + "\n", "Image reference mismatch")
    require((directory / "image-digest.txt").read_text() == entry["digest"] + "\n", "Image digest mismatch")
    require((directory / "SHA256SUMS").read_text() == checksums(directory), "Release checksum mismatch")
    policy = ["--repo", repository, "--signer-workflow", repository + "/.github/workflows/ci.yml",
              "--signer-digest", commit, "--source-digest", commit, "--source-ref", "refs/heads/main",
              "--predicate-type", "https://slsa.dev/provenance/v1", "--deny-self-hosted-runners"]
    for subject, bundle in [(str(directory / "images.lock.json"), "images.lock.sigstore.json"),
                            ("oci://" + reference, "image.sigstore.json"),
                            *((str(directory / name), "release.sigstore.json")
                              for name in ("release.json", "image-release.json", "deployment.json")),
                            (str(directory / "gcp-images.json"), "gcp-images.sigstore.json")]:
        subprocess.run(["gh", "attestation", "verify", subject, "--bundle", str(directory / bundle),
                        *policy], check=True)
    verify_deployment(directory, entry)
    gcp = json.loads((directory / 'gcp-images.json').read_text())
    require(gcp['deployment_sha256'] == digest(directory / 'deployment.json')
            and gcp['source_commit'] == commit and set(gcp['images']) == {'boot', 'workload'},
            'GCP publication must identify both deployment disks')
    for kind, filename in [('boot', 'deployment-gcp.tar.gz'), ('workload', 'workload-disk.tar.gz')]:
        image = gcp['images'][kind]
        require(image['status'] == 'READY' and image['archive_sha256'] == digest(directory / filename)
                and image['image_id'] and image['self_link'], 'GCP image publication mismatch: ' + kind)
    return entry


def checksums(directory):
    return "".join(f"{digest(directory / name)}  {name}\n"
                   for name in sorted(ASSETS) if name != "SHA256SUMS")


def should_publish(github, tag, commit):
    release = github.release(tag)
    target = github.tag_commit(tag)
    if release is not None and not release["draft"]:
        require(target is not None, "Published release has no Git tag")
        # Ordinary main commits can keep the same version. Never rebuild or replace
        # an existing release, but do verify it before treating it as complete.
        with tempfile.TemporaryDirectory(prefix="proxy-release-") as directory:
            github.download(tag, Path(directory))
            verify_assets(Path(directory), github.repository, tag, target)
        require(github.tag_commit(tag) == target, "Release tag changed during verification")
        return False
    require(target is None or target == commit,
            "Unpublished version tag belongs to another commit; choose a new Cargo version")
    if release is not None and target is None:
        require(release["target_commitish"] == commit, "Draft release belongs to another commit")
    return True


def publish(github, tag, commit, directory):
    (directory / "SHA256SUMS").write_text(checksums(directory))
    verify_assets(directory, github.repository, tag, commit)
    if not should_publish(github, tag, commit):
        return
    if github.tag_commit(tag) is None:
        github.api("POST", "git/refs", {"ref": "refs/tags/" + tag, "sha": commit})
    require(github.tag_commit(tag) == commit, "Release tag changed during publication")
    release = github.release(tag)
    if release is None:
        release = github.api("POST", "releases", {
            "tag_name": tag, "target_commitish": commit, "name": tag, "draft": True,
            "prerelease": "-" in tag, "body": (directory / "release-notes.md").read_text(),
        })
    # Only an unpublished draft may have assets replaced after an interrupted run.
    current = github.api("GET", f"releases/{release['id']}")
    require(current["draft"] and current["tag_name"] == tag and github.tag_commit(tag) == commit,
            "Release is no longer this build's draft")
    subprocess.run(["gh", "release", "upload", tag, "--repo", github.repository, "--clobber",
                    *(str(directory / name) for name in ASSETS)], check=True)
    with tempfile.TemporaryDirectory(prefix="proxy-upload-") as downloaded:
        github.download(tag, Path(downloaded))
        for name in ASSETS:
            require(digest(Path(downloaded) / name) == digest(directory / name),
                    f"Uploaded release asset differs: {name}")
    require(github.tag_commit(tag) == commit, "Release tag changed during upload")
    github.api("PATCH", f"releases/{release['id']}", {"draft": False})
    completed = github.release(tag)
    require(completed is not None and not completed["draft"], "Release was not published")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"\nPublished [{tag}](https://github.com/{github.repository}/releases/tag/{tag})\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "publish"])
    args = parser.parse_args()
    require(os.environ["GITHUB_REF"] == "refs/heads/main", "Releases must be built on main")
    commit = os.environ["GITHUB_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Invalid source commit")
    require(os.environ["WORKFLOW_COMMIT"] == commit, "Workflow and source revisions must match")
    tag = version_tag()
    github = GitHub(os.environ["GITHUB_REPOSITORY"])
    if args.command == "plan":
        needed = should_publish(github, tag, commit)
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"tag={tag}\npublish={str(needed).lower()}\n")
        print(f"{tag}: {'publish after successful build' if needed else 'verified existing release; skipped'}")
    else:
        require(os.environ["RELEASE_TAG"] == tag, "Planned version differs from Cargo.toml")
        publish(github, tag, commit, Path("dist"))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
