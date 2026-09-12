#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate C0 Mole V1.53.0 source and release metadata lock."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "benchmarks/c0-mole-v1.53.0-source.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        value, _, name = line.partition("  ")
        if not value or not name:
            raise ValueError(f"invalid SHA256SUMS line: {line!r}")
        entries[name] = value
    return entries


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def verify_git_tag(mole_repo: Path, tag: str, commit: str) -> dict:
    resolved = subprocess.run(
        ["git", "-C", str(mole_repo), "rev-parse", tag],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if resolved != commit:
        raise AssertionError(f"tag {tag} resolves to {resolved}, expected {commit}")
    return {"tag": tag, "resolved_commit": resolved}


def find_asset(assets: list[dict], name: str) -> dict:
    for asset in assets:
        if asset.get("name") == name:
            return asset
    raise AssertionError(f"release metadata missing asset {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--mole-repo", type=Path)
    parser.add_argument("--release-metadata", type=Path)
    parser.add_argument("--sha256sums", type=Path)
    args = parser.parse_args()

    manifest = read_json(MANIFEST)
    comparator = manifest["comparator"]
    release_metadata_path = args.release_metadata or (REPO / "target/c0-artifacts/mole/V1.53.0/mole-release-v1.53.0.json")
    sha256sums_path = args.sha256sums or (REPO / "target/c0-artifacts/mole/V1.53.0/SHA256SUMS")

    if not release_metadata_path.is_file():
        raise SystemExit(f"missing release metadata: {release_metadata_path}")
    if not sha256sums_path.is_file():
        raise SystemExit(f"missing SHA256SUMS: {sha256sums_path}")

    release = read_json(release_metadata_path)
    sums = parse_sha256sums(sha256sums_path)
    assets = release["assets"]

    checks: list[dict] = []
    checks.append({"manifest_sha256": sha256(MANIFEST)})
    checks.append({"release_metadata_sha256": sha256(release_metadata_path)})
    checks.append({"sha256sums_sha256": sha256(sha256sums_path)})

    if release["tagName"] != comparator["tag"]:
        raise AssertionError(f"release tag mismatch: {release['tagName']} != {comparator['tag']}")
    if release["publishedAt"] != comparator["published_at"]:
        raise AssertionError("release publish timestamp mismatch")
    if release["targetCommitish"] != comparator["target_commitish"]:
        raise AssertionError("release target commitish mismatch")

    manifest_assets = manifest["release_assets"]
    for name, expected in manifest_assets.items():
        asset = find_asset(assets, name)
        digest = asset.get("digest", "")
        if not digest.startswith("sha256:"):
            raise AssertionError(f"asset {name} missing sha256 digest")
        actual_sha = digest.split("sha256:", 1)[1]
        if actual_sha != expected["sha256"]:
            raise AssertionError(f"asset digest mismatch for {name}")
        if asset["size"] != expected["size_bytes"]:
            raise AssertionError(f"asset size mismatch for {name}")
        if name != "SHA256SUMS":
            if sums.get(name) != expected["sha256"]:
                raise AssertionError(f"SHA256SUMS mismatch for {name}")

    if args.mole_repo:
        checks.append(verify_git_tag(args.mole_repo, comparator["tag"], comparator["source_commit"]))

    result = {
        "benchmark_id": manifest["benchmark_id"],
        "tag": comparator["tag"],
        "source_commit": comparator["source_commit"],
        "release_url": comparator["release_url"],
        "checks": checks,
        "status": "verified",
    }
    print(json.dumps(result, indent=2))

    if args.verify:
        return


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
