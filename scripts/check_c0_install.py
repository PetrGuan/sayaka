#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate C0 installation/artifact provenance and owned-prefix preflight."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Optional


REPO = Path(__file__).resolve().parent.parent
INSTALL_MANIFEST = REPO / "benchmarks/c0-install-v1.json"
SOURCE_MANIFEST = REPO / "benchmarks/c0-mole-v1.53.0-source.json"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def parse_sha256sums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        hash_value, _, name = line.partition("  ")
        if not hash_value or not name:
            raise ValueError(f"invalid checksum line: {line!r}")
        result[name] = hash_value
    return result


def ensure_under_repo(path: Path) -> None:
    path.resolve().relative_to(REPO.resolve())


def check_artifacts(release_metadata_path: Path, sha256sums_path: Path, artifacts_root: Path) -> dict:
    source = json.loads(SOURCE_MANIFEST.read_text())
    release = json.loads(release_metadata_path.read_text())
    sums = parse_sha256sums(sha256sums_path)
    expected = source["release_assets"]

    metadata_assets = {asset["name"]: asset for asset in release["assets"]}
    missing = sorted(name for name in expected if name not in metadata_assets)
    if missing:
        raise AssertionError(f"release metadata missing assets: {missing}")

    checked = []
    for name, item in expected.items():
        asset = metadata_assets[name]
        digest_value = asset.get("digest", "")
        if not digest_value.startswith("sha256:"):
            raise AssertionError(f"asset {name} missing sha256 digest")
        if digest_value.split("sha256:", 1)[1] != item["sha256"]:
            raise AssertionError(f"asset digest mismatch for {name}")
        if asset["size"] != item["size_bytes"]:
            raise AssertionError(f"asset size mismatch for {name}")
        if name != "SHA256SUMS" and sums.get(name) != item["sha256"]:
            raise AssertionError(f"SHA256SUMS mismatch for {name}")

        local_file = artifacts_root / name
        local_status = "not_downloaded"
        if local_file.is_file():
            local_hash = digest(local_file)
            if local_hash != item["sha256"]:
                raise AssertionError(f"downloaded artifact hash mismatch for {name}")
            if local_file.stat().st_size != item["size_bytes"]:
                raise AssertionError(f"downloaded artifact size mismatch for {name}")
            local_status = "verified_downloaded"
        checked.append({"name": name, "status": local_status})

    return {
        "release_metadata_sha256": digest(release_metadata_path),
        "sha256sums_sha256": digest(sha256sums_path),
        "assets": checked,
    }


def check_owned_prefix_preflight(mole_repo: Optional[Path], allow_install: bool) -> dict:
    install = json.loads(INSTALL_MANIFEST.read_text())
    owned = install["owned_paths"]
    roots = {key: REPO / value for key, value in owned.items()}
    for path in roots.values():
        ensure_under_repo(path)
    for key in ("owned_home_root", "owned_prefix_root", "owned_config_root", "owned_state_root"):
        roots[key].mkdir(parents=True, exist_ok=True)

    blockers = []
    install_script = None
    if mole_repo:
        install_script = subprocess.run(
            ["git", "-C", str(mole_repo), "show", "1b9023b5f151c2d963bbcb9cb658f4824137b8aa:install.sh"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        risky_patterns = [".zshrc", ".bashrc", ".profile", "/usr/local", "sudo", "touchid", "launchctl"]
        for pattern in risky_patterns:
            if pattern in install_script:
                blockers.append(f"install.sh contains pattern requiring deeper confinement proof: {pattern}")
                break
    else:
        blockers.append("mole_repo_not_provided_for_install_source_preflight")

    if not allow_install:
        blockers.append("SAYAKA_C0_ALLOW_MOLE_INSTALL is not 1")

    status = "blocked_install_layout" if blockers else "preflight_passed_install_not_run"
    return {
        "status": status,
        "blockers": blockers,
        "owned_paths": {key: str(path.relative_to(REPO)) for key, path in roots.items()},
        "execution_performed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-artifacts", action="store_true")
    parser.add_argument("--verify-owned-prefix", action="store_true")
    parser.add_argument("--release-metadata", type=Path)
    parser.add_argument("--sha256sums", type=Path)
    parser.add_argument("--artifacts-root", type=Path, default=REPO / "target/c0-artifacts/mole/V1.53.0")
    parser.add_argument("--mole-repo", type=Path)
    args = parser.parse_args()

    install_manifest = json.loads(INSTALL_MANIFEST.read_text())
    ensure_under_repo(args.artifacts_root)
    args.artifacts_root.mkdir(parents=True, exist_ok=True)

    output = {
        "benchmark_id": install_manifest["benchmark_id"],
        "scope": install_manifest["scope"],
    }

    if args.verify_artifacts:
        metadata = args.release_metadata or (args.artifacts_root / "mole-release-v1.53.0.json")
        sums = args.sha256sums or (args.artifacts_root / "SHA256SUMS")
        if not metadata.is_file():
            raise SystemExit(f"missing release metadata: {metadata}")
        if not sums.is_file():
            raise SystemExit(f"missing SHA256SUMS: {sums}")
        output["artifact_verification"] = check_artifacts(metadata, sums, args.artifacts_root)

    if args.verify_owned_prefix:
        allow = os.environ.get("SAYAKA_C0_ALLOW_MOLE_INSTALL") == "1"
        output["owned_prefix_preflight"] = check_owned_prefix_preflight(args.mole_repo, allow)

    if not args.verify_artifacts and not args.verify_owned_prefix:
        raise SystemExit("select --verify-artifacts and/or --verify-owned-prefix")

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
