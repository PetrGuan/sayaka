#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Verify a release binary in one owned temporary installation prefix."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess


REPO = Path(__file__).resolve().parent.parent


def identity(path):
    value = path.lstat()
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)

def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=REPO / "target/release/sayaka")
    parser.add_argument(
        "--baseline-binary",
        type=Path,
        default=None,
        help="optional trusted older/local binary used for install-before-update checks",
    )
    parser.add_argument(
        "--update-binary",
        type=Path,
        default=REPO / "target/debug/sayaka",
        help="second trusted local executable used to validate an actual byte-changing update",
    )
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("BLOCKED: local installation currently requires macOS")
    binary = args.binary.resolve(strict=True)
    baseline_binary = (
        args.baseline_binary.resolve(strict=True) if args.baseline_binary else None
    )
    update_binary = args.update_binary.resolve(strict=True)
    base = REPO / "crates/cli" / (
        f"sayaka-local-install-check-{os.getpid()}-{int.from_bytes(os.urandom(4), 'big'):08x}"
    )
    base.mkdir(mode=0o700)
    original = identity(base)
    marker = base / "ownership-marker"
    marker.write_bytes(b"sayaka-t12-owned-fixture")
    marker_identity = identity(marker)
    prefix = base / "package"
    history = base / "preserved-history"
    history.write_bytes(b"must remain outside package operations")
    env = dict(os.environ, HOME=str(base), PYTHONDONTWRITEBYTECODE="1")

    def invoke(program, *arguments):
        return subprocess.run([str(program), *map(str, arguments)],
            cwd=base, env=env, capture_output=True, timeout=30)

    def json_call_with(program, *arguments):
        result = invoke(program, *arguments, "--prefix", prefix, "--json")
        if result.returncode != 0:
            raise AssertionError("lifecycle command failed: %r %r" % (result.stdout, result.stderr))
        return json.loads(result.stdout)

    def json_call(*arguments):
        return json_call_with(binary, *arguments)

    try:
        install_binary = baseline_binary if baseline_binary is not None else binary
        install_digest = digest(install_binary)
        source_digest = digest(binary)
        update_digest = digest(update_binary)
        preview = json_call_with(install_binary, "install")
        assert preview["effects_performed"] is False
        assert not prefix.exists()
        installed = json_call_with(install_binary, "install", "--execute")
        executable = prefix / "bin/sayaka"
        if source_digest == update_digest and baseline_binary is None:
            raise AssertionError("update fixture binaries must differ in bytes")
        assert digest(executable) == install_digest
        footprint = []
        for parent, directories, files in os.walk(prefix, followlinks=False):
            for name in directories + files:
                path = Path(parent) / name
                info = path.lstat()
                assert not stat.S_ISLNK(info.st_mode)
                if stat.S_ISREG(info.st_mode):
                    footprint.append({"path": str(path.relative_to(prefix)),
                        "logical_bytes": info.st_size, "allocated_bytes": info.st_blocks * 512})
        assert footprint and len(footprint) <= 16
        logical = sum(item["logical_bytes"] for item in footprint)
        allocated = sum(item["allocated_bytes"] for item in footprint)
        outcome = installed["outcome"]
        if outcome["logical_bytes"] is not None:
            assert outcome["logical_bytes"] == logical
        if outcome["allocated_bytes"] is not None:
            assert outcome["allocated_bytes"] == allocated
        update_preview = json_call("update", "--allow-same-version-replace")
        assert update_preview["plan"]["action"] == "Update"
        expected_first_update = "Updated" if install_digest != source_digest else "AlreadyInstalled"
        assert update_preview["plan"]["already_installed"] is (expected_first_update == "AlreadyInstalled")
        first_update = json_call("update", "--execute", "--allow-same-version-replace")
        assert first_update["outcome"]["status"] == expected_first_update
        if expected_first_update == "Updated":
            assert digest(executable) == source_digest
        if baseline_binary is None:
            update_preview_call = invoke(
                update_binary,
                "update",
                "--prefix",
                prefix,
                "--allow-same-version-replace",
                "--json",
            )
            assert update_preview_call.returncode == 0, (
                update_preview_call.stdout,
                update_preview_call.stderr,
            )
            update_preview_from_second = json.loads(update_preview_call.stdout)
            assert update_preview_from_second["plan"]["already_installed"] is False
            update_exec_call = invoke(
                update_binary,
                "update",
                "--execute",
                "--prefix",
                prefix,
                "--allow-same-version-replace",
                "--json",
            )
            assert update_exec_call.returncode == 0, (
                update_exec_call.stdout,
                update_exec_call.stderr,
            )
            update_exec_from_second = json.loads(update_exec_call.stdout)
            assert update_exec_from_second["outcome"]["status"] == "Updated"
            assert digest(executable) == update_digest
        else:
            assert digest(executable) == source_digest
        recovered = json_call("recover", "--execute")
        assert recovered["outcome"]["status"] == "Recovered"
        assert invoke(executable, "--version").returncode == 0
        assert invoke(executable, "completions", "zsh").returncode == 0
        extra = prefix / "not-owned-by-installer"
        extra.write_bytes(b"test-created unowned entry")
        refused = invoke(binary, "remove", "--execute", "--prefix", prefix, "--json")
        assert refused.returncode != 0
        assert executable.exists() and extra.read_bytes() == b"test-created unowned entry"
        extra.unlink()
        json_call("remove")
        assert executable.exists()
        removed = invoke(executable, "remove", "--execute", "--prefix", prefix, "--json")
        assert removed.returncode == 0, (removed.stdout, removed.stderr)
        assert not executable.exists()
        assert history.read_bytes() == b"must remain outside package operations"
        result = {"profile": "t12-local-macos", "os": platform.mac_ver()[0], "arch": platform.machine(),
            "source_sha256": source_digest, "regular_files": footprint,
            "logical_bytes": logical, "allocated_bytes": allocated,
            "scope": "Owned temporary prefix only; regular-file footprint, not full filesystem overhead or a Mole comparison."}
    finally:
        assert identity(base) == original and identity(marker) == marker_identity
        assert marker.read_bytes() == b"sayaka-t12-owned-fixture"
        entries = []
        for parent, directories, files in os.walk(base, followlinks=False):
            for name in directories + files:
                path = Path(parent) / name
                info = path.lstat()
                assert len(entries) < 4096 and info.st_uid == os.getuid() and info.st_dev == original[0]
                entries.append((path, identity(path)))
        for path, expected in sorted(entries, key=lambda item: len(item[0].parts), reverse=True):
            assert identity(path) == expected
            if stat.S_ISDIR(expected[2]):
                path.rmdir()
            else:
                path.unlink()
        base.rmdir()
    result["cleanup"] = "passed"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
