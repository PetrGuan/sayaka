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
import tempfile


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
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("BLOCKED: local installation currently requires macOS")
    binary = args.binary.resolve(strict=True)
    base = Path(tempfile.mkdtemp(prefix="sayaka-local-install-check-", dir=REPO / "crates/cli"))
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

    def json_call(*arguments):
        result = invoke(binary, *arguments, "--prefix", prefix, "--json")
        if result.returncode != 0:
            raise AssertionError("lifecycle command failed: %r %r" % (result.stdout, result.stderr))
        return json.loads(result.stdout)

    try:
        preview = json_call("install")
        assert preview["effects_performed"] is False
        assert not prefix.exists()
        installed = json_call("install", "--execute")
        executable = prefix / "bin/sayaka"
        source_digest = digest(binary)
        assert digest(executable) == source_digest
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
