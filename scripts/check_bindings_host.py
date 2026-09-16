#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build and run C/Swift hosts on owned macOS fixtures; never invokes Sayaka CLI."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parent.parent


def run(command, cwd, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError(f"host command failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
    return result.stdout


def fingerprint(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError("owned fixture replaced by a symlink")
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def main():
    if sys.platform != "darwin":
        raise RuntimeError("C/Swift host runner requires macOS; it does not certify Windows")
    library = REPO / "target/debug/libsayaka_bindings.dylib"
    if not library.is_file():
        raise RuntimeError("build first: cargo build -p sayaka-bindings --locked")
    sdk = run(["xcrun", "--sdk", "macosx", "--show-sdk-path"], REPO).decode().strip()
    root = Path(tempfile.mkdtemp(prefix="bindings-host-", dir=REPO / "target"))
    identity = fingerprint(root)
    directories = []
    registered = []
    passed = False
    try:
        for name in ("fixture-\u8d44\u6599", "home", "tmp"):
            path = root / name
            path.mkdir(mode=0o700)
            directories.append((path, fingerprint(path)))
        fixture, home, tmp = [path for path, _ in directories]
        truth = {}
        for index in range(64):
            name = f"file-{index:03d}" if index else "newline\nfile"
            path = fixture / name
            payload = f"owned-{index}\n".encode()
            path.write_bytes(payload)
            registered.append((path, fingerprint(path)))
            truth[name] = hashlib.sha256(payload).hexdigest(), len(payload)
        include = REPO / "crates/bindings/include"
        c_host, swift_host = root / "c-host", root / "swift-host"
        run(["xcrun", "--sdk", "macosx", "clang", "-isysroot", sdk, "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-I", str(include), str(REPO / "crates/bindings/examples/scan_host.c"),
             "-L", str(library.parent), "-lsayaka_bindings",
             f"-Wl,-rpath,{library.parent}", "-o", str(c_host)], root)
        registered.append((c_host, fingerprint(c_host)))
        run(["xcrun", "--sdk", "macosx", "swiftc", "-sdk", sdk, "-import-objc-header", str(include / "sayaka.h"),
             str(REPO / "crates/bindings/examples/scan_host.swift"),
             "-L", str(library.parent), "-lsayaka_bindings",
             "-Xlinker", "-rpath", "-Xlinker", str(library.parent), "-o", str(swift_host)], root)
        registered.append((swift_host, fingerprint(swift_host)))
        env = {"HOME": str(home), "TMPDIR": str(tmp), "XDG_STATE_HOME": str(home / "state"),
               "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
               "PATH": "/usr/bin:/bin"}
        for host in (c_host, swift_host):
            payload = json.loads(run([str(host), str(fixture)], root, env))
            if payload["schema_version"] != 1 or payload["status"] != "complete" or not payload["complete"]:
                raise RuntimeError("host returned incomplete fixture report")
            totals = payload["totals"]
            if (totals["unique_files"] != len(truth) or totals["regular_files"] != len(truth)
                    or totals["directories"] != 1
                    or totals["logical_bytes_known"] != sum(size for _, size in truth.values())
                    or payload["issues"] or payload["issues_omitted"] != 0
                    or len(payload["entries"]) != len(truth) + 1):
                raise RuntimeError("native result counts/bytes differ from fixture truth")
            names = set()
            for entry in payload["entries"]:
                native = entry["path"]
                if native["encoding"] != "unix_bytes_hex":
                    raise RuntimeError("native path encoding mismatch")
                path = Path(os.fsdecode(bytes.fromhex(native["raw"])))
                if entry["kind"] == "file":
                    if path.parent != fixture or path.name not in truth or path.name in names:
                        raise RuntimeError("unexpected native path")
                    info = path.lstat()
                    if entry["identity"]["device"] != info.st_dev or entry["identity"]["inode"] != info.st_ino:
                        raise RuntimeError("native result identity mismatch")
                    names.add(path.name)
                elif entry["kind"] != "directory" or path != fixture:
                    raise RuntimeError("unexpected directory or special entry")
            if names != set(truth):
                raise RuntimeError("native result omitted fixture entries")
        failed = json.loads(run([str(c_host), str(fixture / "missing"), "expect-failure"], root, env))
        if failed["status"] != "failed" or failed["complete"]:
            raise RuntimeError("missing root became empty success")
        for path, expected in registered:
            if fingerprint(path) != expected:
                raise RuntimeError("registered fixture identity changed")
        for name, (digest, _) in truth.items():
            if hashlib.sha256((fixture / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("fixture content changed")
        if fingerprint(root) != identity or any(fingerprint(path) != original for path, original in directories):
            raise RuntimeError("fixture ancestry changed")
        if list(home.iterdir()) or list(tmp.iterdir()):
            raise RuntimeError("read-only native hosts created unexpected auxiliary state")
        for path, _ in reversed(registered):
            path.unlink()
        for path, _ in reversed(directories):
            path.rmdir()
        root.rmdir()
        passed = True
        print("C and Swift hosts passed: 64 files, exact bytes/identities/native paths; "
              "error/capacity/stale-handle/cancel/release controls; owned fixture cleaned.")
    finally:
        if not passed:
            print(f"Failed host evidence retained without cleanup: {root}", file=sys.stderr)


if __name__ == "__main__":
    main()
