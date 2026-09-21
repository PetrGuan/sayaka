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
import zlib

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
        for name in ("a", "b", "empty"):
            path = fixture / name
            path.mkdir(mode=0o700)
            directories.append((path, fingerprint(path)))
        for name in ("a/shared", "b/shared"):
            path = fixture / name
            os.link(fixture / "newline\nfile", path)
            registered.append((path, fingerprint(path)))
            truth[name] = truth["newline\nfile"]
        installer_root = root / "installer-fixture"
        installer_root.mkdir(mode=0o700)
        directories.append((installer_root, fingerprint(installer_root)))
        dmg = bytearray(2048)
        dmg[1536:1540] = b"koly"
        dmg[1540:1544] = (4).to_bytes(4, "big")
        dmg[1544:1548] = (512).to_bytes(4, "big")
        dmg[1536 + 0xd8:1536 + 0xe0] = (128).to_bytes(8, "big")
        dmg[1536 + 0xe0:1536 + 0xe8] = (64).to_bytes(8, "big")
        xml = b"<xar><toc><file><name>PackageInfo</name><type>file</type></file></toc></xar>"
        compressed = zlib.compress(xml)
        pkg = (b"xar!" + (28).to_bytes(2, "big") + (1).to_bytes(2, "big") +
               len(compressed).to_bytes(8, "big") + len(xml).to_bytes(8, "big") +
               (0).to_bytes(4, "big") + compressed)
        installer_payloads = {"one.dmg": bytes(dmg), "two.pkg": pkg,
                              "unknown.pkg": b"not a package", "sentinel.txt": b"not a target"}
        for name, payload in installer_payloads.items():
            path = installer_root / name
            path.write_bytes(payload)
            path.chmod(0o600)
            registered.append((path, fingerprint(path)))
        include = REPO / "crates/bindings/include"
        hosts = {}
        for kind in ("scan", "installer"):
            c_host, swift_host = root / f"{kind}-c-host", root / f"{kind}-swift-host"
            run(["xcrun", "--sdk", "macosx", "clang", "-isysroot", sdk, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(include), str(REPO / f"crates/bindings/examples/{kind}_host.c"),
                 "-L", str(library.parent), "-lsayaka_bindings",
                 f"-Wl,-rpath,{library.parent}", "-o", str(c_host)], root)
            registered.append((c_host, fingerprint(c_host)))
            run(["xcrun", "--sdk", "macosx", "swiftc", "-sdk", sdk, "-import-objc-header", str(include / "sayaka.h"),
                 str(REPO / f"crates/bindings/examples/{kind}_host.swift"),
                 "-L", str(library.parent), "-lsayaka_bindings",
                 "-Xlinker", "-rpath", "-Xlinker", str(library.parent), "-o", str(swift_host)], root)
            registered.append((swift_host, fingerprint(swift_host)))
            hosts[kind] = (c_host, swift_host)
        env = {"HOME": str(home), "TMPDIR": str(tmp), "XDG_STATE_HOME": str(home / "state"),
               "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
               "PATH": "/usr/bin:/bin"}
        for host in hosts["scan"]:
            payload = json.loads(run([str(host), str(fixture)], root, env))
            if payload["schema_version"] != 1 or payload["status"] != "complete" or not payload["complete"]:
                raise RuntimeError("host returned incomplete fixture report")
            totals = payload["totals"]
            if (totals["unique_files"] != 64 or totals["regular_files"] != len(truth)
                    or totals["directories"] != 4 or totals["duplicate_files"] != 2
                    or totals["logical_bytes_known"] != sum(size for _, size in truth.values()) -
                    2 * truth["newline\nfile"][1]
                    or payload["issues"] or payload["issues_omitted"] != 0
                    or len(payload["entries"]) != len(truth) + 4):
                raise RuntimeError("native result counts/bytes differ from fixture truth")
            names = set()
            for entry in payload["entries"]:
                native = entry["path"]
                if native["encoding"] != "unix_bytes_hex":
                    raise RuntimeError("native path encoding mismatch")
                path = Path(os.fsdecode(bytes.fromhex(native["raw"])))
                if entry["kind"] == "file":
                    name = str(path.relative_to(fixture))
                    if name not in truth or name in names:
                        raise RuntimeError("unexpected native path")
                    info = path.lstat()
                    if entry["identity"]["device"] != info.st_dev or entry["identity"]["inode"] != info.st_ino:
                        raise RuntimeError("native result identity mismatch")
                    names.add(name)
                elif entry["kind"] != "directory" or path not in [
                        fixture, fixture / "a", fixture / "b", fixture / "empty"]:
                    raise RuntimeError("unexpected directory or special entry")
            if names != set(truth):
                raise RuntimeError("native result omitted fixture entries")
        failed = json.loads(run([str(hosts["scan"][0]), str(fixture / "missing"), "expect-failure"], root, env))
        if failed["status"] != "failed" or failed["complete"]:
            raise RuntimeError("missing root became empty success")
        for index, host in enumerate(hosts["installer"]):
            payload = json.loads(run([str(host), str(installer_root)], root, env))
            discovery = payload["discovery"]["data"]
            selection = payload["selection"]["data"]
            if (discovery["kind"] != "installer_preview" or discovery["status"] != "complete" or
                    not discovery["complete"] or discovery["effects_performed"] or
                    discovery["counts"]["named_candidates"] != 3 or
                    discovery["counts"]["recognized"] != 2 or
                    discovery["counts"]["corrupt"] != 1 or discovery["issues"] or discovery["scan_issues"]):
                raise RuntimeError("installer discovery differs from fixture truth")
            candidates = {Path(os.fsdecode(bytes.fromhex(item["path"]["raw"]))).name: item
                          for item in discovery["candidates"]}
            if set(candidates) != {"one.dmg", "two.pkg", "unknown.pkg"}:
                raise RuntimeError("installer candidate set differs")
            for name, candidate in candidates.items():
                if (candidate["path"]["encoding"] != "unix_bytes_hex" or
                        bytes.fromhex(candidate["path"]["raw"]) != os.fsencode(installer_root / name) or
                        candidate["logical_bytes"] != len(installer_payloads[name])):
                    raise RuntimeError("installer native path or bytes differ")
            expected_selected = {"one.dmg"} if index == 0 else {"one.dmg", "two.pkg"}
            selected = {Path(os.fsdecode(bytes.fromhex(item["path"]["raw"]))).name
                        for item in selection["selected"]}
            if (selection["status"] != "checked" or not selection["batch_checks_passed"] or
                    selection["effects_performed"] or selection["execution_authority"] or
                    not selection["snapshot_only"] or selection["issues"] or
                    "plan" in selection or "approval" in selection or selected != expected_selected or
                    selection["bytes"]["matched_logical_bytes"] !=
                    sum(len(installer_payloads[name]) for name in expected_selected)):
                raise RuntimeError("read-only selection changed scope or produced authority")
            if payload["selection"]["source_task_handle"] != payload["discovery"]["task_handle"]:
                raise RuntimeError("selection lost source-task binding")
        for path, expected in registered:
            if fingerprint(path) != expected:
                raise RuntimeError("registered fixture identity changed")
        for name, (digest, _) in truth.items():
            if hashlib.sha256((fixture / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("fixture content changed")
        for name, expected in installer_payloads.items():
            if (installer_root / name).read_bytes() != expected:
                raise RuntimeError("read-only installer host changed fixture contents")
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
        print("C and Swift hosts passed: 64 unique files, 2 aliases, 4 directories; "
              "exact bytes/identities/native paths, roots/detail/paging, diagnostic pages and both size sorts; "
              "installer DMG/PKG/corrupt discovery and read-only explicit-selection checks; "
              "error/shared-capacity/stale-task/cancel/release controls; owned fixtures cleaned.")
    finally:
        if not passed:
            print(f"Failed host evidence retained without cleanup: {root}", file=sys.stderr)


if __name__ == "__main__":
    main()
