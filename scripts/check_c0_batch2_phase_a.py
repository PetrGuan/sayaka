#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Prepare and verify guarded-host C0 batch-2 Phase A (no Mole execution)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import random
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
from typing import Any


REPO = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO / "benchmarks/c0-batch2-manifest-v1.json"
RESULT_SCHEMA_PATH = REPO / "benchmarks/c0-batch2-results-schema-v1.json"


class ValidationError(Exception):
    """Phase A validation error."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def is_permission_denied(stderr: str) -> bool:
    lowered = stderr.lower()
    return "operation not permitted" in lowered or "permission denied" in lowered


def sanitize_text(text: str, run_root: Path) -> str:
    sanitized = text.replace(str(run_root), "<run-root>")
    sanitized = sanitized.replace(str(Path.home()), "<home>")
    return sanitized


def build_schedule(seed: int, repetitions: int) -> list[str]:
    randomizer = random.Random(seed)
    pairs = ["AB", "BA"] * ((repetitions + 1) // 2)
    randomizer.shuffle(pairs)
    return pairs[:repetitions]


def load_json(path: Path, label: str) -> dict[str, Any]:
    ensure(path.is_file(), f"missing {label}: {path}")
    payload = json.loads(path.read_text())
    ensure(isinstance(payload, dict), f"{label} must be a JSON object")
    return payload


def ensure_repo_relative(path: Path) -> None:
    path.resolve().relative_to(REPO.resolve())


def check_output_path(path: Path) -> None:
    ensure_repo_relative(path)
    allowed = (REPO / "benchmarks/results").resolve()
    ensure(path.resolve().parent == allowed, "output path must be under benchmarks/results")


def _line_range_has_snippet(lines: list[str], line_range: str, snippet: str) -> bool:
    start_text, end_text = line_range.split("-", 1)
    start = int(start_text)
    end = int(end_text)
    segment = "\n".join(lines[start - 1 : end])
    return snippet in segment


def verify_reference_assets(manifest: dict[str, Any], reference_root: Path) -> dict[str, Any]:
    verification = load_json(reference_root / "verification.json", "verification.json")
    release = load_json(reference_root / "release.json", "release.json")
    expected = manifest["reference_lock"]

    ensure(verification["source_commit"] == expected["source_commit"], "reference source_commit mismatch")
    ensure(release["tag_name"] == expected["tag"], "reference release tag mismatch")
    ensure(release["target_commitish"] == expected["target_commitish"], "reference release target_commitish mismatch")

    tarball = reference_root / "source.tar.gz"
    ensure(tarball.is_file(), "missing reference source.tar.gz")
    tar_sha = sha256(tarball)
    ensure(tar_sha == expected["source_archive_sha256"], "source archive sha256 mismatch")

    assets: dict[str, dict[str, Any]] = expected["assets"]
    release_assets = {asset["name"]: asset for asset in release.get("assets", [])}
    verified_assets = []
    for name, item in assets.items():
        path = reference_root / "assets" / name
        ensure(path.is_file(), f"missing reference asset: {name}")
        file_sha = sha256(path)
        file_size = path.stat().st_size
        ensure(file_sha == item["sha256"], f"asset sha256 mismatch: {name}")
        ensure(file_size == item["size_bytes"], f"asset size mismatch: {name}")
        release_asset = release_assets.get(name)
        ensure(release_asset is not None, f"release metadata missing asset {name}")
        ensure(release_asset.get("digest") == f"sha256:{item['sha256']}", f"release metadata digest mismatch: {name}")
        ensure(release_asset.get("size") == item["size_bytes"], f"release metadata size mismatch: {name}")
        verified_assets.append({"name": name, "sha256": file_sha, "size_bytes": file_size})

    return {
        "source_commit": verification["source_commit"],
        "source_archive_sha256": tar_sha,
        "source_archive_member_count": verification["source_archive_member_count"],
        "assets": verified_assets,
    }


def create_owned_run_root(base_root: Path) -> tuple[Path, dict[Path, tuple[int, int]]]:
    ensure_repo_relative(base_root)
    base_root.mkdir(parents=True, exist_ok=True)
    run_id = f"run-{os.getpid()}-{random.getrandbits(32):08x}"
    run_root = base_root / run_id
    run_root.mkdir(mode=0o700)
    marker = run_root / ".sayaka-c0-b2-owned"
    marker.write_text("sayaka-c0-b2-owned")

    chain: dict[Path, tuple[int, int]] = {}
    current = run_root
    repo_root = REPO.resolve()
    while True:
        info = current.lstat()
        ensure(stat.S_ISDIR(info.st_mode), f"non-directory ancestor in run root chain: {current}")
        ensure(not stat.S_ISLNK(info.st_mode), f"symlink ancestor in run root chain: {current}")
        chain[current] = (info.st_dev, info.st_ino)
        if current.resolve() == repo_root:
            break
        current = current.parent
        ensure(current != current.parent, "run root is outside repository")
    return run_root, chain


def verify_identity_chain(chain: dict[Path, tuple[int, int]]) -> None:
    for path, expected in chain.items():
        info = path.lstat()
        ensure(not stat.S_ISLNK(info.st_mode), f"path replaced with symlink: {path}")
        ensure(stat.S_ISDIR(info.st_mode), f"path replaced with non-directory: {path}")
        ensure((info.st_dev, info.st_ino) == expected, f"path identity changed: {path}")


def make_layout(run_root: Path) -> dict[str, Path]:
    layout = {
        "allowed_root": run_root / "allowed",
        "common_root": run_root / "allowed/common",
        "fixture_root": run_root / "allowed/common/fixture",
        "mole_root": run_root / "allowed/mole",
        "mole_home": run_root / "allowed/mole/home",
        "mole_tmp": run_root / "allowed/mole/tmp",
        "mole_prefix": run_root / "allowed/mole/prefix",
        "mole_config": run_root / "allowed/mole/config",
        "mole_source": run_root / "allowed/mole/source",
        "sayaka_root": run_root / "allowed/sayaka",
        "sayaka_home": run_root / "allowed/sayaka/home",
        "sayaka_tmp": run_root / "allowed/sayaka/tmp",
        "sayaka_install_root": run_root / "allowed/sayaka/installation",
        "sayaka_prefix": run_root / "allowed/sayaka/installation/package",
        "sayaka_source_binary": run_root / "allowed/sayaka/source-binary",
        "control_outside_allow": run_root / "denied-control",
        "control_exec_readable": run_root / "denied-control/exec-readable",
        "private_logs": run_root / "private-logs",
    }
    for key in (
        "allowed_root",
        "common_root",
        "fixture_root",
        "mole_root",
        "mole_home",
        "mole_tmp",
        "mole_prefix",
        "mole_config",
        "control_outside_allow",
        "control_exec_readable",
        "private_logs",
        "sayaka_root",
        "sayaka_home",
        "sayaka_tmp",
        "sayaka_install_root",
        "sayaka_source_binary",
    ):
        layout[key].mkdir(mode=0o700, parents=True, exist_ok=True)

    (layout["control_outside_allow"] / "read-sentinel.txt").write_text("outside-read")
    (layout["control_outside_allow"] / "write-parent").mkdir(mode=0o700, parents=True, exist_ok=True)
    (layout["control_outside_allow"] / "write-parent" / "parent-sentinel.txt").write_text("unchanged")
    exec_copy = layout["control_exec_readable"] / "true-copy"
    shutil.copyfile("/usr/bin/true", exec_copy)
    os.chmod(exec_copy, 0o755)
    return layout


def _safe_member_path(name: str, root_name: str) -> tuple[str, Path]:
    pp = PurePosixPath(name)
    ensure(not pp.is_absolute(), f"archive member must be relative: {name}")
    ensure(".." not in pp.parts, f"archive member escapes extraction root: {name}")
    if len(pp.parts) == 1 and pp.parts[0] == root_name:
        return "", Path(".")
    ensure(len(pp.parts) >= 2, f"archive member lacks root directory: {name}")
    ensure(pp.parts[0] == root_name, f"archive member must be under archive root {root_name}: {name}")
    rel = PurePosixPath(*pp.parts[1:])
    ensure(str(rel) not in {"", "."}, f"archive member path empty: {name}")
    return str(rel), Path(*rel.parts)


def _tree_digest(member_hashes: list[dict[str, Any]]) -> str:
    payload = "\n".join(
        f"{item['path']}|{item['type']}|{item.get('mode','')}|{item.get('size',0)}|{item.get('sha256','')}|{item.get('link_target','')}"
        for item in sorted(member_hashes, key=lambda x: x["path"])
    ).encode()
    return sha256_bytes(payload)


def stage_source_from_archive(reference_root: Path, layout: dict[str, Path], manifest: dict[str, Any]) -> dict[str, Any]:
    tarball = reference_root / "source.tar.gz"
    limits = manifest["archive_validation"]
    added_helper_names = set(manifest["source_staging"]["canonical_helper_additions"])
    allowed_symlink_map = {item["path"]: item for item in manifest["archive_validation"]["allowed_symlinks"]}

    member_hashes: list[dict[str, Any]] = []
    extracted_paths: list[Path] = []
    file_count = 0

    with tarfile.open(tarball, "r:gz") as archive:
        members = archive.getmembers()
        ensure(len(members) <= limits["max_member_count"], "archive member count exceeds preregistered bound")
        ensure(members, "archive has no members")
        root_name = PurePosixPath(members[0].name).parts[0]

        staged: list[tuple[tarfile.TarInfo, str, Path]] = []
        seen_paths: set[str] = set()
        symlink_paths: set[str] = set()
        seen_symlink_pairs: set[tuple[str, str]] = set()

        for member in members:
            rel_str, rel_path = _safe_member_path(member.name, root_name)
            if rel_str == "":
                continue
            ensure(member.size <= limits["max_member_size_bytes"], f"archive member too large: {rel_str}")
            ensure(rel_str not in seen_paths, f"duplicate archive member path: {rel_str}")
            seen_paths.add(rel_str)
            staged.append((member, rel_str, rel_path))

            if member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise ValidationError(f"unsupported archive member type: {rel_str}")

            if member.issym():
                link_target = member.linkname
                ensure(not link_target.startswith("/"), f"archive symlink target must be relative: {rel_str}")
                joined = posixpath.normpath(posixpath.join(str(PurePosixPath(rel_str).parent), link_target))
                ensure(not joined.startswith("../"), f"archive symlink escapes root: {rel_str} -> {link_target}")
                symlink_paths.add(rel_str)
                seen_symlink_pairs.add((rel_str, link_target))

        expected_pairs = {(item["path"], item["target"]) for item in manifest["archive_validation"]["allowed_symlinks"]}
        ensure(seen_symlink_pairs == expected_pairs, "archive symlink set does not match preregistered allowed_symlinks")

        for member, rel_str, _ in staged:
            if member.issym():
                continue
            for symlink_path in symlink_paths:
                if rel_str.startswith(symlink_path + "/"):
                    raise ValidationError(f"archive member appears under symlink ancestor: {rel_str}")

        directories = [item for item in staged if item[0].isdir()]
        files = [item for item in staged if item[0].isfile()]
        symlinks = [item for item in staged if item[0].issym()]

        for member, rel_str, rel_path in directories:
            target = layout["mole_source"] / rel_path
            ensure_repo_relative(target)
            target.mkdir(parents=True, exist_ok=True)
            mode = stat.S_IMODE(member.mode)
            os.chmod(target, mode or 0o755)
            member_hashes.append({"path": rel_str, "type": "dir", "mode": mode})
            extracted_paths.append(target)

        for member, rel_str, rel_path in files:
            target = layout["mole_source"] / rel_path
            ensure_repo_relative(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            ensure(extracted is not None, f"failed to read archive member: {rel_str}")
            data = extracted.read()
            ensure(len(data) == member.size, f"archive member size mismatch: {rel_str}")
            mode = stat.S_IMODE(member.mode)
            target.write_bytes(data)
            os.chmod(target, mode or 0o644)
            member_hashes.append(
                {
                    "path": rel_str,
                    "type": "file",
                    "mode": mode,
                    "size": member.size,
                    "sha256": sha256_bytes(data),
                }
            )
            extracted_paths.append(target)
            file_count += 1

        for member, rel_str, rel_path in symlinks:
            target = layout["mole_source"] / rel_path
            ensure_repo_relative(target)
            link_target = member.linkname
            expected = allowed_symlink_map.get(rel_str)
            ensure(expected is not None, f"archive symlink not preregistered: {rel_str}")
            ensure(link_target == expected["target"], f"archive symlink target mismatch: {rel_str}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                target.unlink()
            os.symlink(link_target, target)
            mode = stat.S_IMODE(member.mode)
            member_hashes.append(
                {
                    "path": rel_str,
                    "type": "symlink",
                    "mode": mode,
                    "link_target": link_target,
                }
            )
            extracted_paths.append(target)

    expected_count = load_json(reference_root / "verification.json", "verification.json")["source_archive_member_count"]
    ensure(len(members) == expected_count, "archive member count does not match verification.json")

    helper_assets = manifest["reference_lock"]["assets"]
    analyze_target = layout["mole_source"] / "bin/analyze-go"
    status_target = layout["mole_source"] / "bin/status-go"
    shutil.copy2(reference_root / "assets/analyze-darwin-arm64", analyze_target)
    shutil.copy2(reference_root / "assets/status-darwin-arm64", status_target)
    os.chmod(analyze_target, 0o755)
    os.chmod(status_target, 0o755)

    ensure(sha256(analyze_target) == helper_assets["analyze-darwin-arm64"]["sha256"], "staged analyze-go hash mismatch")
    ensure(sha256(status_target) == helper_assets["status-darwin-arm64"]["sha256"], "staged status-go hash mismatch")

    additions = {"bin/analyze-go", "bin/status-go"}
    ensure(additions == added_helper_names, "manifest canonical helper additions mismatch")

    for path in extracted_paths + [analyze_target, status_target]:
        info = path.lstat()
        ensure(
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode),
            f"staged path must be file/dir/symlink: {path}",
        )

    member_hashes.extend(
        [
            {
                "path": "bin/analyze-go",
                "type": "file",
                "mode": stat.S_IMODE(analyze_target.lstat().st_mode),
                "size": analyze_target.lstat().st_size,
                "sha256": sha256(analyze_target),
                "added": True,
            },
            {
                "path": "bin/status-go",
                "type": "file",
                "mode": stat.S_IMODE(status_target.lstat().st_mode),
                "size": status_target.lstat().st_size,
                "sha256": sha256(status_target),
                "added": True,
            },
        ]
    )

    return {
        "archive_member_count": len(member_hashes) - 2,
        "archive_file_count": file_count,
        "staged_tree_sha256": _tree_digest(member_hashes),
        "member_hashes": member_hashes,
        "staged_helpers": [
            {"path": "bin/analyze-go", "sha256": sha256(analyze_target)},
            {"path": "bin/status-go", "sha256": sha256(status_target)},
        ],
    }


def verify_source_audit(manifest: dict[str, Any], staged_source: Path) -> list[dict[str, Any]]:
    checks = manifest["source_audit"]["checks"]
    results = []
    for check in checks:
        rel = check["file"]
        target = staged_source / rel
        ensure(target.is_file(), f"source audit file missing: {rel}")
        lines = target.read_text().splitlines()
        for requirement in check["requirements"]:
            snippet = requirement["snippet"]
            ranges = requirement["line_ranges"]
            matched = any(_line_range_has_snippet(lines, item, snippet) for item in ranges)
            ensure(matched, f"source audit failed for {check['id']} snippet {snippet!r} in {rel}")
        results.append({"id": check["id"], "file": rel, "requirement_count": len(check["requirements"])})
    return results


def _literal(path: str) -> str:
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _ancestor_literals(path: Path) -> list[str]:
    literals: list[str] = []
    current = path.resolve()
    while True:
        literals.append(str(current))
        if current == current.parent:
            break
        current = current.parent
    literals.reverse()
    return [item for item in literals if item != "/"]


def write_sandbox_profile(run_root: Path, layout: dict[str, Path], manifest: dict[str, Any]) -> tuple[Path, list[str]]:
    profile = run_root / "c0-b2.sb"
    helpers = manifest["sandbox"]["helper_exec_allowlist"]
    helper_paths = [item["path"] for item in helpers]

    exec_rules = "\n".join(f'  (literal "{_literal(path)}")' for path in helper_paths)
    metadata_base = REPO / "target/c0-batch2/runs"
    ancestor_literals = "\n".join(f'  (literal "{_literal(path)}")' for path in _ancestor_literals(metadata_base))

    runtime_read_literals = manifest["sandbox"]["runtime_read_literals"]
    runtime_read_roots = manifest["sandbox"]["runtime_read_allowlist"]
    runtime_read_rules = "\n".join(f'  (subpath "{_literal(path)}")' for path in runtime_read_roots)
    runtime_literal_rules = "\n".join(f'  (literal "{_literal(path)}")' for path in runtime_read_literals)

    content = f"""(version 1)
(deny default)

(allow process-fork)
(allow process-exec
{exec_rules}
  (subpath (param "ALLOWED_ROOT"))
)
(allow sysctl-read)
(allow signal process-info-pidinfo (target same-sandbox))

(allow file-read*
{runtime_literal_rules}
{runtime_read_rules}
  (subpath (param "ALLOWED_ROOT"))
  (subpath (param "EXEC_READABLE"))
)

(allow file-read-metadata
  (literal "/System/Volumes/Data")
{ancestor_literals}
  (subpath (param "RUN_ROOT"))
)

(allow file-write*
  (subpath (param "MOLE_HOME"))
  (subpath (param "MOLE_TMP"))
  (subpath (param "MOLE_PREFIX"))
  (subpath (param "MOLE_CONFIG"))
  (subpath (param "SAYAKA_HOME"))
  (subpath (param "SAYAKA_TMP"))
  (subpath (param "SAYAKA_INSTALL_ROOT"))
  (literal "/dev/null")
)

(deny network*)
"""
    profile.write_text(content)
    return profile, helper_paths


def run_command(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    start = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
    )
    ensure(process.stdout is not None and process.stderr is not None, "failed to capture process streams")

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_total = 0
    stderr_total = 0
    stdout_captured = 0
    stderr_captured = 0
    stdout_truncated = False
    stderr_truncated = False
    stdout_done = False
    stderr_done = False

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, data="stdout")
    selector.register(process.stderr, selectors.EVENT_READ, data="stderr")

    timed_out = False
    output_cap_exceeded = False
    sent_term = False
    sent_kill = False
    rc: int | None = None
    while True:
        events = selector.select(timeout=0.05)
        for key, _ in events:
            stream = key.fileobj
            chunk = stream.read1(65536)
            if not chunk:
                selector.unregister(stream)
                if key.data == "stdout":
                    stdout_done = True
                else:
                    stderr_done = True
                continue
            if key.data == "stdout":
                stdout_total += len(chunk)
                if stdout_captured < max_output_bytes:
                    keep = min(max_output_bytes - stdout_captured, len(chunk))
                    if keep:
                        stdout_chunks.append(chunk[:keep])
                        stdout_captured += keep
                if stdout_total > max_output_bytes:
                    stdout_truncated = True
            else:
                stderr_total += len(chunk)
                if stderr_captured < max_output_bytes:
                    keep = min(max_output_bytes - stderr_captured, len(chunk))
                    if keep:
                        stderr_chunks.append(chunk[:keep])
                        stderr_captured += keep
                if stderr_total > max_output_bytes:
                    stderr_truncated = True

        overflow_now = stdout_truncated or stderr_truncated
        if overflow_now and not sent_term:
            output_cap_exceeded = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            sent_term = True

        elapsed = time.monotonic() - start
        if elapsed > timeout_seconds and not sent_term:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            sent_term = True

        if sent_term and not sent_kill:
            time.sleep(0.1)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            sent_kill = True

        rc = process.poll()
        if rc is not None and stdout_done and stderr_done:
            break

    selector.close()
    process.stdout.close()
    process.stderr.close()
    process.wait(timeout=2)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    rc = process.returncode if process.returncode is not None else -999
    stdout_bytes = b"".join(stdout_chunks)
    stderr_bytes = b"".join(stderr_chunks)
    return {
        "status": "output_cap_exceeded" if output_cap_exceeded else ("timeout" if timed_out else "completed"),
        "returncode": rc,
        "elapsed_ms": elapsed_ms,
        "stdout": stdout_bytes.decode(errors="replace"),
        "stderr": stderr_bytes.decode(errors="replace"),
        "stdout_bytes": stdout_total,
        "stderr_bytes": stderr_total,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "pid": process.pid,
    }


def sandbox_run(
    profile_path: Path,
    layout: dict[str, Path],
    command: list[str],
    *,
    timeout_seconds: int,
    tool_home: Path,
    tool_tmp: Path,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = {
        "HOME": str(tool_home),
        "TMPDIR": str(tool_tmp),
        "XDG_CACHE_HOME": str(tool_home / ".cache"),
        "XDG_CONFIG_HOME": str(tool_home / ".config"),
        "XDG_STATE_HOME": str(tool_home / ".local/state"),
        "PATH": "/bin:/usr/bin",
        "NO_COLOR": "1",
        "MO_NO_OPLOG": "1",
    }
    if extra_env:
        env.update(extra_env)

    args = [
        "/usr/bin/sandbox-exec",
        "-f",
        str(profile_path),
        "-D",
        f"RUN_ROOT={layout['allowed_root'].parent}",
        "-D",
        f"ALLOWED_ROOT={layout['allowed_root']}",
        "-D",
        f"EXEC_READABLE={layout['control_exec_readable']}",
        "-D",
        f"MOLE_HOME={layout['mole_home']}",
        "-D",
        f"MOLE_TMP={layout['mole_tmp']}",
        "-D",
        f"MOLE_PREFIX={layout['mole_prefix']}",
        "-D",
        f"MOLE_CONFIG={layout['mole_config']}",
        "-D",
        f"SAYAKA_HOME={layout['sayaka_home']}",
        "-D",
        f"SAYAKA_TMP={layout['sayaka_tmp']}",
        "-D",
        f"SAYAKA_INSTALL_ROOT={layout['sayaka_install_root']}",
        "/usr/bin/env",
        "-i",
    ]
    for key, value in env.items():
        args.append(f"{key}={value}")
    args.extend(command)
    return run_command(args, env=env, cwd=tool_home, timeout_seconds=timeout_seconds, max_output_bytes=8 * 1024 * 1024)


def plain_run(layout: dict[str, Path], command: list[str], *, timeout_seconds: int) -> dict[str, Any]:
    env = {
        "HOME": str(layout["mole_home"]),
        "TMPDIR": str(layout["mole_tmp"]),
        "PATH": "/bin:/usr/bin",
    }
    return run_command(command, env=env, cwd=layout["mole_home"], timeout_seconds=timeout_seconds, max_output_bytes=32768)


def classify_outcome(result: dict[str, Any]) -> str:
    if result["status"] == "timeout":
        return "timeout"
    if result["returncode"] == -6 and not result["stderr"].strip():
        return "sandbox_runtime_abort"
    if result["returncode"] == 127:
        return "not_found"
    if result["returncode"] == 126:
        return "permission_or_exec"
    if result["returncode"] == 0:
        return "passed"
    if is_permission_denied(result["stderr"]):
        return "policy_denied"
    return "program_failed"


def finalize_not_run(canaries: list[dict[str, Any]], planned_ids: list[str], executed_ids: list[str]) -> list[dict[str, Any]]:
    missing = [item for item in planned_ids if item not in executed_ids]
    for canary_id in missing:
        canaries.append(
            {
                "id": canary_id,
                "status": "not_run",
                "classification": "not_run_precondition",
                "exit_code": -1,
                "stderr": "",
            }
        )
    return canaries


def run_canaries(profile_path: Path, layout: dict[str, Path], helper_paths: list[str], manifest: dict[str, Any], run_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    timeouts = manifest["canary_timeouts_seconds"]
    raw_logs: dict[str, Any] = {"runs": []}
    canaries: list[dict[str, Any]] = []
    helper_specs = manifest["sandbox"]["helper_exec_allowlist"]
    planned_ids = list(manifest["canary_contract"]["required_ids"]) + [f"allowed-helper-{Path(spec['path']).name}" for spec in helper_specs]
    executed_ids: list[str] = []
    halted = False
    privileged = privileged_helper_paths(helper_paths)
    if privileged:
        raw_logs["blocked_prerequisite"] = {
            "code": "required_privileged_system_helper",
            "detail": "The unchanged official install path requires a setuid/setgid OS helper; guarded-host execution forbids privilege transitions.",
            "helpers": privileged,
        }
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    def maybe_halt(canary_id: str, result: dict[str, Any]) -> None:
        nonlocal halted
        classification = classify_outcome(result)
        if classification in {"sandbox_runtime_abort", "not_found"}:
            halted = True
            raw_logs["runs"].append({"id": "canary-stop", "result": result, "extra": {"stopped_after": canary_id, "classification": classification}})

    def record(canary_id: str, result: dict[str, Any], status: str, **extra: Any) -> None:
        nonlocal halted
        executed_ids.append(canary_id)
        raw_logs["runs"].append({"id": canary_id, "result": result, "extra": extra})
        canaries.append(
            {
                "id": canary_id,
                "status": status,
                "classification": classify_outcome(result),
                "exit_code": result["returncode"],
                "stderr": sanitize_text(result["stderr"].strip(), run_root)[:400],
                **extra,
            }
        )
        maybe_halt(canary_id, result)
        if status != "passed":
            halted = True

    allowed = sandbox_run(
        profile_path,
        layout,
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "set -e; p1=\"$1\"; p2=\"$2\"; t1=\"$3\"; t2=\"$4\"; echo ok >\"$p1\"; /bin/test -r \"$p1\"; /bin/mv \"$p1\" \"${p1}.mv\"; /bin/rm \"${p1}.mv\"; echo ok >\"$p2\"; /bin/test -r \"$p2\"; /bin/mv \"$p2\" \"${p2}.mv\"; /bin/rm \"${p2}.mv\"; echo x >\"$t1\"; /bin/rm \"$t1\"; echo y >\"$t2\"; /bin/rm \"$t2\"",
            "--",
            str(layout["mole_home"] / "rw.txt"),
            str(layout["sayaka_home"] / "rw.txt"),
            str(layout["mole_tmp"] / "rw.tmp"),
            str(layout["sayaka_tmp"] / "rw.tmp"),
        ],
        timeout_seconds=timeouts["allowed_rw"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    record("allowed-rw", allowed, "passed" if allowed["returncode"] == 0 else "failed")
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    outside_pid = str(os.getpid())
    query = ["/bin/ps", "-p", outside_pid, "-o", "lstart="]
    baseline_before = plain_run(layout, query, timeout_seconds=timeouts["allowed_rw"])
    outside_signal = sandbox_run(
        profile_path, layout,
        ["/bin/bash", "--noprofile", "--norc", "-c", 'kill -0 "$1"', "--", outside_pid],
        timeout_seconds=timeouts["allowed_rw"],
        tool_home=layout["mole_home"], tool_tmp=layout["mole_tmp"],
    )
    signal_denied = (
        baseline_before["returncode"] == 0
        and bool(baseline_before["stdout"].strip())
        and outside_signal["returncode"] != 0
        and is_permission_denied(outside_signal["stderr"])
    )
    raw_logs["runs"].append({"id": "outside-process-baseline-before", "result": baseline_before})
    record("denied-signal-outside-sandbox", outside_signal, "passed" if signal_denied else "failed")
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    outside_info = sandbox_run(
        profile_path, layout, query,
        timeout_seconds=timeouts["allowed_rw"],
        tool_home=layout["mole_home"], tool_tmp=layout["mole_tmp"],
    )
    baseline_after = plain_run(layout, query, timeout_seconds=timeouts["allowed_rw"])
    raw_logs["runs"].append({"id": "outside-process-baseline-after", "result": baseline_after})
    info_denied = (
        baseline_after["returncode"] == 0
        and baseline_before["stdout"].strip() == baseline_after["stdout"].strip()
        and not outside_info["stdout"].strip()
        and outside_info["returncode"] != 0
    )
    record("denied-process-info-outside-sandbox", outside_info, "passed" if info_denied else "failed")
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    outside_read = layout["control_outside_allow"] / "read-sentinel.txt"
    denied_read = sandbox_run(
        profile_path,
        layout,
        ["/bin/bash", "--noprofile", "--norc", "-c", "f=\"$1\"; /bin/test -r \"$f\"; <\"$f\" >/dev/null", "--", str(outside_read)],
        timeout_seconds=timeouts["denied_read"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    read_ok = denied_read["returncode"] != 0 and is_permission_denied(denied_read["stderr"]) and "No such file" not in denied_read["stderr"]
    record("denied-read-owned-outside-allow", denied_read, "passed" if read_ok else "failed")
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    root_literal = sandbox_run(
        profile_path,
        layout,
        ["/bin/bash", "--noprofile", "--norc", "-c", "/bin/test -d /"],
        timeout_seconds=timeouts["denied_read"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    child_denied = sandbox_run(
        profile_path,
        layout,
        ["/bin/bash", "--noprofile", "--norc", "-c", "f=\"$1\"; <\"$f\" >/dev/null", "--", str(layout["control_outside_allow"] / "read-sentinel.txt")],
        timeout_seconds=timeouts["denied_read"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    root_literal_ok = root_literal["returncode"] == 0 and child_denied["returncode"] != 0 and is_permission_denied(child_denied["stderr"])
    raw_logs["runs"].append({"id": "literal-root-runtime-only.child-check", "result": child_denied, "extra": {}})
    record(
        "literal-root-runtime-only",
        root_literal,
        "passed" if root_literal_ok else "failed",
        child_path_denied=is_permission_denied(child_denied["stderr"]),
    )
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    denied_write_target = layout["control_outside_allow"] / "write-parent" / "must-not-exist.txt"
    parent_sentinel = layout["control_outside_allow"] / "write-parent" / "parent-sentinel.txt"
    parent_before = sorted(p.name for p in (layout["control_outside_allow"] / "write-parent").iterdir())
    sentinel_before = parent_sentinel.read_text()
    denied_write = sandbox_run(
        profile_path,
        layout,
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "echo deny >\"$1\"",
            "--",
            str(denied_write_target),
        ],
        timeout_seconds=timeouts["denied_write"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    parent_after = sorted(p.name for p in (layout["control_outside_allow"] / "write-parent").iterdir())
    write_ok = (
        denied_write["returncode"] != 0
        and is_permission_denied(denied_write["stderr"])
        and not denied_write_target.exists()
        and parent_after == parent_before
        and parent_sentinel.read_text() == sentinel_before
    )
    record(
        "denied-write-owned-outside-allow",
        denied_write,
        "passed" if write_ok else "failed",
        file_absent=not denied_write_target.exists(),
        parent_unchanged=parent_after == parent_before,
    )
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    exec_copy = layout["control_exec_readable"] / "true-copy"
    readable = sandbox_run(
        profile_path,
        layout,
        ["/bin/bash", "--noprofile", "--norc", "-c", "f=\"$1\"; /bin/test -r \"$f\"; <\"$f\" >/dev/null", "--", str(exec_copy)],
        timeout_seconds=timeouts["denied_exec"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    baseline_exec = plain_run(layout, [str(exec_copy)], timeout_seconds=timeouts["denied_exec"])
    denied_exec = sandbox_run(
        profile_path,
        layout,
        [str(exec_copy)],
        timeout_seconds=timeouts["denied_exec"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    exec_ok = (
        readable["returncode"] == 0
        and baseline_exec["returncode"] == 0
        and denied_exec["returncode"] != 0
        and is_permission_denied(denied_exec["stderr"])
    )
    raw_logs["runs"].append({"id": "denied-exec-readable-control.readable", "result": readable, "extra": {}})
    raw_logs["runs"].append({"id": "denied-exec-readable-control.baseline", "result": baseline_exec, "extra": {}})
    record("denied-exec-readable-control", denied_exec, "passed" if exec_ok else "failed", readable_ok=readable["returncode"] == 0, baseline_exec_ok=baseline_exec["returncode"] == 0)
    if halted:
        return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    for spec in helper_specs:
        canary_id = f"allowed-helper-{Path(spec['path']).name}"
        result = sandbox_run(
            profile_path,
            layout,
            spec["canary_command"],
            timeout_seconds=timeouts["helper_each"],
            tool_home=layout["mole_home"],
            tool_tmp=layout["mole_tmp"],
        )
        record(canary_id, result, "passed" if result["returncode"] == 0 else "failed")
        if halted:
            return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    accepted = {"count": 0}
    stop = threading.Event()

    def accept_loop() -> None:
        while not stop.is_set():
            try:
                conn, _addr = listener.accept()
                accepted["count"] += 1
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=False)
    thread.start()
    baseline_before = plain_run(layout, ["/bin/bash", "--noprofile", "--norc", "-c", "exec 3<>/dev/tcp/127.0.0.1/$1", "--", str(port)], timeout_seconds=timeouts["network"])
    denied_network = sandbox_run(
        profile_path,
        layout,
        ["/bin/bash", "--noprofile", "--norc", "-c", "exec 3<>/dev/tcp/127.0.0.1/$1", "--", str(port)],
        timeout_seconds=timeouts["network"],
        tool_home=layout["mole_home"],
        tool_tmp=layout["mole_tmp"],
    )
    baseline_after = plain_run(layout, ["/bin/bash", "--noprofile", "--norc", "-c", "exec 3<>/dev/tcp/127.0.0.1/$1", "--", str(port)], timeout_seconds=timeouts["network"])

    stop.set()
    try:
        listener.close()
    finally:
        thread.join(timeout=3)

    network_ok = (
        baseline_before["returncode"] == 0
        and baseline_after["returncode"] == 0
        and denied_network["returncode"] != 0
        and is_permission_denied(denied_network["stderr"])
        and accepted["count"] >= 2
    )
    raw_logs["runs"].append({"id": "denied-network-loopback.baseline-before", "result": baseline_before, "extra": {"port": port}})
    raw_logs["runs"].append({"id": "denied-network-loopback.baseline-after", "result": baseline_after, "extra": {"port": port}})
    record(
        "denied-network-loopback",
        denied_network,
        "passed" if network_ok else "failed",
        listener_accept_count=accepted["count"],
        baseline_before_ok=baseline_before["returncode"] == 0,
        baseline_after_ok=baseline_after["returncode"] == 0,
    )

    return finalize_not_run(canaries, planned_ids, executed_ids), raw_logs


def stage_sayaka_binary(manifest: dict[str, Any], layout: dict[str, Path]) -> dict[str, Any]:
    ref = manifest["sayaka_reference"]
    source_path = REPO / ref["binary_path"]
    ensure(source_path.is_file(), f"Sayaka reference binary missing: {source_path}")
    source_sha = sha256(source_path)
    ensure(source_sha == ref["binary_sha256"], "Sayaka reference binary hash mismatch")

    staged_source = layout["sayaka_source_binary"] / "sayaka"
    shutil.copy2(source_path, staged_source)
    os.chmod(staged_source, 0o755)

    staged_source_sha = sha256(staged_source)
    ensure(staged_source_sha == ref["binary_sha256"], "staged Sayaka source binary hash mismatch")
    return {
        "source_binary": "allowed/sayaka/source-binary/sayaka",
        "sha256": staged_source_sha,
    }


def generate_flat_fixture(layout: dict[str, Path], fixture_spec: dict[str, Any]) -> dict[str, Any]:
    fixture_root = layout["fixture_root"]
    ensure(fixture_root.is_dir() and not fixture_root.is_symlink(), "fixture root must be a physical directory")
    ensure(not any(fixture_root.iterdir()), "fixture root must be empty; existing data is never removed")

    seed = int(fixture_spec["payload_seed"])
    file_count = int(fixture_spec["file_count"])
    bytes_per_file = int(fixture_spec["bytes_per_file"])
    name_width = int(fixture_spec["name_width"])
    prefix = fixture_spec["filename_prefix"]
    suffix = fixture_spec["filename_suffix"]

    entries: list[dict[str, Any]] = []
    allocation_observed = 0
    for index in range(file_count):
        name = f"{prefix}{index:0{name_width}d}{suffix}"
        path = fixture_root / name
        payload = hashlib.shake_256(seed.to_bytes(8, "big") + index.to_bytes(4, "big")).digest(bytes_per_file)
        with path.open("xb") as handle:
            handle.write(payload)
        info = path.lstat()
        ensure(stat.S_ISREG(info.st_mode), f"fixture file is not regular: {name}")
        ensure(info.st_nlink == 1, f"fixture file linkcount != 1: {name}")
        ensure(info.st_size == bytes_per_file, f"fixture file size mismatch: {name}")
        allocated = info.st_blocks * 512
        ensure(allocated >= info.st_size, f"fixture file allocation smaller than logical size: {name}")
        allocation_observed += allocated
        entries.append(
            {
                "path": name,
                "kind": "file",
                "depth": 1,
                "logical_bytes": info.st_size,
                "allocated_bytes": allocated,
                "link_count": info.st_nlink,
                "device": info.st_dev,
                "inode": info.st_ino,
                "sha256": sha256(path),
            }
        )

    actual_names = sorted(entry["path"] for entry in entries)
    expected_names = [f"{prefix}{index:0{name_width}d}{suffix}" for index in range(file_count)]
    ensure(actual_names == expected_names, "fixture filenames mismatch preregistered sequence")

    total_logical = sum(entry["logical_bytes"] for entry in entries)
    ensure(total_logical == file_count * bytes_per_file, "fixture logical bytes mismatch preregistered size")
    run_root_info = layout["fixture_root"].lstat()
    listing_hash = sha256_bytes(
        "\n".join(
            f"{entry['path']}|{entry['logical_bytes']}|{entry['allocated_bytes']}|{entry['sha256']}" for entry in entries
        ).encode()
    )
    return {
        "fixture_id": fixture_spec["fixture_id"],
        "file_count": file_count,
        "bytes_per_file": bytes_per_file,
        "logical_bytes": total_logical,
        "allocation_observed_bytes": allocation_observed,
        "entries_sha256": listing_hash,
        "run_identity": {
            "fixture_root_device": run_root_info.st_dev,
            "fixture_root_inode": run_root_info.st_ino,
        },
        "entries": entries,
    }


def decode_unix_hex(raw_hex: str) -> str:
    return bytes.fromhex(raw_hex).decode("utf-8", errors="strict")


def normalize_sayaka_scan_output(payload: dict[str, Any], fixture_root: Path, fixture_truth: dict[str, Any]) -> dict[str, Any]:
    ensure(payload.get("schema_version") == 1, "Sayaka output schema_version must be 1")
    ensure(payload.get("status") == "complete", "Sayaka status must be complete")
    ensure(payload.get("complete") is True, "Sayaka complete must be true")
    ensure(isinstance(payload.get("roots"), list) and len(payload["roots"]) == 1, "Sayaka roots must contain exactly one root")

    root = payload["roots"][0]
    ensure(root.get("encoding") == "unix_bytes_hex", "Sayaka root encoding must be unix_bytes_hex")
    root_path = decode_unix_hex(root["raw"])
    ensure(Path(root_path) == fixture_root, "Sayaka root path does not match fixture root")

    entries = payload.get("entries")
    ensure(isinstance(entries, list), "Sayaka entries must be a list")
    totals = payload.get("totals")
    ensure(isinstance(totals, dict), "Sayaka totals must be object")
    ensure(payload.get("issues") == [], "Sayaka issues must be empty for control scan")
    ensure(payload.get("issues_omitted") == 0, "Sayaka issues_omitted must be zero")

    root_dir_seen = False
    files: dict[str, dict[str, Any]] = {}
    for entry in entries:
        ensure(entry.get("path", {}).get("encoding") == "unix_bytes_hex", "Sayaka entry encoding must be unix_bytes_hex")
        raw_path = decode_unix_hex(entry["path"]["raw"])
        entry_path = Path(raw_path)
        kind = entry.get("kind")
        if kind == "directory":
            ensure(entry_path == fixture_root, "Sayaka directory entry must be fixture root only")
            ensure(entry.get("depth") == 0, "Sayaka root directory depth must be 0")
            ensure(entry.get("counted") is False, "Sayaka root directory counted must be false")
            root_dir_seen = True
            continue

        ensure(kind == "file", "Sayaka entries must contain only file entries beyond root")
        ensure(entry.get("depth") == 1, "Sayaka file depth must be 1")
        ensure(entry.get("counted") is True, "Sayaka file counted must be true")
        ensure(entry.get("dataless") is False, "Sayaka dataless must be false")
        ensure(entry.get("logical_bytes") is not None, "Sayaka logical_bytes must be present")
        ensure(entry.get("allocated_bytes") is not None, "Sayaka allocated_bytes must be present")
        rel = entry_path.relative_to(fixture_root)
        ensure(len(rel.parts) == 1, "Sayaka file path must be flat depth-1")
        rel_text = str(rel)
        ensure(rel_text not in files, f"Sayaka duplicate file entry: {rel_text}")
        files[rel_text] = {
            "logical_bytes": int(entry["logical_bytes"]),
            "allocated_bytes": int(entry["allocated_bytes"]),
        }

    ensure(root_dir_seen, "Sayaka root directory entry missing")
    expected_files = {item["path"]: item for item in fixture_truth["entries"]}
    ensure(set(files.keys()) == set(expected_files.keys()), "Sayaka file set mismatch fixture truth")

    logical_sum = 0
    for path_name, item in files.items():
        expected = expected_files[path_name]
        ensure(item["logical_bytes"] == expected["logical_bytes"], f"Sayaka logical bytes mismatch for {path_name}")
        ensure(item["allocated_bytes"] >= item["logical_bytes"], f"Sayaka allocated bytes invalid for {path_name}")
        logical_sum += item["logical_bytes"]

    ensure(totals.get("regular_files") == fixture_truth["file_count"], "Sayaka totals.regular_files mismatch")
    ensure(totals.get("unique_files") == fixture_truth["file_count"], "Sayaka totals.unique_files mismatch")
    ensure(totals.get("links") == 0, "Sayaka totals.links must be zero")
    ensure(totals.get("logical_bytes_known") == logical_sum, "Sayaka totals.logical_bytes_known mismatch")
    ensure(totals.get("logical_bytes_unknown_files") == 0, "Sayaka totals.logical_bytes_unknown_files must be zero")
    ensure(totals.get("allocated_bytes_unknown_files") == 0, "Sayaka totals.allocated_bytes_unknown_files must be zero")

    return {
        "file_count": len(files),
        "logical_bytes": logical_sum,
        "paths_sha256": sha256_bytes("\n".join(sorted(files.keys())).encode()),
        "output_bytes": len(json.dumps(payload, separators=(",", ":")).encode()),
    }


def run_sayaka_control_scan(profile_path: Path, layout: dict[str, Path], fixture_root: Path, fixture_truth: dict[str, Any], timeout_seconds: int, run_root: Path) -> dict[str, Any]:
    binary = layout["sayaka_source_binary"] / "sayaka"
    result = sandbox_run(
        profile_path,
        layout,
        [str(binary), "scan", "--json", str(fixture_root)],
        timeout_seconds=timeout_seconds,
        tool_home=layout["sayaka_home"],
        tool_tmp=layout["sayaka_tmp"],
    )
    parsed: dict[str, Any] | None = None
    if result["stdout"].strip().startswith("{"):
        try:
            candidate = json.loads(result["stdout"])
            if isinstance(candidate, dict):
                parsed = candidate
        except json.JSONDecodeError:
            parsed = None

    if parsed is not None and parsed.get("status") == "failed":
        issue_codes = []
        for issue in parsed.get("issues", []):
            code = issue.get("code")
            if isinstance(code, str):
                issue_codes.append(code)
        return {
            "status": "failed",
            "exit_code": result["returncode"],
            "classification": "sayaka_scan_reported_failure",
            "stderr": sanitize_text(result["stderr"], run_root)[:400],
            "failure_issue_codes": issue_codes,
            "normalized": None,
            "_private_raw": {
                "status": result["status"],
                "pid": result["pid"],
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "stdout_bytes": result["stdout_bytes"],
                "stderr_bytes": result["stderr_bytes"],
                "stdout_truncated": result.get("stdout_truncated", False),
                "stderr_truncated": result.get("stderr_truncated", False),
            },
        }

    if result["returncode"] != 0:
        return {
            "status": "failed",
            "exit_code": result["returncode"],
            "classification": classify_outcome(result),
            "stderr": sanitize_text(result["stderr"], run_root)[:400],
            "normalized": None,
            "_private_raw": {
                "status": result["status"],
                "pid": result["pid"],
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "stdout_bytes": result["stdout_bytes"],
                "stderr_bytes": result["stderr_bytes"],
                "stdout_truncated": result.get("stdout_truncated", False),
                "stderr_truncated": result.get("stderr_truncated", False),
            },
        }

    ensure(parsed is not None, "Sayaka control scan did not emit parseable JSON")
    normalized = normalize_sayaka_scan_output(parsed, fixture_root, fixture_truth)
    return {
        "status": "passed",
        "exit_code": result["returncode"],
        "classification": "passed",
        "stderr": "",
        "normalized": normalized,
        "_private_raw": {
            "status": result["status"],
            "pid": result["pid"],
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "stdout_bytes": result["stdout_bytes"],
            "stderr_bytes": result["stderr_bytes"],
            "stdout_truncated": result.get("stdout_truncated", False),
            "stderr_truncated": result.get("stderr_truncated", False),
        },
    }


def verify_result_schema(result: dict[str, Any], schema: dict[str, Any], manifest: dict[str, Any]) -> None:
    ensure(set(result.keys()) == set(schema["required_top_level_fields"]), "result top-level fields mismatch required schema")
    ensure(result["phase"] == "A", "result phase must be A")
    ensure(result["status"] in schema["status_values"], "result status is invalid")

    scenario = result["scenario"]
    ensure(scenario["scenario_id"] == manifest["scenario"]["scenario_id"], "scenario id mismatch")
    ensure(scenario["pair_repetitions"] == manifest["repetitions"]["paired_ab_ba"], "pair repetitions mismatch")
    ensure(scenario["pair_schedule"] == manifest["scenario"]["pair_schedule"], "pair schedule mismatch")

    expected_canary_ids = list(manifest["canary_contract"]["required_ids"])
    helper_ids = [f"allowed-helper-{Path(item['path']).name}" for item in manifest["sandbox"]["helper_exec_allowlist"]]
    expected_all = set(expected_canary_ids + helper_ids)
    actual_ids = [item["id"] for item in result["canaries"]]
    ensure(len(actual_ids) == len(set(actual_ids)), "canary ids must be unique")
    ensure(set(actual_ids) == expected_all, "canary id set mismatch")
    for item in result["canaries"]:
        ensure(item["status"] in set(schema["canary_status_values"]), f"invalid canary status for {item['id']}")
        ensure(item["classification"] in set(schema["canary_classification_values"]), f"invalid canary classification for {item['id']}")

    all_passed = all(item["status"] == "passed" for item in result["canaries"])
    sayaka_ok = result["sayaka_control_scan"]["status"] == "passed"
    expected_status = "phase_a_ready" if (all_passed and sayaka_ok) else "blocked"
    ensure(result["status"] == expected_status, "result status must reflect canary and Sayaka control scan pass/fail")


def validate_manifest(manifest: dict[str, Any]) -> None:
    schedule = build_schedule(int(manifest["ordering"]["seed"]), int(manifest["repetitions"]["paired_ab_ba"]))
    ensure(schedule == manifest["scenario"]["pair_schedule"], "manifest pair_schedule does not match seed schedule")

    fixture_truth = manifest["scenario"]["fixture_truth"]
    ensure(fixture_truth["fixture_id"] == "c0-b2-flat-regular-v1", "fixture_id must be c0-b2-flat-regular-v1")
    ensure(fixture_truth["file_count"] == 1024, "fixture file_count must be 1024")
    ensure(fixture_truth["bytes_per_file"] == 4096, "fixture bytes_per_file must be 4096")
    ensure(fixture_truth["logical_bytes"] == 4_194_304, "fixture logical_bytes must be 4194304")
    mapping = manifest["scenario"].get("ab_mapping")
    ensure(isinstance(mapping, dict), "scenario.ab_mapping must be object")
    ensure(mapping.get("A") in {"mole", "sayaka"}, "scenario.ab_mapping.A must be mole or sayaka")
    ensure(mapping.get("B") in {"mole", "sayaka"}, "scenario.ab_mapping.B must be mole or sayaka")
    ensure(mapping["A"] != mapping["B"], "scenario.ab_mapping must map A/B to distinct tools")

    runtime_literals = manifest["sandbox"]["runtime_read_literals"]
    ensure("/" in runtime_literals, 'runtime_read_literals must include "/"')
    ensure("probe_result_path" not in manifest.get("runtime_only_preflight_evidence", {}), "public manifest must not contain private probe_result_path")

    symlinks = manifest["archive_validation"]["allowed_symlinks"]
    ensure(len(symlinks) == 5, "allowed_symlinks must list exactly 5 entries")

    for helper in manifest["sandbox"]["helper_exec_allowlist"]:
        helper_path = Path(helper["path"])
        ensure(helper_path.is_absolute(), f"helper path must be absolute: {helper_path}")
        ensure(helper_path.is_file(), f"helper path missing: {helper_path}")
        ensure(os.access(helper_path, os.X_OK), f"helper path not executable: {helper_path}")


def privileged_helper_paths(helper_paths: list[str]) -> list[str]:
    return [
        path for path in helper_paths
        if Path(path).stat().st_mode & (stat.S_ISUID | stat.S_ISGID)
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--result-schema", type=Path, default=RESULT_SCHEMA_PATH)
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--run-root-base", type=Path, default=REPO / "target/c0-batch2/runs")
    parser.add_argument("--output", type=Path, default=REPO / "benchmarks/results/c0-batch2-phase-a-ready-v1.json")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    check_output_path(args.output)
    manifest = load_json(args.manifest, "batch2 manifest")
    schema = load_json(args.result_schema, "batch2 result schema")
    validate_manifest(manifest)

    source_lock = verify_reference_assets(manifest, args.reference_root)

    run_root, identity_chain = create_owned_run_root(args.run_root_base)
    verify_identity_chain(identity_chain)
    layout = make_layout(run_root)

    staging = stage_source_from_archive(args.reference_root, layout, manifest)
    verify_identity_chain(identity_chain)
    source_audit = verify_source_audit(manifest, layout["mole_source"])
    sayaka_staging = stage_sayaka_binary(manifest, layout)

    fixture_truth = generate_flat_fixture(layout, manifest["scenario"]["fixture_truth"])

    profile_path, helper_paths = write_sandbox_profile(run_root, layout, manifest)
    verify_identity_chain(identity_chain)
    profile_hash = sha256(profile_path)

    canary_results, raw_logs = run_canaries(profile_path, layout, helper_paths, manifest, run_root)
    if all(item["status"] == "passed" for item in canary_results):
        sayaka_control = run_sayaka_control_scan(
            profile_path, layout, layout["fixture_root"], fixture_truth,
            timeout_seconds=manifest["canary_timeouts_seconds"]["sayaka_control_scan"],
            run_root=run_root,
        )
    else:
        sayaka_control = {
            "status": "not_run", "exit_code": None,
            "classification": "not_run_precondition", "stderr": "",
            "normalized": None,
        }

    sayaka_control_private = sayaka_control.pop("_private_raw", None)
    private_log = layout["private_logs"] / "phase-a-transcripts.json"
    private_log.write_text(json.dumps({"canaries": raw_logs, "sayaka_control_raw": sayaka_control_private}, indent=2) + "\n")

    result = {
        "benchmark_id": manifest["benchmark_id"],
        "phase": "A",
        "status": "phase_a_ready" if all(item["status"] == "passed" for item in canary_results) and sayaka_control["status"] == "passed" else "blocked",
        "manifest_path": str(args.manifest.relative_to(REPO)),
        "manifest_sha256": sha256(args.manifest),
        "result_schema_sha256": sha256(args.result_schema),
        "superseded_proofs": manifest["superseded_proofs"],
        "reference_lock": source_lock,
        "staged_source": {
            "tree_sha256": staging["staged_tree_sha256"],
            "archive_member_count": staging["archive_member_count"],
            "archive_file_count": staging["archive_file_count"],
            "canonical_helper_additions": staging["staged_helpers"],
        },
        "source_audit": source_audit,
        "run_root": str(run_root.relative_to(REPO)),
        "profile": {
            "path": str(profile_path.relative_to(REPO)),
            "sha256": profile_hash,
            "helper_exec_allowlist": helper_paths,
        },
        "source_helper_mapping": manifest["source_helper_mapping"],
        "fixture_truth_lock": {
            "fixture_id": fixture_truth["fixture_id"],
            "file_count": fixture_truth["file_count"],
            "bytes_per_file": fixture_truth["bytes_per_file"],
            "logical_bytes": fixture_truth["logical_bytes"],
            "allocation_observed_bytes": fixture_truth["allocation_observed_bytes"],
            "entries_sha256": fixture_truth["entries_sha256"],
            "run_identity": fixture_truth["run_identity"],
        },
        "sayaka_staging": sayaka_staging,
        "sayaka_control_scan": sayaka_control,
        "scenario": {
            "scenario_id": manifest["scenario"]["scenario_id"],
            "ab_mapping": manifest["scenario"]["ab_mapping"],
            "pair_repetitions": manifest["repetitions"]["paired_ab_ba"],
            "pair_schedule": manifest["scenario"]["pair_schedule"],
            "samples": [],
            "performance_not_measured": True,
        },
        "canaries": canary_results,
        "blocked_prerequisite": None,
        "phase_b_gate": {
            "requires_independent_review": True,
            "requires_parent_authorization": True,
            "requires_phase_a_revalidation": True,
            "prohibits_mole_execution_before_gate": True,
        },
    }

    if result["status"] == "blocked":
        result["blocked_prerequisite"] = {
            "code": "guard_or_control_failure",
            "detail": "Canary and/or Sayaka control scan failed; Phase B must not proceed.",
        }
        if sayaka_control["status"] != "passed":
            issue_codes = set(sayaka_control.get("failure_issue_codes", []))
            result["blocked_prerequisite"] = {
                "code": "sayaka_control_scan_failed",
                "detail": "Sayaka control scan under frozen profile failed; Phase B must not proceed.",
            }
            if "volume_unknown" in issue_codes:
                result["blocked_prerequisite"] = {
                    "code": "sayaka_control_scan_os_prerequisite",
                    "detail": "Sayaka control scan reported volume_unknown under strict sandbox profile; Phase B remains blocked until required read-only OS metadata/API exception is preregistered and independently reviewed.",
                }
        if any(item["classification"] == "not_run_precondition" for item in canary_results):
            result["blocked_prerequisite"] = {
                "code": "guard_canary_precondition_failure",
                "detail": "Canary execution stopped early after runtime/precondition failure; remaining checks marked not_run.",
            }
        if any(item["classification"] == "sandbox_runtime_abort" for item in canary_results):
            result["blocked_prerequisite"] = {
                "code": "sandbox_exec_strict_profile_abort",
                "detail": "sandbox-exec aborted under strict positive-read profile; Phase B must not proceed until validated on host.",
            }
        if "blocked_prerequisite" in raw_logs:
            result["blocked_prerequisite"] = raw_logs["blocked_prerequisite"]

    verify_result_schema(result, schema, manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))

    if result["status"] == "blocked":
        raise SystemExit(3)

    if args.verify:
        return


if __name__ == "__main__":
    try:
        main()
    except (ValidationError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
