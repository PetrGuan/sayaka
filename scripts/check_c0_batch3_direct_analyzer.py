#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""C0 batch-3 direct analyzer runner (guarded, explicit --execute)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import random
import shutil
import socket
import stat
import subprocess
import tarfile
from typing import Any, Callable


REPO = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO / "benchmarks/c0-batch3-direct-analyzer-v2.json"
OUTPUT_PATH = REPO / "benchmarks/results/c0-batch3-direct-analyzer-results-v2.json"
RUN_ROOT_BASE = REPO / "target/c0-batch3/runs"


class ValidationError(Exception):
    """Batch-3 validation failure."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _load_module(module_name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, path)
    ensure(spec is not None and spec.loader is not None, f"failed to import {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PHASE_A = _load_module("check_c0_batch2_phase_a", REPO / "scripts/check_c0_batch2_phase_a.py")
PHASE_B = _load_module("check_c0_batch2_phase_b", REPO / "scripts/check_c0_batch2_phase_b.py")


def load_json(path: Path, label: str) -> dict[str, Any]:
    ensure(path.is_file(), f"missing {label}: {path}")
    payload = json.loads(path.read_text())
    ensure(isinstance(payload, dict), f"{label} must be a JSON object")
    return payload


def _line_range_has_snippet(lines: list[str], line_range: str, snippet: str) -> bool:
    start_text, end_text = line_range.split("-", 1)
    start = int(start_text)
    end = int(end_text)
    segment = "\n".join(lines[start - 1 : end])
    return snippet in segment


def verify_pinned_source_audit(reference_root: Path, checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tarball = reference_root / "source.tar.gz"
    ensure(tarball.is_file(), "missing source.tar.gz for pinned startup-source audit")
    file_map: dict[str, list[str]] = {}
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if len(parts) < 2:
                continue
            rel = str(Path(*parts[1:]))
            if rel not in {item["file"] for item in checks}:
                continue
            extracted = archive.extractfile(member)
            ensure(extracted is not None, f"failed to read source member {rel}")
            file_map[rel] = extracted.read().decode("utf-8", errors="strict").splitlines()

    results: list[dict[str, Any]] = []
    for check in checks:
        rel = check["file"]
        ensure(rel in file_map, f"source audit file missing from archive: {rel}")
        lines = file_map[rel]
        for requirement in check["requirements"]:
            snippet = requirement["snippet"]
            line_ranges = requirement["line_ranges"]
            matched = any(_line_range_has_snippet(lines, line_range, snippet) for line_range in line_ranges)
            ensure(matched, f"source audit failed for {check['id']} snippet {snippet!r}")
        results.append({"id": check["id"], "file": rel, "requirement_count": len(check["requirements"])})
    return results


def create_owned_run_root(base_root: Path) -> tuple[Path, dict[Path, tuple[int, int]]]:
    PHASE_A.ensure_repo_relative(base_root)
    base_root.mkdir(parents=True, exist_ok=True)
    run_id = f"run-{os.getpid()}-{random.getrandbits(32):08x}"
    run_root = base_root / run_id
    run_root.mkdir(mode=0o700)
    (run_root / ".sayaka-c0-b3-owned").write_text("sayaka-c0-b3-owned")

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
        ensure(current != current.parent, "run root escaped repository")
    return run_root, chain


def verify_identity_chain(chain: dict[Path, tuple[int, int]]) -> None:
    for path, expected in chain.items():
        info = path.lstat()
        ensure(not stat.S_ISLNK(info.st_mode), f"path replaced with symlink: {path}")
        ensure(stat.S_ISDIR(info.st_mode), f"path replaced with non-directory: {path}")
        ensure((info.st_dev, info.st_ino) == expected, f"path identity changed: {path}")


def make_layout(run_root: Path) -> dict[str, Path]:
    layout = {
        "run_root": run_root,
        "allowed_root": run_root / "allowed",
        "bin": run_root / "allowed/bin",
        "fixture_root": run_root / "allowed/fixture/root",
        "mole_home": run_root / "allowed/home/mole",
        "sayaka_home": run_root / "allowed/home/sayaka",
        "mole_tmp": run_root / "allowed/tmp/mole",
        "sayaka_tmp": run_root / "allowed/tmp/sayaka",
        "empty_path": run_root / "allowed/empty-path",
        "private_logs": run_root / "private-logs",
        "raw_output": run_root / "private-logs/raw-output",
        "control_root": run_root / "denied-control",
        "control_write_parent": run_root / "denied-control/write-parent",
        "control_exec_readable": run_root / "denied-control/exec-readable",
        "control_read_sentinel": run_root / "denied-control/read-sentinel.txt",
        "control_parent_sentinel": run_root / "denied-control/write-parent/parent-sentinel.txt",
    }
    for key in (
        "allowed_root",
        "bin",
        "fixture_root",
        "mole_home",
        "sayaka_home",
        "mole_tmp",
        "sayaka_tmp",
        "empty_path",
        "private_logs",
        "raw_output",
        "control_root",
        "control_write_parent",
        "control_exec_readable",
    ):
        layout[key].mkdir(parents=True, mode=0o700, exist_ok=True)

    layout["control_read_sentinel"].write_text("outside-read")
    layout["control_parent_sentinel"].write_text("unchanged")
    true_copy = layout["control_exec_readable"] / "true-copy"
    shutil.copyfile("/usr/bin/true", true_copy)
    os.chmod(true_copy, 0o755)
    return layout


def validate_manifest_contract(manifest: dict[str, Any]) -> None:
    benchmark_id = manifest.get("benchmark_id")
    ensure(
        benchmark_id in {"c0-batch3-direct-analyzer-v1", "c0-batch3-direct-analyzer-v2"},
        "unexpected benchmark_id",
    )
    scenario_id = manifest.get("scenario", {}).get("scenario_id")
    ensure(
        scenario_id in {
            "c0-b3-direct-analyzer-flat-regular-json-v1",
            "c0-b3-direct-analyzer-flat-regular-json-v2",
        },
        "unexpected scenario_id",
    )
    fixture = manifest["scenario"]["fixture_truth"]
    ensure(fixture["fixture_id"] == "c0-b3-flat-regular-v1", "fixture_id must be c0-b3-flat-regular-v1")
    ensure(int(fixture["file_count"]) == 1024, "fixture file_count must be 1024")
    ensure(int(fixture["bytes_per_file"]) == 4096, "fixture bytes_per_file must be 4096")
    ensure(int(fixture["logical_bytes"]) == 4_194_304, "fixture logical_bytes must be 4194304")
    ensure(int(fixture["payload_seed"]) == 260026, "fixture payload_seed must be 260026")

    mapping = manifest["scenario"]["ab_mapping"]
    ensure(mapping == {"A": "mole", "B": "sayaka"}, "batch-3 AB mapping must be A=mole, B=sayaka")
    schedule = PHASE_A.build_schedule(int(manifest["ordering"]["seed"]), int(manifest["repetitions"]["paired_ab_ba"]))
    ensure(schedule == manifest["scenario"]["pair_schedule"], "pair_schedule must match preregistered seed")

    runtime_literals = manifest["sandbox"]["runtime_read_literals"]
    ensure("/" in runtime_literals, 'runtime_read_literals must include "/"')
    ensure("/System/Volumes/Data" in manifest["sandbox"]["metadata_read_literals"], "metadata_read_literals must include /System/Volumes/Data")

    assets = manifest["reference_lock"]["assets"]
    ensure(set(assets.keys()) == {"analyze-darwin-arm64"}, "batch-3 direct profile allows only analyze asset staging")


def verify_reference_assets(manifest: dict[str, Any], reference_root: Path) -> dict[str, Any]:
    verification = load_json(reference_root / "verification.json", "verification.json")
    expected = manifest["reference_lock"]
    ensure(verification["source_commit"] == expected["source_commit"], "reference source_commit mismatch")
    tarball = reference_root / "source.tar.gz"
    ensure(PHASE_A.sha256(tarball) == expected["source_archive_sha256"], "source archive hash mismatch")

    assets = []
    for name, lock in expected["assets"].items():
        target = reference_root / "assets" / name
        ensure(target.is_file(), f"missing reference asset: {name}")
        ensure(PHASE_A.sha256(target) == lock["sha256"], f"asset hash mismatch: {name}")
        ensure(target.stat().st_size == lock["size_bytes"], f"asset size mismatch: {name}")
        assets.append({"name": name, "sha256": lock["sha256"], "size_bytes": lock["size_bytes"]})

    return {
        "source_commit": verification["source_commit"],
        "source_archive_sha256": expected["source_archive_sha256"],
        "source_archive_member_count": verification["source_archive_member_count"],
        "assets": assets,
    }


def _resolve_sayaka_binary_source(manifest: dict[str, Any], sayaka_binary_override: Path | None) -> Path:
    if sayaka_binary_override is None:
        return REPO / manifest["sayaka_reference"]["binary_path"]
    return sayaka_binary_override if sayaka_binary_override.is_absolute() else (REPO / sayaka_binary_override)


def stage_binaries(
    manifest: dict[str, Any],
    reference_root: Path,
    layout: dict[str, Path],
    sayaka_binary_override: Path | None = None,
) -> dict[str, Any]:
    analyzer_lock = manifest["reference_lock"]["assets"]["analyze-darwin-arm64"]
    analyzer_src = reference_root / "assets" / "analyze-darwin-arm64"
    analyzer_dst = layout["bin"] / "analyze-darwin-arm64"
    shutil.copy2(analyzer_src, analyzer_dst)
    os.chmod(analyzer_dst, 0o755)
    ensure(PHASE_A.sha256(analyzer_dst) == analyzer_lock["sha256"], "staged analyzer hash mismatch")

    sayaka_lock = manifest["sayaka_reference"]
    sayaka_src = _resolve_sayaka_binary_source(manifest, sayaka_binary_override)
    ensure(sayaka_src.is_file(), f"Sayaka comparator missing: {sayaka_src}")
    ensure(PHASE_A.sha256(sayaka_src) == sayaka_lock["binary_sha256"], "Sayaka source binary hash mismatch")
    sayaka_dst = layout["bin"] / "sayaka"
    shutil.copy2(sayaka_src, sayaka_dst)
    os.chmod(sayaka_dst, 0o755)
    ensure(PHASE_A.sha256(sayaka_dst) == sayaka_lock["binary_sha256"], "staged Sayaka hash mismatch")

    return {
        "analyzer": {
            "path": "allowed/bin/analyze-darwin-arm64",
            "sha256": PHASE_A.sha256(analyzer_dst),
            "size_bytes": analyzer_dst.stat().st_size,
            "runtime_class": "direct_verified_artifact",
        },
        "sayaka": {
            "path": "allowed/bin/sayaka",
            "sha256": PHASE_A.sha256(sayaka_dst),
            "size_bytes": sayaka_dst.stat().st_size,
            "runtime_class": "owned_sayaka_scan",
        },
    }


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
    profile = run_root / "c0-b3-direct.sb"
    allow_exec = [
        "/usr/bin/env",
        str(layout["bin"] / "analyze-darwin-arm64"),
        str(layout["bin"] / "sayaka"),
        str(layout["bin"] / "trusted-canary"),
    ]
    exec_rules = """  (literal "/usr/bin/env")
  (literal (param "ANALYZER"))
  (literal (param "SAYAKA"))
  (literal (param "CANARY"))"""

    runtime_read_rules = "\n".join(
        f'  (subpath "{_literal(path)}")' for path in manifest["sandbox"]["runtime_read_allowlist"]
    )
    runtime_literals = "\n".join(
        f'  (literal "{_literal(path)}")' for path in manifest["sandbox"]["runtime_read_literals"]
    )
    metadata_literals = "\n".join(
        f'  (literal "{_literal(path)}")' for path in manifest["sandbox"]["metadata_read_literals"]
    )
    ancestor_literals = "\n".join(
        f'  (literal "{_literal(path)}")' for path in _ancestor_literals(run_root.parent)
    )

    content = f"""(version 1)
(deny default)

(allow process-fork)
(allow process-exec
{exec_rules}
)
(allow sysctl-read)

(allow file-read*
{runtime_literals}
{runtime_read_rules}
  (subpath (param "ALLOWED_ROOT"))
  (subpath (param "EXEC_READABLE"))
)

(allow file-read-metadata
{metadata_literals}
{ancestor_literals}
  (subpath (param "RUN_ROOT"))
)

(allow file-write*
  (subpath (param "WRITE_HOME"))
  (subpath (param "WRITE_TMP"))
  (literal "/dev/null")
)

(deny network*)
"""
    profile.write_text(content)
    return profile, allow_exec


def _append_journal(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _tool_env(layout: dict[str, Path], tool: str, run_label: str) -> tuple[dict[str, str], Path]:
    if tool == "mole":
        home_base = layout["mole_home"]
        tmp_base = layout["mole_tmp"]
    else:
        home_base = layout["sayaka_home"]
        tmp_base = layout["sayaka_tmp"]
    home = home_base / run_label
    tmp = tmp_base / run_label
    home.mkdir(parents=True, mode=0o700, exist_ok=True)
    tmp.mkdir(parents=True, mode=0o700, exist_ok=True)
    env_map = {
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "PATH": str(layout["empty_path"]),
        "NO_COLOR": "1",
        "MO_NO_OPLOG": "1",
    }
    return env_map, home


def compile_trusted_canary(layout: dict[str, Path]) -> Path:
    source = layout["bin"] / "trusted-canary.c"
    binary = layout["bin"] / "trusted-canary"
    source.write_text(
        """
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int fail_errno(const char* op, const char* path) {
  int err = errno;
  fprintf(stderr, "%s %s failed: %s\\n", op, path ? path : "", strerror(err));
  return err == 0 ? 1 : err;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: trusted-canary <mode> ...\\n");
    return 2;
  }
  if (strcmp(argv[1], "read") == 0 && argc == 3) {
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) return fail_errno("read", argv[2]);
    close(fd);
    return 0;
  }
  if (strcmp(argv[1], "write") == 0 && argc == 3) {
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return fail_errno("write", argv[2]);
    char b = 'x';
    if (write(fd, &b, 1) != 1) {
      close(fd);
      return fail_errno("write", argv[2]);
    }
    close(fd);
    return 0;
  }
  if (strcmp(argv[1], "stat") == 0 && argc == 3) {
    struct stat st;
    if (lstat(argv[2], &st) != 0) return fail_errno("stat", argv[2]);
    return 0;
  }
  if (strcmp(argv[1], "connect") == 0 && argc == 3) {
    int port = atoi(argv[2]);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return fail_errno("socket", "127.0.0.1");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
      close(fd);
      return fail_errno("connect", "127.0.0.1");
    }
    close(fd);
    return 0;
  }
  if (strcmp(argv[1], "exec") == 0 && argc == 3) {
    char* const exec_argv[] = {argv[2], NULL};
    execv(argv[2], exec_argv);
    return fail_errno("exec", argv[2]);
  }
  fprintf(stderr, "invalid mode\\n");
  return 2;
}
""".strip()
        + "\n"
    )
    completed = subprocess.run(
        ["/usr/bin/cc", "-O2", "-Wall", "-Wextra", "-o", str(binary), str(source)],
        cwd=layout["bin"],
        capture_output=True,
        text=True,
        check=False,
    )
    ensure(completed.returncode == 0, f"failed to compile trusted canary: {completed.stderr.strip()}")
    os.chmod(binary, 0o755)
    return binary


def _classify(result: dict[str, Any]) -> str:
    if result["status"] == "timeout":
        return "timeout"
    if result["status"] == "output_cap_exceeded" or result["stdout_truncated"] or result["stderr_truncated"]:
        return "output_cap_exceeded"
    if result["returncode"] == 0:
        return "passed"
    if PHASE_A.is_permission_denied(result.get("stderr", "")):
        return "policy_denied"
    return "program_failed"


def _run_raw(profile: Path, params: dict[str, str], command: list[str], env_map: dict[str, str], cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    return PHASE_B._run_broker(
        profile,
        {**params, "WRITE_HOME": env_map["HOME"], "WRITE_TMP": env_map["TMPDIR"]},
        command,
        env_map,
        cwd,
        timeout_seconds,
        stdout_cap_bytes=65536,
        stderr_cap_bytes=65536,
    )


def run_guard_canaries(profile: Path, params: dict[str, str], layout: dict[str, Path], canary: Path, timeout_seconds: int) -> tuple[list[dict[str, Any]], bool]:
    canaries: list[dict[str, Any]] = []

    def record(canary_id: str, result: dict[str, Any], passed: bool, **extra: Any) -> bool:
        item = {
            "id": canary_id,
            "status": "passed" if passed else "failed",
            "classification": _classify(result),
            "exit_code": result["returncode"],
            "stderr": result.get("stderr", "")[:400],
        }
        item.update(extra)
        canaries.append(item)
        return passed

    env_map, cwd = _tool_env(layout, "mole", "guard")

    root_result = _run_raw(profile, params, [str(canary), "stat", "/"], env_map, cwd, timeout_seconds)
    root_ok = record("literal-root-runtime-only", root_result, root_result["returncode"] == 0)

    metadata_result = _run_raw(profile, params, [str(canary), "stat", "/System/Volumes/Data"], env_map, cwd, timeout_seconds)
    metadata_ok = record("metadata-system-volumes-data", metadata_result, metadata_result["returncode"] == 0)

    owned_target = cwd / "guard-owned.txt"
    owned_write = _run_raw(profile, params, [str(canary), "write", str(owned_target)], env_map, cwd, timeout_seconds)
    owned_read = _run_raw(profile, params, [str(canary), "read", str(owned_target)], env_map, cwd, timeout_seconds)
    allowed_rw_ok = record(
        "allowed-rw-owned",
        owned_read,
        owned_write["returncode"] == 0 and owned_read["returncode"] == 0,
        write_exit_code=owned_write["returncode"],
    )
    isolated_writes_ok = True
    previous_home = layout["mole_home"] / "previous-sample"
    previous_home.mkdir(mode=0o700)
    for label, parent in (
        ("denied-other-tool-home-write", layout["sayaka_home"]),
        ("denied-other-tool-tmp-write", layout["sayaka_tmp"]),
        ("denied-prior-sample-write", previous_home),
    ):
        target = parent / "must-not-exist"
        denied = _run_raw(profile, params, [str(canary), "write", str(target)], env_map, cwd, timeout_seconds)
        ok = denied["returncode"] != 0 and PHASE_A.is_permission_denied(denied.get("stderr", "")) and not target.exists()
        isolated_writes_ok = record(label, denied, ok) and isolated_writes_ok

    denied_read = _run_raw(
        profile,
        params,
        [str(canary), "read", str(layout["control_read_sentinel"])],
        env_map,
        cwd,
        timeout_seconds,
    )
    denied_read_ok = record(
        "denied-read-owned-outside-allow",
        denied_read,
        denied_read["returncode"] != 0 and PHASE_A.is_permission_denied(denied_read.get("stderr", "")) and "No such file" not in denied_read.get("stderr", ""),
    )

    denied_write_path = layout["control_write_parent"] / f"blocked-{os.getpid()}-{random.getrandbits(16):04x}.txt"
    parent_before = sorted(item.name for item in layout["control_write_parent"].iterdir())
    sentinel_before = layout["control_parent_sentinel"].read_text()
    denied_write = _run_raw(profile, params, [str(canary), "write", str(denied_write_path)], env_map, cwd, timeout_seconds)
    parent_after = sorted(item.name for item in layout["control_write_parent"].iterdir())
    denied_write_ok = record(
        "denied-write-owned-outside-allow",
        denied_write,
        denied_write["returncode"] != 0
        and PHASE_A.is_permission_denied(denied_write.get("stderr", ""))
        and not denied_write_path.exists()
        and parent_before == parent_after
        and sentinel_before == layout["control_parent_sentinel"].read_text(),
    )

    exec_copy = layout["control_exec_readable"] / "true-copy"
    readable = _run_raw(profile, params, [str(canary), "read", str(exec_copy)], env_map, cwd, timeout_seconds)
    baseline_exec = subprocess.run([str(exec_copy)], cwd=cwd, env=env_map, capture_output=True, text=True, check=False, timeout=timeout_seconds)
    denied_exec = _run_raw(profile, params, [str(exec_copy)], env_map, cwd, timeout_seconds)
    denied_exec_ok = record(
        "denied-exec-readable-control",
        denied_exec,
        readable["returncode"] == 0
        and baseline_exec.returncode == 0
        and denied_exec["returncode"] != 0
        and PHASE_A.is_permission_denied(denied_exec.get("stderr", "")),
        readable_exit_code=readable["returncode"],
        baseline_exec_exit_code=baseline_exec.returncode,
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    accepted = 0

    def baseline_connect() -> int:
        nonlocal accepted
        proc = subprocess.run([str(canary), "connect", str(port)], cwd=cwd, env=env_map, capture_output=True, text=True, check=False, timeout=timeout_seconds)
        if proc.returncode == 0:
            conn, _addr = listener.accept()
            conn.close()
            accepted += 1
        return proc.returncode

    baseline_before = baseline_connect()
    denied_network = _run_raw(profile, params, [str(canary), "connect", str(port)], env_map, cwd, timeout_seconds)
    baseline_after = baseline_connect()
    listener.close()
    denied_network_ok = record(
        "denied-network-loopback",
        denied_network,
        baseline_before == 0
        and baseline_after == 0
        and denied_network["returncode"] != 0
        and PHASE_A.is_permission_denied(denied_network.get("stderr", ""))
        and accepted >= 2,
        listener_accept_count=accepted,
    )

    all_passed = all(
        [
            root_ok,
            metadata_ok,
            allowed_rw_ok,
            isolated_writes_ok,
            denied_read_ok,
            denied_write_ok,
            denied_exec_ok,
            denied_network_ok,
        ]
    )
    return canaries, all_passed


def _mole_command(layout: dict[str, Path]) -> list[str]:
    return [str(layout["bin"] / "analyze-darwin-arm64"), "--json", str(layout["fixture_root"])]


def _sayaka_command(layout: dict[str, Path]) -> list[str]:
    return [str(layout["bin"] / "sayaka"), "scan", "--json", str(layout["fixture_root"])]


def normalize_sayaka_json(payload: dict[str, Any], *, fixture_root: Path, truth_entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ensure(isinstance(payload, dict), "Sayaka JSON must be an object")
    ensure(payload.get("schema_version") == 1, "Sayaka schema_version must be 1")
    ensure(payload.get("status") == "complete", "Sayaka status must be complete")
    ensure(payload.get("complete") is True, "Sayaka complete must be true")
    ensure(payload.get("issues") == [], "Sayaka issues must be empty")
    ensure(payload.get("issues_omitted") == 0, "Sayaka issues_omitted must be zero")

    roots = payload.get("roots")
    ensure(isinstance(roots, list) and len(roots) == 1, "Sayaka roots must have one entry")
    root = roots[0]
    ensure(root.get("encoding") == "unix_bytes_hex", "Sayaka root encoding must be unix_bytes_hex")
    ensure(Path(PHASE_B.decode_unix_hex(root["raw"])) == fixture_root, "Sayaka root path mismatch")

    entries = payload.get("entries")
    ensure(isinstance(entries, list), "Sayaka entries must be list")
    totals = payload.get("totals")
    ensure(isinstance(totals, dict), "Sayaka totals must be object")

    saw_root_directory = False
    files: dict[str, tuple[int, int]] = {}
    for entry in entries:
        path_obj = entry.get("path")
        ensure(isinstance(path_obj, dict), "Sayaka entry.path must be object")
        ensure(path_obj.get("encoding") == "unix_bytes_hex", "Sayaka path encoding must be unix_bytes_hex")
        decoded = Path(PHASE_B.decode_unix_hex(path_obj["raw"]))
        kind = entry.get("kind")
        if kind == "directory":
            ensure(not saw_root_directory, "duplicate Sayaka root directory entry")
            ensure(decoded == fixture_root, "only fixture root directory entry is allowed")
            ensure(entry.get("depth") == 0, "root directory depth must be 0")
            ensure(entry.get("counted") is False, "root directory counted must be false")
            saw_root_directory = True
            continue
        ensure(kind == "file", "non-root Sayaka entries must be files")
        ensure(entry.get("depth") == 1, "Sayaka file depth must be 1")
        ensure(entry.get("counted") is True, "Sayaka file counted must be true")
        ensure(entry.get("dataless") is False, "Sayaka dataless must be false")
        logical = entry.get("logical_bytes")
        allocated = entry.get("allocated_bytes")
        ensure(type(logical) is int and logical >= 0, "Sayaka logical_bytes must be non-negative int")
        ensure(type(allocated) is int and allocated >= logical, "Sayaka allocated_bytes must be >= logical")
        rel = str(decoded.relative_to(fixture_root))
        ensure(len(Path(rel).parts) == 1, "Sayaka file path must be flat depth-1")
        ensure(rel not in files, f"Sayaka duplicate file entry: {rel}")
        ensure(rel in truth_entries, "unexpected Sayaka file path")
        truth = truth_entries[rel]
        if "device" in truth and "inode" in truth:
            identity = entry.get("identity", {})
            variant = identity.get("platform", identity.get("variant"))
            ensure(variant == "unix", "Sayaka native identity missing")
            ensure(identity.get("device") == truth["device"] and identity.get("inode") == truth["inode"], "Sayaka file identity mismatch")
        files[rel] = (logical, allocated)

    ensure(saw_root_directory, "Sayaka root directory entry missing")
    ensure(set(files.keys()) == set(truth_entries.keys()), "Sayaka path set mismatch fixture truth")
    logical_sum = 0
    for rel, (logical, _allocated) in files.items():
        ensure(logical == int(truth_entries[rel]["logical_bytes"]), f"Sayaka logical-size mismatch for {rel}")
        logical_sum += logical

    ensure(totals.get("regular_files") == len(files), "Sayaka totals.regular_files mismatch")
    ensure(totals.get("unique_files") == len(files), "Sayaka totals.unique_files mismatch")
    ensure(totals.get("links") == 0, "Sayaka totals.links must be 0")
    ensure(totals.get("duplicate_files") == 0, "Sayaka duplicate total must be zero")
    ensure(totals.get("other") == 0, "Sayaka other total must be zero")
    ensure(totals.get("directories") == 1, "Sayaka directory total must be one")
    ensure(totals.get("logical_bytes_known") == logical_sum, "Sayaka totals.logical_bytes_known mismatch")
    ensure(totals.get("logical_bytes_unknown_files") == 0, "Sayaka logical unknown count must be 0")
    ensure(totals.get("allocated_bytes_unknown_files") == 0, "Sayaka allocated unknown count must be 0")

    return {
        "path_set_sha256": PHASE_B.sha256_bytes("\n".join(sorted(files.keys())).encode()),
        "file_count": len(files),
        "logical_bytes": logical_sum,
    }


def _run_tool_sample(
    *,
    profile: Path,
    params: dict[str, str],
    layout: dict[str, Path],
    tool: str,
    phase: str,
    index: int,
    fixture_map: dict[str, dict[str, Any]],
    timeout_seconds: int,
    stdout_cap: int,
    stderr_cap: int,
    run_root: Path,
    raw_sink: Callable[[dict[str, Any]], None],
    expected_immutable: dict[str, str],
    first_useful_result_method_id: str,
) -> dict[str, Any]:
    env_map, cwd = _tool_env(layout, tool, f"{phase}-{tool}-{index:03d}")
    if tool == "mole":
        command = _mole_command(layout)
        normalizer = lambda payload: PHASE_B.normalize_mole_json(payload, fixture_root=layout["fixture_root"], truth_entries=fixture_map)
    else:
        command = _sayaka_command(layout)
        normalizer = lambda payload: normalize_sayaka_json(payload, fixture_root=layout["fixture_root"], truth_entries=fixture_map)

    immutable = {
        "fixture": layout["fixture_root"], "binaries": layout["bin"],
        "controls": layout["control_root"], "empty_path": layout["empty_path"],
    }
    def fingerprints() -> dict[str, str]:
        return {name: PHASE_B.snapshot_tree(path)["tree_sha256"] for name, path in immutable.items()}
    before = fingerprints()
    ensure(before == expected_immutable, "immutable input changed before invocation")
    home_before = PHASE_B.snapshot_tree(cwd)["tree_sha256"]
    tmp_before = PHASE_B.snapshot_tree(Path(env_map["TMPDIR"]))["tree_sha256"]
    sample = PHASE_B.run_sample(
        profile=profile,
        params={**params, "WRITE_HOME": env_map["HOME"], "WRITE_TMP": env_map["TMPDIR"]},
        command=command,
        env_map=env_map,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        stdout_cap_bytes=stdout_cap,
        stderr_cap_bytes=stderr_cap,
        normalizer=normalizer,
        run_root=run_root,
        first_useful_result_method_id=first_useful_result_method_id,
        raw_sink=raw_sink,
    )
    after = fingerprints()
    sample["no_effects"] = {"immutable_before": before, "immutable_after": after, "unchanged": after == before}
    sample["owned_state_effects"] = {
        "home_before": home_before, "home_after": PHASE_B.snapshot_tree(cwd)["tree_sha256"],
        "tmp_before": tmp_before, "tmp_after": PHASE_B.snapshot_tree(Path(env_map["TMPDIR"]))["tree_sha256"],
    }
    if after != before:
        sample["status"] = "failed"
        sample["failure_class"] = "unexpected_effect"
    return sample


def execute(
    manifest: dict[str, Any],
    manifest_path: Path,
    reference_root: Path,
    run_root_base: Path,
    output: Path,
    *,
    execute_mole: bool,
    approved_profile_sha256: str | None,
    sayaka_binary_override: Path | None,
) -> dict[str, Any]:
    if output.exists():
        previous = load_json(output, "existing result")
        ensure(
            previous.get("mole_execution_attempted") is not True,
            "refusing to overwrite a recorded Mole run; choose a new result path",
        )
    validate_manifest_contract(manifest)
    source_lock = verify_reference_assets(manifest, reference_root)
    source_audit = verify_pinned_source_audit(reference_root, manifest["source_audit"]["checks"])

    run_root, identity = create_owned_run_root(run_root_base)
    layout = make_layout(run_root)
    journal = layout["private_logs"] / "batch3-journal.jsonl"

    result: dict[str, Any] = {
        "benchmark_id": manifest["benchmark_id"],
        "scenario_id": manifest["scenario"]["scenario_id"],
        "status": "running",
        "execution_performed": False,
        "mole_execution_attempted": False,
        "manifest_sha256": PHASE_A.sha256(manifest_path),
        "runner_sha256": PHASE_A.sha256(Path(__file__)),
        "run_root": str(run_root.relative_to(REPO)),
        "journal": str(journal.relative_to(REPO)),
        "reference_lock": source_lock,
        "source_audit": source_audit,
        "notes": [
            "Runtime class is direct_verified_artifact for Mole analyzer only; this is not installed CLI or full footprint.",
            "PATH is pinned to an owned empty directory during guarded runs; optional mdfind/du helper lookup is intentionally suppressed.",
            "Conclusions are limited to common flat-file statistics projection for this preregistered fixture.",
        ],
    }

    try:
        verify_identity_chain(identity)
        staged = stage_binaries(
            manifest,
            reference_root,
            layout,
            sayaka_binary_override=sayaka_binary_override,
        )
        fixture_truth = PHASE_A.generate_flat_fixture({"fixture_root": layout["fixture_root"]}, manifest["scenario"]["fixture_truth"])
        fixture_map = {item["path"]: item for item in fixture_truth["entries"]}

        canary_binary = compile_trusted_canary(layout)
        profile_path, exec_allowlist = write_sandbox_profile(run_root, layout, manifest)
        verify_identity_chain(identity)
        profile_sha = PHASE_A.sha256(profile_path)

        params = {
            "RUN_ROOT": str(run_root),
            "ALLOWED_ROOT": str(layout["allowed_root"]),
            "EXEC_READABLE": str(layout["control_exec_readable"]),
            "ANALYZER": str(layout["bin"] / "analyze-darwin-arm64"),
            "SAYAKA": str(layout["bin"] / "sayaka"),
            "CANARY": str(canary_binary),
        }
        first_useful_result_method_id = PHASE_B.resolve_first_useful_result_method_id(
            manifest["phase_b"]["measurement_fixed"].get("first_useful_result_method_id")
        )

        canaries, canary_ok = run_guard_canaries(
            profile_path,
            params,
            layout,
            canary_binary,
            timeout_seconds=int(manifest["canary_timeouts_seconds"]["guard_default"]),
        )

        result.update(
            {
                "profile": {
                    "path": str(profile_path.relative_to(REPO)),
                    "sha256": profile_sha,
                    "exec_allowlist": exec_allowlist,
                },
                "staged_binaries": staged,
                "fixture_truth_lock": {
                    "fixture_id": fixture_truth["fixture_id"],
                    "file_count": fixture_truth["file_count"],
                    "logical_bytes": fixture_truth["logical_bytes"],
                    "entries_sha256": fixture_truth["entries_sha256"],
                },
                "canaries": canaries,
                "phase_b_gate": manifest["phase_b_gate"],
                "collector_binding": {
                    "collector_sha256": PHASE_A.sha256(Path(PHASE_B.__file__)),
                    "first_useful_result_method_id": first_useful_result_method_id,
                },
            }
        )

        if not canary_ok:
            result["status"] = "blocked"
            result["blocked_prerequisite"] = "guard_canary_failed"
            return PHASE_B._public_result(result, run_root)

        fixed = manifest["phase_b"]["measurement_fixed"]
        expected_immutable = {
            name: PHASE_B.snapshot_tree(path)["tree_sha256"] for name, path in {
                "fixture": layout["fixture_root"], "binaries": layout["bin"],
                "controls": layout["control_root"], "empty_path": layout["empty_path"],
            }.items()
        }
        sayaka_smoke = _run_tool_sample(
            profile=profile_path,
            params=params,
            layout=layout,
            tool="sayaka",
            phase="correctness_gate",
            index=1,
            fixture_map=fixture_map,
            timeout_seconds=int(fixed["timeout_seconds_per_sample"]),
            stdout_cap=int(fixed["stdout_capture_cap_bytes"]),
            stderr_cap=int(fixed["stderr_capture_cap_bytes"]),
            run_root=run_root,
            raw_sink=lambda capture: _append_journal(journal, {"event": "sayaka_smoke_raw", "capture": capture}),
            expected_immutable=expected_immutable,
            first_useful_result_method_id=first_useful_result_method_id,
        )
        result["sayaka_control_scan"] = sayaka_smoke
        if sayaka_smoke["status"] != "passed":
            result["status"] = "blocked"
            result["blocked_prerequisite"] = "sayaka_control_failed"
            return PHASE_B._public_result(result, run_root)

        if not execute_mole:
            result["status"] = "ready_for_review_authorization"
            result["execution_performed"] = False
            result["mole_execution_attempted"] = False
            return PHASE_B._public_result(result, run_root)

        ensure(
            manifest.get("current_batch_decision", {}).get("runtime_execution_authorized") is True,
            "manifest runtime_execution_authorized is false; Mole execution remains blocked",
        )
        ensure(approved_profile_sha256 is not None, "--approved-profile-sha256 is required with --execute")
        ensure(approved_profile_sha256 == profile_sha, "approved profile sha256 does not match generated profile")

        result["execution_performed"] = True
        rows: list[dict[str, Any]] = []
        result["samples"] = rows

        def run_row(tool: str, phase: str, index: int, pair_id: int | None, order: str | None) -> bool:
            row = {
                "phase": phase,
                "tool": tool,
                "index": index,
                "pair_id": pair_id,
                "order": order,
                "status": "failed",
                "failure_class": "invocation_not_completed",
            }
            rows.append(row)
            if tool == "mole":
                result["mole_execution_attempted"] = True
                _append_journal(journal, {"event": "mole_invocation_start", "phase": phase, "index": index})
            sample = _run_tool_sample(
                profile=profile_path,
                params=params,
                layout=layout,
                tool=tool,
                phase=phase,
                index=index,
                fixture_map=fixture_map,
                timeout_seconds=int(fixed["timeout_seconds_per_sample"]),
                stdout_cap=int(fixed["stdout_capture_cap_bytes"]),
                stderr_cap=int(fixed["stderr_capture_cap_bytes"]),
                run_root=run_root,
                raw_sink=lambda capture: _append_journal(
                    journal,
                    {
                        "event": "sample_capture",
                        "phase": phase,
                        "tool": tool,
                        "index": index,
                        "capture": capture,
                    },
                ),
                expected_immutable=expected_immutable,
                first_useful_result_method_id=first_useful_result_method_id,
            )
            row.update(sample)
            if tool == "mole":
                result["mole_execution_attempted"] = True
            return row["status"] == "passed"

        if not run_row("mole", "correctness_gate", 1, None, None):
            result["status"] = "blocked"
            result["blocked_prerequisite"] = "mole_smoke_failed"
            return PHASE_B._public_result(result, run_root)
        if not run_row("sayaka", "correctness_gate", 2, None, None):
            result["status"] = "blocked"
            result["blocked_prerequisite"] = "sayaka_smoke_failed"
            return PHASE_B._public_result(result, run_root)
        if not run_row("mole", "warmup", 1, None, None):
            result["status"] = "blocked"
            result["blocked_prerequisite"] = "mole_warmup_failed"
            return PHASE_B._public_result(result, run_root)
        if not run_row("sayaka", "warmup", 1, None, None):
            result["status"] = "blocked"
            result["blocked_prerequisite"] = "sayaka_warmup_failed"
            return PHASE_B._public_result(result, run_root)

        mapping = manifest["scenario"]["ab_mapping"]
        indexes = {"mole": 1, "sayaka": 1}
        for pair_id, order in enumerate(manifest["scenario"]["pair_schedule"], start=1):
            ensure(order in {"AB", "BA"}, f"unsupported schedule entry: {order}")
            for letter in order:
                tool = mapping[letter]
                indexes[tool] += 1
                if not run_row(tool, "measurement", indexes[tool], pair_id, order):
                    result["status"] = "blocked"
                    result["blocked_prerequisite"] = "measurement_failed"
                    return PHASE_B._public_result(result, run_root)

        measurement_rows = [row for row in rows if row["phase"] == "measurement"]
        sayaka_times = [float(item["complete_result_ms"]) for item in measurement_rows if item["tool"] == "sayaka" and item["status"] == "passed"]
        mole_times = [float(item["complete_result_ms"]) for item in measurement_rows if item["tool"] == "mole" and item["status"] == "passed"]
        result["summary"] = {
            "sayaka": {
                "passed": len(sayaka_times),
                "median_complete_ms": __import__("statistics").median(sayaka_times) if sayaka_times else None,
                "p95_complete_ms": PHASE_B.nearest_rank_percentile(sayaka_times, 95.0) if sayaka_times else None,
            },
            "mole": {
                "passed": len(mole_times),
                "median_complete_ms": __import__("statistics").median(mole_times) if mole_times else None,
                "p95_complete_ms": PHASE_B.nearest_rank_percentile(mole_times, 95.0) if mole_times else None,
            },
        }
        result["status"] = "completed"
        return PHASE_B._public_result(result, run_root)
    except (ValidationError, PHASE_A.ValidationError, PHASE_B.ValidationError, OSError, ValueError, KeyError, TypeError) as error:
        _append_journal(journal, {"event": "runner_failure", "error": str(error)})
        result["status"] = "blocked"
        result["blocked_prerequisite"] = "runner_or_integrity_failure"
        result["summary"] = None
        return PHASE_B._public_result(result, run_root)
    finally:
        if result["status"] == "running":
            result["status"] = "failed"
            result["blocked_prerequisite"] = "unexpected_runner_error"
        public = PHASE_B._public_result(result, run_root)
        _append_journal(journal, {"event": "final_result", "result": public})
        PHASE_B._write_report(output, public)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--run-root-base", type=Path, default=RUN_ROOT_BASE)
    parser.add_argument("--output", type=Path, help="result path; defaults to the selected manifest version")
    parser.add_argument("--sayaka-binary", type=Path, help="override Sayaka comparator binary path; hash must match manifest")
    parser.add_argument("--prepare", action="store_true", help="run guard canaries and Sayaka control only (default)")
    parser.add_argument("--verify", action="store_true", help="alias for --prepare")
    parser.add_argument("--execute", action="store_true", help="run Mole+Sayaka smoke/warmup/measurements after prepare")
    parser.add_argument("--approved-profile-sha256")
    args = parser.parse_args()

    manifest = load_json(args.manifest, "batch3 manifest")
    validate_manifest_contract(manifest)
    output = args.output or (
        REPO / "benchmarks/results/c0-batch3-direct-analyzer-results-v1.json"
        if manifest["benchmark_id"] == "c0-batch3-direct-analyzer-v1" else OUTPUT_PATH
    )
    mode_execute = args.execute
    if mode_execute:
        ensure(not args.prepare and not args.verify, "--execute cannot be combined with --prepare/--verify")
    result = execute(
        manifest,
        args.manifest,
        args.reference_root,
        args.run_root_base,
        output,
        execute_mole=mode_execute,
        approved_profile_sha256=args.approved_profile_sha256,
        sayaka_binary_override=args.sayaka_binary,
    )
    print(json.dumps(result, indent=2))
    if result["status"] in {"blocked", "failed"}:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (ValidationError, PHASE_A.ValidationError, PHASE_B.ValidationError, OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        raise SystemExit(2) from exc
