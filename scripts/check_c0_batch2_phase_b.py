#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""C0 batch-2 Phase B runner; execution is gated by explicit --execute."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import statistics
import subprocess
import sys
import time
from typing import Any, Callable


REPO = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO / "benchmarks/c0-batch2-manifest-v1.json"
PHASE_A_RESULT_PATH = REPO / "benchmarks/results/c0-batch2-phase-a-ready-v1.json"
OUTPUT_PATH = REPO / "benchmarks/results/c0-batch2-phase-b-results-v1.json"


class ValidationError(Exception):
    """Phase B validation failure."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    import hashlib

    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    ensure(path.is_file(), f"missing {label}: {path}")
    data = json.loads(path.read_text())
    ensure(isinstance(data, dict), f"{label} must be JSON object")
    return data


def decode_unix_hex(raw_hex: str) -> str:
    return bytes.fromhex(raw_hex).decode("utf-8", errors="strict")


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    ensure(values, "cannot compute percentile for empty list")
    ensure(0.0 <= percentile <= 100.0, "percentile must be [0,100]")
    ordered = sorted(values)
    if percentile == 0:
        return ordered[0]
    index = math.ceil((percentile / 100.0) * len(ordered)) - 1
    return ordered[max(0, min(index, len(ordered) - 1))]


def validate_manifest_contract(manifest: dict[str, Any]) -> None:
    mapping = manifest["scenario"].get("ab_mapping")
    ensure(isinstance(mapping, dict), "scenario.ab_mapping must be object")
    ensure(mapping.get("A") in {"mole", "sayaka"}, "scenario.ab_mapping.A must be mole or sayaka")
    ensure(mapping.get("B") in {"mole", "sayaka"}, "scenario.ab_mapping.B must be mole or sayaka")
    ensure(mapping["A"] != mapping["B"], "scenario.ab_mapping must map A/B to distinct tools")

    fixture = manifest["scenario"].get("fixture_truth", {})
    ensure(fixture.get("fixture_id") == "c0-b2-flat-regular-v1", "fixture id must be c0-b2-flat-regular-v1")
    ensure(int(fixture.get("file_count", -1)) == 1024, "fixture file_count must be 1024")
    ensure(int(fixture.get("bytes_per_file", -1)) == 4096, "fixture bytes_per_file must be 4096")
    ensure(int(fixture.get("logical_bytes", -1)) == 4194304, "fixture logical_bytes must be 4194304")
    ensure(int(fixture.get("payload_seed", -1)) == 260026, "fixture payload_seed must be 260026")

    fixed = manifest["phase_b"].get("measurement_fixed")
    ensure(isinstance(fixed, dict), "phase_b.measurement_fixed must be object")
    ensure(int(fixed.get("stdout_capture_cap_bytes", 0)) > 0, "stdout_capture_cap_bytes must be > 0")
    ensure(int(fixed.get("stderr_capture_cap_bytes", 0)) > 0, "stderr_capture_cap_bytes must be > 0")
    ensure(int(fixed.get("timeout_seconds_per_sample", 0)) > 0, "timeout_seconds_per_sample must be > 0")


def _load_phase_a_module() -> Any:
    phase_a_path = REPO / "scripts/check_c0_batch2_phase_a.py"
    spec = importlib.util.spec_from_file_location("check_c0_batch2_phase_a", phase_a_path)
    ensure(spec is not None and spec.loader is not None, "failed to import Phase A module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize_mole_json(payload: dict[str, Any], *, fixture_root: Path, truth_entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ensure(isinstance(payload, dict), "Mole JSON must be an object")
    ensure(payload.get("path") == str(fixture_root), "Mole root path mismatch")
    ensure(payload.get("overview") is False, "Mole JSON must have overview=false")
    entries = payload.get("entries")
    ensure(isinstance(entries, list), "Mole entries must be list")
    ensure(type(payload.get("total_size")) is int, "Mole total_size must be int")
    ensure(type(payload.get("total_files")) is int, "Mole total_files must be int")
    ensure(payload.get("error") in (None, "", []), "Mole error must be empty")

    files: dict[str, int] = {}
    for entry in entries:
        ensure(isinstance(entry, dict), "Mole entry must be an object")
        ensure(entry.get("is_dir") is False, "Mole entries must be file-only for this fixture")
        path_text = entry.get("path")
        ensure(isinstance(path_text, str), "Mole path must be string")
        path = Path(path_text)
        ensure(path.is_absolute(), "Mole path must be absolute")
        ensure(path.as_posix().startswith(fixture_root.as_posix() + "/"), "Mole path must stay inside fixture root")
        rel = str(path.relative_to(fixture_root))
        ensure(len(Path(rel).parts) == 1, "Mole file path must be flat depth-1")
        ensure(entry.get("name") == rel, "Mole entry name/path mismatch")
        size = entry.get("size")
        ensure(type(size) is int and size >= 0, "Mole entry size must be non-negative integer")
        ensure(rel not in files, f"Mole duplicate file entry: {rel}")
        files[rel] = size

    ensure(set(files.keys()) == set(truth_entries.keys()), "Mole path set mismatch fixture truth")
    logical_sum = 0
    for rel, size in files.items():
        expected = int(truth_entries[rel]["logical_bytes"])
        ensure(size == expected, f"Mole logical-size mismatch for {rel}")
        logical_sum += size

    ensure(payload["total_files"] == len(files), "Mole total_files mismatch")
    ensure(payload["total_size"] == logical_sum, "Mole total_size mismatch")

    return {
        "path_set_sha256": sha256_bytes("\n".join(sorted(files.keys())).encode()),
        "file_count": len(files),
        "logical_bytes": logical_sum,
    }


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
    ensure(Path(decode_unix_hex(root["raw"])) == fixture_root, "Sayaka root path mismatch")

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
        decoded = Path(decode_unix_hex(path_obj["raw"]))
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
            ensure(identity.get("platform") == "unix", "Sayaka native identity missing")
            ensure(identity.get("device") == truth["device"] and identity.get("inode") == truth["inode"], "Sayaka file identity mismatch")
        files[rel] = (logical, allocated)

    ensure(saw_root_directory, "Sayaka root directory entry missing")
    ensure(set(files.keys()) == set(truth_entries.keys()), "Sayaka path set mismatch fixture truth")

    logical_sum = 0
    for rel, (logical, _allocated) in files.items():
        expected = int(truth_entries[rel]["logical_bytes"])
        ensure(logical == expected, f"Sayaka logical-size mismatch for {rel}")
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
        "path_set_sha256": sha256_bytes("\n".join(sorted(files.keys())).encode()),
        "file_count": len(files),
        "logical_bytes": logical_sum,
    }


def _parse_json_complete(text: str) -> bool:
    decoder = json.JSONDecoder()
    stripped = text.lstrip()
    if not stripped:
        return False
    try:
        _, offset = decoder.raw_decode(stripped)
    except json.JSONDecodeError:
        return False
    return stripped[offset:].strip() == ""


def _signal_owned_group(pid: int, signum: int) -> None:
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def _run_broker(
    profile: Path,
    params: dict[str, str],
    command: list[str],
    env_map: dict[str, str],
    cwd: Path,
    timeout_seconds: int,
    stdout_cap_bytes: int,
    stderr_cap_bytes: int,
) -> dict[str, Any]:
    sandbox_args: list[str] = [
        "/usr/bin/sandbox-exec",
        "-f",
        str(profile),
    ]
    for key, value in params.items():
        sandbox_args.extend(["-D", f"{key}={value}"])
    sandbox_args.extend(["/usr/bin/env", "-i"])
    for key, value in env_map.items():
        sandbox_args.append(f"{key}={value}")
    sandbox_args.extend(command)

    ensure(stdout_cap_bytes > 0 and stderr_cap_bytes > 0, "capture caps must be positive")
    start_ns = time.monotonic_ns()
    process = subprocess.Popen(
        sandbox_args,
        cwd=cwd,
        env=env_map,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
    )
    ensure(process.stdout is not None and process.stderr is not None, "failed to capture child pipes")

    first_json_ns: int | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}
    caps = {"stdout": stdout_cap_bytes, "stderr": stderr_cap_bytes}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    timed_out = False
    overflow_killed = False
    terminate_ns: int | None = None
    kill_sent = False
    waited = False
    rusage = None
    try:
        while not waited:
            for key, _ in selector.select(timeout=0.005):
                stream = key.fileobj
                chunk = stream.read1(65536)
                received_ns = time.monotonic_ns()
                if not chunk:
                    selector.unregister(stream)
                    continue
                name = key.data
                totals[name] += len(chunk)
                remaining = caps[name] - len(buffers[name])
                buffers[name].extend(chunk[:max(0, remaining)])
                if totals[name] > caps[name]:
                    overflow_killed = True
                    if terminate_ns is None:
                        terminate_ns = received_ns
                        _signal_owned_group(process.pid, signal.SIGTERM)
                elif name == "stdout" and first_json_ns is None and not overflow_killed:
                    try:
                        text = buffers[name].decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    if _parse_json_complete(text):
                        first_json_ns = received_ns

            now = time.monotonic_ns()
            if (now - start_ns) / 1_000_000_000 >= timeout_seconds and terminate_ns is None:
                timed_out = True
                terminate_ns = now
                _signal_owned_group(process.pid, signal.SIGTERM)
            if terminate_ns is not None and now - terminate_ns >= 250_000_000 and not kill_sent:
                _signal_owned_group(process.pid, signal.SIGKILL)
                kill_sent = True
            # Retain the leader's PID until its inherited output pipes close.
            # A helper retaining those pipes is stopped by the same timeout.
            if not selector.get_map():
                pid, status, rusage = os.wait4(process.pid, os.WNOHANG)
                if pid == process.pid:
                    end_ns = time.monotonic_ns()
                    process.returncode = os.waitstatus_to_exitcode(status)
                    waited = True
    finally:
        if not waited:
            _signal_owned_group(process.pid, signal.SIGKILL)
            _, status, _ = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        selector.close()
        process.stdout.close()
        process.stderr.close()
    ensure(rusage is not None, "child resource usage missing")
    peak_rss = int(rusage.ru_maxrss)

    if overflow_killed:
        status_text = "output_cap_exceeded"
    elif timed_out:
        status_text = "timeout"
    else:
        status_text = "completed"
    return {
        "status": status_text,
        "pid": process.pid,
        "returncode": process.returncode,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "first_json_ns": first_json_ns,
        "stdout": buffers["stdout"].decode(errors="replace"),
        "stderr": buffers["stderr"].decode(errors="replace"),
        "stdout_bytes": totals["stdout"],
        "stderr_bytes": totals["stderr"],
        "stdout_truncated": totals["stdout"] > caps["stdout"],
        "stderr_truncated": totals["stderr"] > caps["stderr"],
        "peak_rss_bytes": peak_rss,
    }


def run_sample(
    *,
    profile: Path,
    params: dict[str, str],
    command: list[str],
    env_map: dict[str, str],
    cwd: Path,
    timeout_seconds: int,
    stdout_cap_bytes: int,
    stderr_cap_bytes: int,
    normalizer: Callable[[dict[str, Any]], dict[str, Any]],
    run_root: Path,
    raw_sink: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    result = _run_broker(profile, params, command, env_map, cwd, timeout_seconds, stdout_cap_bytes, stderr_cap_bytes)
    if raw_sink is not None:
        raw_sink(result)

    complete_ms = (result["end_ns"] - result["start_ns"]) / 1_000_000
    first_ms = None
    first_status = "not_measured"
    if result["first_json_ns"] is not None:
        first_ms = (result["first_json_ns"] - result["start_ns"]) / 1_000_000
        first_status = "measured"

    output = {
        "status": "failed",
        "failure_class": "unknown",
        "first_useful_result_ms": None,
        "first_useful_result_status": "not_measured",
        "complete_result_ms": complete_ms,
        "peak_rss_bytes": result["peak_rss_bytes"],
        "stdout_bytes": result["stdout_bytes"],
        "stderr_bytes": result["stderr_bytes"],
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
        "exit_code": result["returncode"],
        "stderr": "",
        "normalized": None,
    }

    if result["status"] == "timeout":
        output["status"] = "timeout"
        output["failure_class"] = "timeout"
        return output
    if result["status"] == "output_cap_exceeded" or result["stdout_truncated"] or result["stderr_truncated"]:
        output["failure_class"] = "output_cap_exceeded"
        return output
    if result["returncode"] != 0:
        output["failure_class"] = "nonzero_exit"
        return output
    try:
        payload = json.loads(result["stdout"])
    except json.JSONDecodeError:
        output["failure_class"] = "invalid_json"
        return output

    try:
        normalized = normalizer(payload)
    except (ValidationError, ValueError, KeyError, TypeError) as exc:
        if raw_sink is not None:
            raw_sink({"normalization_error": str(exc)})
        output["failure_class"] = "normalization_failed"
        return output

    output["status"] = "passed"
    output["failure_class"] = "none"
    output["normalized"] = normalized
    output["first_useful_result_ms"] = first_ms
    output["first_useful_result_status"] = first_status
    return output


def validate_phase_a_binding(manifest: dict[str, Any], phase_a_result: dict[str, Any], approved_profile_sha256: str, manifest_path: Path) -> None:
    ensure(phase_a_result.get("manifest_sha256") == sha256(manifest_path), "Phase A manifest hash binding mismatch")
    profile_sha = phase_a_result.get("profile", {}).get("sha256")
    ensure(profile_sha == approved_profile_sha256, "approved profile hash does not match Phase A profile hash")
    ensure(approved_profile_sha256 == manifest["phase_b"]["approved_profile_sha256"], "approved profile hash does not match manifest phase_b binding")


def validate_phase_a_ready_for_execute(phase_a_result: dict[str, Any]) -> None:
    ensure(phase_a_result.get("status") == "phase_a_ready", "Phase A result status must be phase_a_ready")
    canaries = phase_a_result.get("canaries")
    ensure(isinstance(canaries, list) and canaries, "Phase A canaries missing")
    ensure(all(item.get("status") == "passed" for item in canaries), "Phase A canaries are not all passed")
    sayaka_control = phase_a_result.get("sayaka_control_scan")
    ensure(isinstance(sayaka_control, dict) and sayaka_control.get("status") == "passed", "Phase A Sayaka control scan must be passed")


def build_non_execute_output(manifest: dict[str, Any], phase_a_result: dict[str, Any], approved_profile_sha256: str, manifest_path: Path, phase_a_result_path: Path) -> dict[str, Any]:
    fixture = manifest["scenario"]["fixture_truth"]
    return {
        "benchmark_id": manifest["benchmark_id"],
        "phase": "B",
        "status": "not_executed_requires_operator_flag" if phase_a_result.get("status") == "phase_a_ready" else "not_executed_phase_a_not_ready",
        "execution_performed": False,
        "manifest_sha256": sha256(manifest_path),
        "phase_a_result_sha256": sha256(phase_a_result_path),
        "approved_profile_sha256": approved_profile_sha256,
        "phase_a_profile_sha256": phase_a_result["profile"]["sha256"],
        "scenario_id": manifest["scenario"]["scenario_id"],
        "pair_schedule": manifest["scenario"]["pair_schedule"],
        "ab_mapping": manifest["scenario"]["ab_mapping"],
        "pair_repetitions": manifest["repetitions"]["paired_ab_ba"],
        "fixture_contract": {
            "fixture_id": fixture["fixture_id"],
            "file_count": fixture["file_count"],
            "bytes_per_file": fixture["bytes_per_file"],
            "logical_bytes": fixture["logical_bytes"],
            "payload_seed": fixture["payload_seed"],
        },
        "phase_b_contract": manifest["phase_b"],
        "notes": [
            "Phase B code path is implemented and gated by explicit --execute.",
            "No Mole command/help/install/analyze/status was executed in this run.",
        ],
        "phase_a_status": phase_a_result.get("status"),
        "phase_a_blocked_prerequisite": phase_a_result.get("blocked_prerequisite"),
    }


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
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    env_map = {
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "PATH": "/bin:/usr/bin",
        "NO_COLOR": "1",
        "MO_NO_OPLOG": "1",
    }
    return env_map, home


def _stat_stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_nlink,
            info.st_mtime_ns, info.st_ctime_ns)


def snapshot_tree(root: Path) -> dict[str, Any]:
    """Read an owned tree through no-follow directory descriptors."""
    import hashlib

    ensure(root.is_absolute() and ".." not in root.parts, "snapshot requires an absolute physical root")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in root.parts[1:]:
            following = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = following
    except BaseException:
        os.close(descriptor)
        raise

    records: list[dict[str, Any]] = []
    bytes_hashed = 0

    def record(path: str, info: os.stat_result, kind: str) -> dict[str, Any]:
        return {
            "path": path, "kind": kind, "device": info.st_dev, "inode": info.st_ino,
            "mode": info.st_mode, "logical_bytes": info.st_size,
            "allocated_bytes": info.st_blocks * 512, "link_count": info.st_nlink,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
        }

    def visit(fd: int, relative: str) -> None:
        nonlocal bytes_hashed
        before = os.fstat(fd)
        ensure(len(records) < 8192, "footprint entry budget exceeded")
        records.append(record(relative or ".", before, "directory"))
        with os.scandir(fd) as listing:
            names = sorted(entry.name for entry in listing)
        for name in names:
            ensure(len(records) < 8192, "footprint entry budget exceeded")
            path = f"{relative}/{name}" if relative else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            ensure(info.st_dev == before.st_dev, "footprint traversal crosses a device boundary")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    ensure(_stat_stamp(os.fstat(child)) == _stat_stamp(info), "snapshot directory changed while opening")
                    visit(child, path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                ensure(info.st_size <= 64 * 1024 * 1024, "footprint file-size budget exceeded")
                bytes_hashed += info.st_size
                ensure(bytes_hashed <= 256 * 1024 * 1024, "footprint hash budget exceeded")
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    ensure(_stat_stamp(os.fstat(child)) == _stat_stamp(info), "snapshot file changed while opening")
                    value = hashlib.sha256()
                    while True:
                        chunk = os.read(child, 65536)
                        if not chunk:
                            break
                        value.update(chunk)
                    ensure(_stat_stamp(os.fstat(child)) == _stat_stamp(info), "snapshot file changed while reading")
                    item = record(path, info, "file")
                    item["sha256"] = value.hexdigest()
                    records.append(item)
                finally:
                    os.close(child)
            elif stat.S_ISLNK(info.st_mode):
                item = record(path, info, "symlink")
                item["target"] = os.readlink(name, dir_fd=fd)
                records.append(item)
            else:
                raise ValidationError("unsupported object in owned footprint")
            ensure(
                _stat_stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == _stat_stamp(info),
                "snapshot entry mapping changed",
            )
        ensure(_stat_stamp(os.fstat(fd)) == _stat_stamp(before), "snapshot directory changed while enumerating")

    try:
        visit(descriptor, "")
        ensure(_stat_stamp(root.lstat()) == _stat_stamp(os.fstat(descriptor)), "snapshot root mapping changed")
    finally:
        os.close(descriptor)
    records.sort(key=lambda entry: entry["path"])
    return {
        "exists": True, "entries": records,
        "tree_sha256": sha256_bytes(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()),
    }


def _snapshot_tree_if_exists(path: Path) -> dict[str, Any]:
    try:
        path.lstat()
    except FileNotFoundError:
        return {"exists": False, "entries": []}
    return snapshot_tree(path)


def footprint_totals(snapshots: dict[str, dict[str, Any]]) -> dict[str, int]:
    result = {
        "regular_entries": 0, "unique_regular_files": 0,
        "regular_logical_bytes": 0, "regular_allocated_bytes": 0,
        "directories": 0, "directory_allocated_bytes": 0,
        "symlinks": 0, "symlink_logical_bytes": 0, "symlink_allocated_bytes": 0,
    }
    seen: set[tuple[int, int]] = set()
    for snapshot in snapshots.values():
        for entry in snapshot["entries"]:
            kind = entry["kind"]
            if kind == "file":
                result["regular_entries"] += 1
                identity = (entry["device"], entry["inode"])
                if identity in seen:
                    continue
                seen.add(identity)
                result["unique_regular_files"] += 1
                result["regular_logical_bytes"] += entry["logical_bytes"]
                result["regular_allocated_bytes"] += entry["allocated_bytes"]
            elif kind == "directory":
                result["directories"] += 1
                result["directory_allocated_bytes"] += entry["allocated_bytes"]
            elif kind == "symlink":
                result["symlinks"] += 1
                result["symlink_logical_bytes"] += entry["logical_bytes"]
                result["symlink_allocated_bytes"] += entry["allocated_bytes"]
    return result


def _public_result(value: Any, run_root: Path) -> Any:
    if isinstance(value, str):
        return value.replace(str(run_root), "<run-root>")
    if isinstance(value, list):
        return [_public_result(item, run_root) for item in value]
    if isinstance(value, dict):
        return {key: _public_result(item, run_root) for key, item in value.items()}
    return value


def _write_report(path: Path, result: dict[str, Any]) -> None:
    import tempfile

    destination = path.absolute()
    ensure(
        destination.parent.resolve().is_relative_to(REPO / "benchmarks/results")
        or destination.parent.resolve().is_relative_to(REPO / "target"),
        "results must be written under benchmarks/results or an owned target workspace",
    )
    ensure(not destination.is_symlink(), "result destination must not be a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=destination.parent, prefix=".c0-result-", delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(result, handle, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_install(
    *, profile: Path, params: dict[str, str], command: list[str],
    env_map: dict[str, str], cwd: Path, timeout_seconds: int,
    stdout_cap_bytes: int, stderr_cap_bytes: int,
    raw_sink: Callable[[dict[str, Any]], None],
    expects_json: bool,
    expected_prefix: Path | None = None,
) -> dict[str, Any]:
    capture = _run_broker(profile, params, command, env_map, cwd, timeout_seconds, stdout_cap_bytes, stderr_cap_bytes)
    raw_sink(capture)
    ensure(capture["status"] == "completed", "installer capture failed or exceeded a bound")
    ensure(capture["returncode"] == 0, "installer exited unsuccessfully")
    denied = capture["stderr"].lower()
    ensure("operation not permitted" not in denied and "permission denied" not in denied, "installer reported a permission denial")
    payload = None
    if expects_json:
        payload = json.loads(capture["stdout"])
        ensure(isinstance(payload, dict), "installer JSON must be an object")
        ensure(payload.get("schema_version") == 1 and payload.get("kind") == "installation_result", "unexpected Sayaka installation result schema")
        ensure(payload.get("outcome", {}).get("status") == "Installed", "Sayaka did not report a fresh installation")
        ensure(payload["outcome"].get("error") is None, "Sayaka installation reported an error")
        preview = payload["outcome"].get("preview", {})
        ensure(preview.get("action") == "Install" and preview.get("already_installed") is False, "Sayaka result is not a fresh install")
        if expected_prefix is not None:
            prefix = preview.get("prefix", {})
            ensure(prefix.get("encoding") == "unix_bytes", "unexpected installed prefix encoding")
            ensure(Path(os.fsdecode(bytes(prefix["bytes"]))) == expected_prefix, "Sayaka installed prefix mismatch")
    return {
        "status": "passed", "exit_code": capture["returncode"],
        "stdout_bytes": capture["stdout_bytes"], "stderr_bytes": capture["stderr_bytes"],
        "output_contract": "json" if expects_json else "official_text",
    }


def verify_mole_installation(
    source_snapshot: dict[str, Any], prefix_snapshot: dict[str, Any],
    config_snapshot: dict[str, Any],
) -> None:
    prefix = {entry["path"]: entry for entry in prefix_snapshot["entries"]}
    config = {entry["path"]: entry for entry in config_snapshot["entries"]}
    for name in ("mole", "mo"):
        ensure(name in prefix and prefix[name]["kind"] == "file", "Mole launcher or alias missing")
        ensure(prefix[name]["mode"] & 0o111 != 0, "Mole launcher is not executable")
    ensure(".helper_install_incomplete" not in config, "Mole helper installation is incomplete")
    for entry in source_snapshot["entries"]:
        name = entry["path"]
        if entry["kind"] != "file":
            continue
        if not (name.startswith(("bin/", "lib/")) or name in {"README.md", "LICENSE", "install.sh"}):
            continue
        installed = config.get(name)
        ensure(installed is not None and installed["kind"] == "file", "Mole installed resource missing")
        ensure(installed["sha256"] == entry["sha256"], "Mole installed resource differs from pinned source")
    for name in ("bin/analyze-go", "bin/status-go"):
        ensure(name in config and config[name]["mode"] & 0o111 != 0, "Mole native helper missing or not executable")


def execute_phase_b(
    manifest: dict[str, Any], phase_a: Any, reference_root: Path,
    run_root_base: Path, approved_profile_sha256: str,
    output_path: Path | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "benchmark_id": manifest["benchmark_id"], "phase": "B",
        "status": "running", "execution_performed": False,
        "mole_execution_attempted": False, "samples": [],
        "profile_sha256": approved_profile_sha256, "current_stage": "setup",
        "runner_sha256": sha256(Path(__file__)),
    }
    run_root = None
    journal_path = None
    try:
        run_root, identity = phase_a.create_owned_run_root(run_root_base)
        phase_a.verify_identity_chain(identity)
        layout = phase_a.make_layout(run_root)
        journal_path = layout["private_logs"] / "phase-b-journal.jsonl"
        result["run_root"] = str(run_root.relative_to(REPO))
        result["journal"] = str(journal_path.relative_to(REPO))

        def checkpoint(stage: str) -> None:
            result["current_stage"] = stage
            _append_journal(journal_path, {"event": "stage", "stage": stage})
            if output_path is not None:
                _write_report(output_path, _public_result(result, run_root))

        checkpoint("preflight")
        completed = _execute_phase_b(
            manifest, phase_a, reference_root, approved_profile_sha256,
            run_root, identity, layout, journal_path, result, checkpoint,
        )
        result.update(completed)
    except (ValidationError, phase_a.ValidationError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if journal_path is not None:
            _append_journal(journal_path, {
                "event": "blocked", "stage": result["current_stage"],
                "exception": type(error).__name__, "message": str(error),
            })
        result["status"] = "blocked"
        result["blocked_prerequisite"] = result["current_stage"] + "_failed"
        result["summary"] = None
    finally:
        if result["status"] == "running":
            result["status"] = "failed"
            result["blocked_prerequisite"] = "unexpected_runner_error"
            result["summary"] = None
            if journal_path is not None:
                _append_journal(journal_path, {
                    "event": "runner_exception",
                    "stage": result["current_stage"],
                    "exception": str(sys.exc_info()[1]),
                })
        public = _public_result(result, run_root) if run_root is not None else result
        if journal_path is not None:
            _append_journal(journal_path, {"event": "final_result", "result": public})
        if output_path is not None:
            _write_report(output_path, public)
    return public


def _execute_phase_b(
    manifest: dict[str, Any], phase_a: Any, reference_root: Path,
    approved_profile_sha256: str, run_root: Path,
    identity: dict[Path, tuple[int, int]], layout: dict[str, Path],
    journal_path: Path, result: dict[str, Any],
    checkpoint: Callable[[str], None],
) -> dict[str, Any]:

    source_lock = phase_a.verify_reference_assets(manifest, reference_root)
    staged_source = phase_a.stage_source_from_archive(reference_root, layout, manifest)
    sayaka_staging = phase_a.stage_sayaka_binary(manifest, layout)
    source_fingerprint = snapshot_tree(layout["mole_source"])
    sayaka_source_fingerprint = snapshot_tree(layout["sayaka_source_binary"])
    fixture_truth = phase_a.generate_flat_fixture(layout, manifest["scenario"]["fixture_truth"])
    profile_path, helper_paths = phase_a.write_sandbox_profile(run_root, layout, manifest)
    profile_sha = phase_a.sha256(profile_path)
    ensure(profile_sha == approved_profile_sha256, "executed profile hash differs from approved hash")

    _append_journal(journal_path, {"event": "phase_b_start", "profile_sha256": profile_sha})

    canaries, _raw = phase_a.run_canaries(profile_path, layout, helper_paths, manifest, run_root)
    _append_journal(journal_path, {"event": "canary_raw", "records": _raw})
    _append_journal(journal_path, {"event": "phase_a_recheck_canaries", "all_passed": all(item["status"] == "passed" for item in canaries)})
    ensure(all(item["status"] == "passed" for item in canaries), "Phase B preflight canary revalidation failed")

    sayaka_control = phase_a.run_sayaka_control_scan(
        profile_path,
        layout,
        layout["fixture_root"],
        fixture_truth,
        timeout_seconds=manifest["canary_timeouts_seconds"]["sayaka_control_scan"],
        run_root=run_root,
    )
    _append_journal(journal_path, {"event": "sayaka_control_raw", "record": sayaka_control.pop("_private_raw", None)})
    _append_journal(journal_path, {"event": "phase_a_recheck_sayaka_control", "status": sayaka_control["status"]})
    ensure(sayaka_control["status"] == "passed", "Phase B preflight Sayaka control scan failed")

    params = {
        "RUN_ROOT": str(layout["allowed_root"].parent),
        "ALLOWED_ROOT": str(layout["allowed_root"]),
        "EXEC_READABLE": str(layout["control_exec_readable"]),
        "MOLE_HOME": str(layout["mole_home"]),
        "MOLE_TMP": str(layout["mole_tmp"]),
        "MOLE_PREFIX": str(layout["mole_prefix"]),
        "MOLE_CONFIG": str(layout["mole_config"]),
        "SAYAKA_HOME": str(layout["sayaka_home"]),
        "SAYAKA_TMP": str(layout["sayaka_tmp"]),
        "SAYAKA_INSTALL_ROOT": str(layout["sayaka_install_root"]),
    }
    fixed = manifest["phase_b"]["measurement_fixed"]
    measured_roots = {
        key: layout[key] for key in
        ("mole_prefix", "mole_config", "mole_home", "sayaka_prefix", "sayaka_home")
    }
    before_install = {key: _snapshot_tree_if_exists(path) for key, path in measured_roots.items()}
    for key in ("mole_prefix", "mole_config", "sayaka_prefix"):
        ensure(
            all(item["kind"] == "directory" for item in before_install[key]["entries"]),
            "installation destination contains pre-existing files",
        )
    result["footprint_pre_install"] = before_install
    phase_a.verify_identity_chain(identity)
    ensure(snapshot_tree(layout["mole_source"])["tree_sha256"] == source_fingerprint["tree_sha256"], "staged Mole source changed during preflight")
    ensure(snapshot_tree(layout["sayaka_source_binary"])["tree_sha256"] == sayaka_source_fingerprint["tree_sha256"], "staged Sayaka source changed during preflight")
    # The guard canaries use an empty prefix; the real installer requires an
    # absent destination, rather than adopting an unmanifested directory.
    prefix_before = before_install["sayaka_prefix"]
    if prefix_before["exists"]:
        ensure(len(prefix_before["entries"]) == 1, "Sayaka control prefix is not empty")
        original = prefix_before["entries"][0]
        current = layout["sayaka_prefix"].lstat()
        ensure(
            stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino) == (original["device"], original["inode"]),
            "Sayaka control prefix identity changed",
        )
        layout["sayaka_prefix"].rmdir()

    sayaka_install_cmd = [
        str(layout["sayaka_source_binary"] / "sayaka"),
        "install",
        "--prefix",
        str(layout["sayaka_prefix"]),
        "--execute",
        "--json",
    ]
    install_env, install_home = _tool_env(layout, "sayaka", "install")
    result["execution_performed"] = True
    checkpoint("sayaka_install")
    install_result = run_install(
        profile=profile_path,
        params=params,
        command=sayaka_install_cmd,
        env_map=install_env,
        cwd=install_home,
        timeout_seconds=240,
        stdout_cap_bytes=int(fixed["stdout_capture_cap_bytes"]),
        stderr_cap_bytes=int(fixed["stderr_capture_cap_bytes"]),
        expects_json=True,
        expected_prefix=layout["sayaka_prefix"],
        raw_sink=lambda capture: _append_journal(journal_path, {"event": "sayaka_install_raw", "capture": capture}),
    )
    _append_journal(journal_path, {"event": "sayaka_install", "result": install_result})
    sayaka_installed = snapshot_tree(layout["sayaka_prefix"])
    sayaka_files = {entry["path"]: entry for entry in sayaka_installed["entries"] if entry["kind"] == "file"}
    ensure(set(sayaka_files) == {"bin/sayaka", "ownership-v1.json", ".lock"}, "unexpected Sayaka installation file set")
    ensure(sayaka_files["bin/sayaka"]["sha256"] == manifest["sayaka_reference"]["binary_sha256"], "installed Sayaka binary hash mismatch")

    mole_install_cmd = [
        "/bin/bash",
        "--noprofile",
        "--norc",
        str(layout["mole_source"] / "install.sh"),
        "--prefix",
        str(layout["mole_prefix"]),
        "--config",
        str(layout["mole_config"]),
    ]
    mole_install_env, mole_install_home = _tool_env(layout, "mole", "install")
    result["mole_execution_attempted"] = True
    checkpoint("mole_install")
    mole_install_result = run_install(
        profile=profile_path,
        params=params,
        command=mole_install_cmd,
        env_map=mole_install_env,
        cwd=mole_install_home,
        timeout_seconds=240,
        stdout_cap_bytes=int(fixed["stdout_capture_cap_bytes"]),
        stderr_cap_bytes=int(fixed["stderr_capture_cap_bytes"]),
        expects_json=False,
        raw_sink=lambda capture: _append_journal(journal_path, {"event": "mole_install_raw", "capture": capture}),
    )
    _append_journal(journal_path, {"event": "mole_install", "result": mole_install_result})

    fixture_map = {item["path"]: item for item in fixture_truth["entries"]}
    fingerprints_before = {key: _snapshot_tree_if_exists(path) for key, path in measured_roots.items()}
    fingerprints_before["fixture"] = snapshot_tree(layout["fixture_root"])
    verify_mole_installation(source_fingerprint, fingerprints_before["mole_prefix"], fingerprints_before["mole_config"])
    product_groups = {
        "mole": ("mole_prefix", "mole_config"),
        "sayaka": ("sayaka_prefix",),
        "mole_install_home": ("mole_home",),
        "sayaka_install_home": ("sayaka_home",),
    }
    footprints = {}
    for product, keys in product_groups.items():
        baseline = footprint_totals({key: before_install[key] for key in keys})
        installed = footprint_totals({key: fingerprints_before[key] for key in keys})
        footprints[product] = {
            "before_install": baseline, "after_install": installed,
            "net_change": {key: installed[key] - baseline[key] for key in installed},
        }
    result["footprints"] = footprints
    result["fingerprints_post_install"] = fingerprints_before
    result["install_result"] = {"sayaka": install_result, "mole": mole_install_result}
    immutable_roots = {
        "fixture": layout["fixture_root"],
        "mole_prefix": layout["mole_prefix"], "mole_config": layout["mole_config"],
        "sayaka_prefix": layout["sayaka_prefix"],
    }

    def verify_immutable() -> None:
        phase_a.verify_identity_chain(identity)
        for key, path in immutable_roots.items():
            ensure(snapshot_tree(path)["tree_sha256"] == fingerprints_before[key]["tree_sha256"], "immutable " + key + " changed")

    def run_tool_sample(tool: str, phase: str, run_idx: int) -> dict[str, Any]:
        if tool == "mole":
            command = [str(layout["mole_prefix"] / "mole"), "analyze", "--json", str(layout["fixture_root"])]
            normalizer = lambda payload: normalize_mole_json(payload, fixture_root=layout["fixture_root"], truth_entries=fixture_map)
        else:
            command = [str(layout["sayaka_prefix"] / "bin/sayaka"), "scan", "--json", str(layout["fixture_root"])]
            normalizer = lambda payload: normalize_sayaka_json(payload, fixture_root=layout["fixture_root"], truth_entries=fixture_map)

        env_map, cwd = _tool_env(layout, tool, f"{phase}-{tool}-{run_idx:03d}")
        return run_sample(
            profile=profile_path,
            params=params,
            command=command,
            env_map=env_map,
            cwd=cwd,
            timeout_seconds=int(fixed["timeout_seconds_per_sample"]),
            stdout_cap_bytes=int(fixed["stdout_capture_cap_bytes"]),
            stderr_cap_bytes=int(fixed["stderr_capture_cap_bytes"]),
            normalizer=normalizer,
            run_root=run_root,
            raw_sink=lambda capture: _append_journal(journal_path, {
                "event": "process_capture", "tool": tool, "phase": phase,
                "index": run_idx, "capture": capture,
            }),
        )

    rows: list[dict[str, Any]] = result["samples"]

    def run_phase_row(tool: str, phase: str, index: int, pair_id: int | None, order: str | None) -> bool:
        checkpoint(f"{phase}_{tool}_{index}")
        event = {
            "phase": phase,
            "tool": tool,
            "index": index,
            "pair_id": pair_id,
            "order": order,
            "status": "failed",
            "failure_class": "invocation_not_completed",
        }
        rows.append(event)
        try:
            verify_immutable()
            event.update(run_tool_sample(tool, phase, index))
            verify_immutable()
        except (ValidationError, phase_a.ValidationError, OSError, ValueError, KeyError, TypeError) as error:
            event["status"] = "failed"
            event["failure_class"] = "integrity_or_runner_failure"
            _append_journal(journal_path, {"event": "sample_error", "message": str(error)})
        finally:
            _append_journal(journal_path, {"event": "sample", **event})
        checkpoint(f"{phase}_{tool}_{index}_recorded")
        return event["status"] == "passed"

    if not run_phase_row("mole", "correctness_gate", 1, None, None):
        return {
            "status": "blocked",
            "blocked_prerequisite": "correctness_gate_failed",
            "journal": str(journal_path.relative_to(REPO)),
            "samples": rows,
        }
    if not run_phase_row("sayaka", "correctness_gate", 1, None, None):
        return {
            "status": "blocked",
            "blocked_prerequisite": "correctness_gate_failed",
            "journal": str(journal_path.relative_to(REPO)),
            "samples": rows,
        }
    if not run_phase_row("mole", "warmup", 1, None, None):
        return {
            "status": "blocked",
            "blocked_prerequisite": "warmup_failed",
            "journal": str(journal_path.relative_to(REPO)),
            "samples": rows,
        }
    if not run_phase_row("sayaka", "warmup", 1, None, None):
        return {
            "status": "blocked",
            "blocked_prerequisite": "warmup_failed",
            "journal": str(journal_path.relative_to(REPO)),
            "samples": rows,
        }

    schedule = manifest["scenario"]["pair_schedule"]
    mapping = manifest["scenario"]["ab_mapping"]
    run_indexes = {"mole": 0, "sayaka": 0}

    for pair_id, order in enumerate(schedule, start=1):
        ensure(order in {"AB", "BA"}, f"unsupported order value: {order}")
        sequence = [mapping[order[0]], mapping[order[1]]]
        for tool in sequence:
            run_indexes[tool] += 1
            ok = run_phase_row(tool, "measurement", run_indexes[tool], pair_id, order)
            if not ok:
                return {
                    "status": "blocked",
                    "blocked_prerequisite": "measurement_failed",
                    "journal": str(journal_path.relative_to(REPO)),
                    "samples": rows,
                }

    fingerprints_after = {key: _snapshot_tree_if_exists(path) for key, path in measured_roots.items()}
    fingerprints_after["fixture"] = snapshot_tree(layout["fixture_root"])

    ensure(fingerprints_before["fixture"]["tree_sha256"] == fingerprints_after["fixture"]["tree_sha256"], "fixture tree changed during run")
    ensure(fingerprints_before["mole_prefix"].get("tree_sha256") == fingerprints_after["mole_prefix"].get("tree_sha256"), "mole prefix changed after install")
    ensure(fingerprints_before["mole_config"].get("tree_sha256") == fingerprints_after["mole_config"].get("tree_sha256"), "mole config changed after install")
    ensure(fingerprints_before["sayaka_prefix"].get("tree_sha256") == fingerprints_after["sayaka_prefix"].get("tree_sha256"), "sayaka prefix changed after install")

    measurement_rows = [row for row in rows if row["phase"] == "measurement"]
    sayaka_times = [float(item["complete_result_ms"]) for item in measurement_rows if item["tool"] == "sayaka" and item["status"] == "passed"]
    mole_times = [float(item["complete_result_ms"]) for item in measurement_rows if item["tool"] == "mole" and item["status"] == "passed"]

    return {
        "status": "completed",
        "run_root": str(run_root.relative_to(REPO)),
        "profile_sha256": profile_sha,
        "reference_lock": source_lock,
        "staged_source_tree_sha256": staged_source["staged_tree_sha256"],
        "sayaka_staging": sayaka_staging,
        "fixture_truth_lock": {
            "fixture_id": fixture_truth["fixture_id"],
            "file_count": fixture_truth["file_count"],
            "logical_bytes": fixture_truth["logical_bytes"],
            "entries_sha256": fixture_truth["entries_sha256"],
        },
        "install_result": {
            "sayaka": install_result,
            "mole": mole_install_result,
        },
        "fingerprints_before": fingerprints_before,
        "fingerprints_after": fingerprints_after,
        "journal": str(journal_path.relative_to(REPO)),
        "samples": rows,
        "summary": {
            "sayaka": {
                "passed": len(sayaka_times),
                "median_complete_ms": statistics.median(sayaka_times) if sayaka_times else None,
                "p95_complete_ms": nearest_rank_percentile(sayaka_times, 95.0) if sayaka_times else None,
            },
            "mole": {
                "passed": len(mole_times),
                "median_complete_ms": statistics.median(mole_times) if mole_times else None,
                "p95_complete_ms": nearest_rank_percentile(mole_times, 95.0) if mole_times else None,
            },
        },
        "ab_mapping": mapping,
        "measurement_fixed": fixed,
        "cancellation": {
            "status": "not_measured",
            "reason": manifest["phase_b"].get("cancellation_reason", "no shared preregistered method"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--phase-a-result", type=Path, default=PHASE_A_RESULT_PATH)
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--run-root-base", type=Path, default=REPO / "target/c0-batch2/runs")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--approved-profile-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    manifest = load_json(args.manifest, "batch2 manifest")
    validate_manifest_contract(manifest)
    phase_a_result = load_json(args.phase_a_result, "phase-a result")
    validate_phase_a_binding(manifest, phase_a_result, args.approved_profile_sha256, args.manifest)

    if not args.execute:
        output = build_non_execute_output(manifest, phase_a_result, args.approved_profile_sha256, args.manifest, args.phase_a_result)
        _write_report(args.output, output)
        print(json.dumps(output, indent=2))
        return

    ensure(
        manifest.get("current_batch_decision", {}).get("runtime_execution_authorized") is True,
        "this preregistration is closed as blocked tooling; runtime requires new authorization",
    )
    ensure(args.reference_root is not None, "--reference-root is required with --execute")
    validate_phase_a_ready_for_execute(phase_a_result)
    phase_a = _load_phase_a_module()
    _write_report(args.output, {
        **build_non_execute_output(manifest, phase_a_result, args.approved_profile_sha256, args.manifest, args.phase_a_result),
        "status": "running",
    })
    result = execute_phase_b(manifest, phase_a, args.reference_root, args.run_root_base, args.approved_profile_sha256, args.output)
    print(json.dumps(result, indent=2))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (ValidationError, OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
