#!/usr/bin/env python3
"""Read-only CLI performance measurement on synthetic, isolated macOS trees.

This is a benchmark, not a unit/UI test runner. It never reads a user folder.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import statistics
import tempfile
import time


def fixture(root: Path, case: dict) -> Path:
    root.mkdir()
    dirs = [root]
    for number in range(1, case["directories"]):
        directory = root / f"d{number:05d}"
        directory.mkdir()
        dirs.append(directory)
    payload = b"x" * case["file_bytes"]
    for number in range(case["files"]):
        (dirs[number % len(dirs)] / f"f{number:06d}.bin").write_bytes(payload)
    return root


def wait_for_child(pid: int, deadline: float) -> tuple[int, object, bool]:
    """Reap a child by the deadline, terminating and then killing a stuck scan."""
    timed_out = False
    while True:
        waited, status, usage = os.wait4(pid, os.WNOHANG)
        if waited:
            return status, usage, timed_out
        if time.perf_counter() >= deadline:
            timed_out = True
            break
        time.sleep(0.005)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    grace = time.perf_counter() + 1.0
    while time.perf_counter() < grace:
        waited, status, usage = os.wait4(pid, os.WNOHANG)
        if waited:
            return status, usage, timed_out
        time.sleep(0.005)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    kill_deadline = time.perf_counter() + 1.0
    while time.perf_counter() < kill_deadline:
        waited, status, usage = os.wait4(pid, os.WNOHANG)
        if waited:
            return status, usage, timed_out
        time.sleep(0.005)
    raise RuntimeError(f"scan process {pid} did not exit after SIGKILL")


def run(binary: Path, root: Path, cancel_delay: float | None, timeout: float) -> dict:
    import subprocess

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.perf_counter()
        child = subprocess.Popen(
            [str(binary), "scan", str(root), "--json", "--profile-scan-stderr"],
            stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
        )
        deadline = started + timeout
        signal_sent = None
        if cancel_delay is not None:
            time.sleep(min(cancel_delay, max(0, deadline - time.perf_counter())))
            if time.perf_counter() < deadline:
                try:
                    os.kill(child.pid, signal.SIGINT)
                    signal_sent = time.perf_counter()
                except ProcessLookupError:
                    pass
        status, usage, timed_out = wait_for_child(child.pid, deadline)
        child.returncode = os.waitstatus_to_exitcode(status)
        finished = time.perf_counter()
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read(64 * 1024 * 1024 + 1)
        errors = stderr.read(1024 * 1024 + 1)
        profiles = []
        for line in errors.splitlines():
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(value, dict) and value.get("type") == "scan_profile":
                profiles.append(value)
        profile = profiles[0] if len(profiles) == 1 else {}
        try:
            report = json.loads(output) if output and len(output) <= 64 * 1024 * 1024 else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            report = {}
        if not isinstance(report, dict):
            report = {}
        return {
            "exit_status": child.returncode,
            "timed_out": timed_out,
            "signal_sent": signal_sent is not None,
            "output_truncated": len(output) > 64 * 1024 * 1024 or len(errors) > 1024 * 1024,
            "profile_count": len(profiles),
            "wall_ms": round((finished - started) * 1000, 3),
            "cancel_latency_ms": round((finished - signal_sent) * 1000, 3) if signal_sent else None,
            "peak_rss_bytes": usage.ru_maxrss,
            "scan_ms": profile.get("scan_ms"),
            "json_ms": profile.get("json_encode_write_flush_ms"),
            "profile_status": profile.get("status"),
            "stdout_bytes": len(output),
            "report_status": report.get("status"),
            "entry_count": len(report.get("entries", [])),
        }


def validate(sample: dict, case: dict, name: str, run_label: str) -> None:
    cancelling = "signal_delay_ms" in case
    expected_status = "cancelled" if cancelling else "complete"
    expected_exit = 130 if cancelling else 0
    expected_entries = case["directories"] + case["files"]
    errors = []
    if sample["timed_out"] or sample["output_truncated"]:
        errors.append("timeout or truncated output")
    if sample["exit_status"] != expected_exit:
        errors.append(f"exit {sample['exit_status']} != {expected_exit}")
    if sample["profile_count"] != 1:
        errors.append(f"profile count {sample['profile_count']} != 1")
    if sample["profile_status"] != expected_status or sample["report_status"] != expected_status:
        errors.append("profile/report status mismatch")
    if cancelling:
        if not sample["signal_sent"] or sample["cancel_latency_ms"] is None:
            errors.append("missing cancellation signal or latency")
        if not 0 < sample["entry_count"] <= expected_entries:
            errors.append("invalid partial entry count")
    elif sample["entry_count"] != expected_entries:
        errors.append(f"entry count {sample['entry_count']} != {expected_entries}")
    for field in ("wall_ms", "scan_ms", "json_ms", "peak_rss_bytes"):
        value = sample[field]
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            errors.append(f"invalid {field}")
    if errors:
        raise RuntimeError(f"{case['id']} {name} {run_label}: {', '.join(errors)}")


def percentile(values: list[float], proportion: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int(len(ordered) * proportion + 0.999999) - 1))]


def summary(samples: list[dict]) -> dict:
    fields = ["wall_ms", "scan_ms", "json_ms", "peak_rss_bytes", "cancel_latency_ms"]
    return {
        key: {"median": round(statistics.median(values), 3),
              "p95": round(percentile(values, 0.95), 3)}
        for key in fields
        if (values := [sample[key] for sample in samples if sample[key] is not None])
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--raw-output", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    binaries = {"baseline": args.baseline.resolve()}
    if args.candidate:
        binaries["candidate"] = args.candidate.resolve()
    results = {}
    timeout = manifest["conditions"]["timeout_seconds"]
    # /var is a symlink on macOS; the native scanner deliberately refuses it.
    with tempfile.TemporaryDirectory(prefix="sayaka-scan-benchmark-", dir="/private/tmp") as temporary:
        for case in manifest["scenarios"]:
            root = fixture(Path(temporary) / case["id"], case)
            delay = case.get("signal_delay_ms")
            cancel_delay = delay / 1000 if delay is not None else None
            for name, binary in binaries.items():
                validate(run(binary, root, cancel_delay, timeout), case, name, "warmup")
            samples = {name: [] for name in binaries}
            for index in range(case["runs"]):
                order = list(binaries) if index % 2 == 0 else list(reversed(binaries))
                for name in order:
                    sample = run(binaries[name], root, cancel_delay, timeout)
                    validate(sample, case, name, f"sample {index + 1}")
                    samples[name].append(sample)
            results[case["id"]] = {name: {"runs": len(rows), "summary": summary(rows),
                                          "report_statuses": sorted({r["report_status"] for r in rows}),
                                          "exit_statuses": sorted({r["exit_status"] for r in rows}),
                                          "entry_count_min": min(r["entry_count"] for r in rows),
                                          "entry_count_max": max(r["entry_count"] for r in rows)}
                                   for name, rows in samples.items()}
            if args.raw_output:
                results[case["id"]]["_raw_samples"] = samples
    if args.raw_output:
        raw = {case: versions.pop("_raw_samples") for case, versions in results.items()}
        args.raw_output.write_text(json.dumps({"benchmark_id": manifest["benchmark_id"],
                                              "samples": raw}, indent=2) + "\n")
    artifact = {"benchmark_id": manifest["benchmark_id"],
                "host": {"macos": platform.mac_ver()[0], "architecture": platform.machine()},
                "source_base_commit": manifest["source_base_commit"],
                "binary_sha256": {name: sha256(path) for name, path in binaries.items()},
                "method": "Paired alternating baseline/candidate, warmed macOS cache, one synthetic explicit root; release CLI with --json --profile-scan-stderr. No unit or UI tests.",
                "results": results,
                "interpretation": manifest["conditions"]["interpretation"]}
    args.output.write_text(json.dumps(artifact, indent=2) + "\n")
    for scenario, versions in results.items():
        print(scenario, {name: data["summary"] for name, data in versions.items()})


if __name__ == "__main__":
    main()
