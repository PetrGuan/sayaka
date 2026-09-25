#!/usr/bin/env python3
"""Read-only CLI performance measurement on synthetic, isolated macOS trees.

This is a benchmark, not a unit/UI test runner. It never reads a user folder.
"""

import argparse
import json
import os
from pathlib import Path
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


def run(binary: Path, root: Path, cancel_delay: float | None) -> dict:
    import subprocess

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.perf_counter()
        child = subprocess.Popen(
            [str(binary), "scan", str(root), "--json", "--profile-scan-stderr"],
            stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
        )
        signal_sent = None
        if cancel_delay is not None:
            time.sleep(cancel_delay)
            try:
                os.kill(child.pid, signal.SIGINT)
                signal_sent = time.perf_counter()
            except ProcessLookupError:
                pass
        pid, status, usage = os.wait4(child.pid, 0)
        finished = time.perf_counter()
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read(64 * 1024 * 1024 + 1)
        errors = stderr.read(1024 * 1024 + 1)
        profile = next((json.loads(line) for line in errors.splitlines()
                        if line.startswith(b'{"schema_version":2,"type":"scan_profile"')), {})
        report = json.loads(output) if output and len(output) <= 64 * 1024 * 1024 else {}
        return {
            "exit_status": os.waitstatus_to_exitcode(status),
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    binaries = {"baseline": args.baseline.resolve()}
    if args.candidate:
        binaries["candidate"] = args.candidate.resolve()
    results = {}
    # /var is a symlink on macOS; the native scanner deliberately refuses it.
    with tempfile.TemporaryDirectory(prefix="sayaka-scan-benchmark-", dir="/private/tmp") as temporary:
        for case in manifest["scenarios"]:
            root = fixture(Path(temporary) / case["id"], case)
            delay = case.get("signal_delay_ms")
            cancel_delay = delay / 1000 if delay is not None else None
            for binary in binaries.values():
                run(binary, root, cancel_delay)  # Warmup; not a measurement.
            samples = {name: [] for name in binaries}
            for index in range(case["runs"]):
                order = list(binaries) if index % 2 == 0 else list(reversed(binaries))
                for name in order:
                    samples[name].append(run(binaries[name], root, cancel_delay))
            results[case["id"]] = {name: {"summary": summary(rows), "samples": rows}
                                   for name, rows in samples.items()}
    args.output.write_text(json.dumps({"benchmark_id": manifest["benchmark_id"],
                                       "binaries": {k: str(v) for k, v in binaries.items()},
                                       "results": results}, indent=2) + "\n")
    for scenario, versions in results.items():
        print(scenario, {name: data["summary"] for name, data in versions.items()})


if __name__ == "__main__":
    main()
