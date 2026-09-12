#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Run only the generated M2 fixture; validate results and optional local budgets."""

import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


def numbers(line):
    return {key: int(value) for key, value in re.findall(r"([a-z_]+)=(\d+)", line)}


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("native M2 measurements require macOS")
    import resource
    repository = Path(__file__).resolve().parent.parent
    binary = repository / "target/release/examples/scan_fixture_bench"
    if not binary.is_file():
        parser.error("build first: cargo build -p sayaka-engine --release --example scan_fixture_bench --locked")
    budget = json.loads((repository / "benchmarks/m2-v1.json").read_text())
    with tempfile.TemporaryDirectory(prefix="sayaka-m2-runner-", dir=repository / "target") as owned:
        root = Path(owned).resolve()
        for name in ("home", "config", "state", "temp", "fixtures"):
            (root / name).mkdir()
        environment = {
            "HOME": str(root / "home"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_STATE_HOME": str(root / "state"),
            "TMPDIR": str(root / "temp"),
            "M2_BENCH_PARENT": str(root / "fixtures"),
        }
        # This binary creates no subprocesses; timeout kills its owned process
        # and threads before the parent's fixture container is removed.
        completed = subprocess.run(
            [str(binary)], cwd=root, env=environment, capture_output=True,
            text=True, timeout=120, check=False,
        )
        # The runner starts exactly one child. On macOS ru_maxrss is in bytes.
        peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if completed.returncode != 0:
            raise RuntimeError(f"benchmark failed ({completed.returncode}):\n{completed.stdout}\n{completed.stderr}")
        if list((root / "fixtures").iterdir()):
            raise RuntimeError("benchmark did not clean up its owned fixture")
    lines = completed.stdout.splitlines()
    headers = [line for line in lines if line.startswith("fixture=")]
    if len(headers) != 1 or not headers[0].startswith("fixture=m2-v1 "):
        raise RuntimeError("unexpected fixture manifest")
    header = numbers(headers[0])
    for key in ("unique_files", "file_entries", "logical_bytes", "runs"):
        if header[key] != budget[key]:
            raise RuntimeError(f"fixture changed without versioning: {key}")
    samples = [numbers(line) for line in lines if line.startswith("sample=")]
    cancellations = [numbers(line) for line in lines if line.startswith("cancel_latency_ms=")]
    if len(samples) != budget["runs"] or [item["sample"] for item in samples] != list(range(budget["runs"])):
        raise RuntimeError("missing or duplicated benchmark samples")
    if len(cancellations) != 1 or "cleanup=complete" not in lines:
        raise RuntimeError("missing cancellation or cleanup evidence")
    failures = []
    limits = {
        "elapsed_ms": "max_elapsed_ms",
        "first_result_ms": "max_first_result_ms",
        "peak_workers": "max_workers",
        "peak_queued_dirs": "max_queued_dirs",
        "peak_open_dirs": "max_open_dirs",
        "peak_pending_events": "max_pending_events",
        "retained_path_bytes": "max_retained_path_bytes",
    }
    for sample in samples:
        for metric, maximum in limits.items():
            if sample[metric] > budget[maximum]:
                failures.append(f"sample {sample['sample']}: {metric} exceeds {budget[maximum]}")
    if cancellations[0]["cancel_latency_us"] > budget["max_cancel_latency_us"]:
        failures.append("cancellation latency exceeds budget")
    if peak_rss > budget["max_peak_rss_bytes"]:
        failures.append("peak RSS exceeds budget")
    result = {
        "fixture": budget["fixture"],
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"macos": platform.mac_ver()[0], "architecture": os.uname().machine, "logical_cpus": os.cpu_count()},
        "samples": samples,
        "cancellation": cancellations[0],
        "peak_rss_bytes": peak_rss,
        "cleanup": "complete",
        "budget_failures": failures,
        "scope": budget["scope"],
    }
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")
    if args.verify and failures:
        raise SystemExit("M2 local acceptance failed: " + "; ".join(failures))


if __name__ == "__main__":
    run()
