#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Readonly native status/PTY baseline; no load generator or maintenance action."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time
from check_m7_benchmark import ANSI, Fixture, REPO, TerminalProcess


def stream_run(binary, fixture, budget):
    result = subprocess.run(
        [str(binary), "status", "--watch", "--json", "--count", str(budget["samples"]),
         "--interval-ms", str(budget["interval_ms"])],
        cwd=fixture.base, env=fixture.env(), capture_output=True,
        timeout=budget["samples"] * budget["interval_ms"] / 1000 + 15,
    )
    assert result.returncode == 0, "native primary surface unavailable: %s" % result.stderr.decode(errors="replace")
    samples = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(samples) == budget["samples"]
    for index, sample in enumerate(samples):
        assert sample["schema_version"] == 1
        assert sample["sampler_id"] == samples[0]["sampler_id"]
        assert sample["interval_ms"] == budget["interval_ms"]
        assert sample["slow_interval_ms"] == budget["slow_interval_ms"]
        if index:
            assert sample["sequence"] > samples[index - 1]["sequence"]
        for name in ["memory", "network", "disk", "sampler_process"]:
            assert sample[name]["state"] == "fresh", "%s not fresh" % name
        for name in ["temperature_celsius", "gpu_utilization_percent", "process_top"]:
            assert sample[name]["state"] == "unsupported"
            assert sample[name]["value"] is None
    steady = samples[budget["warmup_samples"]:]
    cpu = [sample["sampler_process"]["value"]["cpu_percent_one_core"] for sample in steady]
    assert all(value is not None for value in cpu)
    rss = max(sample["sampler_process"]["value"]["resident_bytes"] for sample in steady)
    latency = max(sample["collection_ms"] for sample in steady)
    assert max(cpu) <= budget["max_steady_cpu_percent_one_core"], "steady sampler CPU exceeded budget: %r" % cpu
    assert rss <= budget["max_resident_bytes"]
    assert latency + 1 <= budget["max_steady_collection_ms"], "collection duration upper bound exceeded budget"
    assert any(sample["disk"]["age_ms"] > 0 for sample in steady), "slow observations were not cached"
    return {"max_cpu_percent_one_core": max(cpu), "max_resident_bytes": rss,
            "max_collection_ms": latency, "collection_ms_upper_bound": latency + 1, "emitted_samples": len(samples),
            "coalesced_samples": sum(sample["coalesced_samples"] for sample in samples)}


def panel_run(binary, fixture, budget):
    terminal = TerminalProcess(binary, fixture, columns=200, rows=40,
        arguments=["status", "--watch", "--interval-ms", str(budget["interval_ms"])])
    try:
        first = terminal.wait_for(b"Sayaka / System status")
        terminal.wait_for(("Sample %d |" % budget["samples"]).encode(),
            timeout=budget["samples"] * budget["interval_ms"] / 1000 + 15)
        start = time.monotonic()
        os.write(terminal.master, b"q")
        terminal.finish(0)
        shutdown = (time.monotonic() - start) * 1000
        text = ANSI.sub(b"", bytes(terminal.transcript)).decode(errors="replace")
        cpu = [float(value) for value in re.findall(r"Sampler:.*?CPU ([0-9.]+)%", text)]
        assert cpu, "terminal did not display measured sampler CPU"
        # Renderer repeats a cached observation as age changes. Discard the first
        # two intervals, then bound every displayed steady-state CPU value.
        marker = text.find("Sample %d |" % (budget["warmup_samples"] + 1))
        steady_text = text[marker:] if marker >= 0 else ""
        steady_cpu = [float(value) for value in re.findall(r"Sampler:.*?CPU ([0-9.]+)%", steady_text)]
        assert steady_cpu, "no terminal steady-state observations"
        cpu_upper_bound = max(steady_cpu) + 0.005
        assert cpu_upper_bound <= budget["max_steady_cpu_percent_one_core"]
        assert first <= budget["max_first_frame_ms"]
        assert shutdown <= budget["max_shutdown_ms"]
        assert terminal.rss <= budget["max_resident_bytes"]
        return {"first_frame_ms": first, "displayed_max_cpu_percent_one_core": max(steady_cpu),
                "cpu_percent_one_core_upper_bound": cpu_upper_bound,
                "peak_resident_bytes": terminal.rss, "shutdown_ms": shutdown}
    finally:
        terminal.close()


def signal_run(binary, fixture, budget, sig, code):
    terminal = TerminalProcess(binary, fixture, arguments=["status", "--watch"])
    try:
        terminal.wait_for(b"Sayaka / System status")
        start = time.monotonic()
        terminal.process.send_signal(sig)
        terminal.finish(code)
        elapsed = (time.monotonic() - start) * 1000
        assert elapsed <= budget["max_shutdown_ms"]
        return elapsed
    finally:
        terminal.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=REPO / "target/release/sayaka")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("BLOCKED: native status baseline requires macOS")
    binary = args.binary.resolve(strict=True)
    budget = json.loads((REPO / "benchmarks/t11-v1.json").read_text())
    fixture = Fixture(file_count=0)
    try:
        stream = stream_run(binary, fixture, budget)
        panel = panel_run(binary, fixture, budget)
        signals = {
            "sigint_ms": signal_run(binary, fixture, budget, signal.SIGINT, 130),
            "sigterm_ms": signal_run(binary, fixture, budget, signal.SIGTERM, 143),
        }
        fixture.verify_payload()
        result = {"fixture": budget["fixture"], "os": platform.mac_ver()[0], "arch": platform.machine(),
                  "scope": budget["scope"], "ndjson": stream, "terminal": panel, "signals": signals}
    finally:
        fixture.close()
    result["cleanup"] = "passed"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
