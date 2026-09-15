#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Owned-fixture scan phase diagnostics, separate from comparative baselines."""

import argparse
import hashlib
import importlib.util
import json
import random
import shutil
import statistics
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIRECT = load_module("direct_profile_helpers", REPO / "scripts/check_c0_batch3_direct_analyzer.py")
COLLECTOR = DIRECT.PHASE_B
STATS = load_module("profile_statistics", REPO / "scripts/check_c0_statistics.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(manifest_path, binary, output):
    manifest = json.loads(manifest_path.read_text())
    DIRECT.ensure(digest(binary) == manifest["binary_sha256"], "diagnostic binary hash mismatch")
    DIRECT.ensure(not output.exists(), "diagnostic result already exists; choose a new path")
    direct_manifest = json.loads((REPO / "benchmarks/c0-batch3-direct-analyzer-v2.json").read_text())
    root, identity = DIRECT.create_owned_run_root(REPO / "target/c0-scan-profile/runs")
    layout = DIRECT.make_layout(root)
    staged = layout["bin"] / "sayaka"
    shutil.copyfile(binary, staged)
    staged.chmod(0o700)
    DIRECT.ensure(digest(staged) == manifest["binary_sha256"], "staged diagnostic hash mismatch")
    truth = DIRECT.PHASE_A.generate_flat_fixture(
        {"fixture_root": layout["fixture_root"]}, direct_manifest["scenario"]["fixture_truth"]
    )
    empty = layout["allowed_root"] / "empty-fixture"
    empty.mkdir(mode=0o700)
    canary = DIRECT.compile_trusted_canary(layout)
    profile, _ = DIRECT.write_sandbox_profile(root, layout, direct_manifest)
    params = {
        "RUN_ROOT": str(root), "ALLOWED_ROOT": str(layout["allowed_root"]),
        "EXEC_READABLE": str(layout["control_exec_readable"]),
        "ANALYZER": str(layout["bin"] / "unused-analyzer"),
        "SAYAKA": str(staged), "CANARY": str(canary),
    }
    canaries, guard_ok = DIRECT.run_guard_canaries(profile, params, layout, canary, 15)
    report = {
        "benchmark_id": manifest["benchmark_id"], "class": manifest["class"],
        "manifest_sha256": digest(manifest_path), "binary_sha256": digest(staged),
        "collector_sha256": digest(Path(COLLECTOR.__file__)),
        "profile_sha256": digest(profile), "run_root": str(root.relative_to(REPO)),
        "status": "running", "canaries": canaries, "samples": [],
        "mole_executed": False,
    }
    journal = layout["private_logs"] / "scan-profile.jsonl"
    immutable_paths = {
        "flat": layout["fixture_root"], "empty": empty, "binaries": layout["bin"],
        "controls": layout["control_root"], "empty_path": layout["empty_path"],
    }

    def fingerprints():
        return {key: COLLECTOR.snapshot_tree(path)["tree_sha256"] for key, path in immutable_paths.items()}

    baseline = fingerprints()

    def invoke(label, command, normalize, profiling):
        DIRECT.verify_identity_chain(identity)
        DIRECT.ensure(fingerprints() == baseline, "diagnostic inputs changed before invocation")
        env, cwd = DIRECT._tool_env(layout, "sayaka", label)
        captures = []
        sample = COLLECTOR.run_sample(
            profile=profile,
            params={**params, "WRITE_HOME": env["HOME"], "WRITE_TMP": env["TMPDIR"]},
            command=command, env_map=env, cwd=cwd,
            timeout_seconds=manifest["limits"]["timeout_seconds"],
            stdout_cap_bytes=manifest["limits"]["stdout_cap_bytes"],
            stderr_cap_bytes=manifest["limits"]["stderr_cap_bytes"],
            normalizer=normalize, run_root=root, raw_sink=captures.append,
            first_useful_result_method_id=manifest["collector_method"],
        )
        DIRECT._append_journal(journal, {"label": label, "captures": captures})
        sample["label"] = label
        sample["profiling_enabled"] = profiling
        report["samples"].append(sample)
        DIRECT.ensure(sample["status"] == "passed", "diagnostic command failed")
        DIRECT.ensure(fingerprints() == baseline, "diagnostic inputs changed")
        if profiling:
            lines = captures[0]["stderr"].splitlines()
            DIRECT.ensure(len(lines) == 1, "expected exactly one diagnostic stderr record")
            phases = json.loads(lines[0])
            DIRECT.ensure(phases["type"] == "scan_profile" and phases["status"] == "complete", "invalid phase record")
            DIRECT.ensure(phases["stdout_json_bytes"] == captures[0]["stdout_bytes"], "profile byte count mismatch")
            sample["phases"] = phases
        else:
            DIRECT.ensure(not captures[0]["stderr"], "unprofiled diagnostic emitted stderr")
        return sample

    try:
        DIRECT.ensure(guard_ok, "diagnostic guard failed")
        rng = random.Random(manifest["order_seed"])
        summaries = {}
        for scenario in manifest["paired_scenarios"]:
            fixture = layout["fixture_root"] if scenario["id"] == "flat-1024" else empty
            entries = {entry["path"]: entry for entry in truth["entries"]} if scenario["files"] else {}
            pairs = []
            profiled = []
            off_times = []
            on_times = []
            for index in range(scenario["pairs"]):
                order = [False, True]
                rng.shuffle(order)
                pair = {}
                for enabled in order:
                    command = [str(staged), "scan", "--json"]
                    if enabled:
                        command.append(manifest["profiling_flag"])
                    command.append(str(fixture))
                    sample = invoke(
                        f"{scenario['id']}-{index:03d}-{'on' if enabled else 'off'}",
                        command,
                        lambda value, fixture=fixture, entries=entries: DIRECT.normalize_sayaka_json(
                            value, fixture_root=fixture, truth_entries=entries
                        ),
                        enabled,
                    )
                    sample["scenario"] = scenario["id"]
                    sample["pair_index"] = index
                    pair[enabled] = sample["complete_result_ms"]
                    (on_times if enabled else off_times).append(sample["complete_result_ms"])
                    if enabled:
                        profiled.append(sample["phases"])
                pairs.append(pair[True] - pair[False])
            settings = manifest["instrumentation_overhead"]
            interval = STATS.paired_bootstrap_ci(
                pairs, confidence=settings["confidence"],
                resamples=settings["bootstrap_resamples"], seed=settings["bootstrap_seed"],
            )
            fields = ("main_to_dispatch_ms", "setup_ms", "scan_ms", "json_encode_write_flush_ms")
            summaries[scenario["id"]] = {
                "pairs": len(pairs), "median_phase_ms": {
                    field: statistics.median(row[field] for row in profiled) for field in fields
                },
                "median_profile_overhead_ms": statistics.median(pairs),
                "paired_overhead_ci_ms": list(interval),
                "median_flag_off_ms": statistics.median(off_times),
                "median_flag_on_ms": statistics.median(on_times),
            }
        version_times = []
        for index in range(manifest["version_only_runs"]):
            DIRECT.ensure(fingerprints() == baseline, "version control inputs changed")
            env, cwd = DIRECT._tool_env(layout, "sayaka", f"version-{index:03d}")
            captured = COLLECTOR._run_broker(
                profile,
                {**params, "WRITE_HOME": env["HOME"], "WRITE_TMP": env["TMPDIR"]},
                [str(staged), "--version"], env, cwd,
                manifest["limits"]["timeout_seconds"], 65536, 65536,
                first_useful_result_method_id=manifest["collector_method"],
            )
            DIRECT._append_journal(journal, {"label": "version_control", "capture": captured})
            DIRECT.ensure(captured["status"] == "completed" and captured["returncode"] == 0, "version control failed")
            DIRECT.ensure(captured["stdout"].startswith("sayaka ") and not captured["stderr"], "unexpected version output")
            elapsed = (captured["end_ns"] - captured["start_ns"]) / 1_000_000
            version_times.append(elapsed)
            report["samples"].append({
                "scenario": "version-only", "index": index, "status": "passed",
                "complete_result_ms": elapsed, "peak_rss_bytes": captured["peak_rss_bytes"],
            })
        summaries["version-only"] = {"runs": len(version_times), "median_complete_ms": statistics.median(version_times)}
        report["summary"] = summaries
        report["status"] = "completed"
        report["immutable_inputs_unchanged"] = fingerprints() == baseline
    finally:
        if report["status"] == "running":
            report["status"] = "failed"
        COLLECTOR._write_report(output, COLLECTOR._public_result(report, root))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=REPO / "benchmarks/c0-sayaka-scan-profile-diagnostic-v1.json")
    parser.add_argument("--binary", type=Path, default=REPO / "target/release/sayaka")
    parser.add_argument("--output", type=Path, default=REPO / "benchmarks/results/c0-sayaka-scan-profile-diagnostic-v1.json")
    args = parser.parse_args()
    result = run(args.manifest, args.binary, args.output)
    print(json.dumps(result["summary"], indent=2))
