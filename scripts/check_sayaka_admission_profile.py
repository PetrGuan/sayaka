#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Guarded admission/launch diagnostics; freeze separately before --execute."""

import argparse
import json
import math
import platform
import random
import shutil
import statistics
import sys
import time
from pathlib import Path

from check_sayaka_scan_profile import DIRECT, COLLECTOR, STATS, REPO, digest

BENCHMARK_ID = "c0-sayaka-admission-profile-v3"
MANIFEST = REPO / "benchmarks" / f"{BENCHMARK_ID}.json"
OUTPUT = REPO / "benchmarks/results" / f"{BENCHMARK_ID}.json"
SOURCES = [
    "scripts/check_sayaka_admission_profile.py",
    "scripts/check_sayaka_scan_profile.py",
    "scripts/check_c0_batch3_direct_analyzer.py",
    "scripts/check_c0_batch2_phase_a.py",
    "scripts/check_c0_batch2_phase_b.py",
    "scripts/check_c0_statistics.py",
    "benchmarks/c0-batch3-direct-analyzer-v2.json",
]
HISTORICAL = [
    "benchmarks/c0-sayaka-admission-profile-v2.json",
    "benchmarks/results/c0-sayaka-admission-profile-v2.json",
    "benchmarks/c0-sayaka-admission-profile-v1.json",
    "benchmarks/results/c0-sayaka-admission-profile-v1.json",
    "benchmarks/c0-batch3-direct-analyzer-v1.json",
    "benchmarks/results/c0-batch3-direct-analyzer-results-v1.json",
    "benchmarks/results/c0-batch3-direct-analyzer-results-v2.json",
    "benchmarks/c0-sayaka-scan-profile-diagnostic-v1.json",
    "benchmarks/results/c0-sayaka-scan-profile-diagnostic-v1.json",
    "benchmarks/c0-batch2-manifest-v1.json",
    "benchmarks/results/c0-batch2-phase-a-ready-v1.json",
    "benchmarks/results/c0-batch2-phase-b-results-v1.json",
]
ROOT_FIELDS = (
    "open_ms", "volume_ms", "directory_setup_ms", "volume_url_ms",
    "volume_local_ms", "volume_internal_ms", "volume_removable_ms", "volume_ejectable_ms",
)
PHASE_FIELDS = ("main_to_dispatch_ms", "setup_ms", "scan_ms", "json_encode_write_flush_ms")
NATIVE_FIELDS = ("caller_policy_enter_ms", "native_walk_ms", "caller_policy_restore_ms")


def write_new(path, value):
    DIRECT.PHASE_A.ensure_repo_relative(path)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def input_hashes():
    return {path: digest(REPO / path) for path in SOURCES + HISTORICAL}


def freeze(path, baseline, binary):
    DIRECT.ensure(sys.platform == "darwin" and platform.machine() == "arm64", "requires macOS arm64")
    DIRECT.ensure(hasattr(time, "CLOCK_UPTIME_RAW"), "shared uptime clock unavailable")
    for artifact in (baseline, binary):
        DIRECT.ensure(artifact.is_file() and not artifact.is_symlink(), "binary must be a regular non-symlink file")
    DIRECT.ensure(digest(baseline) == digest(binary), "exit observer comparison requires the same binary")
    rng = random.Random(260915)
    scenarios = []
    for name in ("flat-1024", "empty"):
        schedule = []
        for _ in range(31):
            order = ["baseline", "off", "on"]
            rng.shuffle(order)
            schedule.append(order)
        scenarios.append({"id": name, "schedule": schedule})
    collector_schedule = []
    for _ in range(15):
        order = [False, True]
        rng.shuffle(order)
        collector_schedule.append(order)
    manifest = {
        "benchmark_id": BENCHMARK_ID,
        "class": "diagnostic_only_not_competitive_baseline",
        "binaries": {"baseline": digest(baseline), "diagnostic": digest(binary)},
        "comparison": "same_binary_exit_observers",
        "variant_exit_observation": {
            "baseline": COLLECTOR.EXIT_OBSERVATION_POLL,
            "off": COLLECTOR.EXIT_OBSERVATION_KQUEUE,
            "on": COLLECTOR.EXIT_OBSERVATION_KQUEUE,
        },
        "primary_metric": "paired pipe_eof_to_reap_ms; complete time is secondary, not product speed",
        "inputs": input_hashes(),
        "environment": {"os": platform.system(), "release": platform.release(),
                        "architecture": platform.machine(), "python": platform.python_version(),
                        "monotonic_clock": "darwin_clock_uptime_raw_ns"},
        "scenarios": scenarios,
        "collector_overhead_schedule": collector_schedule,
        "version_stdout": "sayaka 0.1.0\n",
        "collector_method": COLLECTOR.FIRST_USEFUL_RESULT_METHOD_V2,
        "limits": {"timeout_seconds": 30, "stdout_cap_bytes": 8388608, "stderr_cap_bytes": 1048576},
        "statistics": {"confidence": 0.95, "bootstrap_resamples": 10000, "bootstrap_seed": 260915},
        "semantics": [
            "Baseline/off/on randomized matched triples; no OS-cold-cache claim",
            "v3 baseline/off use the identical binary with profiling off; only poll/kqueue exit observation differs",
            "Parent timers enabled for all scan triples; version-only off/on pairs estimate their overhead",
            "Dispatch uses mach-absolute nanoseconds; diagnostic parent uses CLOCK_UPTIME_RAW, not Python's potentially rebased monotonic",
            "Dispatch is sampled after flag lookup, not executable entry or OS-loader time",
            "Popen duration overlaps child execution; it is not additive with parent-start-to-dispatch",
            "Last stdout receipt, pipe EOF and wait4 reaping are observations, not exact child exit timestamps",
            "Volume property phases nest inside volume_ms, root phases nest inside native_walk_ms",
            "v2 three-root attribution is retained separately; v3 only remeasures flat/empty fixtures",
            "Only complete exact JSON/count/path/identity results with unchanged inputs become timings",
            "No Mole, installers, real Trash, privilege expansion, or historical evidence overwrite",
        ],
    }
    write_new(path, manifest)
    return manifest


def milliseconds(start, end):
    DIRECT.ensure(type(start) is int and type(end) is int and 0 <= start <= end, "invalid clock ordering")
    return (end - start) / 1_000_000


def observer_summary(capture, phases=None):
    DIRECT.ensure(capture["clock_domain"] == "darwin_clock_uptime_raw_ns", "cross-process clock domain mismatch")
    times = capture["observer_timing"]
    DIRECT.ensure(isinstance(times, dict), "missing observer timing")
    start, end = capture["start_ns"], capture["end_ns"]
    last = capture["honest_last_stdout_content_ns"]
    eof = times["pipes_closed_ns"]
    result = {
        "popen_ms": milliseconds(start, times["spawn_return_ns"]),
        "parent_to_first_stdout_ms": milliseconds(start, times["first_stdout_ns"]),
        "parent_to_last_stdout_ms": milliseconds(start, last),
        "last_stdout_to_pipe_eof_ms": milliseconds(last, eof),
        "pipe_eof_to_reap_ms": milliseconds(eof, end),
        "post_eof_wait_misses": times["post_eof_wait_misses"],
        "exit_notification_count": times["exit_notification_count"],
    }
    if phases is not None:
        dispatch = phases["dispatch_clock_ns"]
        result["parent_start_to_dispatch_ms"] = milliseconds(start, dispatch)
        result["dispatch_to_last_stdout_ms"] = milliseconds(dispatch, last)
    return result


def finite_ms(value):
    DIRECT.ensure(type(value) in (int, float) and math.isfinite(value) and value >= 0, "invalid phase duration")
    return value


def validate_phases(capture, root_count):
    lines = capture["stderr"].splitlines()
    DIRECT.ensure(len(lines) == 1, "expected exactly one diagnostic record")
    phases = json.loads(lines[0])
    DIRECT.ensure(phases["schema_version"] == 2 and phases["type"] == "scan_profile", "wrong profile schema")
    DIRECT.ensure(phases["status"] == "complete" and phases["output_error"] is None, "incomplete phase record")
    DIRECT.ensure(phases["stdout_json_bytes"] == capture["stdout_bytes"], "profile byte count mismatch")
    for field in PHASE_FIELDS:
        finite_ms(phases[field])
    native = phases["native_admission"]
    for field in NATIVE_FIELDS:
        finite_ms(native[field])
    DIRECT.ensure(sum(native[field] for field in NATIVE_FIELDS) <= phases["scan_ms"], "native phases exceed scan")
    DIRECT.ensure(len(native["roots"]) == root_count, "root admission count mismatch")
    root_total = 0.0
    for root in native["roots"]:
        DIRECT.ensure(root["error_code"] is None, "root admission failed")
        for field in ROOT_FIELDS:
            finite_ms(root[field])
        root_total += sum(root[field] for field in ROOT_FIELDS[:3])
        DIRECT.ensure(sum(root[field] for field in ROOT_FIELDS[3:]) <= root["volume_ms"], "volume phases exceed parent")
    DIRECT.ensure(root_total <= native["native_walk_ms"], "root phases exceed native walk")
    return phases


def normalize_empty_roots(payload, roots):
    DIRECT.ensure(payload["schema_version"] == 1 and payload["status"] == "complete" and payload["complete"] is True,
                  "incomplete empty-roots report")
    DIRECT.ensure(payload["issues"] == [] and payload["issues_omitted"] == 0, "unexpected scan issues")
    decode = lambda value: Path(COLLECTOR.decode_unix_hex(value["raw"])) if value["encoding"] == "unix_bytes_hex" else None
    reported_roots = [decode(value) for value in payload["roots"]]
    DIRECT.ensure(len(reported_roots) == len(roots) and set(reported_roots) == set(roots), "root set mismatch")
    DIRECT.ensure(len(payload["entries"]) == len(roots), "unexpected entries")
    seen = set()
    for entry in payload["entries"]:
        path = decode(entry["path"])
        DIRECT.ensure(path in roots and path not in seen, "unexpected/duplicate root entry")
        seen.add(path)
        DIRECT.ensure(entry["kind"] == "directory" and entry["depth"] == 0 and entry["counted"] is False
                      and entry["dataless"] is False, "invalid root entry")
        identity = entry["identity"]
        info = path.stat()
        DIRECT.ensure(identity["variant"] == "unix" and identity["device"] == info.st_dev
                      and identity["inode"] == info.st_ino, "root identity mismatch")
        DIRECT.ensure(entry["logical_bytes"] is None and entry["allocated_bytes"] is None, "directory bytes must be absent")
    DIRECT.ensure(set(payload["totals"]) == {
        "regular_files", "unique_files", "duplicate_files", "directories", "links", "other",
        "logical_bytes_known", "logical_bytes_unknown_files", "allocated_bytes_known", "allocated_bytes_unknown_files",
    }, "unexpected/missing total fields")
    for field, value in payload["totals"].items():
        DIRECT.ensure(value == (len(roots) if field == "directories" else 0), f"invalid empty total: {field}")
    DIRECT.ensure(payload["totals"]["directories"] == len(roots), "missing directory count")
    DIRECT.ensure(payload["metrics"]["accepted_roots"] == len(roots), "accepted-root count mismatch")
    return {"root_count": len(roots), "file_count": 0, "logical_bytes": 0}


def paired_summary(deltas, settings):
    interval = STATS.paired_bootstrap_ci(
        deltas, confidence=settings["confidence"], resamples=settings["bootstrap_resamples"],
        seed=settings["bootstrap_seed"],
    )
    return {"pairs": len(deltas), "median_delta_ms": statistics.median(deltas), "ci_ms": list(interval)}


def summarize(rows, settings):
    variants = ("baseline", "off", "on")
    result = {"completion_ms": {
        variant: {
            "median": statistics.median(row["complete_result_ms"] for row in rows if row["variant"] == variant),
            "p95": COLLECTOR.nearest_rank_percentile(
                [row["complete_result_ms"] for row in rows if row["variant"] == variant], 95),
        } for variant in variants
    }}
    pairs = {}
    for row in rows:
        pairs.setdefault(row["pair_index"], {})[row["variant"]] = row["complete_result_ms"]
    for label, left, right in (("exit_observer_off_minus_baseline", "off", "baseline"),
                               ("instrumentation_on_minus_off", "on", "off")):
        result[label] = paired_summary([pair[left] - pair[right] for pair in pairs.values()], settings)
    tails = {}
    for row in rows:
        tails.setdefault(row["pair_index"], {})[row["variant"]] = row["observer"]["pipe_eof_to_reap_ms"]
    result["exit_tail_off_minus_baseline"] = paired_summary(
        [pair["off"] - pair["baseline"] for pair in tails.values()], settings)
    result["exit_tail_ms"] = {
        variant: {
            "median": statistics.median(row["observer"]["pipe_eof_to_reap_ms"] for row in rows if row["variant"] == variant),
            "p95": COLLECTOR.nearest_rank_percentile(
                [row["observer"]["pipe_eof_to_reap_ms"] for row in rows if row["variant"] == variant], 95),
        } for variant in variants
    }
    on = [row for row in rows if row["variant"] == "on"]
    result["median_phase_ms"] = {
        field: statistics.median(row["phases"][field] for row in on) for field in PHASE_FIELDS
    }
    result["median_native_ms"] = {
        field: statistics.median(row["phases"]["native_admission"][field] for row in on) for field in NATIVE_FIELDS
    }
    result["median_roots_ms"] = [{
        field: statistics.median(row["phases"]["native_admission"]["roots"][index][field] for row in on)
        for field in ROOT_FIELDS
    } for index in range(len(on[0]["phases"]["native_admission"]["roots"]))]
    result["median_observer"] = {
        field: statistics.median(row["observer"][field] for row in on) for field in on[0]["observer"]
    }
    return result


def run(manifest_path, baseline_binary, binary, output):
    DIRECT.ensure(not output.exists(), "result exists; choose a new path")
    manifest = json.loads(manifest_path.read_text())
    DIRECT.ensure(manifest["benchmark_id"] == BENCHMARK_ID, "unexpected benchmark")
    DIRECT.ensure(input_hashes() == manifest["inputs"], "frozen inputs changed")
    DIRECT.ensure(sys.platform == "darwin" and platform.machine() == "arm64", "requires macOS arm64")
    DIRECT.ensure(hasattr(time, "CLOCK_UPTIME_RAW") and manifest["environment"]["monotonic_clock"]
                  == "darwin_clock_uptime_raw_ns", "clock domain mismatch")
    DIRECT.ensure(digest(binary) == manifest["binaries"]["diagnostic"], "diagnostic binary mismatch")
    DIRECT.ensure(digest(baseline_binary) == manifest["binaries"]["baseline"], "baseline binary mismatch")
    DIRECT.ensure(manifest["binaries"]["baseline"] == manifest["binaries"]["diagnostic"], "comparison binary mismatch")
    DIRECT.ensure(manifest["variant_exit_observation"] == {
        "baseline": COLLECTOR.EXIT_OBSERVATION_POLL, "off": COLLECTOR.EXIT_OBSERVATION_KQUEUE,
        "on": COLLECTOR.EXIT_OBSERVATION_KQUEUE,
    }, "exit observation contract mismatch")
    manifest_hash = digest(manifest_path)
    direct_manifest = json.loads((REPO / "benchmarks/c0-batch3-direct-analyzer-v2.json").read_text())
    root, identity = DIRECT.create_owned_run_root(REPO / "target/c0-admission-profile/runs")
    report = {"benchmark_id": BENCHMARK_ID, "class": manifest["class"], "manifest_sha256": manifest_hash,
              "binaries": manifest["binaries"], "inputs": manifest["inputs"], "status": "running",
              "mole_executed": False, "samples": [], "run_root": str(root.relative_to(REPO))}
    try:
        layout = DIRECT.make_layout(root)
        staged = {}
        for key, source in (("baseline", baseline_binary), ("diagnostic", binary)):
            staged[key] = layout["bin"] / key
            shutil.copyfile(source, staged[key])
            staged[key].chmod(0o700)
            DIRECT.ensure(digest(staged[key]) == manifest["binaries"][key], "staged binary mismatch")
        truth = DIRECT.PHASE_A.generate_flat_fixture(
            {"fixture_root": layout["fixture_root"]}, direct_manifest["scenario"]["fixture_truth"])
        empty_roots = [layout["allowed_root"] / f"empty-{index}" for index in range(3)]
        for path in empty_roots:
            path.mkdir(mode=0o700)
        canary = DIRECT.compile_trusted_canary(layout)
        profile, _ = DIRECT.write_sandbox_profile(root, layout, direct_manifest)
        params = {"RUN_ROOT": str(root), "ALLOWED_ROOT": str(layout["allowed_root"]),
                  "EXEC_READABLE": str(layout["control_exec_readable"]), "ANALYZER": str(layout["bin"] / "unused"),
                  "SAYAKA": str(staged["diagnostic"]), "CANARY": str(canary)}
        report["profile_sha256"] = digest(profile)
        immutable = {"flat": layout["fixture_root"], "binaries": layout["bin"],
                     "controls": layout["control_root"], "empty_path": layout["empty_path"],
                     **{f"empty-{index}": path for index, path in enumerate(empty_roots)}}
        fingerprints = lambda: {key: COLLECTOR.snapshot_tree(path)["tree_sha256"] for key, path in immutable.items()}
        original = fingerprints()
        report["immutable_before"] = original
        journal = layout["private_logs"] / "admission-profile.jsonl"
        canaries, guard_ok = DIRECT.run_guard_canaries(profile, params, layout, canary, 15)
        report["canaries"] = canaries
        DIRECT.ensure(guard_ok and fingerprints() == original, "diagnostic guard failed")

        def check_inputs():
            DIRECT.verify_identity_chain(identity)
            DIRECT.ensure(digest(manifest_path) == manifest_hash and input_hashes() == manifest["inputs"],
                          "frozen protocol/source changed")
            DIRECT.ensure(digest(profile) == report["profile_sha256"], "guard profile changed")
            DIRECT.ensure(fingerprints() == original, "immutable diagnostic inputs changed")

        def invoke(label, command, normalize, diagnostic_timing=True,
                   exit_observation=COLLECTOR.EXIT_OBSERVATION_KQUEUE):
            check_inputs()
            env, cwd = DIRECT._tool_env(layout, "sayaka", label)
            captures = []
            arguments = {
                "profile": profile, "params": {**params, "SAYAKA": command[0],
                    "WRITE_HOME": env["HOME"], "WRITE_TMP": env["TMPDIR"]},
                "command": command, "env_map": env, "cwd": cwd,
                **manifest["limits"], "first_useful_result_method_id": manifest["collector_method"],
                "diagnostic_timing": diagnostic_timing,
                "exit_observation": exit_observation,
            }
            if normalize is None:
                capture = COLLECTOR._run_broker(**arguments)
                captures.append(capture)
                valid = capture["status"] == "completed" and capture["returncode"] == 0 \
                    and capture["stdout_utf8_valid"] and capture["stdout"] == manifest["version_stdout"] \
                    and capture["stderr"] == ""
                sample = {"status": "passed" if valid else "failed",
                          "complete_result_ms": milliseconds(capture["start_ns"], capture["end_ns"]),
                          "peak_rss_bytes": capture["peak_rss_bytes"]}
            else:
                sample = COLLECTOR.run_sample(**arguments, normalizer=normalize, run_root=root, raw_sink=captures.append)
            DIRECT._append_journal(journal, {"label": label, "captures": captures})
            sample["label"] = label
            sample["exit_observation_method"] = exit_observation
            report["samples"].append(sample)
            sample["immutable_inputs_unchanged"] = fingerprints() == original
            DIRECT.ensure(sample["status"] == "passed", f"diagnostic command failed: {label}")
            check_inputs()
            return sample, captures[0]

        report["summary"] = {}
        for scenario in manifest["scenarios"]:
            name = scenario["id"]
            roots = [layout["fixture_root"]] if name == "flat-1024" else empty_roots[:1 if name == "empty" else 3]
            if name == "flat-1024":
                entries = {entry["path"]: entry for entry in truth["entries"]}
                normalize = lambda payload: DIRECT.normalize_sayaka_json(
                    payload, fixture_root=layout["fixture_root"], truth_entries=entries)
            else:
                normalize = lambda payload, roots=roots: normalize_empty_roots(payload, roots)
            rows = []
            for index, order in enumerate(scenario["schedule"]):
                DIRECT.ensure(sorted(order) == ["baseline", "off", "on"], "invalid triple order")
                for variant in order:
                    command = [str(staged["baseline" if variant == "baseline" else "diagnostic"]), "scan", "--json"]
                    if variant == "on":
                        command.append("--profile-scan-stderr")
                    command.extend(str(path) for path in roots)
                    sample, capture = invoke(f"{name}-{index:03d}-{variant}", command, normalize,
                                             exit_observation=manifest["variant_exit_observation"][variant])
                    sample.update(scenario=name, pair_index=index, variant=variant)
                    sample["diagnostics_status"] = "pending"
                    if variant == "on":
                        sample["phases"] = validate_phases(capture, len(roots))
                    else:
                        DIRECT.ensure(capture["stderr"] == "", "unprofiled scan emitted stderr")
                    sample["observer"] = observer_summary(capture, sample.get("phases"))
                    sample["diagnostics_status"] = "passed"
                    rows.append(sample)
            report["summary"][name] = summarize(rows, manifest["statistics"])
        deltas = []
        for index, order in enumerate(manifest["collector_overhead_schedule"]):
            DIRECT.ensure(sorted(order) == [False, True], "invalid collector pair")
            pair = {}
            for enabled in order:
                sample, capture = invoke(f"version-{index:03d}-{enabled}", [str(staged["diagnostic"]), "--version"],
                                         None, diagnostic_timing=enabled)
                sample.update(scenario="version-collector-overhead", pair_index=index, observer_enabled=enabled)
                if enabled:
                    sample["observer"] = observer_summary(capture)
                pair[enabled] = sample["complete_result_ms"]
            deltas.append(pair[True] - pair[False])
        report["summary"]["collector_overhead"] = paired_summary(deltas, manifest["statistics"])
        check_inputs()
        report["immutable_after"] = fingerprints()
        report["immutable_inputs_unchanged"] = True
        report["status"] = "completed"
    except (DIRECT.ValidationError, COLLECTOR.ValidationError, ValueError, KeyError, TypeError, OSError) as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if report["status"] == "running":
            report["status"] = "failed"
        write_new(output, COLLECTOR._public_result(report, root))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--execute", action="store_true")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=REPO / "target/release/sayaka")
    args = parser.parse_args()
    if args.freeze:
        freeze(args.manifest, args.baseline_binary, args.binary)
        print(f"Frozen {args.manifest.name}: {digest(args.manifest)}")
    else:
        result = run(args.manifest, args.baseline_binary, args.binary, args.output)
        print(json.dumps(result["summary"], indent=2))
