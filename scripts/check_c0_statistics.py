#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate the preregistered C0 statistical protocol and scenario contracts."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import sys
from typing import Any


REPO = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO / "benchmarks/c0-statistics-v1.json"

REQUIRED_EQUAL_WORK_CHECKS = {
    "same_logical_user_task",
    "same_eligible_target_set",
    "same_freshness_expectation",
    "same_output_accounting_fields",
    "same_safety_preconditions",
}

REQUIRED_RESULT_SAMPLE_FIELDS = {
    "pair_id",
    "order",
    "tool",
    "run_index",
    "first_useful_result_ms",
    "complete_result_ms",
    "peak_rss_bytes",
    "p95_collection_ms",
    "status",
}

SUPPORTED_RESULT_TOOLS = {"sayaka", "mole"}
SUPPORTED_ORDERS = {"AB", "BA"}
SUPPORTED_SAMPLE_STATUSES = {"passed", "failed", "skipped"}
ALLOWED_CLAIM_FLAGS = {
    "supports_full_c1_parity",
    "sayaka_faster",
    "sayaka_smaller",
    "sayaka_easier",
}


class ValidationError(Exception):
    """Validation error with a user-facing message."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def is_hex_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(character in "0123456789abcdefABCDEF" for character in value)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def build_schedule(seed: int, repetitions: int) -> list[str]:
    randomizer = random.Random(seed)
    pairs = ["AB", "BA"] * ((repetitions + 1) // 2)
    randomizer.shuffle(pairs)
    return pairs[:repetitions]


def ensure_repo_file(path: Path) -> None:
    path.resolve().relative_to(REPO.resolve())
    ensure(path.is_file(), f"missing required preregistered input: {path}")


def as_finite_number(value: Any, *, field: str) -> float:
    ensure(isinstance(value, (int, float)) and not isinstance(value, bool), f"{field} must be numeric")
    result = float(value)
    ensure(math.isfinite(result), f"{field} must be finite")
    return result


def as_non_negative_number(value: Any, *, field: str) -> float:
    result = as_finite_number(value, field=field)
    ensure(result >= 0.0, f"{field} must be >= 0")
    return result


def as_non_negative_int(value: Any, *, field: str) -> int:
    ensure(isinstance(value, int) and not isinstance(value, bool), f"{field} must be integer")
    ensure(value >= 0, f"{field} must be >= 0")
    return value


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    ensure(values, "cannot compute percentile for empty values")
    ensure(0.0 <= percentile <= 100.0, "percentile must be within [0, 100]")
    ordered = sorted(values)
    if percentile == 0.0:
        return ordered[0]
    index = math.ceil((percentile / 100.0) * len(ordered)) - 1
    return ordered[max(0, min(index, len(ordered) - 1))]


def paired_bootstrap_ci(paired_differences: list[float], *, confidence: float, resamples: int, seed: int) -> tuple[float, float]:
    ensure(0.0 < confidence < 1.0, "confidence must be in (0,1)")
    ensure(resamples > 0, "resamples must be positive")
    ensure(paired_differences, "paired differences must not be empty")
    randomizer = random.Random(seed)
    size = len(paired_differences)
    medians: list[float] = []
    for _ in range(resamples):
        sample = [paired_differences[randomizer.randrange(size)] for _ in range(size)]
        medians.append(float(statistics.median(sample)))
    alpha = (1.0 - confidence) / 2.0
    lower = nearest_rank_percentile(medians, alpha * 100.0)
    upper = nearest_rank_percentile(medians, (1.0 - alpha) * 100.0)
    return lower, upper


def load_json(path: Path, description: str) -> dict[str, Any]:
    ensure(path.is_file(), f"{description} file does not exist: {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{description} is not valid JSON: {exc}") from exc
    ensure(isinstance(data, dict), f"{description} must be a JSON object")
    return data


def validate_required_hashes(manifest: dict[str, Any]) -> None:
    required_inputs = manifest["required_inputs"]
    fixture_path = REPO / required_inputs["fixture_manifest_path"]
    ledger_path = REPO / required_inputs["ledger_manifest_path"]
    source_path = REPO / required_inputs["source_manifest_path"]

    for path in (fixture_path, ledger_path, source_path):
        ensure_repo_file(path)

    ensure(
        required_inputs["fixture_manifest_sha256"] == digest(fixture_path),
        "fixture_manifest_sha256 does not match frozen fixture manifest",
    )
    ensure(
        required_inputs["ledger_manifest_sha256"] == digest(ledger_path),
        "ledger_manifest_sha256 does not match frozen ledger manifest",
    )
    ensure(
        required_inputs["source_manifest_sha256"] == digest(source_path),
        "source_manifest_sha256 does not match frozen source manifest",
    )


def validate_scenario(manifest: dict[str, Any], scenario: dict[str, Any]) -> None:
    required = {
        "scenario_id",
        "family",
        "fixture_id",
        "pair_repetitions",
        "schedule",
        "sayaka_command",
        "mole_command",
        "expected_output_fields",
        "cleanup_rule",
        "eligibility_rule",
        "supported_now",
        "adapter_command_status",
    }
    missing = sorted(required - set(scenario))
    ensure(not missing, f"scenario {scenario.get('scenario_id', '<unknown>')} missing fields: {missing}")
    ensure(bool(scenario["sayaka_command"]) and bool(scenario["mole_command"]), f"scenario {scenario['scenario_id']} requires command lines")
    ensure(bool(scenario["expected_output_fields"]), f"scenario {scenario['scenario_id']} requires expected output fields")
    ensure(
        scenario["adapter_command_status"] == "candidate_not_runnable_while_blocked",
        f"scenario {scenario['scenario_id']} must label command adapters as candidate_not_runnable_while_blocked",
    )

    if not scenario["supported_now"]:
        ensure(
            bool(scenario.get("blocked_reason")),
            f"scenario {scenario['scenario_id']} must include blocked_reason when unsupported",
        )

    ensure(
        scenario["pair_repetitions"] in {
        manifest["repetitions"]["read_only_fixture_scenarios"],
        manifest["repetitions"]["install_layout_scenarios"],
    },
        f"scenario {scenario['scenario_id']} pair_repetitions must use preregistered repetition counts",
    )


def validate_protocol(manifest: dict[str, Any]) -> dict[str, Any]:
    validate_required_hashes(manifest)
    ordering = manifest["ordering"]
    repetitions = manifest["repetitions"]["read_only_fixture_scenarios"]
    schedule = build_schedule(ordering["seed"], repetitions)

    ensure(len(schedule) == repetitions, "schedule length mismatch")
    ensure({"AB", "BA"}.issubset(set(schedule)), "schedule must include both AB and BA orders")

    ci = manifest["estimators"]["confidence_interval"]
    ensure(ci["confidence_level"] == 0.95, "confidence level must remain fixed at 95%")
    ensure(ci["seed"] == ordering["seed"], "bootstrap and ordering seeds must match")
    ensure(not manifest["cache_policy"]["global_os_cache_flush_allowed"], "global OS cache flushing must stay disabled")

    equal_work_checks = set(manifest.get("equal_work_checks", []))
    missing_equal_work = sorted(REQUIRED_EQUAL_WORK_CHECKS - equal_work_checks)
    ensure(not missing_equal_work, f"equal_work_checks missing requirements: {missing_equal_work}")

    scenario_ids = []
    scenarios_by_id: dict[str, dict[str, Any]] = {}
    for scenario in manifest.get("scenario_matrix", []):
        validate_scenario(manifest, scenario)
        scenario_id = scenario["scenario_id"]
        scenario_ids.append(scenario_id)
        scenarios_by_id[scenario_id] = scenario

    ensure(len(scenario_ids) == len(set(scenario_ids)), "scenario IDs must be unique")

    sample_fields = set(manifest["result_schema"]["required_sample_fields"])
    missing_sample_fields = sorted(REQUIRED_RESULT_SAMPLE_FIELDS - sample_fields)
    ensure(not missing_sample_fields, f"result_schema.required_sample_fields missing: {missing_sample_fields}")

    ensure(manifest["retention"].get("keep_all_raw_samples"), "retention must keep all raw samples")
    ensure(manifest["retention"].get("keep_failures_and_skips"), "retention must keep failures and skips")

    return {
        "scenario_ids": scenario_ids,
        "scenarios_by_id": scenarios_by_id,
    }


def validate_pair_schedule(expected_orders: list[str], pair_schedule: list[dict[str, Any]], scenario_id: str) -> None:
    ensure(isinstance(pair_schedule, list), f"scenario {scenario_id} pair_schedule must be a list")
    ensure(len(pair_schedule) == len(expected_orders), f"scenario {scenario_id} pair_schedule length mismatch")
    seen_pairs: set[int] = set()
    for index, pair in enumerate(pair_schedule, start=1):
        ensure(isinstance(pair, dict), f"scenario {scenario_id} pair_schedule entries must be objects")
        pair_id = pair.get("pair_id")
        order = pair.get("order")
        ensure(pair_id == index, f"scenario {scenario_id} pair_schedule pair_id mismatch at index {index}")
        ensure(order in SUPPORTED_ORDERS, f"scenario {scenario_id} pair_schedule order must be AB or BA")
        ensure(order == expected_orders[index - 1], f"scenario {scenario_id} pair_schedule order mismatch at pair {index}")
        ensure(pair_id not in seen_pairs, f"scenario {scenario_id} duplicate pair_id in schedule: {pair_id}")
        seen_pairs.add(pair_id)


def validate_results_binding(manifest: dict[str, Any], results: dict[str, Any], manifest_path: Path) -> None:
    ensure(
        results.get("protocol_manifest_path") == str(manifest_path.relative_to(REPO)),
        "results protocol_manifest_path must bind to the exact protocol path",
    )
    ensure(
        results.get("protocol_manifest_sha256") == digest(manifest_path),
        "results protocol_manifest_sha256 does not match protocol file hash",
    )
    frozen_inputs = results.get("frozen_inputs")
    ensure(isinstance(frozen_inputs, dict), "results frozen_inputs must be an object")
    required_inputs = manifest["required_inputs"]
    for key in ("fixture_manifest_sha256", "ledger_manifest_sha256", "source_manifest_sha256"):
        ensure(frozen_inputs.get(key) == required_inputs[key], f"results frozen_inputs {key} mismatch")


def validate_sample_provenance(
    manifest: dict[str, Any],
    scenario_id: str,
    sample: dict[str, Any],
    source_manifest: dict[str, Any],
) -> None:
    provenance = sample.get("raw_provenance")
    ensure(isinstance(provenance, dict), f"scenario {scenario_id} sample raw_provenance must be object")

    string_fields = ("tool_version", "host_os", "host_arch", "filesystem", "power_mode")
    for field_name in string_fields:
        field_value = provenance.get(field_name)
        ensure(isinstance(field_value, str) and bool(field_value.strip()), f"scenario {scenario_id} sample raw_provenance.{field_name} must be non-empty string")

    fixture_sha = provenance.get("fixture_manifest_sha256")
    expected_fixture_sha = manifest["required_inputs"]["fixture_manifest_sha256"]
    ensure(isinstance(fixture_sha, str) and is_hex_sha256(fixture_sha), f"scenario {scenario_id} sample raw_provenance.fixture_manifest_sha256 must be sha256")
    ensure(fixture_sha == expected_fixture_sha, f"scenario {scenario_id} sample raw_provenance.fixture_manifest_sha256 mismatch")

    artifact_sha = provenance.get("artifact_sha256")
    ensure(isinstance(artifact_sha, str) and is_hex_sha256(artifact_sha), f"scenario {scenario_id} sample raw_provenance.artifact_sha256 must be sha256")

    command_line = provenance.get("command_line")
    ensure(isinstance(command_line, list) and bool(command_line), f"scenario {scenario_id} sample raw_provenance.command_line must be non-empty list")
    ensure(all(isinstance(part, str) and bool(part.strip()) for part in command_line), f"scenario {scenario_id} sample raw_provenance.command_line entries must be non-empty strings")

    environment_redactions = provenance.get("environment_redactions")
    ensure(isinstance(environment_redactions, list), f"scenario {scenario_id} sample raw_provenance.environment_redactions must be a list")
    ensure(all(isinstance(value, str) for value in environment_redactions), f"scenario {scenario_id} sample raw_provenance.environment_redactions entries must be strings")

    tool = sample["tool"]
    if tool == "mole":
        release_assets = source_manifest.get("release_assets", {})
        allowed_hashes = {asset.get("sha256") for asset in release_assets.values() if isinstance(asset, dict) and isinstance(asset.get("sha256"), str)}
        ensure(artifact_sha in allowed_hashes, f"scenario {scenario_id} Mole artifact_sha256 is not in comparator release assets")
        expected_version = manifest["comparator_lock"]["tag"]
        ensure(provenance["tool_version"] == expected_version, f"scenario {scenario_id} Mole tool_version must equal comparator tag {expected_version}")


def validate_summary(
    manifest: dict[str, Any],
    scenario_id: str,
    summary: dict[str, Any],
    samples: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    required_fields = set(manifest["result_schema"]["required_summary_fields"])
    missing = sorted(required_fields - set(summary))
    ensure(not missing, f"scenario {scenario_id} summary missing fields: {missing}")

    paired_median = as_finite_number(summary["paired_median_difference_ms"], field=f"{scenario_id}.summary.paired_median_difference_ms")
    ci = summary["paired_bootstrap_ci_95"]
    ensure(isinstance(ci, list) and len(ci) == 2, f"scenario {scenario_id} summary paired_bootstrap_ci_95 must be [low, high]")
    ci_low = as_finite_number(ci[0], field=f"{scenario_id}.summary.paired_bootstrap_ci_95[0]")
    ci_high = as_finite_number(ci[1], field=f"{scenario_id}.summary.paired_bootstrap_ci_95[1]")
    ensure(ci_low <= ci_high, f"scenario {scenario_id} summary CI must be ordered [low, high]")

    p95_regression = as_finite_number(summary["p95_regression_percent"], field=f"{scenario_id}.summary.p95_regression_percent")
    rss_regression = as_finite_number(summary["peak_rss_regression_percent"], field=f"{scenario_id}.summary.peak_rss_regression_percent")
    ensure(abs(p95_regression) <= 100000.0, f"scenario {scenario_id} summary p95 regression out of range")
    ensure(abs(rss_regression) <= 100000.0, f"scenario {scenario_id} summary peak RSS regression out of range")

    failure_count = summary["failure_count"]
    skip_count = summary["skip_count"]
    ensure(
        isinstance(failure_count, int) and not isinstance(failure_count, bool) and failure_count >= 0,
        f"scenario {scenario_id} summary failure_count must be non-negative int",
    )
    ensure(
        isinstance(skip_count, int) and not isinstance(skip_count, bool) and skip_count >= 0,
        f"scenario {scenario_id} summary skip_count must be non-negative int",
    )
    failure_records = sum(1 for failure in failures if failure.get("classification") == "failed")
    skip_records = sum(1 for failure in failures if failure.get("classification") == "skipped")
    observed_failures = sum(1 for sample in samples if sample["status"] == "failed")
    observed_skips = sum(1 for sample in samples if sample["status"] == "skipped")
    ensure(failure_count == failure_records, f"scenario {scenario_id} summary failure_count mismatch")
    ensure(skip_count == skip_records, f"scenario {scenario_id} summary skip_count mismatch")
    ensure(failure_records == observed_failures, f"scenario {scenario_id} failure record classification mismatch")
    ensure(skip_records == observed_skips, f"scenario {scenario_id} skip record classification mismatch")

    pair_valid_differences: list[float] = []
    completion_by_pair: dict[int, dict[str, float]] = {}
    for sample in samples:
        if sample["status"] != "passed":
            continue
        pair_id = int(sample["pair_id"])
        completion_by_pair.setdefault(pair_id, {})[sample["tool"]] = float(sample["complete_result_ms"])
    for pair_id, pair_values in completion_by_pair.items():
        if "sayaka" in pair_values and "mole" in pair_values:
            pair_valid_differences.append(pair_values["sayaka"] - pair_values["mole"])

    ensure(pair_valid_differences, f"scenario {scenario_id} requires at least one valid paired passed sample difference")

    expected_median = float(statistics.median(pair_valid_differences))
    ci_config = manifest["estimators"]["confidence_interval"]
    expected_ci_low, expected_ci_high = paired_bootstrap_ci(
        pair_valid_differences,
        confidence=float(ci_config["confidence_level"]),
        resamples=int(ci_config["resamples"]),
        seed=int(ci_config["seed"]),
    )
    passed_completion = {tool: [] for tool in SUPPORTED_RESULT_TOOLS}
    passed_rss = {tool: [] for tool in SUPPORTED_RESULT_TOOLS}
    for sample in samples:
        if sample["status"] != "passed":
            continue
        passed_completion[sample["tool"]].append(float(sample["complete_result_ms"]))
        passed_rss[sample["tool"]].append(float(sample["peak_rss_bytes"]))

    ensure(passed_completion["sayaka"] and passed_completion["mole"], f"scenario {scenario_id} requires passed completion samples for both tools")
    ensure(passed_rss["sayaka"] and passed_rss["mole"], f"scenario {scenario_id} requires passed RSS samples for both tools")
    sayaka_p95 = nearest_rank_percentile(passed_completion["sayaka"], 95.0)
    mole_p95 = nearest_rank_percentile(passed_completion["mole"], 95.0)
    sayaka_rss_p95 = nearest_rank_percentile(passed_rss["sayaka"], 95.0)
    mole_rss_p95 = nearest_rank_percentile(passed_rss["mole"], 95.0)
    ensure(mole_p95 > 0.0, f"scenario {scenario_id} requires positive Mole p95 baseline")
    ensure(mole_rss_p95 > 0.0, f"scenario {scenario_id} requires positive Mole peak RSS baseline")
    expected_p95_regression = ((sayaka_p95 - mole_p95) / mole_p95) * 100.0
    expected_rss_regression = ((sayaka_rss_p95 - mole_rss_p95) / mole_rss_p95) * 100.0

    tolerance = 1e-9
    ensure(abs(paired_median - expected_median) <= tolerance, f"scenario {scenario_id} summary paired_median_difference_ms mismatch")
    ensure(abs(ci_low - expected_ci_low) <= tolerance, f"scenario {scenario_id} summary CI low mismatch")
    ensure(abs(ci_high - expected_ci_high) <= tolerance, f"scenario {scenario_id} summary CI high mismatch")
    ensure(abs(p95_regression - expected_p95_regression) <= tolerance, f"scenario {scenario_id} summary p95_regression_percent mismatch")
    ensure(abs(rss_regression - expected_rss_regression) <= tolerance, f"scenario {scenario_id} summary peak_rss_regression_percent mismatch")


def validate_scenario_results(
    manifest: dict[str, Any],
    protocol_scenario: dict[str, Any],
    result_scenario: dict[str, Any],
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    scenario_id = protocol_scenario["scenario_id"]
    required_fields = set(manifest["result_schema"]["required_scenario_fields"]) | {"scenario_status"}
    missing = sorted(required_fields - set(result_scenario))
    ensure(not missing, f"scenario {scenario_id} result missing fields: {missing}")
    ensure(result_scenario["scenario_id"] == scenario_id, f"scenario {scenario_id} result scenario_id mismatch")
    ensure(
        result_scenario["fixture_id"] == protocol_scenario["fixture_id"],
        f"scenario {scenario_id} fixture_id must match preregistered fixture_id",
    )
    ensure(
        result_scenario["supported_now"] == protocol_scenario["supported_now"],
        f"scenario {scenario_id} cannot change supported_now from preregistered protocol",
    )

    scenario_status = result_scenario["scenario_status"]
    ensure(
        scenario_status in {"not_measured", "measured"},
        f"scenario {scenario_id} scenario_status must be not_measured or measured",
    )
    eligibility = result_scenario["eligibility_outcome"]
    equal_work = result_scenario["equal_work_outcome"]
    ensure(isinstance(eligibility, dict), f"scenario {scenario_id} eligibility_outcome must be object")
    ensure(isinstance(equal_work, dict), f"scenario {scenario_id} equal_work_outcome must be object")
    ensure(eligibility.get("status") in {"eligible", "ineligible", "failed"}, f"scenario {scenario_id} invalid eligibility_outcome.status")
    ensure(equal_work.get("status") in {"verified", "failed", "ineligible"}, f"scenario {scenario_id} invalid equal_work_outcome.status")
    ensure(bool(eligibility.get("reason")), f"scenario {scenario_id} eligibility_outcome.reason is required")
    ensure(bool(equal_work.get("reason")), f"scenario {scenario_id} equal_work_outcome.reason is required")

    pair_repetitions = int(protocol_scenario["pair_repetitions"])
    expected_orders = build_schedule(int(manifest["ordering"]["seed"]), pair_repetitions)
    pair_schedule = result_scenario["pair_schedule"]
    validate_pair_schedule(expected_orders, pair_schedule, scenario_id)

    samples = result_scenario.get("samples", [])
    ensure(isinstance(samples, list), f"scenario {scenario_id} samples must be a list")
    failures = result_scenario.get("failures", [])
    ensure(isinstance(failures, list), f"scenario {scenario_id} failures must be a list")

    if not protocol_scenario["supported_now"]:
        ensure(scenario_status == "not_measured", f"scenario {scenario_id} is preregistered blocked and must be not_measured")
        ensure(eligibility["status"] in {"ineligible", "failed"}, f"scenario {scenario_id} blocked scenario cannot be eligible")
        ensure(equal_work["status"] in {"ineligible", "failed"}, f"scenario {scenario_id} blocked scenario cannot pass equal-work")
        ensure(not samples, f"scenario {scenario_id} blocked/not_measured scenario must not include measurement samples")
        ensure(not failures, f"scenario {scenario_id} blocked/not_measured scenario must not include failures list")
        ensure("summary" not in result_scenario, f"scenario {scenario_id} blocked/not_measured scenario must not include summary")
        return {"status": scenario_status, "passed_slots": 0}

    retention_fields = manifest["retention"]["raw_provenance_fields"]
    expected_slots = {(pair_id, tool) for pair_id in range(1, pair_repetitions + 1) for tool in SUPPORTED_RESULT_TOOLS}
    seen_slots: set[tuple[int, str]] = set()
    skipped_slots: set[tuple[int, str, int]] = set()
    failed_slots: set[tuple[int, str, int]] = set()
    passed_slots = 0
    for sample in samples:
        ensure(isinstance(sample, dict), f"scenario {scenario_id} samples entries must be objects")
        missing_sample = sorted(set(manifest["result_schema"]["required_sample_fields"]) - set(sample))
        ensure(not missing_sample, f"scenario {scenario_id} sample missing fields: {missing_sample}")
        pair_id = sample["pair_id"]
        run_index = sample["run_index"]
        tool = sample["tool"]
        order = sample["order"]
        status = sample["status"]
        ensure(isinstance(pair_id, int) and 1 <= pair_id <= pair_repetitions, f"scenario {scenario_id} sample pair_id out of range")
        ensure(isinstance(run_index, int) and run_index >= 1, f"scenario {scenario_id} sample run_index must be positive int")
        ensure(tool in SUPPORTED_RESULT_TOOLS, f"scenario {scenario_id} sample tool must be one of {sorted(SUPPORTED_RESULT_TOOLS)}")
        ensure(order in SUPPORTED_ORDERS, f"scenario {scenario_id} sample order must be AB or BA")
        ensure(order == expected_orders[pair_id - 1], f"scenario {scenario_id} sample order mismatch for pair_id {pair_id}")
        ensure(status in SUPPORTED_SAMPLE_STATUSES, f"scenario {scenario_id} sample status must be passed/failed/skipped")
        slot = (pair_id, tool)
        ensure(slot not in seen_slots, f"scenario {scenario_id} duplicate sample slot pair_id={pair_id} tool={tool}")
        seen_slots.add(slot)
        as_non_negative_number(sample["first_useful_result_ms"], field=f"{scenario_id}.sample.first_useful_result_ms")
        as_non_negative_number(sample["complete_result_ms"], field=f"{scenario_id}.sample.complete_result_ms")
        as_non_negative_int(sample["peak_rss_bytes"], field=f"{scenario_id}.sample.peak_rss_bytes")
        as_non_negative_number(sample["p95_collection_ms"], field=f"{scenario_id}.sample.p95_collection_ms")
        provenance = sample.get("raw_provenance")
        ensure(isinstance(provenance, dict), f"scenario {scenario_id} sample raw_provenance must be object")
        for retention_field in retention_fields:
            ensure(retention_field in provenance, f"scenario {scenario_id} sample raw_provenance missing field {retention_field}")
        validate_sample_provenance(manifest, scenario_id, sample, source_manifest)
        expected_output = sample.get("expected_output")
        ensure(isinstance(expected_output, dict), f"scenario {scenario_id} sample expected_output must be object")
        for expected_field in protocol_scenario["expected_output_fields"]:
            ensure(expected_field in expected_output, f"scenario {scenario_id} sample expected_output missing {expected_field}")
        if status == "skipped":
            skipped_slots.add((pair_id, tool, run_index))
        elif status == "failed":
            failed_slots.add((pair_id, tool, run_index))
        else:
            passed_slots += 1

    missing_slots = sorted(expected_slots - seen_slots)
    ensure(not missing_slots, f"scenario {scenario_id} missing expected sample slots: {missing_slots}")

    status_by_sample_slot: dict[tuple[int, str, int], str] = {}
    for sample in samples:
        status_by_sample_slot[(sample["pair_id"], sample["tool"], sample["run_index"])] = sample["status"]

    failure_slots: set[tuple[int, str, int]] = set()
    for failure in failures:
        ensure(isinstance(failure, dict), f"scenario {scenario_id} failures entries must be objects")
        missing_failure = sorted(set(manifest["result_schema"]["required_failure_fields"]) - set(failure))
        ensure(not missing_failure, f"scenario {scenario_id} failure missing fields: {missing_failure}")
        pair_id = failure["pair_id"]
        tool = failure["tool"]
        run_index = failure.get("run_index")
        ensure(isinstance(pair_id, int) and 1 <= pair_id <= pair_repetitions, f"scenario {scenario_id} failure pair_id out of range")
        ensure(tool in SUPPORTED_RESULT_TOOLS, f"scenario {scenario_id} failure tool must be sayaka or mole")
        ensure(isinstance(run_index, int) and run_index >= 1, f"scenario {scenario_id} failure run_index must be positive int")
        ensure(bool(failure["reason"]), f"scenario {scenario_id} failure reason must be non-empty")
        ensure(bool(failure["raw_log_reference"]), f"scenario {scenario_id} failure raw_log_reference must be non-empty")
        ensure(failure["classification"] in {"failed", "skipped"}, f"scenario {scenario_id} failure classification must be failed/skipped")
        slot = (pair_id, tool, run_index)
        ensure(slot not in failure_slots, f"scenario {scenario_id} duplicate failure entry for pair/tool/run_index")
        ensure(slot in status_by_sample_slot, f"scenario {scenario_id} failure record missing matching sample slot")
        ensure(
            status_by_sample_slot[slot] in {"failed", "skipped"},
            f"scenario {scenario_id} failure record references non-failed/skipped sample slot",
        )
        ensure(
            failure["classification"] == status_by_sample_slot[slot],
            f"scenario {scenario_id} failure classification does not match sample status",
        )
        failure_slots.add(slot)

    required_failure_slots = failed_slots | skipped_slots
    ensure(
        required_failure_slots == failure_slots,
        f"scenario {scenario_id} failure records must match failed/skipped sample slots exactly",
    )

    ensure(scenario_status == "measured", f"scenario {scenario_id} supported scenario must be measured")
    ensure(eligibility["status"] == "eligible", f"scenario {scenario_id} supported scenario must be eligible")
    ensure(equal_work["status"] == "verified", f"scenario {scenario_id} supported scenario must verify equal work")
    ensure(passed_slots > 0, f"scenario {scenario_id} supported scenario must include passed sample slots")
    summary = result_scenario.get("summary")
    ensure(isinstance(summary, dict), f"scenario {scenario_id} measured scenario requires summary")
    validate_summary(manifest, scenario_id, summary, samples, failures)

    return {"status": scenario_status, "passed_slots": passed_slots}


def validate_results(manifest: dict[str, Any], manifest_path: Path, protocol_info: dict[str, Any], results_path: Path) -> dict[str, Any]:
    results = load_json(results_path, "results")
    validate_results_binding(manifest, results, manifest_path)
    source_manifest_path = REPO / manifest["required_inputs"]["source_manifest_path"]
    source_manifest = load_json(source_manifest_path, "source manifest")
    ensure("claims" in results, "results claims is required")
    claims = results["claims"]
    ensure(isinstance(claims, dict), "results claims must be an object")
    unknown_claims = sorted(set(claims) - ALLOWED_CLAIM_FLAGS)
    ensure(not unknown_claims, f"results claims contains unknown keys: {unknown_claims}")
    missing_claims = sorted(ALLOWED_CLAIM_FLAGS - set(claims))
    ensure(not missing_claims, f"results claims missing required keys: {missing_claims}")
    for claim_flag in sorted(ALLOWED_CLAIM_FLAGS):
        ensure(
            isinstance(claims[claim_flag], bool),
            f"results claim {claim_flag} must be boolean false for C0 preregistration",
        )
        ensure(
            claims[claim_flag] is False,
            f"results claim {claim_flag} must be false for C0 preregistration",
        )

    result_scenarios = results.get("scenarios")
    ensure(isinstance(result_scenarios, list), "results scenarios must be a list")
    preregistered_ids = protocol_info["scenario_ids"]
    result_ids = [entry.get("scenario_id") for entry in result_scenarios if isinstance(entry, dict)]
    ensure(len(result_ids) == len(set(result_ids)), "results scenario IDs must be unique")
    unknown_ids = sorted(set(result_ids) - set(preregistered_ids))
    missing_ids = sorted(set(preregistered_ids) - set(result_ids))
    ensure(not unknown_ids, f"results contains unregistered scenario IDs: {unknown_ids}")
    ensure(not missing_ids, f"results missing preregistered scenario IDs: {missing_ids}")

    by_id = {entry["scenario_id"]: entry for entry in result_scenarios}
    checked = []
    for scenario_id in preregistered_ids:
        protocol_scenario = protocol_info["scenarios_by_id"][scenario_id]
        checked.append(validate_scenario_results(manifest, protocol_scenario, by_id[scenario_id], source_manifest))
    return {
        "scenario_count": len(checked),
        "measured_count": sum(1 for entry in checked if entry["status"] == "measured"),
        "not_measured_count": sum(1 for entry in checked if entry["status"] == "not_measured"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    manifest_path.relative_to(REPO.resolve())
    manifest = load_json(manifest_path, "protocol manifest")
    protocol_info = validate_protocol(manifest)
    supported_scenarios = [
        scenario["scenario_id"]
        for scenario in manifest["scenario_matrix"]
        if scenario["supported_now"]
    ]

    mode = "protocol-only"
    result_validation = None
    if args.results:
        mode = "results"
        result_validation = validate_results(manifest, manifest_path, protocol_info, args.results.resolve())
    else:
        ensure(
            not supported_scenarios,
            "supported_now=true scenario exists; --results evidence is required before protocol can validate",
        )

    print(
        json.dumps(
            {
                "benchmark_id": manifest["benchmark_id"],
                "mode": mode,
                "protocol_manifest_path": str(manifest_path.relative_to(REPO)),
                "protocol_manifest_sha256": digest(manifest_path),
                "seed": manifest["ordering"]["seed"],
                "scenario_repetitions": manifest["repetitions"]["read_only_fixture_scenarios"],
                "schedule_preview": build_schedule(
                    manifest["ordering"]["seed"],
                    manifest["repetitions"]["read_only_fixture_scenarios"],
                )[:12],
                "scenario_count": len(protocol_info["scenario_ids"]),
                "supported_now": supported_scenarios,
                "blocked_now": [scenario["scenario_id"] for scenario in manifest["scenario_matrix"] if not scenario["supported_now"]],
                "result_validation": result_validation,
                "classification_note": (
                    "protocol-only validation confirms preregistration shape and blocked status; "
                    "it is not competitive result evidence"
                    if mode == "protocol-only"
                    else "result validation checks preregistered evidence shape and retention; it is not full C1 parity proof"
                ),
                "status": "verified",
            },
            indent=2,
        )
    )

    if args.verify:
        return


if __name__ == "__main__":
    try:
        main()
    except (ValidationError, ValueError, KeyError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
