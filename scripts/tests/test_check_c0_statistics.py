#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check_c0_statistics.py"
CANONICAL_MANIFEST = REPO / "benchmarks/c0-statistics-v1.json"
BLOCKED_RESULTS = REPO / "benchmarks/results/c0-blocked-results-v1.json"
SOURCE_MANIFEST = REPO / "benchmarks/c0-mole-v1.53.0-source.json"
WORKSPACE_ROOT = REPO / "target/test-workspaces/check_c0_statistics"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CheckC0StatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("check_c0_statistics", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to import check_c0_statistics.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module
        cls.base_protocol = json.loads(CANONICAL_MANIFEST.read_text())
        cls.source_manifest = json.loads(SOURCE_MANIFEST.read_text())
        cls.mole_hashes = [asset["sha256"] for asset in cls.source_manifest["release_assets"].values()]
        WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.test_workspace = WORKSPACE_ROOT / self._testMethodName
        if self.test_workspace.exists():
            shutil.rmtree(self.test_workspace)
        self.test_workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.test_workspace, ignore_errors=True)

    def write_json(self, relative_path: str, payload: dict) -> Path:
        path = self.test_workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n")
        return path

    def run_checker(self, *arguments: str, expect_ok: bool) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(SCRIPT), "--verify", *arguments]
        completed = subprocess.run(command, cwd=REPO, text=True, capture_output=True, check=False)
        if expect_ok and completed.returncode != 0:
            self.fail(f"expected success, got {completed.returncode}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
        if not expect_ok and completed.returncode == 0:
            self.fail(f"expected failure\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
        return completed

    def make_pair_schedule(self, seed: int, repetitions: int) -> list[dict]:
        return [{"pair_id": index + 1, "order": order} for index, order in enumerate(self.module.build_schedule(seed, repetitions))]

    def make_result_base(self, protocol: dict) -> dict:
        manifest_path = self.write_json("protocol.json", protocol)
        return {
            "manifest_path": manifest_path,
            "result": {
                "benchmark_id": "c0-statistics-results-v1",
                "protocol_manifest_path": str(manifest_path.relative_to(REPO)),
                "protocol_manifest_sha256": digest(manifest_path),
                "frozen_inputs": {
                    "fixture_manifest_sha256": protocol["required_inputs"]["fixture_manifest_sha256"],
                    "ledger_manifest_sha256": protocol["required_inputs"]["ledger_manifest_sha256"],
                    "source_manifest_sha256": protocol["required_inputs"]["source_manifest_sha256"],
                },
                "claims": {
                    "supports_full_c1_parity": False,
                    "sayaka_faster": False,
                    "sayaka_smaller": False,
                    "sayaka_easier": False,
                },
                "scenarios": [],
            },
        }

    def make_supported_protocol(self) -> dict:
        protocol = copy.deepcopy(self.base_protocol)
        protocol["repetitions"]["read_only_fixture_scenarios"] = 3
        protocol["repetitions"]["install_layout_scenarios"] = 3
        protocol["scenario_matrix"] = copy.deepcopy(protocol["scenario_matrix"][:2])
        first = protocol["scenario_matrix"][0]
        first["supported_now"] = True
        first.pop("blocked_reason", None)
        first["pair_repetitions"] = 3
        second = protocol["scenario_matrix"][1]
        second["supported_now"] = False
        second["pair_repetitions"] = 3
        second["blocked_reason"] = "synthetic blocked scenario"
        return protocol

    def make_supported_result_scenario(self, protocol: dict, scenario: dict) -> dict:
        repetitions = scenario["pair_repetitions"]
        schedule = self.make_pair_schedule(protocol["ordering"]["seed"], repetitions)
        expected = scenario["expected_output_fields"]
        samples = []
        for pair in schedule:
            pair_id = pair["pair_id"]
            for tool in ("sayaka", "mole"):
                base_time = 90.0 + pair_id if tool == "sayaka" else 100.0 + pair_id
                sample = {
                    "pair_id": pair_id,
                    "order": pair["order"],
                    "tool": tool,
                    "run_index": pair_id,
                    "first_useful_result_ms": base_time - 10.0,
                    "complete_result_ms": base_time,
                    "peak_rss_bytes": 1500 + pair_id if tool == "sayaka" else 1600 + pair_id,
                    "p95_collection_ms": 3.0 + (pair_id / 10.0),
                    "status": "passed",
                    "raw_provenance": {
                        "tool_version": protocol["comparator_lock"]["tag"] if tool == "mole" else "sayaka-synthetic-1",
                        "artifact_sha256": self.mole_hashes[0] if tool == "mole" else "0" * 64,
                        "host_os": "synthetic",
                        "host_arch": "arm64",
                        "filesystem": "apfs",
                        "power_mode": "ac",
                        "fixture_manifest_sha256": protocol["required_inputs"]["fixture_manifest_sha256"],
                        "command_line": [tool, "synthetic"],
                        "environment_redactions": [],
                    },
                    "expected_output": {field: 1 for field in expected},
                }
                samples.append(sample)

        differences = []
        sayaka_completion = []
        mole_completion = []
        sayaka_rss = []
        mole_rss = []
        for pair in schedule:
            pair_id = pair["pair_id"]
            sayaka_sample = next(sample for sample in samples if sample["pair_id"] == pair_id and sample["tool"] == "sayaka")
            mole_sample = next(sample for sample in samples if sample["pair_id"] == pair_id and sample["tool"] == "mole")
            differences.append(sayaka_sample["complete_result_ms"] - mole_sample["complete_result_ms"])
            sayaka_completion.append(sayaka_sample["complete_result_ms"])
            mole_completion.append(mole_sample["complete_result_ms"])
            sayaka_rss.append(sayaka_sample["peak_rss_bytes"])
            mole_rss.append(mole_sample["peak_rss_bytes"])

        ci_conf = protocol["estimators"]["confidence_interval"]
        ci_low, ci_high = self.module.paired_bootstrap_ci(
            differences,
            confidence=ci_conf["confidence_level"],
            resamples=ci_conf["resamples"],
            seed=ci_conf["seed"],
        )
        sayaka_p95 = self.module.nearest_rank_percentile(sayaka_completion, 95.0)
        mole_p95 = self.module.nearest_rank_percentile(mole_completion, 95.0)
        sayaka_rss_p95 = self.module.nearest_rank_percentile(sayaka_rss, 95.0)
        mole_rss_p95 = self.module.nearest_rank_percentile(mole_rss, 95.0)

        summary = {
            "paired_median_difference_ms": self.module.statistics.median(differences),
            "paired_bootstrap_ci_95": [ci_low, ci_high],
            "p95_regression_percent": ((sayaka_p95 - mole_p95) / mole_p95) * 100.0,
            "peak_rss_regression_percent": ((sayaka_rss_p95 - mole_rss_p95) / mole_rss_p95) * 100.0,
            "failure_count": 0,
            "skip_count": 0,
        }
        return {
            "scenario_id": scenario["scenario_id"],
            "fixture_id": scenario["fixture_id"],
            "supported_now": True,
            "scenario_status": "measured",
            "eligibility_outcome": {"status": "eligible", "reason": "synthetic eligibility satisfied"},
            "equal_work_outcome": {"status": "verified", "reason": "synthetic equal-work satisfied"},
            "pair_schedule": schedule,
            "samples": samples,
            "failures": [],
            "summary": summary,
        }

    def recompute_summary(self, protocol: dict, scenario_result: dict) -> None:
        samples = scenario_result["samples"]
        failures = scenario_result["failures"]
        differences = []
        sayaka_completion = []
        mole_completion = []
        sayaka_rss = []
        mole_rss = []
        by_pair = {}
        for sample in samples:
            if sample["status"] != "passed":
                continue
            by_pair.setdefault(sample["pair_id"], {})[sample["tool"]] = sample
            if sample["tool"] == "sayaka":
                sayaka_completion.append(sample["complete_result_ms"])
                sayaka_rss.append(sample["peak_rss_bytes"])
            else:
                mole_completion.append(sample["complete_result_ms"])
                mole_rss.append(sample["peak_rss_bytes"])
        for pair in by_pair.values():
            if "sayaka" in pair and "mole" in pair:
                differences.append(pair["sayaka"]["complete_result_ms"] - pair["mole"]["complete_result_ms"])

        ci_conf = protocol["estimators"]["confidence_interval"]
        ci_low, ci_high = self.module.paired_bootstrap_ci(
            differences,
            confidence=ci_conf["confidence_level"],
            resamples=ci_conf["resamples"],
            seed=ci_conf["seed"],
        )
        sayaka_p95 = self.module.nearest_rank_percentile(sayaka_completion, 95.0)
        mole_p95 = self.module.nearest_rank_percentile(mole_completion, 95.0)
        sayaka_rss_p95 = self.module.nearest_rank_percentile(sayaka_rss, 95.0)
        mole_rss_p95 = self.module.nearest_rank_percentile(mole_rss, 95.0)
        scenario_result["summary"] = {
            "paired_median_difference_ms": self.module.statistics.median(differences),
            "paired_bootstrap_ci_95": [ci_low, ci_high],
            "p95_regression_percent": ((sayaka_p95 - mole_p95) / mole_p95) * 100.0,
            "peak_rss_regression_percent": ((sayaka_rss_p95 - mole_rss_p95) / mole_rss_p95) * 100.0,
            "failure_count": sum(1 for item in failures if item["classification"] == "failed"),
            "skip_count": sum(1 for item in failures if item["classification"] == "skipped"),
        }

    def make_blocked_result_scenario(self, protocol: dict, scenario: dict) -> dict:
        return {
            "scenario_id": scenario["scenario_id"],
            "fixture_id": scenario["fixture_id"],
            "supported_now": False,
            "scenario_status": "not_measured",
            "eligibility_outcome": {"status": "ineligible", "reason": scenario["blocked_reason"]},
            "equal_work_outcome": {"status": "ineligible", "reason": scenario["blocked_reason"]},
            "pair_schedule": self.make_pair_schedule(protocol["ordering"]["seed"], scenario["pair_repetitions"]),
            "samples": [],
            "failures": [],
        }

    def test_protocol_flip_supported_without_results_rejected(self) -> None:
        protocol = copy.deepcopy(self.base_protocol)
        protocol["scenario_matrix"][0]["supported_now"] = True
        protocol["scenario_matrix"][0].pop("blocked_reason", None)
        manifest = self.write_json("protocol.json", protocol)
        completed = self.run_checker("--manifest", str(manifest), expect_ok=False)
        self.assertIn("--results evidence is required", completed.stderr)

    def test_valid_blocked_only_report_accepted(self) -> None:
        self.run_checker("--manifest", str(CANONICAL_MANIFEST), "--results", str(BLOCKED_RESULTS), expect_ok=True)

    def test_protocol_hash_mismatch_rejected(self) -> None:
        protocol = copy.deepcopy(self.base_protocol)
        made = self.make_result_base(protocol)
        scenario = protocol["scenario_matrix"][0]
        made["result"]["scenarios"] = [self.make_blocked_result_scenario(protocol, scenario)]
        made["result"]["protocol_manifest_sha256"] = "f" * 64
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("protocol_manifest_sha256", completed.stderr)

    def test_unknown_duplicate_missing_scenario_rejected(self) -> None:
        protocol = copy.deepcopy(self.base_protocol)
        made = self.make_result_base(protocol)
        first = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][0])
        duplicate = copy.deepcopy(first)
        unknown = copy.deepcopy(first)
        unknown["scenario_id"] = "c0-unknown"
        made["result"]["scenarios"] = [first, duplicate, unknown]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("scenario IDs must be unique", completed.stderr)

    def test_missing_sample_slots_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        supported["samples"].pop()
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("missing expected sample slots", completed.stderr)

    def test_eligibility_or_equal_work_failure_cannot_pass(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        supported["eligibility_outcome"] = {"status": "failed", "reason": "fixture mismatch"}
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("must be eligible", completed.stderr)

    def test_missing_failure_skip_records_and_counts_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        supported["samples"][0]["status"] = "failed"
        supported["summary"]["failure_count"] = 0
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("failure records must match failed/skipped sample slots exactly", completed.stderr)

    def test_missing_raw_provenance_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        supported["samples"][0].pop("raw_provenance")
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("raw_provenance", completed.stderr)

    def test_wrong_pair_order_index_count_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        supported["pair_schedule"][0]["order"] = "BA" if supported["pair_schedule"][0]["order"] == "AB" else "AB"
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("pair_schedule order mismatch", completed.stderr)

    def test_missing_or_bogus_summary_ci_p95_rss_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        supported["summary"]["paired_bootstrap_ci_95"] = [1.0]
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("paired_bootstrap_ci_95", completed.stderr)

    def test_blocked_scenario_cannot_become_pass(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        blocked["supported_now"] = True
        blocked["scenario_status"] = "measured"
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("cannot change supported_now", completed.stderr)

    def test_valid_synthetic_supported_record_is_accepted_for_tests(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("results.json", made["result"])
        self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=True)

    def test_forbidden_claim_flags_require_boolean_false(self) -> None:
        invalid_values = [1, "true", None, {}, []]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                protocol = self.make_supported_protocol()
                made = self.make_result_base(protocol)
                supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
                blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
                made["result"]["claims"]["sayaka_faster"] = invalid_value
                made["result"]["scenarios"] = [supported, blocked]
                result = self.write_json(f"claim-invalid-{type(invalid_value).__name__}.json", made["result"])
                completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
                self.assertIn("must be boolean false", completed.stderr)

    def test_claims_object_is_required_and_complete(self) -> None:
        invalid_claim_payloads = [
            ("missing-claims", "__remove__", "results claims is required"),
            ("null-claims", None, "results claims must be an object"),
            ("list-claims", [], "results claims must be an object"),
            ("number-claims", 0, "results claims must be an object"),
            ("empty-object", {}, "results claims missing required keys"),
        ]
        for case_name, payload, expected_error in invalid_claim_payloads:
            with self.subTest(case=case_name):
                protocol = self.make_supported_protocol()
                made = self.make_result_base(protocol)
                supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
                blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
                if payload == "__remove__":
                    made["result"].pop("claims", None)
                else:
                    made["result"]["claims"] = payload
                made["result"]["scenarios"] = [supported, blocked]
                result = self.write_json(f"claims-required-{case_name}.json", made["result"])
                completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
                self.assertIn(expected_error, completed.stderr)

    def test_claims_missing_each_required_key_rejected(self) -> None:
        required_keys = (
            "supports_full_c1_parity",
            "sayaka_faster",
            "sayaka_smaller",
            "sayaka_easier",
        )
        for missing in required_keys:
            with self.subTest(missing=missing):
                protocol = self.make_supported_protocol()
                made = self.make_result_base(protocol)
                supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
                blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
                made["result"]["claims"].pop(missing)
                made["result"]["scenarios"] = [supported, blocked]
                result = self.write_json(f"claims-missing-{missing}.json", made["result"])
                completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
                self.assertIn("results claims missing required keys", completed.stderr)

    def test_unknown_claim_alias_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["claims"]["sayaka_is_faster"] = True
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("claim-unknown-alias.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("claims contains unknown keys", completed.stderr)

    def test_summary_counts_reject_booleans(self) -> None:
        for field in ("failure_count", "skip_count"):
            with self.subTest(field=field):
                protocol = self.make_supported_protocol()
                made = self.make_result_base(protocol)
                supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
                blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
                supported["summary"][field] = False
                made["result"]["scenarios"] = [supported, blocked]
                result = self.write_json(f"summary-{field}-bool.json", made["result"])
                completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
                self.assertIn(f"{field} must be non-negative int", completed.stderr)

    def test_valid_false_claims_and_zero_counts_still_pass(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        made["result"]["claims"] = {
            "supports_full_c1_parity": False,
            "sayaka_faster": False,
            "sayaka_smaller": False,
            "sayaka_easier": False,
        }
        supported["summary"]["failure_count"] = 0
        supported["summary"]["skip_count"] = 0
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("valid-false-claims-zero-counts.json", made["result"])
        self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=True)

    def test_sample_provenance_requires_meaningful_values(self) -> None:
        invalid_cases = [
            ("null-fixture-sha", "fixture_manifest_sha256", None, "fixture_manifest_sha256 must be sha256"),
            ("empty-tool-version", "tool_version", "", "tool_version must be non-empty string"),
            ("malformed-artifact-sha", "artifact_sha256", "ff", "artifact_sha256 must be sha256"),
            ("mismatch-fixture-sha", "fixture_manifest_sha256", "f" * 64, "fixture_manifest_sha256 mismatch"),
            ("null-host-os", "host_os", None, "host_os must be non-empty string"),
        ]
        for case_name, field_name, value, expected_error in invalid_cases:
            with self.subTest(case=case_name):
                protocol = self.make_supported_protocol()
                made = self.make_result_base(protocol)
                supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
                blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
                supported["samples"][0]["raw_provenance"][field_name] = value
                made["result"]["scenarios"] = [supported, blocked]
                result = self.write_json(f"provenance-{case_name}.json", made["result"])
                completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
                self.assertIn(expected_error, completed.stderr)

    def test_sample_metrics_negative_values_rejected(self) -> None:
        invalid_metrics = [
            ("first-useful-negative", "first_useful_result_ms", -0.1, "first_useful_result_ms must be >= 0"),
            ("complete-negative", "complete_result_ms", -1.0, "complete_result_ms must be >= 0"),
            ("peak-rss-negative", "peak_rss_bytes", -1, "peak_rss_bytes must be >= 0"),
            ("p95-negative", "p95_collection_ms", -0.5, "p95_collection_ms must be >= 0"),
        ]
        for case_name, field_name, value, expected_error in invalid_metrics:
            with self.subTest(case=case_name):
                protocol = self.make_supported_protocol()
                made = self.make_result_base(protocol)
                supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
                blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
                target_sample = supported["samples"][0]
                target_sample[field_name] = value
                self.recompute_summary(protocol, supported)
                made["result"]["scenarios"] = [supported, blocked]
                result = self.write_json(f"negative-metric-{case_name}.json", made["result"])
                completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
                self.assertIn(expected_error, completed.stderr)

    def test_sample_metrics_zero_values_accepted(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        target_sample = supported["samples"][0]
        target_sample["first_useful_result_ms"] = 0.0
        target_sample["complete_result_ms"] = 0.0
        target_sample["peak_rss_bytes"] = 0
        target_sample["p95_collection_ms"] = 0.0
        self.recompute_summary(protocol, supported)
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("zero-metrics-accepted.json", made["result"])
        self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=True)

    def test_sample_provenance_enforces_mole_lock_consistency(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        mole_sample = next(sample for sample in supported["samples"] if sample["tool"] == "mole")
        mole_sample["raw_provenance"]["artifact_sha256"] = "f" * 64
        made["result"]["scenarios"] = [supported, blocked]
        result = self.write_json("provenance-mole-artifact-mismatch.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(result), expect_ok=False)
        self.assertIn("Mole artifact_sha256 is not in comparator release assets", completed.stderr)

    def test_failure_record_counts_and_classification(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])

        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        skip_sample = supported["samples"][0]
        skip_sample["status"] = "skipped"
        supported["failures"] = [{
            "pair_id": skip_sample["pair_id"],
            "tool": skip_sample["tool"],
            "run_index": skip_sample["run_index"],
            "classification": "skipped",
            "reason": "fixture skip",
            "raw_log_reference": "logs/skip.log",
        }]
        self.recompute_summary(protocol, supported)
        made["result"]["scenarios"] = [supported, blocked]
        valid_skip = self.write_json("valid-skip-record.json", made["result"])
        self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(valid_skip), expect_ok=True)

        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        fail_sample = supported["samples"][1]
        fail_sample["status"] = "failed"
        supported["failures"] = [{
            "pair_id": fail_sample["pair_id"],
            "tool": fail_sample["tool"],
            "run_index": fail_sample["run_index"],
            "classification": "failed",
            "reason": "fixture fail",
            "raw_log_reference": "logs/fail.log",
        }]
        self.recompute_summary(protocol, supported)
        valid_fail = self.write_json("valid-failed-record.json", made["result"])
        self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(valid_fail), expect_ok=True)

        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        mix_skip = supported["samples"][0]
        mix_fail = supported["samples"][1]
        mix_skip["status"] = "skipped"
        mix_fail["status"] = "failed"
        supported["failures"] = [
            {
                "pair_id": mix_skip["pair_id"],
                "tool": mix_skip["tool"],
                "run_index": mix_skip["run_index"],
                "classification": "skipped",
                "reason": "skip mixed",
                "raw_log_reference": "logs/mixed-skip.log",
            },
            {
                "pair_id": mix_fail["pair_id"],
                "tool": mix_fail["tool"],
                "run_index": mix_fail["run_index"],
                "classification": "failed",
                "reason": "fail mixed",
                "raw_log_reference": "logs/mixed-fail.log",
            },
        ]
        self.recompute_summary(protocol, supported)
        made["result"]["scenarios"] = [supported, blocked]
        valid_mix = self.write_json("valid-mixed-records.json", made["result"])
        self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(valid_mix), expect_ok=True)

    def test_failure_record_mismatch_and_duplicates_rejected(self) -> None:
        protocol = self.make_supported_protocol()
        made = self.make_result_base(protocol)
        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        blocked = self.make_blocked_result_scenario(protocol, protocol["scenario_matrix"][1])
        sample = supported["samples"][0]
        sample["status"] = "skipped"
        supported["failures"] = [{
            "pair_id": sample["pair_id"],
            "tool": sample["tool"],
            "run_index": sample["run_index"],
            "classification": "failed",
            "reason": "wrong class",
            "raw_log_reference": "logs/wrong-class.log",
        }]
        self.recompute_summary(protocol, supported)
        made["result"]["scenarios"] = [supported, blocked]
        bad_class = self.write_json("bad-classification.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(bad_class), expect_ok=False)
        self.assertIn("classification does not match sample status", completed.stderr)

        supported = self.make_supported_result_scenario(protocol, protocol["scenario_matrix"][0])
        sample = supported["samples"][0]
        sample["status"] = "failed"
        record = {
            "pair_id": sample["pair_id"],
            "tool": sample["tool"],
            "run_index": sample["run_index"],
            "classification": "failed",
            "reason": "dup",
            "raw_log_reference": "logs/dup.log",
        }
        supported["failures"] = [record, copy.deepcopy(record)]
        self.recompute_summary(protocol, supported)
        made["result"]["scenarios"] = [supported, blocked]
        duplicate = self.write_json("duplicate-failure-record.json", made["result"])
        completed = self.run_checker("--manifest", str(made["manifest_path"]), "--results", str(duplicate), expect_ok=False)
        self.assertIn("duplicate failure entry", completed.stderr)


if __name__ == "__main__":
    unittest.main()
