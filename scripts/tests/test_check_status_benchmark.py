#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import importlib.util
from pathlib import Path
from typing import Optional
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check_status_benchmark.py"


class CheckStatusBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        scripts_dir = str(REPO / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        spec = importlib.util.spec_from_file_location("check_status_benchmark", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to import check_status_benchmark.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module

    def sample(self, sequence: int, collection_ms: int, observed: Optional[int]) -> dict:
        return {
            "sequence": sequence,
            "interval_ms": 1000,
            "slow_interval_ms": 5000,
            "collection_ms": collection_ms,
            "process_top": {"observed_unix_ms": observed},
        }

    def top_budget(self) -> dict:
        return {"max_steady_collection_ms": 100, "max_top_collection_ms": 150}

    def test_fast_and_slow_classification_with_conservative_rounding_passes(self):
        all_samples = [
            self.sample(1, 99, 1000),
            self.sample(2, 99, 1000),
            self.sample(3, 99, 1000),
            self.sample(4, 99, 1000),
            self.sample(5, 120, 2000),
            self.sample(6, 99, 3000),
        ]
        result = self.module.enforce_collection_budgets(
            all_samples, 2, self.top_budget(), top_enabled=True
        )
        self.assertEqual(result["max_fast_collection_ms"], 99)
        self.assertEqual(result["max_fast_collection_ms_upper_bound"], 100)
        self.assertEqual(result["max_slow_collection_ms"], 120)
        self.assertEqual(result["max_slow_collection_ms_upper_bound"], 121)
        self.assertEqual(result["slow_generation_count"], 2)

    def test_fast_budget_violation_fails(self):
        all_samples = [
            self.sample(1, 99, 1000),
            self.sample(2, 99, 1000),
            self.sample(3, 99, 1000),
            self.sample(4, 101, 1000),
            self.sample(5, 120, 2000),
            self.sample(6, 99, 3000),
        ]
        with self.assertRaisesRegex(AssertionError, "fast collection"):
            self.module.enforce_collection_budgets(
                all_samples, 2, self.top_budget(), top_enabled=True
            )

    def test_slow_budget_violation_fails(self):
        all_samples = [
            self.sample(1, 99, 1000),
            self.sample(2, 99, 1000),
            self.sample(3, 99, 1000),
            self.sample(4, 99, 1000),
            self.sample(5, 151, 2000),
            self.sample(6, 99, 3000),
        ]
        with self.assertRaisesRegex(AssertionError, "slow/top collection"):
            self.module.enforce_collection_budgets(
                all_samples, 2, self.top_budget(), top_enabled=True
            )

    def test_missing_slow_observations_fail(self):
        all_samples = [
            self.sample(1, 99, 1000),
            self.sample(2, 99, 1000),
            self.sample(3, 99, 1000),
            self.sample(4, 99, 1000),
            self.sample(5, 99, 1000),
        ]
        with self.assertRaisesRegex(AssertionError, "missing slow/top generations"):
            self.module.enforce_collection_budgets(
                all_samples, 2, self.top_budget(), top_enabled=True
            )

    def test_count_only_semantics_are_unchanged(self):
        budget = {"max_steady_collection_ms": 100}
        all_samples = [
            self.sample(1, 99, None),
            self.sample(2, 99, None),
            self.sample(3, 99, None),
            self.sample(4, 99, None),
        ]
        result = self.module.enforce_collection_budgets(all_samples, 2, budget, top_enabled=False)
        self.assertEqual(result["collection_ms_upper_bound"], 100)

    def test_warmup_carryover_does_not_count_as_steady_physical_generation(self):
        all_samples = []
        for seq in range(1, 13):
            if seq <= 5:
                obs = 1000
            elif seq <= 10:
                obs = 2000
            else:
                obs = 3000
            all_samples.append(self.sample(seq, 99, obs))
        slow = self.module.classify_top_generation_samples(all_samples, 2)
        self.assertEqual(slow, [3, 8])
        result = self.module.enforce_collection_budgets(
            all_samples, 2, self.top_budget(), top_enabled=True
        )
        self.assertEqual(result["slow_generation_count"], 2)
        self.assertEqual(result["fast_sample_count"], 8)

    def test_one_true_steady_generation_fails_two_generation_guard(self):
        all_samples = []
        for seq in range(1, 13):
            if seq <= 10:
                obs = 1000
            else:
                obs = 2000
            all_samples.append(self.sample(seq, 99, obs))
        with self.assertRaisesRegex(AssertionError, "missing slow/top generations"):
            self.module.enforce_collection_budgets(
                all_samples, 2, self.top_budget(), top_enabled=True
            )


if __name__ == "__main__":
    unittest.main()
