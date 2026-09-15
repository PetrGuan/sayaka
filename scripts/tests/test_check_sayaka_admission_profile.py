#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
with mock.patch.object(sys, "path", [str(REPO / "scripts"), *sys.path]):
    spec = importlib.util.spec_from_file_location("admission_profile", REPO / "scripts/check_sayaka_admission_profile.py")
    PROFILE = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(PROFILE)


class AdmissionProfileTests(unittest.TestCase):
    def capture(self):
        return {
            "start_ns": 100, "end_ns": 900, "honest_last_stdout_content_ns": 600,
            "clock_domain": "darwin_clock_uptime_raw_ns",
            "stdout_bytes": 42,
            "observer_timing": {
                "spawn_return_ns": 300, "first_stdout_ns": 500,
                "first_stderr_ns": 650, "pipes_closed_ns": 700, "post_eof_wait_misses": 1,
                "exit_notification_count": 0,
            },
        }

    def phases(self):
        return {
            "schema_version": 2, "type": "scan_profile", "status": "complete",
            "output_error": None, "stdout_json_bytes": 42, "dispatch_clock_ns": 400,
            **dict.fromkeys(PROFILE.PHASE_FIELDS, 12.0),
            "native_admission": {
                "caller_policy_enter_ms": 0.1, "native_walk_ms": 10.0, "caller_policy_restore_ms": 0.1,
                "roots": [{**dict.fromkeys(PROFILE.ROOT_FIELDS, 0.1), "volume_ms": 2.0, "error_code": None}],
            },
        }

    def test_observer_partition_and_overlapping_spawn(self):
        capture = self.capture()
        result = PROFILE.observer_summary(capture, self.phases())
        fields = ("parent_start_to_dispatch_ms", "dispatch_to_last_stdout_ms",
                  "last_stdout_to_pipe_eof_ms", "pipe_eof_to_reap_ms")
        self.assertAlmostEqual(sum(result[field] for field in fields), (900 - 100) / 1_000_000)
        phases = self.phases()
        phases["dispatch_clock_ns"] = 200
        self.assertGreater(PROFILE.observer_summary(capture, phases)["popen_ms"],
                           PROFILE.observer_summary(capture, phases)["parent_start_to_dispatch_ms"])
        wrong_clock = {**capture, "clock_domain": "python_monotonic_ns"}
        with self.assertRaises(PROFILE.DIRECT.ValidationError):
            PROFILE.observer_summary(wrong_clock, phases)
        for dispatch in (None, True, 99, 601, float("nan")):
            phases["dispatch_clock_ns"] = dispatch
            with self.assertRaises(PROFILE.DIRECT.ValidationError):
                PROFILE.observer_summary(capture, phases)

    def test_profile_shape_rejects_missing_and_invalid_evidence(self):
        capture = self.capture()
        phases = self.phases()
        capture["stderr"] = json.dumps(phases)
        self.assertEqual(PROFILE.validate_phases(capture, 1), phases)
        for path, value in [
            (("schema_version",), 1), (("stdout_json_bytes",), 41), (("scan_ms",), -1),
            (("setup_ms",), float("nan")), (("native_admission", "native_walk_ms"), 20),
            (("native_admission", "roots", 0, "error_code"), "volume_unknown"),
            (("native_admission", "roots", 0, "volume_ms"), 0),
        ]:
            changed = copy.deepcopy(phases)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            capture["stderr"] = json.dumps(changed)
            with self.assertRaises(PROFILE.DIRECT.ValidationError):
                PROFILE.validate_phases(capture, 1)
        capture["stderr"] = json.dumps(phases)
        with self.assertRaises(PROFILE.DIRECT.ValidationError):
            PROFILE.validate_phases(capture, 2)
        capture["stderr"] += "\n{}"
        with self.assertRaises(PROFILE.DIRECT.ValidationError):
            PROFILE.validate_phases(capture, 1)

    def empty_payload(self):
        roots = [Path("/fixture/empty-0"), Path("/fixture/empty-1")]
        native = lambda path: {"encoding": "unix_bytes_hex", "raw": str(path).encode().hex()}
        totals = dict.fromkeys([
            "regular_files", "unique_files", "duplicate_files", "directories", "links", "other",
            "logical_bytes_known", "logical_bytes_unknown_files", "allocated_bytes_known",
            "allocated_bytes_unknown_files",
        ], 0)
        totals["directories"] = 2
        return roots, {
            "schema_version": 1, "status": "complete", "complete": True,
            "issues": [], "issues_omitted": 0, "roots": [native(path) for path in roots],
            "entries": [{
                "path": native(path), "kind": "directory", "depth": 0, "counted": False,
                "dataless": False, "identity": {"variant": "unix", "device": 1, "inode": 2},
                "logical_bytes": None, "allocated_bytes": None,
            } for path in roots],
            "totals": totals, "metrics": {"accepted_roots": 2},
        }

    @mock.patch.object(Path, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2))
    def test_empty_root_truth_rejects_partial_duplicates_identity_and_missing_totals(self, _stat):
        roots, payload = self.empty_payload()
        self.assertEqual(PROFILE.normalize_empty_roots(payload, roots)["root_count"], 2)
        for mutation in ("duplicate", "identity", "partial", "totals", "entry_count"):
            changed = copy.deepcopy(payload)
            if mutation == "duplicate":
                changed["entries"][1] = changed["entries"][0]
            elif mutation == "identity":
                changed["entries"][0]["identity"]["inode"] = 3
            elif mutation == "partial":
                changed["complete"] = False
            elif mutation == "totals":
                del changed["totals"]["links"]
            else:
                changed["entries"].pop()
            with self.assertRaises(PROFILE.DIRECT.ValidationError):
                PROFILE.normalize_empty_roots(changed, roots)

    def test_paired_differences_use_pair_identity(self):
        rows = []
        for index in range(3):
            for variant, elapsed in (("on", 13 + index), ("baseline", 10 + index), ("off", 11 + index)):
                rows.append({"pair_index": index, "variant": variant, "complete_result_ms": elapsed,
                             "phases": self.phases(), "observer": PROFILE.observer_summary(self.capture(), self.phases())})
        settings = {"confidence": 0.95, "bootstrap_resamples": 100, "bootstrap_seed": 1}
        result = PROFILE.summarize(rows, settings)
        self.assertEqual(result["exit_observer_off_minus_baseline"]["median_delta_ms"], 1)
        self.assertEqual(result["instrumentation_on_minus_off"]["ci_ms"], [2, 2])

    def test_actual_flat_normalizer_accepts_current_variant_and_checks_identity(self):
        roots, payload = self.empty_payload()
        root = roots[0]
        payload["roots"] = payload["roots"][:1]
        payload["entries"] = payload["entries"][:1]
        payload["totals"].update(directories=1, regular_files=1, unique_files=1,
                                 logical_bytes_known=4, allocated_bytes_known=4096)
        payload["metrics"]["accepted_roots"] = 1
        payload["entries"].append({
            "path": {"encoding": "unix_bytes_hex", "raw": str(root / "data").encode().hex()},
            "kind": "file", "depth": 1, "counted": True, "dataless": False,
            "identity": {"variant": "unix", "device": 1, "inode": 3},
            "logical_bytes": 4, "allocated_bytes": 4096,
        })
        truth = {"data": {"logical_bytes": 4, "device": 1, "inode": 3}}
        result = PROFILE.DIRECT.normalize_sayaka_json(payload, fixture_root=root, truth_entries=truth)
        self.assertEqual(result["file_count"], 1)
        payload["entries"][1]["identity"]["inode"] = 4
        with self.assertRaises(PROFILE.DIRECT.ValidationError):
            PROFILE.DIRECT.normalize_sayaka_json(payload, fixture_root=root, truth_entries=truth)


if __name__ == "__main__":
    unittest.main()
