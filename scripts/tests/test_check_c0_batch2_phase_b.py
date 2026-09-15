#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check_c0_batch2_phase_b.py"
WORKSPACE_ROOT = REPO / "target/test-workspaces/check_c0_batch2_phase_b"


class CheckC0Batch2PhaseBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("check_c0_batch2_phase_b", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to import check_c0_batch2_phase_b.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module
        WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.test_workspace = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=WORKSPACE_ROOT))
        info = self.test_workspace.lstat()
        self.original_identity = (info.st_dev, info.st_ino)
        (self.test_workspace / "owner-marker").write_text("c0-b2-test-owned")
        self.env = {"PATH": "/bin:/usr/bin", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
        for variable, relative in {
            "HOME": "home", "TMPDIR": "tmp", "XDG_CONFIG_HOME": "config",
            "XDG_STATE_HOME": "state", "XDG_CACHE_HOME": "cache",
        }.items():
            path = self.test_workspace / relative
            path.mkdir()
            self.env[variable] = str(path)

    def tearDown(self) -> None:
        info = self.test_workspace.lstat()
        self.assertFalse(self.test_workspace.is_symlink())
        self.assertEqual((info.st_dev, info.st_ino), self.original_identity)
        self.assertEqual((self.test_workspace / "owner-marker").read_text(), "c0-b2-test-owned")
        shutil.rmtree(self.test_workspace)

    def _write_manifest(self, profile_hash: str) -> Path:
        manifest = {
            "benchmark_id": "c0-b2-test",
            "scenario": {
                "scenario_id": "c0-b2-analyze-flat-regular-json-v1",
                "ab_mapping": {"A": "mole", "B": "sayaka"},
                "fixture_truth": {
                    "fixture_id": "c0-b2-flat-regular-v1",
                    "file_count": 1024,
                    "bytes_per_file": 4096,
                    "logical_bytes": 4194304,
                    "payload_seed": 260026,
                },
                "pair_schedule": ["AB", "BA"],
            },
            "repetitions": {"paired_ab_ba": 2},
            "phase_b": {
                "approved_profile_sha256": profile_hash,
                "measurement_fixed": {
                    "stdout_capture_cap_bytes": 1024,
                    "stderr_capture_cap_bytes": 1024,
                    "timeout_seconds_per_sample": 30,
                },
            },
        }
        path = self.test_workspace / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        return path

    def _write_phase_a(self, profile_hash: str) -> Path:
        phase_a = {
            "status": "phase_a_ready",
            "manifest_sha256": "",
            "profile": {"sha256": profile_hash},
            "canaries": [{"id": "x", "status": "passed"}],
            "sayaka_control_scan": {"status": "passed"},
        }
        path = self.test_workspace / "phase-a.json"
        path.write_text(json.dumps(phase_a, indent=2) + "\n")
        return path

    def _allow_all_profile(self) -> Path:
        profile = self.test_workspace / "allow-all.sb"
        profile.write_text("(version 1)\n(allow default)\n")
        return profile

    def test_phase_b_dry_run_requires_execute_flag(self) -> None:
        profile_hash = "a" * 64
        manifest = self._write_manifest(profile_hash)
        phase_a = self._write_phase_a(profile_hash)
        phase_a_payload = json.loads(phase_a.read_text())
        phase_a_payload["manifest_sha256"] = self.module.sha256(manifest)
        phase_a.write_text(json.dumps(phase_a_payload, indent=2) + "\n")

        output = self.test_workspace / "phase-b-dry-run.json"
        completed = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--manifest",
                str(manifest),
                "--phase-a-result",
                str(phase_a),
                "--approved-profile-sha256",
                profile_hash,
                "--output",
                str(output),
            ],
            cwd=REPO,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        payload = json.loads(output.read_text())
        self.assertEqual(payload["status"], "not_executed_requires_operator_flag")
        self.assertFalse(payload["execution_performed"])

    def test_run_sample_measures_first_payload_before_completion(self) -> None:
        profile = self._allow_all_profile()
        run = self.module.run_sample(
            profile=profile,
            params={},
            command=["/bin/bash", "--noprofile", "--norc", "-c", "printf '{\"ok\":1}\\n'; /bin/sleep 1"],
            env_map=self.env,
            cwd=self.test_workspace,
            timeout_seconds=5,
            stdout_cap_bytes=1024,
            stderr_cap_bytes=1024,
            normalizer=lambda payload: payload,
            run_root=self.test_workspace,
        )
        self.assertEqual(run["status"], "passed")
        self.assertEqual(run["first_useful_result_status"], "measured")
        self.assertLess(run["first_useful_result_ms"], run["complete_result_ms"])
        self.assertGreater(run["complete_result_ms"] - run["first_useful_result_ms"], 500)

    def test_run_sample_v2_uses_last_non_whitespace_chunk(self) -> None:
        profile = self._allow_all_profile()
        run = self.module.run_sample(
            profile=profile,
            params={},
            command=[
                "/usr/bin/python3",
                "-c",
                "import sys,time;sys.stdout.write('1');sys.stdout.flush();time.sleep(1);sys.stdout.write('2');sys.stdout.flush();time.sleep(1)",
            ],
            env_map=self.env,
            cwd=self.test_workspace,
            timeout_seconds=5,
            stdout_cap_bytes=1024,
            stderr_cap_bytes=1024,
            normalizer=lambda payload: payload,
            run_root=self.test_workspace,
            first_useful_result_method_id=self.module.FIRST_USEFUL_RESULT_METHOD_V2,
        )
        self.assertEqual(run["status"], "passed")
        self.assertEqual(run["first_useful_result_status"], "measured")
        self.assertLess(run["first_useful_result_ms"], run["complete_result_ms"])
        self.assertGreater(run["complete_result_ms"] - run["first_useful_result_ms"], 500)

    def test_run_sample_v2_handles_split_utf8_and_whitespace(self) -> None:
        profile = self._allow_all_profile()
        run = self.module.run_sample(
            profile=profile,
            params={},
            command=[
                "/usr/bin/python3",
                "-c",
                (
                    "import sys,time;"
                    "full='{\"msg\":\"😀\",\"nested\":[{\"k\":\"a\\\\\\\\\\\\\"b\"}]}'.encode('utf-8');"
                    "part1=full[:10];part2=full[10:];"
                    "sys.stdout.buffer.write(part1);sys.stdout.buffer.flush();"
                    "time.sleep(1);"
                    "sys.stdout.buffer.write(part2);sys.stdout.buffer.flush();"
                    "time.sleep(1);"
                    "sys.stdout.write(' \\n\\t');sys.stdout.flush()"
                ),
            ],
            env_map=self.env,
            cwd=self.test_workspace,
            timeout_seconds=6,
            stdout_cap_bytes=4096,
            stderr_cap_bytes=1024,
            normalizer=lambda payload: payload,
            run_root=self.test_workspace,
            first_useful_result_method_id=self.module.FIRST_USEFUL_RESULT_METHOD_V2,
        )
        self.assertEqual(run["status"], "passed")
        self.assertEqual(run["first_useful_result_status"], "measured")
        self.assertGreater(run["complete_result_ms"] - run["first_useful_result_ms"], 500)

    def test_run_sample_v2_does_not_call_prefix_json_predicate(self) -> None:
        profile = self._allow_all_profile()
        with mock.patch.object(self.module, "_parse_json_complete", side_effect=AssertionError("must not be called")):
            run = self.module.run_sample(
                profile=profile,
                params={},
                command=["/bin/bash", "--noprofile", "--norc", "-c", "printf '{\"ok\":1}'"],
                env_map=self.env,
                cwd=self.test_workspace,
                timeout_seconds=5,
                stdout_cap_bytes=1024,
                stderr_cap_bytes=1024,
                normalizer=lambda payload: payload,
                run_root=self.test_workspace,
                first_useful_result_method_id=self.module.FIRST_USEFUL_RESULT_METHOD_V2,
            )
        self.assertEqual(run["status"], "passed")
        self.assertEqual(run["first_useful_result_status"], "measured")

    def test_run_sample_stream_cap_trips_and_kills(self) -> None:
        profile = self._allow_all_profile()
        run = self.module.run_sample(
            profile=profile,
            params={},
            command=["/usr/bin/python3", "-c", "import sys,time; sys.stdout.write('x'*2000000); sys.stdout.flush(); time.sleep(3)"],
            env_map=self.env,
            cwd=self.test_workspace,
            timeout_seconds=5,
            stdout_cap_bytes=512,
            stderr_cap_bytes=512,
            normalizer=lambda payload: payload,
            run_root=self.test_workspace,
        )
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["failure_class"], "output_cap_exceeded")
        self.assertTrue(run["stdout_truncated"])
        self.assertLess(run["complete_result_ms"], 2500)
        self.assertLess(run["exit_code"], 0)
        self.assertLess(run["stdout_bytes"], 2000000)

    def test_wait4_peak_rss_not_cumulative(self) -> None:
        profile = self._allow_all_profile()
        high = self.module.run_sample(
            profile=profile,
            params={},
            command=["/usr/bin/python3", "-c", "x=bytearray(60*1024*1024);print('{\"ok\":1}')"],
            env_map=self.env,
            cwd=self.test_workspace,
            timeout_seconds=10,
            stdout_cap_bytes=2048,
            stderr_cap_bytes=2048,
            normalizer=lambda payload: payload,
            run_root=self.test_workspace,
        )
        low = self.module.run_sample(
            profile=profile,
            params={},
            command=["/usr/bin/python3", "-c", "print('{\"ok\":1}')"],
            env_map=self.env,
            cwd=self.test_workspace,
            timeout_seconds=10,
            stdout_cap_bytes=2048,
            stderr_cap_bytes=2048,
            normalizer=lambda payload: payload,
            run_root=self.test_workspace,
        )
        self.assertEqual(high["status"], "passed")
        self.assertEqual(low["status"], "passed")
        self.assertGreater(high["peak_rss_bytes"], low["peak_rss_bytes"])

    def test_mole_normalizer_rejects_directory_entry(self) -> None:
        fixture_root = Path("/x/fixture")
        truth = {"f000000.bin": {"logical_bytes": 4096}}
        payload = {
            "overview": False,
            "entries": [{"name": "dir", "path": "/x/fixture/dir", "size": 0, "is_dir": True}],
            "total_size": 0,
            "total_files": 0,
            "error": "",
        }
        with self.assertRaises(self.module.ValidationError):
            self.module.normalize_mole_json(payload, fixture_root=fixture_root, truth_entries=truth)

    def test_sayaka_normalizer_accepts_valid_payload(self) -> None:
        fixture_root = Path("/x/fixture")
        truth = {"f000000.bin": {"logical_bytes": 4096}}
        payload = {
            "schema_version": 1,
            "status": "complete",
            "complete": True,
            "roots": [{"encoding": "unix_bytes_hex", "raw": fixture_root.as_posix().encode().hex()}],
            "entries": [
                {"path": {"encoding": "unix_bytes_hex", "raw": fixture_root.as_posix().encode().hex()}, "kind": "directory", "logical_bytes": None, "allocated_bytes": None, "counted": False, "dataless": False, "depth": 0},
                {"path": {"encoding": "unix_bytes_hex", "raw": (fixture_root / "f000000.bin").as_posix().encode().hex()}, "kind": "file", "logical_bytes": 4096, "allocated_bytes": 4096, "counted": True, "dataless": False, "depth": 1},
            ],
            "issues": [],
            "issues_omitted": 0,
            "totals": {
                "regular_files": 1,
                "unique_files": 1,
                "links": 0,
                "duplicate_files": 0,
                "other": 0,
                "directories": 1,
                "logical_bytes_known": 4096,
                "logical_bytes_unknown_files": 0,
                "allocated_bytes_unknown_files": 0,
            },
        }
        normalized = self.module.normalize_sayaka_json(payload, fixture_root=fixture_root, truth_entries=truth)
        self.assertEqual(normalized["file_count"], 1)
        self.assertEqual(normalized["logical_bytes"], 4096)

    def test_text_installer_does_not_require_json(self) -> None:
        captures = []
        result = self.module.run_install(
            profile=self._allow_all_profile(), params={},
            command=["/bin/bash", "--noprofile", "--norc", "-c", "printf 'Installation complete\\n'"],
            env_map=self.env, cwd=self.test_workspace, timeout_seconds=5,
            stdout_cap_bytes=1024, stderr_cap_bytes=1024,
            raw_sink=captures.append, expects_json=False,
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["output_contract"], "official_text")
        self.assertEqual(captures[0]["stdout"], "Installation complete\n")

    def test_snapshot_and_config_footprint_are_complete(self) -> None:
        prefix = self.test_workspace / "prefix"
        config = self.test_workspace / "mole-config"
        prefix.mkdir()
        config.mkdir()
        (prefix / "mole").write_bytes(b"launcher")
        (config / "helper").write_bytes(b"required helper" * 100)
        before = self.module.snapshot_tree(prefix)
        measured = self.module.footprint_totals({
            "prefix": before, "config": self.module.snapshot_tree(config),
        })
        self.assertEqual(measured["regular_logical_bytes"], 8 + 1500)
        (prefix / "mole").write_bytes(b"changed")
        self.assertNotEqual(before["tree_sha256"], self.module.snapshot_tree(prefix)["tree_sha256"])

    def test_setup_failure_retains_structured_blocked_result(self) -> None:
        phase_a = self.module._load_phase_a_module()
        output = self.test_workspace / "blocked.json"
        with mock.patch.object(phase_a, "create_owned_run_root", side_effect=OSError("controlled setup failure")):
            result = self.module.execute_phase_b(
                {"benchmark_id": "c0-b2-test"}, phase_a,
                self.test_workspace, self.test_workspace, "a" * 64, output,
            )
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["mole_execution_attempted"])
        self.assertEqual(json.loads(output.read_text())["blocked_prerequisite"], "setup_failed")

    def test_bad_json_and_bad_normalization_remain_failed(self) -> None:
        captures = []
        for text, expected in (("not-json", "invalid_json"), ('{"ok": 1}', "normalization_failed")):
            result = self.module.run_sample(
                profile=self._allow_all_profile(), params={},
                command=["/bin/bash", "--noprofile", "--norc", "-c", 'printf "%s" "$1"', "--", text],
                env_map=self.env, cwd=self.test_workspace, timeout_seconds=5,
                stdout_cap_bytes=1024, stderr_cap_bytes=1024,
                normalizer=lambda _payload: self.module.ensure(False, "controlled mismatch"),
                run_root=self.test_workspace, raw_sink=captures.append,
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_class"], expected)
            self.assertIsNone(result["first_useful_result_ms"])
        self.assertTrue(captures)

    def test_v2_invalid_extra_and_normalizer_fail_do_not_measure(self) -> None:
        profile = self._allow_all_profile()
        cases = [
            ("printf '{\"ok\":1}x'", "invalid_json"),
            ("printf '{\"ok\":1}'", "normalization_failed"),
        ]
        for command, expected in cases:
            result = self.module.run_sample(
                profile=profile,
                params={},
                command=["/bin/bash", "--noprofile", "--norc", "-c", command],
                env_map=self.env,
                cwd=self.test_workspace,
                timeout_seconds=5,
                stdout_cap_bytes=1024,
                stderr_cap_bytes=1024,
                normalizer=lambda _payload: self.module.ensure(False, "controlled mismatch"),
                run_root=self.test_workspace,
                first_useful_result_method_id=self.module.FIRST_USEFUL_RESULT_METHOD_V2,
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_class"], expected)
            self.assertEqual(result["first_useful_result_status"], "not_measured")
            self.assertIsNone(result["first_useful_result_ms"])


if __name__ == "__main__":
    unittest.main()
