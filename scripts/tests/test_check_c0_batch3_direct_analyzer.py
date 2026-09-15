#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import importlib.util
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check_c0_batch3_direct_analyzer.py"
WORKSPACE_ROOT = REPO / "target/test-workspaces/check_c0_batch3_direct_analyzer"


class CheckC0Batch3DirectAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("check_c0_batch3_direct_analyzer", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to import check_c0_batch3_direct_analyzer.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module
        WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.test_workspace = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=WORKSPACE_ROOT))
        info = self.test_workspace.lstat()
        self.identity = (info.st_dev, info.st_ino)

    def tearDown(self) -> None:
        info = self.test_workspace.lstat()
        self.assertFalse(self.test_workspace.is_symlink())
        self.assertEqual((info.st_dev, info.st_ino), self.identity)
        shutil.rmtree(self.test_workspace)

    def test_profile_is_run_independent_and_write_scoped(self) -> None:
        contents = []
        for name in ("first", "second"):
            root = self.test_workspace / name
            root.mkdir()
            layout = self.module.make_layout(root)
            profile, _ = self.module.write_sandbox_profile(root, layout, self._manifest())
            contents.append(profile.read_text())
        self.assertEqual(contents[0], contents[1])
        self.assertIn('(param "WRITE_HOME")', contents[0])
        self.assertIn('(param "WRITE_TMP")', contents[0])
        self.assertNotIn('(param "MOLE_HOME")', contents[0])
        self.assertNotIn('(param "RAW_OUTPUT_ROOT")', contents[0])

    def test_sample_detects_mutation_and_does_not_accept_timing(self) -> None:
        root = self.test_workspace / "run"
        root.mkdir()
        layout = self.module.make_layout(root)
        target = layout["fixture_root"] / "test.bin"
        target.write_bytes(b"before")
        paths = {
            "fixture": layout["fixture_root"], "binaries": layout["bin"],
            "controls": layout["control_root"], "empty_path": layout["empty_path"],
        }
        expected = {key: self.module.PHASE_B.snapshot_tree(path)["tree_sha256"] for key, path in paths.items()}

        def mutate(**kwargs):
            self.assertEqual(kwargs["params"]["WRITE_HOME"], kwargs["env_map"]["HOME"])
            target.write_bytes(b"after")
            return {"status": "passed"}

        with mock.patch.object(self.module.PHASE_B, "run_sample", side_effect=mutate):
            result = self.module._run_tool_sample(
                profile=root / "unused.sb", params={}, layout=layout, tool="sayaka",
                phase="correctness", index=1, fixture_map={}, timeout_seconds=1,
                stdout_cap=100, stderr_cap=100, run_root=root, raw_sink=lambda _: None,
                expected_immutable=expected,
                first_useful_result_method_id=self.module.PHASE_B.FIRST_USEFUL_RESULT_METHOD_V2,
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_class"], "unexpected_effect")
        self.assertFalse(result["no_effects"]["unchanged"])

    def _manifest(self) -> dict:
        return json.loads((self.module.MANIFEST_PATH).read_text())

    def test_defaults_point_to_v2_paths(self) -> None:
        self.assertTrue(str(self.module.MANIFEST_PATH).endswith("c0-batch3-direct-analyzer-v2.json"))
        self.assertTrue(str(self.module.OUTPUT_PATH).endswith("c0-batch3-direct-analyzer-results-v2.json"))

    def test_resolve_sayaka_binary_source_honors_override(self) -> None:
        manifest = self._manifest()
        default_path = self.module._resolve_sayaka_binary_source(manifest, None)
        self.assertEqual(default_path, REPO / manifest["sayaka_reference"]["binary_path"])
        override = Path("/bin/echo")
        self.assertEqual(self.module._resolve_sayaka_binary_source(manifest, override), override)

    def test_validate_manifest_rejects_extra_asset(self) -> None:
        manifest = self._manifest()
        manifest["reference_lock"]["assets"]["status-darwin-arm64"] = {"sha256": "x", "size_bytes": 1}
        with self.assertRaises(self.module.ValidationError):
            self.module.validate_manifest_contract(manifest)

    def test_verify_pinned_source_audit_checks_line_ranges(self) -> None:
        reference = self.test_workspace / "reference"
        (reference / "assets").mkdir(parents=True)
        src = reference / "source"
        (src / "cmd/analyze").mkdir(parents=True)
        (src / "cmd/analyze/main.go").write_text("\n".join(["", "", "", "", "", "", "", "", "", "resolveScanTarget(os.Getenv(\"MO_ANALYZE_PATH\"), flag.Args())"]))
        tar_path = reference / "source.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(src, arcname="tw93-Mole-1b9023b")

        checks = [
            {
                "id": "check",
                "file": "cmd/analyze/main.go",
                "requirements": [
                    {
                        "snippet": "resolveScanTarget(os.Getenv(\"MO_ANALYZE_PATH\"), flag.Args())",
                        "line_ranges": ["1-20"],
                    }
                ],
            }
        ]
        results = self.module.verify_pinned_source_audit(reference, checks)
        self.assertEqual(results[0]["id"], "check")

    def test_tool_env_uses_owned_empty_path(self) -> None:
        run_root = self.test_workspace / "run"
        run_root.mkdir()
        layout = self.module.make_layout(run_root)
        env_map, _cwd = self.module._tool_env(layout, "sayaka", "x")
        self.assertEqual(env_map["PATH"], str(layout["empty_path"]))

    def test_sayaka_normalizer_accepts_identity_variant(self) -> None:
        fixture_root = Path("/x/fixture")
        truth = {"f000000.bin": {"logical_bytes": 4096, "device": 1, "inode": 2}}
        payload = {
            "schema_version": 1,
            "status": "complete",
            "complete": True,
            "roots": [{"encoding": "unix_bytes_hex", "raw": fixture_root.as_posix().encode().hex()}],
            "entries": [
                {
                    "path": {"encoding": "unix_bytes_hex", "raw": fixture_root.as_posix().encode().hex()},
                    "kind": "directory",
                    "logical_bytes": None,
                    "allocated_bytes": None,
                    "counted": False,
                    "dataless": False,
                    "depth": 0,
                },
                {
                    "path": {"encoding": "unix_bytes_hex", "raw": (fixture_root / "f000000.bin").as_posix().encode().hex()},
                    "kind": "file",
                    "identity": {"variant": "unix", "device": 1, "inode": 2},
                    "logical_bytes": 4096,
                    "allocated_bytes": 4096,
                    "counted": True,
                    "dataless": False,
                    "depth": 1,
                },
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

    def test_execute_prepare_mode_skips_mole(self) -> None:
        manifest = self._manifest()
        output = self.test_workspace / "out.json"

        with mock.patch.object(self.module, "verify_reference_assets", return_value={"ok": True}), \
             mock.patch.object(self.module, "verify_pinned_source_audit", return_value=[{"id": "a", "file": "f", "requirement_count": 1}]), \
             mock.patch.object(self.module, "stage_binaries", return_value={"analyzer": {"sha256": "a"}, "sayaka": {"sha256": "b"}}), \
             mock.patch.object(self.module, "compile_trusted_canary", return_value=Path("/x/canary")), \
             mock.patch.object(self.module, "write_sandbox_profile", return_value=(self.test_workspace / "p.sb", ["/usr/bin/env"])), \
             mock.patch.object(self.module.PHASE_A, "sha256", return_value="h"), \
             mock.patch.object(self.module.PHASE_A, "generate_flat_fixture", return_value={
                 "fixture_id": "c0-b3-flat-regular-v1", "file_count": 1024,
                 "logical_bytes": 4194304, "entries_sha256": "eh",
                 "entries": [{"path": "f000000.bin", "logical_bytes": 4096}],
             }), \
             mock.patch.object(self.module, "run_guard_canaries", return_value=([{"id": "c", "status": "passed"}], True)), \
             mock.patch.object(self.module, "_run_tool_sample", return_value={"status": "passed", "failure_class": "none", "normalized": {}, "complete_result_ms": 1, "first_useful_result_status": "measured", "first_useful_result_ms": 1, "peak_rss_bytes": 1, "stdout_bytes": 1, "stderr_bytes": 0, "stdout_truncated": False, "stderr_truncated": False, "exit_code": 0, "stderr": ""}) as run_sample:
            (self.test_workspace / "p.sb").write_text("(version 1)\n")
            result = self.module.execute(
                manifest,
                self.module.MANIFEST_PATH,
                reference_root=self.test_workspace,
                run_root_base=self.test_workspace / "runs",
                output=output,
                execute_mole=False,
                approved_profile_sha256=None,
                sayaka_binary_override=None,
            )

        self.assertEqual(result["status"], "ready_for_review_authorization")
        self.assertFalse(result["mole_execution_attempted"])
        self.assertEqual(run_sample.call_count, 1)
        self.assertEqual(run_sample.call_args.kwargs["tool"], "sayaka")


if __name__ == "__main__":
    unittest.main()
