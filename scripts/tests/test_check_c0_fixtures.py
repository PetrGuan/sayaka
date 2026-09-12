#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import importlib.util
from pathlib import Path
import shutil
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check_c0_fixtures.py"
WORKSPACE_ROOT = REPO / "target/test-workspaces/check_c0_fixtures"


class CheckC0FixturesSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("check_c0_fixtures", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to import check_c0_fixtures.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module
        WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.test_workspace = WORKSPACE_ROOT / self._testMethodName
        if self.test_workspace.exists():
            shutil.rmtree(self.test_workspace)
        self.test_workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.test_workspace, ignore_errors=True)

    def test_remove_owned_tree_rejects_swapped_symlink_root_without_mutation(self) -> None:
        marker_name = ".sayaka-c0-owned"
        marker_value = b"sayaka-c0-owned-fixtures"
        root = self.test_workspace / "owned-root"
        root.mkdir()
        (root / marker_name).write_bytes(marker_value)
        (root / "owned.txt").write_text("owned")

        sentinel = self.test_workspace / "sentinel-dir"
        sentinel.mkdir()
        sentinel_file = sentinel / "do-not-touch.txt"
        sentinel_file.write_text("sentinel")

        backup = self.test_workspace / "owned-backup"
        root.rename(backup)
        root.symlink_to(sentinel, target_is_directory=True)

        with mock.patch.object(self.module.os, "chmod", wraps=self.module.os.chmod) as chmod_mock:
            with self.assertRaises(AssertionError):
                self.module.remove_owned_tree(root, marker_name, marker_value)
            self.assertEqual(chmod_mock.call_count, 0)

        self.assertTrue(sentinel_file.exists())
        self.assertEqual(sentinel_file.read_text(), "sentinel")
        self.assertTrue(backup.exists())

    def test_remove_owned_tree_symlink_target_remains_intact(self) -> None:
        marker_name = ".sayaka-c0-owned"
        marker_value = b"sayaka-c0-owned-fixtures"
        root = self.test_workspace / "owned-root"
        root.mkdir()
        (root / marker_name).write_bytes(marker_value)
        (root / "owned.txt").write_text("owned")

        sentinel = self.test_workspace / "sentinel-dir"
        sentinel.mkdir()
        sentinel_file = sentinel / "keep.txt"
        sentinel_file.write_text("keep")

        backup = self.test_workspace / "owned-backup"
        root.rename(backup)
        root.symlink_to(sentinel, target_is_directory=True)

        with self.assertRaises(AssertionError):
            self.module.remove_owned_tree(root, marker_name, marker_value)

        self.assertTrue(sentinel_file.exists())
        self.assertEqual(sentinel_file.read_text(), "keep")
        self.assertTrue(backup.exists())
        self.assertTrue((backup / "owned.txt").exists())

    def test_create_run_root_does_not_reclaim_legacy_fixed_name_root(self) -> None:
        marker_name = ".sayaka-c0-owned"
        fixture_parent = self.test_workspace / "fixture-parent"
        fixture_parent.mkdir()

        legacy_root = fixture_parent / "scan-readonly-basic-v1"
        legacy_root.mkdir()
        (legacy_root / marker_name).write_text("legacy-marker")
        legacy_file = legacy_root / "legacy.txt"
        legacy_file.write_text("legacy-content")

        run_root, _chain, _identity = self.module.create_run_root(fixture_parent, REPO)
        self.assertTrue(run_root.exists())
        self.assertTrue(run_root.parent == fixture_parent)
        self.assertTrue(legacy_file.exists())
        self.assertEqual(legacy_file.read_text(), "legacy-content")

        (run_root / marker_name).write_bytes(b"sayaka-c0-owned-fixtures")
        self.module.remove_owned_tree(run_root, marker_name, b"sayaka-c0-owned-fixtures")
        self.assertFalse(run_root.exists())
        self.assertTrue(legacy_root.exists())

    def test_remove_owned_tree_handles_denied_fixture_directories(self) -> None:
        marker_name = ".sayaka-c0-owned"
        marker_value = b"sayaka-c0-owned-fixtures"
        root = self.test_workspace / "owned-root"
        denied = root / "denied"
        denied.mkdir(parents=True)
        (root / marker_name).write_bytes(marker_value)
        locked_file = denied / "locked.txt"
        locked_file.write_text("locked")
        self.module.os.chmod(denied, 0o000)

        self.module.remove_owned_tree(root, marker_name, marker_value)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
