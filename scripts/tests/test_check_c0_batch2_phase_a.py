#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check_c0_batch2_phase_a.py"
WORKSPACE_ROOT = REPO / "target/test-workspaces/check_c0_batch2_phase_a"


class CheckC0Batch2PhaseATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("check_c0_batch2_phase_a", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to import check_c0_batch2_phase_a.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module
        WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.test_workspace = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=WORKSPACE_ROOT))
        info = self.test_workspace.lstat()
        self.original_identity = (info.st_dev, info.st_ino)
        (self.test_workspace / "owner-marker").write_text("c0-b2-test-owned")

    def tearDown(self) -> None:
        info = self.test_workspace.lstat()
        self.assertFalse(self.test_workspace.is_symlink())
        self.assertEqual((info.st_dev, info.st_ino), self.original_identity)
        self.assertEqual((self.test_workspace / "owner-marker").read_text(), "c0-b2-test-owned")
        shutil.rmtree(self.test_workspace)

    def test_privileged_helper_is_detected_without_execution(self) -> None:
        helper = self.test_workspace / "harmless-control"
        helper.write_text("this fixture must never be executed")
        helper.chmod(0o4755)
        self.assertEqual(self.module.privileged_helper_paths([str(helper)]), [str(helper)])
        helper.chmod(0o755)
        self.assertEqual(self.module.privileged_helper_paths([str(helper)]), [])

    def _write_reference(self, *, extra_symlink: bool = False) -> Path:
        reference = self.test_workspace / "reference"
        (reference / "assets").mkdir(parents=True)
        source_root = reference / "source"
        (source_root / "bin").mkdir(parents=True)
        (source_root / "cmd/analyze").mkdir(parents=True)
        (source_root / ".agents/skills").mkdir(parents=True)
        (source_root / ".claude/skills").mkdir(parents=True)

        for name in ("bugs", "mole", "release-flow", "release-notes"):
            (source_root / f".claude/skills/{name}").mkdir(parents=True, exist_ok=True)
            (source_root / f".agents/skills/{name}").symlink_to(f"../../.claude/skills/{name}")

        (source_root / "AGENTS.md").write_text("agents\n")
        (source_root / "CLAUDE.md").symlink_to("AGENTS.md")

        if extra_symlink:
            (source_root / "bad-link").symlink_to("AGENTS.md")

        (source_root / "install.sh").write_text(
            "\n".join(
                [
                    "resolve_source_dir() {",
                    "if [[ -f \"$script_dir/mole\" ]]; then",
                    "if [[ -f \"$SOURCE_DIR/bin/${binary_name}-go\" ]]; then",
                    "elif [[ -f \"$SOURCE_DIR/bin/${binary_name}-darwin-${arch_suffix}\" ]]; then",
                    "if ! maybe_sudo cp \"$SOURCE_DIR/mole\" \"$INSTALL_DIR/mole.new\"",
                    "local -a bin_files=(\"$SOURCE_DIR/bin\"/*)",
                    "if run_install_probe_with_timeout 5 \"$INSTALL_DIR/mole\" --help > /dev/null 2>&1; then",
                    "brew uninstall --force mole > /dev/null 2>&1 || true",
                    "brew_bin=$(command -v brew 2> /dev/null || true)",
                ]
            )
            + "\n"
        )
        (source_root / "mole").write_text('"analyze" | "analyse")\nexec "$SCRIPT_DIR/bin/analyze.sh" "${args[@]:1}"\n')
        (source_root / "bin/analyze.sh").write_text('GO_BIN="$SCRIPT_DIR/analyze-go"\nexec "$GO_BIN" "$@"\n')
        (source_root / "bin/status.sh").write_text('GO_BIN="$SCRIPT_DIR/status-go"\nexec "$GO_BIN" "$@"\n')
        (source_root / "cmd/analyze/main.go").write_text(
            "resolveScanTarget(os.Getenv(\"MO_ANALYZE_PATH\"), flag.Args())\n"
            "return []dirEntry{\n{Name: \"Applications\", Path: \"/Applications\", IsDir: true, Size: -1},\n"
            "{Name: \"System Library\", Path: \"/Library\", IsDir: true, Size: -1},\n}\n"
        )
        (source_root / "cmd/analyze/cache.go").write_text(
            'return filepath.Join(home, ".cache", "mole")\nif mkErr := os.MkdirAll(dir, 0755); mkErr != nil {\n'
        )

        assets = {
            "analyze-darwin-arm64": b"analyze-binary",
            "status-darwin-arm64": b"status-binary",
            "binaries-darwin-arm64.tar.gz": b"bundle-archive",
            "SHA256SUMS": b"",
        }
        for name, payload in assets.items():
            (reference / "assets" / name).write_bytes(payload)

        sums = "\n".join(
            f"{self.module.sha256(reference / 'assets' / name)}  {name}"
            for name in ("analyze-darwin-arm64", "status-darwin-arm64", "binaries-darwin-arm64.tar.gz")
        )
        (reference / "assets/SHA256SUMS").write_text(sums + "\n")

        tar_path = reference / "source.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(source_root, arcname="tw93-Mole-1b9023b")

        with tarfile.open(tar_path, "r:gz") as archive:
            member_count = len(archive.getmembers())
        verification = {
            "source_commit": "1b9023b5f151c2d963bbcb9cb658f4824137b8aa",
            "source_archive_sha256": self.module.sha256(tar_path),
            "source_archive_member_count": member_count,
            "verified_assets": [],
            "programs_executed": False,
            "installation_performed": False,
        }
        (reference / "verification.json").write_text(json.dumps(verification))

        release = {
            "tag_name": "V1.53.0",
            "target_commitish": "main",
            "assets": [
                {
                    "name": name,
                    "digest": f"sha256:{self.module.sha256(reference / 'assets' / name)}",
                    "size": (reference / "assets" / name).stat().st_size,
                }
                for name in assets
            ],
        }
        (reference / "release.json").write_text(json.dumps(release))
        return reference

    def _write_manifest(self, reference: Path) -> Path:
        schedule = self.module.build_schedule(260026, 31)
        sayaka_bin = REPO / "target/release/sayaka"
        manifest = {
            "benchmark_id": "c0-b2-test",
            "reference_lock": {
                "tag": "V1.53.0",
                "source_commit": "1b9023b5f151c2d963bbcb9cb658f4824137b8aa",
                "target_commitish": "main",
                "source_archive_sha256": self.module.sha256(reference / "source.tar.gz"),
                "assets": {
                    name: {
                        "sha256": self.module.sha256(reference / "assets" / name),
                        "size_bytes": (reference / "assets" / name).stat().st_size,
                    }
                    for name in [
                        "analyze-darwin-arm64",
                        "status-darwin-arm64",
                        "binaries-darwin-arm64.tar.gz",
                        "SHA256SUMS",
                    ]
                },
            },
            "sayaka_reference": {
                "source_commit": "88d77f491e081a8958de20456e1c5fffc7314ac1",
                "binary_path": "target/release/sayaka",
                "binary_sha256": self.module.sha256(sayaka_bin),
                "rustc": "rustc 1.93.1",
                "cargo": "cargo 1.93.1",
                "product_source_diff_empty": True,
                "installation_measured": False,
                "competitive_runtime_measured": False,
            },
            "ordering": {"seed": 260026},
            "repetitions": {"paired_ab_ba": 31, "warmup_per_tool": 1},
            "scenario": {
                "scenario_id": "c0-b2-analyze-flat-regular-json-v1",
                "ab_mapping": {"A": "mole", "B": "sayaka"},
                "pair_schedule": schedule,
                "fixture_truth": {
                    "fixture_id": "c0-b2-flat-regular-v1",
                    "file_count": 1024,
                    "bytes_per_file": 4096,
                    "logical_bytes": 4194304,
                    "allocated_bytes_policy": "allocated_must_be_gte_logical_per_file",
                    "filename_prefix": "f",
                    "name_width": 6,
                    "filename_suffix": ".bin",
                    "payload_seed": 260026,
                },
            },
            "profile_classes": {},
            "archive_validation": {
                "max_member_count": 400,
                "max_member_size_bytes": 1024 * 1024,
                "reject_member_types": ["hardlink", "character", "block", "fifo"],
                "allowed_symlinks": [
                    {"path": ".agents/skills/bugs", "target": "../../.claude/skills/bugs"},
                    {"path": ".agents/skills/mole", "target": "../../.claude/skills/mole"},
                    {"path": ".agents/skills/release-flow", "target": "../../.claude/skills/release-flow"},
                    {"path": ".agents/skills/release-notes", "target": "../../.claude/skills/release-notes"},
                    {"path": "CLAUDE.md", "target": "AGENTS.md"},
                ],
            },
            "source_staging": {
                "canonical_helper_additions": ["bin/analyze-go", "bin/status-go"]
            },
            "source_helper_mapping": {
                "owned_executable_paths_for_phase_b_profile": [
                    {"path": "allowed/mole/source/install.sh", "role": "installer"},
                    {"path": "allowed/sayaka/source-binary/sayaka", "role": "sayaka_artifact"},
                    {"path": "allowed/sayaka/prefix/bin/sayaka", "role": "sayaka_installed"},
                ],
                "execution_policy": "single-policy",
            },
            "runtime_only_preflight_evidence": {
                "kernel_abort_reason": "x",
                "successful_minimal_fix": "y",
                "successful_probe_profile_sha256": "z",
                "evidence_label": "private",
            },
            "sandbox": {
                "runtime_read_literals": ["/", "/dev/null"],
                "runtime_read_allowlist": ["/bin", "/usr/bin", "/usr/lib", "/usr/share", "/System/Library"],
                "helper_exec_allowlist": [
                    {
                        "path": "/bin/bash",
                        "source_evidence": "install.sh:1-9",
                        "canary_command": ["/bin/bash", "--noprofile", "--norc", "-c", "exit 0"],
                    },
                    {
                        "path": "/usr/bin/env",
                        "source_evidence": "install.sh:1-9",
                        "canary_command": ["/usr/bin/env", "-i", "PATH=/bin:/usr/bin", "/usr/bin/true"],
                    },
                    {
                        "path": "/usr/bin/true",
                        "source_evidence": "install.sh:1-9",
                        "canary_command": ["/usr/bin/true"],
                    },
                ],
            },
            "source_audit": {
                "checks": [
                    {
                        "id": "audit-1",
                        "file": "install.sh",
                        "requirements": [{"snippet": "resolve_source_dir() {", "line_ranges": ["1-9"]}],
                    }
                ]
            },
            "canary_contract": {
                "required_ids": [
                    "allowed-rw",
                    "denied-read-owned-outside-allow",
                    "literal-root-runtime-only",
                    "denied-write-owned-outside-allow",
                    "denied-exec-readable-control",
                    "denied-network-loopback",
                ]
            },
            "canary_timeouts_seconds": {
                "allowed_rw": 10,
                "denied_read": 10,
                "denied_write": 10,
                "denied_exec": 10,
                "helper_each": 10,
                "network": 10,
                "sayaka_control_scan": 60,
            },
            "superseded_proofs": {
                "invalidated_profile_hashes": ["7cf711aa43bd56cdca5460cf0df6d5036d37728d26fe98797ce988fb40a33bfd"],
                "reason": "invalidated",
            },
            "phase_b_gate": {
                "must_not_execute_mole_before_authorization": True,
                "requires_independent_review": True,
                "requires_explicit_parent_message": True,
            },
            "phase_b": {"approved_profile_sha256": "TBD"},
        }
        path = self.test_workspace / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        return path

    def _write_schema(self) -> Path:
        schema = {
            "required_top_level_fields": [
                "benchmark_id",
                "phase",
                "status",
                "manifest_path",
                "manifest_sha256",
                "result_schema_sha256",
                "superseded_proofs",
                "reference_lock",
                "staged_source",
                "source_audit",
                "run_root",
                "profile",
                "source_helper_mapping",
                "fixture_truth_lock",
                "sayaka_staging",
                "sayaka_control_scan",
                "scenario",
                "canaries",
                "blocked_prerequisite",
                "phase_b_gate",
            ],
            "status_values": ["phase_a_ready", "blocked"],
            "canary_status_values": ["passed", "failed", "not_run"],
            "canary_classification_values": [
                "passed",
                "policy_denied",
                "permission_or_exec",
                "program_failed",
                "timeout",
                "not_found",
                "sandbox_runtime_abort",
                "not_run_precondition",
            ],
        }
        path = self.test_workspace / "schema.json"
        path.write_text(json.dumps(schema, indent=2) + "\n")
        return path

    def _run(self, manifest: Path, schema: Path, reference: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--verify",
                "--manifest",
                str(manifest),
                "--result-schema",
                str(schema),
                "--reference-root",
                str(reference),
                "--output",
                str(output),
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_private_probe_path_rejected(self) -> None:
        reference = self._write_reference()
        manifest = json.loads(self._write_manifest(reference).read_text())
        manifest["runtime_only_preflight_evidence"]["probe_result_path"] = "/Users/petr/.copilot/session-state/secret"
        manifest_path = self.test_workspace / "bad-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        schema = self._write_schema()
        output = REPO / "benchmarks/results/test-c0-b2-phase-a-private-path.json"
        completed = self._run(manifest_path, schema, reference, output)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("probe_result_path", completed.stderr)

    def test_archive_unexpected_symlink_rejected(self) -> None:
        reference = self._write_reference(extra_symlink=True)
        manifest = self._write_manifest(reference)
        schema = self._write_schema()
        output = REPO / "benchmarks/results/test-c0-b2-phase-a-extra-symlink.json"
        completed = self._run(manifest, schema, reference, output)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("allowed_symlinks", completed.stderr)

    def test_fixture_generation_contract(self) -> None:
        run_root = self.test_workspace / "run"
        run_root.mkdir(parents=True)
        layout = self.module.make_layout(run_root)
        spec = {
            "fixture_id": "c0-b2-flat-regular-v1",
            "file_count": 1024,
            "bytes_per_file": 4096,
            "logical_bytes": 4194304,
            "filename_prefix": "f",
            "name_width": 6,
            "filename_suffix": ".bin",
            "payload_seed": 260026,
        }
        truth = self.module.generate_flat_fixture(layout, spec)
        self.assertEqual(truth["file_count"], 1024)
        self.assertEqual(truth["logical_bytes"], 4194304)
        self.assertEqual(truth["entries"][0]["path"], "f000000.bin")
        self.assertEqual(truth["entries"][-1]["path"], "f001023.bin")

    def test_sayaka_normalizer_rejects_non_flat_entry(self) -> None:
        fixture_root = Path("/x/fixture")
        truth = {"entries": [{"path": "f000000.bin", "logical_bytes": 4096}], "file_count": 1}
        payload = {
            "schema_version": 1,
            "status": "complete",
            "complete": True,
            "roots": [{"encoding": "unix_bytes_hex", "raw": fixture_root.as_posix().encode().hex()}],
            "entries": [
                {"path": {"encoding": "unix_bytes_hex", "raw": fixture_root.as_posix().encode().hex()}, "kind": "directory", "depth": 0, "counted": False, "logical_bytes": None, "allocated_bytes": None, "dataless": False},
                {"path": {"encoding": "unix_bytes_hex", "raw": (fixture_root / "deep/a.bin").as_posix().encode().hex()}, "kind": "file", "depth": 2, "counted": True, "logical_bytes": 4096, "allocated_bytes": 4096, "dataless": False},
            ],
            "issues": [],
            "issues_omitted": 0,
            "totals": {"regular_files": 1, "unique_files": 1, "links": 0, "logical_bytes_known": 4096, "logical_bytes_unknown_files": 0, "allocated_bytes_unknown_files": 0},
        }
        with self.assertRaises(self.module.ValidationError):
            self.module.normalize_sayaka_scan_output(payload, fixture_root, truth)

    def test_profile_contains_system_volumes_data_metadata_literal(self) -> None:
        run_root = self.test_workspace / "run"
        run_root.mkdir(parents=True)
        layout = self.module.make_layout(run_root)
        manifest = json.loads(self._write_manifest(self._write_reference()).read_text())
        profile_path, _ = self.module.write_sandbox_profile(run_root, layout, manifest)
        profile_text = profile_path.read_text()
        self.assertIn('(literal "/System/Volumes/Data")', profile_text)
        self.assertNotIn('(subpath "/System/Volumes/Data/")', profile_text)

    def test_run_command_enforces_stream_cap(self) -> None:
        result = self.module.run_command(
            ["/usr/bin/python3", "-c", "import sys; sys.stdout.write('x'*2000000); sys.stdout.flush()"],
            env={"PATH": "/bin:/usr/bin"},
            cwd=self.test_workspace,
            timeout_seconds=5,
            max_output_bytes=1024,
        )
        self.assertEqual(result["status"], "output_cap_exceeded")
        self.assertGreater(result["stdout_bytes"], 1024)
        self.assertTrue(result["stdout_truncated"])

    def test_sayaka_control_scan_retains_private_raw(self) -> None:
        run_root = self.test_workspace / "run"
        run_root.mkdir(parents=True, exist_ok=True)
        layout = self.module.make_layout(run_root)
        fixture_root = layout["fixture_root"]
        fixture_root.mkdir(parents=True, exist_ok=True)
        (fixture_root / "f000000.bin").write_bytes(b"x" * 4096)
        truth = {
            "entries": [{"path": "f000000.bin", "logical_bytes": 4096}],
            "file_count": 1,
        }

        original = self.module.sandbox_run
        try:
            self.module.sandbox_run = lambda *args, **kwargs: {
                "status": "completed",
                "returncode": 1,
                "stdout": json.dumps({"status": "failed", "issues": [{"code": "volume_unknown"}]}),
                "stderr": f"{run_root}/private-error",
                "stdout_bytes": 64,
                "stderr_bytes": 32,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "pid": 12345,
            }
            result = self.module.run_sayaka_control_scan(
                Path("/x/profile.sb"),
                layout,
                fixture_root,
                truth,
                timeout_seconds=5,
                run_root=run_root,
            )
        finally:
            self.module.sandbox_run = original

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "sayaka_scan_reported_failure")
        self.assertIn("volume_unknown", result["failure_issue_codes"])
        self.assertIn("<run-root>", result["stderr"])
        self.assertEqual(result["_private_raw"]["pid"], 12345)
        self.assertIn("private-error", result["_private_raw"]["stderr"])


if __name__ == "__main__":
    unittest.main()
