#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate the C0 Mole capability ledger schema and required concrete tasks."""

import argparse
import json
from pathlib import Path
import re
import sys


REPO = Path(__file__).resolve().parent.parent
LEDGER_PATH = REPO / "benchmarks/c0-mole-v1.53.0-ledger.json"

REQUIRED_FIELDS = [
    "family",
    "upstream_commit",
    "upstream_evidence",
    "tasks",
    "sayaka_coverage",
    "fixture_safety_state",
    "equivalence_rule",
    "measurement_status",
]

REQUIRED_CLEAN_TASKS = {
    "external-volume-target-cleanup",
    "system-deep-cleanup",
    "system-local-snapshots-cleanup",
    "user-essentials-cleanup",
    "finder-metadata-cleanup",
    "app-caches-cleanup",
    "browsers-cleanup",
    "cloud-office-cleanup",
    "developer-tools-cleanup",
    "apps-utilities-cleanup",
    "virtualization-cleanup",
    "application-support-logs-cleanup",
    "orphaned-app-data-cleanup",
    "orphaned-system-services-cleanup",
    "orphaned-container-stubs-cleanup",
    "apple-silicon-caches-cleanup",
    "cached-device-firmware-cleanup",
    "time-machine-failed-backups-cleanup",
    "large-file-candidates-review",
    "project-artifact-hints",
}

REQUIRED_OPTIMIZE_ACTIONS = {
    "system_maintenance",
    "cache_refresh",
    "saved_state_cleanup",
    "fix_broken_configs",
    "network_optimization",
    "sqlite_vacuum",
    "launch_services_rebuild",
    "prevent_network_dsstore",
    "legacy_overrides_audit",
    "network_stack_optimize",
    "disk_permissions_repair",
    "spotlight_index_optimize",
    "spotlight_orphan_rules_cleanup",
    "periodic_maintenance",
    "shared_file_list_repair",
    "disk_verify",
    "login_items_audit",
    "quarantine_cleanup",
    "launch_agents_cleanup",
    "notification_cleanup",
    "coreduet_cleanup",
}

EVIDENCE_WITH_LINE_RE = re.compile(r"^[^:]+:\d")


def has_line_scoped_evidence(evidence: list[str]) -> bool:
    return any(EVIDENCE_WITH_LINE_RE.match(item) for item in evidence)


def is_file_placeholder(item: str) -> bool:
    return ":" not in item and item.endswith((".sh", ".go", ".md", "Makefile", "mole", "mo"))


def validate_entry(index: int, entry: dict, source_commit: str) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in entry]
    if missing:
        raise AssertionError(f"entry[{index}] missing fields: {missing}")
    if entry["upstream_commit"] != source_commit:
        raise AssertionError(f"entry[{index}] uses unpinned commit")

    evidence = entry["upstream_evidence"]
    tasks = entry["tasks"]
    if not evidence or not tasks:
        raise AssertionError(f"entry[{index}] requires evidence and tasks")
    if not has_line_scoped_evidence(evidence):
        raise AssertionError(f"entry[{index}] must include line-scoped upstream evidence")
    if all(is_file_placeholder(item) for item in evidence):
        raise AssertionError(f"entry[{index}] has only file-level placeholder evidence")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.parse_args()

    ledger = json.loads(LEDGER_PATH.read_text())
    required_families = set(ledger["required_command_families"])
    entries = ledger["entries"]

    seen: set[str] = set()
    entries_by_family: dict[str, dict] = {}
    for index, entry in enumerate(entries):
        validate_entry(index, entry, ledger["source_commit"])
        family = entry["family"]
        if family in seen:
            raise AssertionError(f"duplicate family entry: {family}")
        seen.add(family)
        entries_by_family[family] = entry

    missing_families = sorted(required_families - seen)
    if missing_families:
        raise AssertionError(f"missing required command families: {missing_families}")

    clean_tasks = set(entries_by_family["clean"]["tasks"])
    missing_clean_tasks = sorted(REQUIRED_CLEAN_TASKS - clean_tasks)
    if missing_clean_tasks:
        raise AssertionError(f"missing concrete clean tasks: {missing_clean_tasks}")

    optimize_tasks = set(entries_by_family["optimize"]["tasks"])
    missing_optimize_tasks = sorted(REQUIRED_OPTIMIZE_ACTIONS - optimize_tasks)
    if missing_optimize_tasks:
        raise AssertionError(f"missing optimize catalog actions: {missing_optimize_tasks}")

    result = {
        "benchmark_id": ledger["benchmark_id"],
        "source_commit": ledger["source_commit"],
        "required_families": sorted(required_families),
        "entry_count": len(entries),
        "clean_task_count": len(clean_tasks),
        "optimize_action_count": len(optimize_tasks),
        "status": "verified",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
