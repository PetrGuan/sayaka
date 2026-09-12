#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Create/verify C0 synthetic fixtures with independent ground truth."""

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


REPO = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO / "benchmarks/c0-fixtures-v1.json"

REQUIRED_FIXTURE_IDS = {
    "scan-readonly-basic-v1",
    "scan-sparse-links-v1",
    "scan-denied-subtree-v1",
    "scan-overlapping-roots-v1",
    "scan-churn-replacement-v1",
    "history-lifecycle-v1",
    "install-owned-prefix-v1",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def digest_bytes(content: bytes) -> str:
    value = hashlib.sha256()
    value.update(content)
    return value.hexdigest()


def ensure_repo_relative(path: Path, root: Path) -> None:
    path.resolve().relative_to(root.resolve())


def path_identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    return (info.st_dev, info.st_ino)


def capture_identity_chain(path: Path, stop_at: Path) -> dict[Path, tuple[int, int]]:
    chain: dict[Path, tuple[int, int]] = {}
    current = path
    stop_resolved = stop_at.resolve()
    while True:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise AssertionError(f"refusing path with symlink ancestor: {current}")
        if not stat.S_ISDIR(info.st_mode):
            raise AssertionError(f"refusing non-directory ancestor in fixture path: {current}")
        chain[current] = (info.st_dev, info.st_ino)
        if current.resolve() == stop_resolved:
            break
        if current == current.parent:
            raise AssertionError(f"stop_at {stop_at} is not an ancestor of {path}")
        current = current.parent
    return chain


def assert_identity_chain(chain: dict[Path, tuple[int, int]]) -> None:
    for path, expected_identity in chain.items():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise AssertionError(f"refusing symlink path during cleanup: {path}")
        if not stat.S_ISDIR(info.st_mode):
            raise AssertionError(f"refusing non-directory path during cleanup: {path}")
        if (info.st_dev, info.st_ino) != expected_identity:
            raise AssertionError(f"refusing replaced path during cleanup: {path}")


def create_run_root(fixture_parent: Path, repo_root: Path) -> tuple[Path, dict[Path, tuple[int, int]], tuple[int, int]]:
    ensure_repo_relative(fixture_parent, repo_root)
    fixture_parent.mkdir(parents=True, exist_ok=True)
    parent_chain = capture_identity_chain(fixture_parent, repo_root)
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=fixture_parent))
    run_info = run_root.lstat()
    if stat.S_ISLNK(run_info.st_mode) or not stat.S_ISDIR(run_info.st_mode):
        raise AssertionError(f"invalid run root created: {run_root}")
    chain = dict(parent_chain)
    chain[run_root] = (run_info.st_dev, run_info.st_ino)
    return run_root, chain, (run_info.st_dev, run_info.st_ino)


def remove_owned_tree(root: Path, marker_name: str, marker_value: bytes) -> None:
    marker = root / marker_name
    if not root.exists():
        return
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode):
        raise AssertionError(f"refusing cleanup of symlink root: {root}")
    if not stat.S_ISDIR(root_info.st_mode):
        raise AssertionError(f"refusing cleanup of non-directory root: {root}")
    marker_info = marker.lstat() if marker.exists() else None
    if marker_info is None or stat.S_ISLNK(marker_info.st_mode) or not marker.is_file() or marker.read_bytes() != marker_value:
        raise AssertionError(f"refusing cleanup: missing ownership marker at {marker}")
    root_identity = path_identity(root)

    os.chmod(root, 0o700)
    for parent, directories, _files in os.walk(root, topdown=True, followlinks=False):
        parent_path = Path(parent)
        parent_info = parent_path.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise AssertionError(f"refusing cleanup walk on non-directory parent: {parent_path}")
        if parent_info.st_uid != os.getuid() or parent_info.st_dev != root_identity[0]:
            raise AssertionError(f"refusing cleanup walk on non-owned parent: {parent_path}")
        for name in directories:
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                os.chmod(path, 0o700)

    entries: list[Path] = []
    for parent, directories, files in os.walk(root, topdown=True, followlinks=False):
        for name in directories + files:
            entries.append(Path(parent) / name)

    for path in sorted(entries, key=lambda item: len(item.parts), reverse=True):
        info = path.lstat()
        if info.st_uid != os.getuid() or info.st_dev != root_identity[0]:
            raise AssertionError(f"refusing cleanup of non-owned entry: {path}")
        if stat.S_ISDIR(info.st_mode):
            path.rmdir()
        else:
            path.unlink()
    root.rmdir()


def write_bytes(target: Path, byte_count: int, fill_byte: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = bytes([fill_byte % 251]) * byte_count
    target.write_bytes(payload)


def materialize_fixture(fixture_root: Path, fixture: dict) -> None:
    layout = fixture["layout"]
    for directory in layout.get("directories", []):
        (fixture_root / directory).mkdir(parents=True, exist_ok=False)

    for file_spec in layout.get("files", []):
        fill = int(file_spec.get("fill_byte", len(file_spec["path"])))
        write_bytes(fixture_root / file_spec["path"], int(file_spec["bytes"]), fill)

    for sparse_spec in layout.get("sparse_files", []):
        target = fixture_root / sparse_spec["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        logical = int(sparse_spec["logical_bytes"])
        fill = int(sparse_spec.get("fill_byte", len(sparse_spec["path"]))) % 251
        with target.open("wb") as handle:
            if logical <= 0:
                raise AssertionError(f"sparse logical_bytes must be > 0 for {target}")
            handle.seek(logical - 1)
            handle.write(bytes([fill]))

    for text_file in layout.get("text_files", []):
        target = fixture_root / text_file["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(text_file["lines"]) + "\n")

    for hard_link in layout.get("hard_links", []):
        os.link(fixture_root / hard_link["source"], fixture_root / hard_link["link"])

    for symlink in layout.get("symlinks", []):
        (fixture_root / symlink["path"]).symlink_to(symlink["target"])

    for chmod_spec in layout.get("chmod", []):
        os.chmod(fixture_root / chmod_spec["path"], int(chmod_spec["mode"], 8))


def collect_scan_truth(fixture_root: Path, scan_path: str, track_unreadable: bool = False) -> dict:
    start = fixture_root / scan_path
    logical_bytes = 0
    allocated_bytes = 0
    file_entries = 0
    sparse_files = 0
    unique = set()
    symlink_entries = 0
    unreadable_directories = 0

    def onerror(error: OSError) -> None:
        nonlocal unreadable_directories
        if track_unreadable and error.errno in (errno.EACCES, errno.EPERM):
            unreadable_directories += 1
            return
        raise error

    for parent, directories, files in os.walk(start, followlinks=False, onerror=onerror):
        for name in files:
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                symlink_entries += 1
                continue
            file_entries += 1
            logical_bytes += info.st_size
            allocated = info.st_blocks * 512
            allocated_bytes += allocated
            if allocated < info.st_size:
                sparse_files += 1
            unique.add((info.st_dev, info.st_ino))
        for name in directories:
            path = Path(parent) / name
            if path.is_symlink():
                symlink_entries += 1

    unique_files = len(unique)
    return {
        "file_entries": file_entries,
        "unique_files": unique_files,
        "logical_bytes": logical_bytes,
        "allocated_bytes": allocated_bytes,
        "hard_link_aliases": file_entries - unique_files,
        "symlink_entries": symlink_entries,
        "sparse_files": sparse_files,
        "unreadable_directories": unreadable_directories,
        "unknown_entries": unreadable_directories,
    }


def assert_expected_values(actual: dict, expected: dict, context: str) -> None:
    for key, value in expected.items():
        if key.endswith("_at_least"):
            actual_key = key[: -len("_at_least")]
            if actual[actual_key] < value:
                raise AssertionError(f"{context} expected {actual_key} >= {value}, got {actual[actual_key]}")
        elif key.endswith("_at_most"):
            actual_key = key[: -len("_at_most")]
            if actual[actual_key] > value:
                raise AssertionError(f"{context} expected {actual_key} <= {value}, got {actual[actual_key]}")
        elif key == "allocated_bytes_less_than_logical":
            if value and not (actual["allocated_bytes"] < actual["logical_bytes"]):
                raise AssertionError(f"{context} expected allocated_bytes < logical_bytes")
        elif key == "expected_refusal":
            if value == "permission_denied" and actual["unreadable_directories"] <= 0:
                raise AssertionError(f"{context} expected permission denied unreadable directories")
        elif key == "expected_refusal_unknown_entries":
            if value and actual.get("unknown_regular_files", 0) <= 0:
                raise AssertionError(f"{context} expected unknown regular files for refusal checks")
        elif isinstance(value, (str, list, dict, bool)):
            if actual.get(key) != value:
                raise AssertionError(f"{context} expected {key}={value!r}, got {actual.get(key)!r}")
        else:
            if actual.get(key) != value:
                raise AssertionError(f"{context} expected {key}={value}, got {actual.get(key)}")


def collect_overlapping_truth(fixture_root: Path, fixture: dict) -> dict:
    scope_results = []
    scope_unique_sets = []

    for scope in fixture["truth"]["root_scopes"]:
        summary = collect_scan_truth(fixture_root, scope["path"])
        summary_with_id = {
            "id": scope["id"],
            "path": scope["path"],
            "file_entries": summary["file_entries"],
            "unique_files": summary["unique_files"],
            "logical_bytes": summary["logical_bytes"],
        }
        scope_results.append(summary_with_id)

        start = fixture_root / scope["path"]
        unique_set = set()
        for parent, _directories, files in os.walk(start, followlinks=False):
            for name in files:
                path = Path(parent) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                unique_set.add((info.st_dev, info.st_ino))
        scope_unique_sets.append(unique_set)

    union_unique_files = len(set().union(*scope_unique_sets))
    overlap_unique_files = len(set.intersection(*scope_unique_sets)) if scope_unique_sets else 0

    return {
        "root_scopes": scope_results,
        "union_unique_files": union_unique_files,
        "overlap_unique_files": overlap_unique_files,
    }


def collect_churn_truth(fixture_root: Path, fixture: dict) -> dict:
    before = collect_scan_truth(fixture_root, "root")
    replacement_results = []

    for replacement in fixture["churn"]["replacements"]:
        path = fixture_root / replacement["path"]
        before_info = path.lstat()
        before_hash = digest(path)

        replacement_tmp = path.with_suffix(path.suffix + ".replacement")
        write_bytes(replacement_tmp, int(replacement["bytes"]), int(replacement.get("fill_byte", 37)))
        os.replace(replacement_tmp, path)

        after_info = path.lstat()
        after_hash = digest(path)

        replacement_results.append({
            "path": replacement["path"],
            "inode_changed": (before_info.st_dev, before_info.st_ino) != (after_info.st_dev, after_info.st_ino),
            "sha256_changed": before_hash != after_hash,
            "size_before": before_info.st_size,
            "size_after": after_info.st_size,
        })

    after = collect_scan_truth(fixture_root, "root")
    return {
        "before": {
            "file_entries": before["file_entries"],
            "unique_files": before["unique_files"],
            "logical_bytes": before["logical_bytes"],
        },
        "after": {
            "file_entries": after["file_entries"],
            "unique_files": after["unique_files"],
            "logical_bytes": after["logical_bytes"],
        },
        "replacements": replacement_results,
    }


def collect_history_truth(fixture_root: Path) -> dict:
    operations = fixture_root / "root/history/operations.jsonl"
    disabled_marker = fixture_root / "root/history/logging-disabled.flag"

    counts = {
        "complete": 0,
        "failed": 0,
        "partial": 0,
        "pending": 0,
        "corrupt": 0,
        "disabled_markers": 1 if disabled_marker.is_file() else 0,
    }

    for raw_line in operations.read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            counts["corrupt"] += 1
            continue
        status_name = payload.get("status")
        if status_name in counts:
            counts[status_name] += 1
        else:
            counts["corrupt"] += 1

    return counts


def collect_install_prefix_truth(fixture_root: Path, fixture: dict) -> dict:
    tracked = set(fixture["truth"]["tracked_paths"])
    regular_files = []

    for parent, _directories, files in os.walk(fixture_root / "root/prefix", followlinks=False):
        for name in files:
            path = Path(parent) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            regular_files.append(str(path.relative_to(fixture_root)))

    unknown = sorted(path for path in regular_files if path not in tracked)
    return {
        "tracked_paths": sorted(tracked),
        "tracked_regular_files": len([p for p in regular_files if p in tracked]),
        "unknown_regular_files": len(unknown),
        "unknown_paths": unknown,
    }


def verify_fixture(fixture_root: Path, fixture: dict) -> dict:
    fixture_class = fixture["class"]
    expected = fixture["truth"]

    if fixture_class == "scan-readonly":
        actual = collect_scan_truth(fixture_root, "root")
        assert_expected_values(actual, expected, fixture["id"])
        return {
            "fixture_id": fixture["id"],
            "class": fixture_class,
            "truth": {k: actual[k] for k in (
                "file_entries",
                "unique_files",
                "logical_bytes",
                "allocated_bytes",
                "hard_link_aliases",
                "symlink_entries",
                "sparse_files",
            )},
            "status": "verified",
        }

    if fixture_class == "scan-denied-subtree":
        actual = collect_scan_truth(fixture_root, "root", track_unreadable=True)
        assert_expected_values(actual, expected, fixture["id"])
        return {
            "fixture_id": fixture["id"],
            "class": fixture_class,
            "truth": {k: actual[k] for k in (
                "file_entries",
                "unique_files",
                "logical_bytes",
                "allocated_bytes",
                "unreadable_directories",
                "unknown_entries",
            )},
            "status": "verified",
        }

    if fixture_class == "scan-overlapping-roots":
        actual = collect_overlapping_truth(fixture_root, fixture)
        assert_expected_values(actual, expected, fixture["id"])
        return {
            "fixture_id": fixture["id"],
            "class": fixture_class,
            "truth": actual,
            "status": "verified",
        }

    if fixture_class == "scan-controlled-churn":
        actual = collect_churn_truth(fixture_root, fixture)
        assert_expected_values(actual, expected, fixture["id"])
        return {
            "fixture_id": fixture["id"],
            "class": fixture_class,
            "truth": actual,
            "status": "verified",
        }

    if fixture_class == "history-lifecycle":
        actual = collect_history_truth(fixture_root)
        assert_expected_values(actual, expected, fixture["id"])
        return {
            "fixture_id": fixture["id"],
            "class": fixture_class,
            "truth": actual,
            "status": "verified",
        }

    if fixture_class == "install-owned-prefix":
        actual = collect_install_prefix_truth(fixture_root, fixture)
        assert_expected_values(actual, expected, fixture["id"])
        return {
            "fixture_id": fixture["id"],
            "class": fixture_class,
            "truth": {
                "tracked_regular_files": actual["tracked_regular_files"],
                "unknown_regular_files": actual["unknown_regular_files"],
                "unknown_paths": actual["unknown_paths"],
            },
            "status": "verified",
        }

    raise AssertionError(f"unsupported fixture class: {fixture_class}")


def verify_manifest_requirements(manifest: dict) -> None:
    fixture_ids = [fixture["id"] for fixture in manifest["fixtures"]]
    if len(set(fixture_ids)) != len(fixture_ids):
        raise AssertionError("fixture IDs must be unique")
    if set(manifest.get("required_fixture_ids", [])) != REQUIRED_FIXTURE_IDS:
        raise AssertionError("required_fixture_ids does not match expected C0 minimum set")

    missing_ids = sorted(REQUIRED_FIXTURE_IDS - set(fixture_ids))
    if missing_ids:
        raise AssertionError(f"missing required fixtures: {missing_ids}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text())
    verify_manifest_requirements(manifest)

    fixture_parent = REPO / manifest["fixture_root"]
    marker_name = manifest["ownership_marker"]
    marker_value = b"sayaka-c0-owned-fixtures"
    run_root, identity_chain, _run_identity = create_run_root(fixture_parent, REPO)

    results = []
    try:
        for fixture in manifest["fixtures"]:
            assert_identity_chain(identity_chain)
            owned = run_root / fixture["id"]
            if owned.exists():
                raise AssertionError(f"refusing to reuse existing fixture root: {owned}")
            owned.mkdir(mode=0o700)
            (owned / marker_name).write_bytes(marker_value)
            try:
                materialize_fixture(owned, fixture)
                verified = verify_fixture(owned, fixture)
                verified["marker_sha256"] = digest_bytes(marker_value)
                results.append(verified)
            finally:
                for chmod_spec in fixture.get("layout", {}).get("chmod", []):
                    target = owned / chmod_spec["path"]
                    if target.exists() or target.is_symlink():
                        os.chmod(target, 0o700)
                remove_owned_tree(owned, marker_name, marker_value)
    finally:
        assert_identity_chain(identity_chain)
        run_marker = run_root / marker_name
        if run_root.exists():
            run_marker.write_bytes(marker_value)
            remove_owned_tree(run_root, marker_name, marker_value)

    print(
        json.dumps(
            {
                "benchmark_id": manifest["benchmark_id"],
                "manifest_sha256": digest(MANIFEST_PATH),
                "fixture_count": len(results),
                "fixtures": results,
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
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
