#!/usr/bin/env python3
"""Import the pinned upstream package without replacing the web application.

The caller must run validation before publishing the resulting commit. This script
never installs upstream dependencies, executes upstream code, or pushes a branch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile


UPSTREAM_REPOSITORY = "https://github.com/khast3x/h8mail.git"
UPSTREAM_BRANCH = "master"
LOCK_NAME = "UPSTREAM.lock.json"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_IMPORT_BYTES = 25 * 1024 * 1024
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


class SyncError(RuntimeError):
    """A refused or failed import that must not be published."""


def run_git(root: Path, *arguments: str, timeout: int = 120) -> bytes:
    """Run Git without a shell; provider responses are never emitted on failure."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SyncError("Git is unavailable or timed out; retry the workflow.") from error
    if result.returncode:
        raise SyncError(f"Git {arguments[0]} failed; verify repository access and retry.")
    return result.stdout


def validate_managed_path(path: str) -> str:
    """Reject paths outside the package and paths unsafe on Windows or Linux."""
    if not isinstance(path, str) or not path or "\\" in path:
        raise SyncError("The upstream manifest contains an unsafe path.")
    parts = PurePosixPath(path).parts
    if path != "/".join(parts) or any(part in (".", "..") for part in parts):
        raise SyncError("The upstream manifest contains a non-canonical path.")
    if path != "LICENSE" and (len(parts) < 2 or parts[0] != "h8mail"):
        raise SyncError("The upstream manifest attempts to replace a web-owned path.")
    for part in parts:
        if (
            part.endswith((" ", "."))
            or part.casefold() == ".git"
            or any(ord(character) < 32 or ord(character) == 127 or character in '<>:"|?*' for character in part)
            or part.split(".")[0].upper() in RESERVED_NAMES
        ):
            raise SyncError("The upstream manifest contains a platform-unsafe path.")
    return path


def validate_manifest(paths: list[str]) -> None:
    if not isinstance(paths, list) or not paths:
        raise SyncError("The upstream manifest must contain managed files.")
    normalized = [validate_managed_path(path) for path in paths]
    if len({path.casefold() for path in normalized}) != len(normalized):
        raise SyncError("The upstream manifest contains duplicate or case-colliding paths.")
    if not {"LICENSE", "h8mail/__init__.py"}.issubset(normalized):
        raise SyncError("The upstream snapshot is missing its license or package initializer.")
    lowered = {path.casefold() for path in normalized}
    for path in normalized:
        if any(parent.as_posix().casefold() in lowered for parent in PurePosixPath(path).parents):
            raise SyncError("The upstream manifest contains a file/directory collision.")


def checked_destination(root: Path, path: str) -> Path:
    destination = root.joinpath(*PurePosixPath(path).parts)
    for candidate in (destination, *destination.parents):
        if candidate == root:
            break
        is_junction = getattr(candidate, "is_junction", lambda: False)
        if candidate.is_symlink() or is_junction():
            raise SyncError("Managed paths must not contain symbolic links or junctions.")
        if candidate != destination and candidate.exists() and not candidate.is_dir():
            raise SyncError("A managed parent path is not a directory.")
    try:
        destination.resolve().relative_to(root)
    except ValueError as error:
        raise SyncError("A managed destination escapes the repository.") from error
    if destination.exists() and not destination.is_file():
        raise SyncError("A managed file destination is not a regular file.")
    return destination


def license_hash(content: bytes) -> str:
    # Git's Windows checkout can change newlines without changing license terms.
    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


def read_lock(root: Path) -> dict:
    try:
        lock = json.loads(checked_destination(root, LOCK_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SyncError("UPSTREAM.lock.json is missing or invalid; restore the tracked baseline.") from error
    if (
        not isinstance(lock, dict)
        or type(lock.get("schema_version")) is not int
        or lock.get("schema_version") != 1
        or lock.get("repository") != UPSTREAM_REPOSITORY
        or lock.get("branch") != UPSTREAM_BRANCH
        or not isinstance(lock.get("commit"), str)
        or not COMMIT_PATTERN.fullmatch(lock["commit"])
        or not isinstance(lock.get("license_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", lock["license_sha256"])
    ):
        raise SyncError("UPSTREAM.lock.json does not describe the approved upstream baseline.")
    validate_manifest(lock.get("managed_paths"))
    return lock


def fetch_snapshot(root: Path, requested_commit: str | None) -> tuple[str, dict[str, bytes], dict[str, int]]:
    """Read only regular package blobs from a verified upstream commit."""
    if requested_commit is not None and not COMMIT_PATTERN.fullmatch(requested_commit):
        raise SyncError("--commit must be a complete lowercase 40-character Git SHA.")
    run_git(root, "fetch", "--no-tags", "--depth=1", UPSTREAM_REPOSITORY, requested_commit or UPSTREAM_BRANCH)
    commit = run_git(root, "rev-parse", "FETCH_HEAD^{commit}").decode("ascii").strip()
    if not COMMIT_PATTERN.fullmatch(commit) or requested_commit is not None and commit != requested_commit:
        raise SyncError("The fetched upstream commit does not match the requested snapshot.")
    tree = run_git(root, "ls-tree", "-rz", "--full-tree", commit)
    entries: dict[str, tuple[str, int]] = {}
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        try:
            path = raw_path.decode("utf-8")
        except UnicodeError as error:
            raise SyncError("The upstream snapshot contains a non-UTF-8 path.") from error
        if path != "LICENSE" and path != "h8mail" and not path.startswith("h8mail/"):
            continue
        validate_managed_path(path)
        mode, kind, object_id = metadata.decode("ascii").split()
        if mode not in ("100644", "100755") or kind != "blob" or not COMMIT_PATTERN.fullmatch(object_id):
            raise SyncError("The upstream package contains a symbolic link or non-regular file.")
        entries[path] = (object_id, int(mode, 8) & 0o777)
    validate_manifest(list(entries))
    snapshot: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    total_size = 0
    for path, (object_id, mode) in entries.items():
        size = int(run_git(root, "cat-file", "-s", object_id))
        total_size += size
        if size > MAX_FILE_BYTES or total_size > MAX_IMPORT_BYTES:
            raise SyncError("The upstream package exceeds safe import size limits; review it manually.")
        snapshot[path] = run_git(root, "cat-file", "blob", object_id)
        modes[path] = mode
    return commit, snapshot, modes


def atomic_write(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(destination.stat().st_mode) if destination.exists() else 0o644
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".upstream-", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
        temporary_path.chmod(mode)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def synchronize(root: Path, requested_commit: str | None = None) -> dict:
    """Apply a bounded import to a clean checkout, preserving every other path."""
    root = root.resolve()
    actual_root = Path(run_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    if root != actual_root:
        raise SyncError("--repository-root must be the Git repository root.")
    lock = read_lock(root)
    destinations = {path: checked_destination(root, path) for path in lock["managed_paths"]}
    if run_git(root, "status", "--porcelain", "--untracked-files=all", "--", "h8mail", "LICENSE", LOCK_NAME):
        raise SyncError("Managed upstream files have local changes; commit or restore them before syncing.")
    if license_hash(destinations["LICENSE"].read_bytes()) != lock["license_sha256"]:
        raise SyncError("The local license differs from the approved baseline; review it manually.")
    commit, snapshot, modes = fetch_snapshot(root, requested_commit)
    if license_hash(snapshot["LICENSE"]) != lock["license_sha256"]:
        raise SyncError("Upstream LICENSE changed; review and retain required notices before updating the lock.")
    destinations.update({path: checked_destination(root, path) for path in snapshot})
    if commit == lock["commit"]:
        return {"changed": False, "commit": commit}
    updated_lock = {**lock, "commit": commit, "managed_paths": sorted(snapshot)}
    updates: dict[str, bytes | None] = {
        path: snapshot.get(path) for path in sorted(set(lock["managed_paths"]) | set(snapshot))
    }
    updates[LOCK_NAME] = (json.dumps(updated_lock, indent=2) + "\n").encode("utf-8")
    destinations[LOCK_NAME] = checked_destination(root, LOCK_NAME)
    originals = {path: target.read_bytes() if target.exists() else None for path, target in destinations.items()}
    original_modes = {path: stat.S_IMODE(target.stat().st_mode) for path, target in destinations.items() if target.exists()}
    touched: list[str] = []
    try:
        for path, content in updates.items():
            destination = destinations[path]
            touched.append(path)
            if content is None:
                destination.unlink(missing_ok=True)
            else:
                previous = originals.get(path)
                if previous and b"\r\n" in previous and b"\r\n" not in content:
                    content = content.replace(b"\n", b"\r\n")
                atomic_write(destination, content)
                if path in modes:
                    destination.chmod(modes[path])
    except OSError as error:
        try:
            for path in reversed(touched):
                previous = originals.get(path)
                if previous is None:
                    destinations[path].unlink(missing_ok=True)
                else:
                    atomic_write(destinations[path], previous)
                    destinations[path].chmod(original_modes[path])
        except OSError as rollback_error:
            raise SyncError("Import and rollback failed; discard this isolated checkout and retry.") from rollback_error
        raise SyncError("The import failed and managed files were restored; retry in a fresh checkout.") from error
    return {"changed": True, "commit": commit}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--commit", help="Import this exact upstream SHA instead of the current master HEAD.")
    arguments = parser.parse_args()
    try:
        print(json.dumps(synchronize(arguments.repository_root, arguments.commit)))
    except (SyncError, OSError) as error:
        print(f"Upstream sync refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
