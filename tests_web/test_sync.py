"""Offline regression tests for the bounded upstream import."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sync_upstream.py"
SPECIFICATION = importlib.util.spec_from_file_location("sync_upstream", SCRIPT_PATH)
sync = importlib.util.module_from_spec(SPECIFICATION)
SPECIFICATION.loader.exec_module(sync)


def git(root, *arguments, content=None):
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=content,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


class UpstreamSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream"
        self.application = self.base / "application"
        for root in (self.upstream, self.application):
            root.mkdir()
            git(root, "init", "-q")
            git(root, "config", "user.name", "Offline test")
            git(root, "config", "user.email", "test@example.invalid")
            git(root, "config", "core.autocrlf", "false")
            (root / "h8mail").mkdir()
            (root / "h8mail" / "__init__.py").write_text('VERSION = "original"\n', encoding="utf-8")
            (root / "h8mail" / "obsolete.py").write_text("OBSOLETE = True\n", encoding="utf-8")
            (root / "LICENSE").write_text("Original license notice\n", encoding="utf-8")
        self.original_commit = self.commit(self.upstream)
        (self.application / "web").mkdir()
        (self.application / "web" / "app.js").write_text("keep web\n", encoding="utf-8")
        (self.application / "requirements.txt").write_text("keep dependencies\n", encoding="utf-8")
        self.lock = {
            "schema_version": 1,
            "repository": str(self.upstream),
            "branch": "master",
            "commit": self.original_commit,
            "license_sha256": hashlib.sha256(b"Original license notice\n").hexdigest(),
            "managed_paths": ["LICENSE", "h8mail/__init__.py", "h8mail/obsolete.py"],
        }
        self.write_lock()
        self.commit(self.application)
        self.repository_patch = patch.object(sync, "UPSTREAM_REPOSITORY", str(self.upstream))
        self.repository_patch.start()
        self.addCleanup(self.repository_patch.stop)

    def write_lock(self):
        (self.application / sync.LOCK_NAME).write_text(json.dumps(self.lock) + "\n", encoding="utf-8")

    @staticmethod
    def commit(root):
        git(root, "add", ".")
        git(root, "commit", "-qm", "Offline fixture")
        return git(root, "rev-parse", "HEAD").decode("ascii").strip()

    def update_upstream(self):
        (self.upstream / "h8mail" / "__init__.py").write_text('VERSION = "updated"\n', encoding="utf-8")
        return self.commit(self.upstream)

    def test_import_preserves_web_and_removes_deleted_upstream_files(self):
        (self.upstream / "h8mail" / "obsolete.py").unlink()
        (self.upstream / "h8mail" / "new.py").write_text("NEW = True\n", encoding="utf-8")
        (self.upstream / "requirements.txt").write_text("untrusted dependencies\n", encoding="utf-8")
        (self.upstream / "web").mkdir()
        (self.upstream / "web" / "app.js").write_text("replace web\n", encoding="utf-8")
        (self.upstream / ".github" / "workflows").mkdir(parents=True)
        (self.upstream / ".github" / "workflows" / "untrusted.yml").write_text("replace workflow\n", encoding="utf-8")
        commit = self.update_upstream()

        result = sync.synchronize(self.application, commit)

        self.assertEqual(result, {"changed": True, "commit": commit})
        self.assertFalse((self.application / "h8mail" / "obsolete.py").exists())
        self.assertEqual((self.application / "h8mail" / "new.py").read_text(), "NEW = True\n")
        self.assertEqual((self.application / "web" / "app.js").read_text(), "keep web\n")
        self.assertEqual((self.application / "requirements.txt").read_text(), "keep dependencies\n")
        self.assertFalse((self.application / ".github").exists())
        updated_lock = json.loads((self.application / sync.LOCK_NAME).read_text())
        self.assertNotIn("h8mail/obsolete.py", updated_lock["managed_paths"])
        self.assertIn("h8mail/new.py", updated_lock["managed_paths"])

    def test_same_commit_is_a_noop(self):
        result = sync.synchronize(self.application, self.original_commit)
        self.assertEqual(result, {"changed": False, "commit": self.original_commit})
        self.assertEqual(git(self.application, "status", "--porcelain"), b"")

    def test_invalid_commit_cannot_be_used_as_a_git_option(self):
        with self.assertRaisesRegex(sync.SyncError, "complete lowercase"):
            sync.synchronize(self.application, "--upload-pack=malicious")
        self.assertEqual(git(self.application, "status", "--porcelain"), b"")

    def test_license_changes_require_manual_review(self):
        (self.upstream / "LICENSE").write_text("Removed original notice\n", encoding="utf-8")
        commit = self.update_upstream()
        with self.assertRaisesRegex(sync.SyncError, "LICENSE changed"):
            sync.synchronize(self.application, commit)
        self.assertEqual(git(self.application, "status", "--porcelain"), b"")

    def test_dirty_managed_files_are_never_overwritten(self):
        (self.application / "h8mail" / "__init__.py").write_text("LOCAL = True\n", encoding="utf-8")
        with self.assertRaisesRegex(sync.SyncError, "local changes"):
            sync.synchronize(self.application, self.update_upstream())
        self.assertEqual((self.application / "h8mail" / "__init__.py").read_text(), "LOCAL = True\n")

    def test_lock_cannot_delete_web_owned_files(self):
        self.lock["managed_paths"].append("web/app.js")
        self.write_lock()
        with self.assertRaisesRegex(sync.SyncError, "web-owned"):
            sync.synchronize(self.application, self.original_commit)
        self.assertEqual((self.application / "web" / "app.js").read_text(), "keep web\n")

    def test_upstream_symlink_blobs_are_rejected_before_any_writes(self):
        object_id = git(self.upstream, "hash-object", "-w", "--stdin", content=b"../../web/app.js").decode().strip()
        git(self.upstream, "update-index", "--add", "--cacheinfo", f"120000,{object_id},h8mail/link.py")
        git(self.upstream, "commit", "-qm", "Untrusted symlink fixture")
        commit = git(self.upstream, "rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(sync.SyncError, "symbolic link"):
            sync.synchronize(self.application, commit)
        self.assertEqual(git(self.application, "status", "--porcelain"), b"")

    def test_destination_symlinks_cannot_escape_the_checkout(self):
        destination = self.application / "h8mail" / "__init__.py"
        destination.unlink()
        outside = self.base / "outside.py"
        outside.write_text("PRIVATE = True\n", encoding="utf-8")
        try:
            destination.symlink_to(outside)
        except OSError:
            self.skipTest("This account cannot create Windows symbolic links.")
        with self.assertRaisesRegex(sync.SyncError, "symbolic links"):
            sync.synchronize(self.application, self.original_commit)
        self.assertEqual(outside.read_text(), "PRIVATE = True\n")

    def test_size_limits_refuse_oversized_snapshots(self):
        with patch.object(sync, "MAX_FILE_BYTES", 8):
            with self.assertRaisesRegex(sync.SyncError, "size limits"):
                sync.synchronize(self.application, self.update_upstream())
        self.assertEqual(git(self.application, "status", "--porcelain"), b"")

    @unittest.skipIf(os.name == "nt", "Git executable bits are not represented by Windows file modes.")
    def test_import_preserves_upstream_executable_file_modes(self):
        executable = self.upstream / "h8mail" / "utility.py"
        executable.write_text("print('utility')\n", encoding="utf-8")
        executable.chmod(0o755)
        commit = self.update_upstream()
        sync.synchronize(self.application, commit)
        self.assertEqual((self.application / "h8mail" / "utility.py").stat().st_mode & 0o777, 0o755)

    def test_partial_file_write_failure_restores_the_baseline(self):
        commit = self.update_upstream()
        original_write = sync.atomic_write
        calls = 0

        def failing_write(destination, content):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("Simulated disk failure")
            original_write(destination, content)

        with patch.object(sync, "atomic_write", side_effect=failing_write):
            with self.assertRaisesRegex(sync.SyncError, "were restored"):
                sync.synchronize(self.application, commit)
        self.assertEqual(git(self.application, "status", "--porcelain"), b"")

    def test_manifest_rejects_nonportable_paths_and_case_collisions(self):
        paths = [
            "../web/app.js", "h8mail/../../web/app.js", "h8mail//module.py",
            "h8mail/./module.py", "h8mail\\module.py", "h8mail/NUL.py",
            "h8mail/file.py.", "h8mail/module:stream.py", "/h8mail/module.py",
            "h8mail/.git/config", "h8mail/.GIT/config", "h8mail/module\x7f.py",
        ]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(sync.SyncError):
                sync.validate_managed_path(path)
        with self.assertRaisesRegex(sync.SyncError, "case-colliding"):
            sync.validate_manifest(["LICENSE", "h8mail/__init__.py", "h8mail/New.py", "h8mail/new.py"])
        with self.assertRaisesRegex(sync.SyncError, "file/directory collision"):
            sync.validate_manifest(["LICENSE", "h8mail/__init__.py", "h8mail/folder", "h8mail/folder/file.py"])


if __name__ == "__main__":
    unittest.main()
