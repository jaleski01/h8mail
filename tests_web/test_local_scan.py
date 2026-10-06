"""Exercise real local streams and process workers using synthetic datasets."""

import gzip
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from web_adapter.local_scan import LocalScanError, MAX_LINE_BYTES, scan_files


class LocalScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def source(self, name="synthetic.txt", content=b"analyst@example.test:synthetic-secret\nother@example.test:other-secret\n"):
        path = self.directory / name
        path.write_bytes(content)
        return path

    def test_text_stream_preserves_case_sensitive_loose_substring_matching(self):
        path = self.source()
        found = scan_files([path], ["analyst", "analyst@example.test", "Analyst"], single_file=True)
        self.assertEqual([entry.target for entry in found], ["analyst", "analyst@example.test"])
        self.assertTrue(all(entry.line == 0 for entry in found))
        self.assertTrue(all("synthetic-secret" in entry.content for entry in found))
        self.assertTrue(all(entry.filepath == str(path) for entry in found))

    def test_plain_gzip_stream_is_read_without_str_decode_errors(self):
        path = self.directory / "synthetic.gz"
        with gzip.open(path, "wb") as stream:
            stream.write(b"analyst@example.test:synthetic-secret\n")
        found = scan_files([path], ["analyst@example.test"], gzip_mode=True, single_file=True)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].content, "analyst@example.test:synthetic-secret\n")

    def test_tar_gzip_members_are_scanned_without_extracting_to_disk(self):
        path = self.directory / "synthetic.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, content in (("nested/first.txt", b"other@example.test:other-secret\n"),
                                  ("../../second.txt", b"analyst@example.test:synthetic-secret\n")):
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        found = scan_files([path], ["analyst@example.test"], gzip_mode=True, single_file=True)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].filepath.endswith("!../../second.txt"))
        self.assertEqual(list(self.directory.iterdir()), [path])

    def test_parallel_workers_preserve_all_file_matches(self):
        first = self.source("first.txt")
        second = self.source("second.txt", b"analyst@example.test:second-secret\n")
        found = scan_files([first, second], ["analyst@example.test"])
        self.assertEqual(len(found), 2)
        self.assertEqual({entry.filepath for entry in found}, {str(first), str(second)})

    def test_missing_or_corrupt_source_fails_instead_of_becoming_empty(self):
        invalid = self.source("corrupt.gz", b"not-a-gzip-file")
        for files, compressed, single in (([self.directory / "missing.txt"], False, True),
                                           ([self.directory / "missing.txt"], False, False),
                                           ([invalid], True, True)):
            with self.subTest(single=single, compressed=compressed), self.assertRaises(LocalScanError):
                scan_files(files, ["analyst@example.test"], gzip_mode=compressed, single_file=single)

    def test_line_and_result_bounds_fail_explicitly(self):
        oversized = self.source("oversized.txt", b"x" * (MAX_LINE_BYTES + 1))
        with self.assertRaises(LocalScanError):
            scan_files([oversized], ["analyst"], single_file=True)
        matches = self.source("matches.txt", b"analyst\nanalyst\n")
        with patch("web_adapter.local_scan.MAX_RESULTS", 1), self.assertRaises(LocalScanError):
            scan_files([matches], ["analyst"], single_file=True)

    def test_global_result_budget_is_enforced_across_files(self):
        first = self.source("first.txt", b"analyst\n")
        second = self.source("second.txt", b"analyst\n")
        with patch("web_adapter.local_scan.MAX_RESULTS", 1), self.assertRaises(LocalScanError):
            scan_files([first, second], ["analyst"], single_file=True)

    def test_empty_files_and_no_matches_are_confirmed_empty(self):
        empty = self.source("empty.txt", b"")
        unmatched = self.source("unmatched.txt", b"other@example.test:synthetic-secret\n")
        self.assertEqual(scan_files([empty, unmatched], ["analyst"], single_file=True), [])


if __name__ == "__main__":
    unittest.main()
