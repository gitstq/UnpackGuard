# -*- coding: utf-8 -*-
"""Tests for the archive readers (ZIP, TAR family, nested detection)."""

from __future__ import annotations

import os
import tarfile
import tempfile
import unittest
import warnings
import zipfile

from unpackguard.model import Member
from unpackguard.reader import (
    SUPPORTED_READERS,
    SUPPORTED_EXTRACTORS,
    ReaderError,
    iter_nested,
    open_archive,
)

from .fixtures import (
    write_nested_chain,
    write_tar_gz,
    write_tar_simple,
    write_tar_sneaky,
    write_zip_bomb,
    write_zip_legacy_names,
    write_zip_mixed_attacks,
    write_zip_simple,
    write_zip_traversal,
)

warnings.filterwarnings("ignore", message="Duplicate name")


class ZipReaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_simple_archive(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        self.assertEqual(archive.fmt, "zip")
        self.assertEqual(archive.file_count, 4)
        self.assertTrue(any(m.is_dir for m in archive.members))
        self.assertGreater(archive.total_size, 0)

    def test_sizes_are_sane(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        for member in archive.members:
            self.assertGreaterEqual(member.size, 0)
            self.assertGreaterEqual(member.compressed_size, 0)

    def test_legacy_names_recover_encoding(self) -> None:
        archive = open_archive(write_zip_legacy_names(self.tmp.name), "zip")
        names = {m.name for m in archive.members}
        self.assertIn("中文合同.txt", names)
        self.assertIn("報告-2026.pdf", names)
        self.assertIn("plain.txt", names)

    def test_bomb_ratio_is_measured(self) -> None:
        archive = open_archive(write_zip_bomb(self.tmp.name), "zip")
        bomb = archive.members[0]
        self.assertGreater(bomb.ratio, 100)

    def test_duplicate_names_are_all_reported(self) -> None:
        archive = open_archive(write_zip_mixed_attacks(self.tmp.name), "zip")
        dupes = [m.name for m in archive.members if m.name == "twice.txt"]
        self.assertEqual(len(dupes), 2)

    def test_nested_detection(self) -> None:
        archive = open_archive(write_nested_chain(self.tmp.name), "zip")
        nested = list(iter_nested(archive))
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0].inner_format, "zip")

    def test_no_probe_skips_detection(self) -> None:
        path = write_nested_chain(self.tmp.name)
        archive = open_archive(path, "zip", probe_nested=False)
        self.assertTrue(all(m.inner_format is None for m in archive.members))

    def test_unreadable_format_raises(self) -> None:
        with self.assertRaises(ReaderError):
            open_archive("/nowhere", "7z")


class TarReaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_simple_tar(self) -> None:
        archive = open_archive(write_tar_simple(self.tmp.name), "tar")
        self.assertEqual(archive.file_count, 2)
        self.assertGreater(archive.total_size, 0)

    def test_symlink_and_fifo_metadata(self) -> None:
        archive = open_archive(write_tar_sneaky(self.tmp.name), "tar")
        links = [m for m in archive.members if m.is_symlink]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].link_target, "/etc/passwd")
        methods = {m.method for m in archive.members}
        self.assertIn("fifo", methods)

    def test_tar_gz_variants_read_as_tar(self) -> None:
        archive = open_archive(write_tar_gz(self.tmp.name), "gzip")
        self.assertEqual(archive.fmt, "gzip")
        self.assertEqual(archive.file_count, 1)


class SupportMatrixTest(unittest.TestCase):
    def test_reader_superset_of_extractors(self) -> None:
        self.assertTrue(SUPPORTED_EXTRACTORS.issubset(SUPPORTED_READERS))

    def test_member_dataclass_defaults(self) -> None:
        member = Member(name="x.txt")
        self.assertEqual(member.size, 0)
        self.assertFalse(member.is_dir)
        self.assertEqual(member.ratio, 1.0)


if __name__ == "__main__":
    unittest.main()
