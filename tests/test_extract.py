# -*- coding: utf-8 -*-
"""Tests for the extraction writer: it must never escape the destination."""

from __future__ import annotations

import os
import tempfile
import unittest
import warnings

from unpackguard.extract import ExtractConfig, Extractor, extract_archive
from unpackguard.reader import open_archive
from unpackguard.safety import PathPolicy

from .fixtures import (
    write_tar_gz,
    write_tar_sneaky,
    write_tar_simple,
    write_zip_mixed_attacks,
    write_zip_simple,
    write_zip_traversal,
)

warnings.filterwarnings("ignore", message="Duplicate name")


class ExtractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _dest(self, name: str = "out") -> str:
        path = os.path.join(self.tmp.name, name)
        os.makedirs(path, exist_ok=True)
        return path

    def test_simple_extraction_writes_files(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        outcome = extract_archive(archive, self._dest(), PathPolicy())
        self.assertGreaterEqual(len(outcome.written), 3)
        self.assertEqual(outcome.errors, [])
        for path in outcome.written:
            self.assertTrue(os.path.exists(path), path)
        self.assertTrue(os.path.isfile(os.path.join(outcome.dest, "README.md")))

    def test_traversal_never_escapes(self) -> None:
        root = self._dest("escapable")
        archive = open_archive(write_zip_traversal(self.tmp.name), "zip")
        outcome = extract_archive(archive, root, PathPolicy())
        for written in outcome.written:
            self.assertTrue(
                os.path.abspath(written).startswith(os.path.abspath(root)),
                f"{written} escaped {root}",
            )
        # "../../escaped.txt" must land inside root, not in the parent
        self.assertTrue(os.path.exists(os.path.join(root, "escaped.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "escaped.txt")))

    def test_strict_policy_blocks_hostile_entries(self) -> None:
        archive = open_archive(write_zip_traversal(self.tmp.name), "zip")
        policy = PathPolicy(strip_absolute=False, strip_traversal=False)
        outcome = extract_archive(archive, self._dest("strict"), policy)
        # Only the innocent member survives; every hostile path is skipped.
        self.assertTrue(outcome.skipped)
        hostile = {name for name, _ in outcome.skipped}
        self.assertIn("../../escaped.txt", hostile)
        self.assertTrue(any(n.startswith("/") for n in hostile))

    def test_symlinks_not_created_by_default(self) -> None:
        archive = open_archive(write_tar_sneaky(self.tmp.name), "tar")
        dest = self._dest("links")
        outcome = extract_archive(archive, dest, PathPolicy())
        for name in os.listdir(dest):
            self.assertFalse(os.path.islink(os.path.join(dest, name)))

    def test_dry_run_writes_nothing(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        dest = self._dest("dry")
        outcome = extract_archive(archive, dest, PathPolicy(), ExtractConfig(dry_run=True))
        self.assertTrue(outcome.written)
        self.assertEqual(list(os.listdir(dest)), [])

    def test_byte_budget_stops_extraction(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        outcome = extract_archive(
            archive, self._dest("budget"), PathPolicy(),
            ExtractConfig(max_total_bytes=8),
        )
        self.assertIsNotNone(outcome.aborted)

    def test_file_size_limit_skips_big_members(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        outcome = extract_archive(
            archive, self._dest("size"), PathPolicy(),
            ExtractConfig(max_file_bytes=1),
        )
        self.assertTrue(outcome.skipped)

    def test_overwrite_modes(self) -> None:
        path = write_tar_simple(self.tmp.name, name="a.tar")
        dest = self._dest("dup")
        extract_archive(open_archive(path, "tar"), dest, PathPolicy())
        first = sorted(os.listdir(dest))
        # second pass with --overwrite=skip must not duplicate files
        outcome = extract_archive(
            open_archive(path, "tar"), dest, PathPolicy(), ExtractConfig(overwrite="skip")
        )
        self.assertTrue(outcome.skipped)
        self.assertEqual(sorted(os.listdir(dest)), first)

    def test_rename_mode_creates_unique_names(self) -> None:
        path = write_tar_simple(self.tmp.name, name="b.tar")
        dest = self._dest("rename")
        extract_archive(open_archive(path, "tar"), dest, PathPolicy())
        extract_archive(open_archive(path, "tar"), dest, PathPolicy())
        self.assertTrue(any(".1" in n for n in os.listdir(dest)))

    def test_tar_gz_extracts(self) -> None:
        archive = open_archive(write_tar_gz(self.tmp.name), "gzip")
        dest = self._dest("tgz")
        outcome = extract_archive(archive, dest, PathPolicy())
        self.assertTrue(outcome.written)
        self.assertTrue(os.path.isfile(os.path.join(dest, "bundle/payload.dat")))

    def test_strip_components(self) -> None:
        archive = open_archive(write_tar_gz(self.tmp.name), "gzip")
        dest = self._dest("strip")
        outcome = extract_archive(
            archive, dest, PathPolicy(strip_components=1)
        )
        self.assertTrue(outcome.written)
        self.assertTrue(os.path.isfile(os.path.join(dest, "payload.dat")))

    def test_flat_mode(self) -> None:
        archive = open_archive(write_tar_gz(self.tmp.name), "gzip")
        dest = self._dest("flat")
        extract_archive(archive, dest, PathPolicy(flatten=True))
        flat = os.listdir(dest)
        self.assertTrue(all(os.path.isfile(os.path.join(dest, n)) for n in flat))

    def test_outcome_serialisable(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        outcome = extract_archive(archive, self._dest(), PathPolicy())
        payload = outcome.to_dict()
        self.assertIn("written", payload)
        self.assertIn("skipped", payload)

    def test_extractor_root_is_created(self) -> None:
        archive = open_archive(write_zip_mixed_attacks(self.tmp.name), "zip")
        dest = os.path.join(self.tmp.name, "new", "deep", "root")
        Extractor(dest, PathPolicy(), ExtractConfig(dry_run=False)).run(archive)
        self.assertTrue(os.path.isdir(dest))


if __name__ == "__main__":
    unittest.main()
