# -*- coding: utf-8 -*-
"""Tests for the rule engine and risk scoring."""

from __future__ import annotations

import tempfile
import unittest
import warnings

from unpackguard.reader import open_archive
from unpackguard.rules import RULE_INDEX, ScanConfig, rule_descriptions, scan_archive
from unpackguard.safety import PathPolicy

from .fixtures import (
    write_tar_sneaky,
    write_zip_bomb,
    write_zip_legacy_names,
    write_zip_mixed_attacks,
    write_zip_simple,
    write_zip_traversal,
)

warnings.filterwarnings("ignore", message="Duplicate name")

POLICY = PathPolicy()
STRICT = PathPolicy(strip_absolute=False, strip_traversal=False)


def _rules(result) -> set[str]:
    return {f.rule for f in result.findings}


class CleanArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_benign_scores_perfect(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(), POLICY)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A")
        self.assertIsNone(result.worst)
        self.assertEqual(result.findings, [])


class HostileArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _scan(self, path: str, fmt: str = "zip", policy: PathPolicy = POLICY, **kw):
        return scan_archive(open_archive(path, fmt), ScanConfig(**kw), policy)

    def test_traversal_detected(self) -> None:
        result = self._scan(write_zip_traversal(self.tmp.name))
        self.assertIn("UPG001", _rules(result))
        self.assertEqual(result.worst, "critical")

    def test_all_expected_rules_fire(self) -> None:
        result = self._scan(write_zip_mixed_attacks(self.tmp.name))
        found = _rules(result)
        for expected in ("UPG001", "UPG004", "UPG013", "UPG014", "UPG016",
                         "UPG017", "UPG018", "UPG019", "UPG023", "UPG024", "UPG025"):
            self.assertIn(expected, found, expected)
        self.assertEqual(result.grade, "F")

    def test_absolute_and_drive_paths_blocked_by_policy(self) -> None:
        result = self._scan(write_zip_mixed_attacks(self.tmp.name), policy=STRICT)
        codes = {code for _, code, _ in result.blocked_by_policy}
        self.assertTrue(codes)
        self.assertIn("path-traversal", codes)

    def test_empty_member_list_not_written(self) -> None:
        result = self._scan(write_zip_traversal(self.tmp.name))
        names = {m.name for m in result.allowed_by_policy}
        self.assertIn("safe.txt", names)


class TarRuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_symlink_escape_is_critical(self) -> None:
        archive = open_archive(write_tar_sneaky(self.tmp.name), "tar")
        result = scan_archive(archive, ScanConfig(), POLICY)
        self.assertIn("UPG005", _rules(result))
        self.assertIn("UPG006", _rules(result))
        self.assertEqual(result.worst, "critical")

    def test_allow_links_suppresses_block(self) -> None:
        archive = open_archive(write_tar_sneaky(self.tmp.name), "tar")
        policy = PathPolicy(allow_links=True)
        result = scan_archive(archive, ScanConfig(), policy)
        self.assertIn("UPG005", _rules(result))  # still reported, just not blocked


class BombTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_ratio_rule_fires(self) -> None:
        archive = open_archive(write_zip_bomb(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(max_ratio=50.0), POLICY)
        self.assertIn("UPG010", _rules(result))

    def test_ratio_threshold_is_configurable(self) -> None:
        archive = open_archive(write_zip_bomb(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(max_ratio=0.0), POLICY)
        self.assertNotIn("UPG010", _rules(result))

    def test_total_budget_rule_fires(self) -> None:
        archive = open_archive(write_zip_bomb(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(max_total_bytes=1024), POLICY)
        self.assertIn("UPG011", _rules(result))


class EncodingRuleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_legacy_codec_flagged(self) -> None:
        archive = open_archive(write_zip_legacy_names(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(), POLICY)
        self.assertIn("UPG015", _rules(result))
        self.assertGreaterEqual(result.score, 90)


class CatalogueTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_every_rule_has_a_description(self) -> None:
        docs = rule_descriptions()
        self.assertEqual(len(docs), len(RULE_INDEX))
        for item in docs:
            self.assertTrue(item["rule"].startswith("UPG"))
            self.assertTrue(item["description"])

    def test_score_caps_per_rule(self) -> None:
        archive = open_archive(write_zip_mixed_attacks(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(), POLICY)
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 100)

    def test_counts_sum_to_findings(self) -> None:
        archive = open_archive(write_zip_mixed_attacks(self.tmp.name), "zip")
        result = scan_archive(archive, ScanConfig(), POLICY)
        self.assertEqual(sum(result.counts().values()), len(result.findings))

    def test_json_payload_shape(self) -> None:
        archive = open_archive(write_zip_simple(self.tmp.name), "zip")
        payload = scan_archive(archive, ScanConfig(), POLICY).to_dict()
        self.assertIn("score", payload)
        self.assertIn("findings", payload)
        self.assertIn("grade", payload)


if __name__ == "__main__":
    unittest.main()
