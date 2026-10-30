# -*- coding: utf-8 -*-
"""End-to-end CLI tests: report formats, exit codes and plan output."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import warnings
from contextlib import redirect_stdout

from unpackguard.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, run_argv
from unpackguard.plan import PLAN_DEFAULTS, human_bytes

from .fixtures import (
    write_zip_bomb,
    write_zip_mixed_attacks,
    write_zip_simple,
    write_zip_traversal,
)

warnings.filterwarnings("ignore", message="Duplicate name")


def _run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_argv(argv)
    return code, buf.getvalue()


class HumanBytesTest(unittest.TestCase):
    def test_scales(self) -> None:
        self.assertEqual(human_bytes(0), "0 B")
        self.assertEqual(human_bytes(512), "512 B")
        self.assertEqual(human_bytes(2048), "2.0 KiB")
        self.assertEqual(human_bytes(3 * 1024 ** 2), "3.0 MiB")
        self.assertEqual(human_bytes(-1), "-")


class PlanConfigDefaultTest(unittest.TestCase):
    def test_defaults_exist(self) -> None:
        self.assertIn("reserve_ratio", PLAN_DEFAULTS)


class CliOutputTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_scan_text_output(self) -> None:
        path = write_zip_simple(self.tmp.name)
        code, out = _run(["scan", path, "--no-color"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("UnpackGuard scan", out)
        self.assertIn("score", out)

    def test_scan_json_output(self) -> None:
        path = write_zip_mixed_attacks(self.tmp.name)
        code, out = _run(["scan", path, "--no-color", "--json"])
        self.assertEqual(code, EXIT_FINDINGS)
        payload = json.loads(out)
        self.assertIn("findings", payload)
        self.assertGreater(len(payload["findings"]), 0)

    def test_scan_sarif_output(self) -> None:
        path = write_zip_traversal(self.tmp.name)
        code, out = _run(["scan", path, "--no-color", "--sarif"])
        payload = json.loads(out)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn("results", payload["runs"][0])

    def test_fail_level_none_returns_zero(self) -> None:
        path = write_zip_traversal(self.tmp.name)
        code, _ = _run(["scan", path, "--no-color", "--fail-level", "none"])
        self.assertEqual(code, EXIT_OK)

    def test_fail_level_low_trips_on_traversal(self) -> None:
        path = write_zip_traversal(self.tmp.name)
        code, _ = _run(["scan", path, "--no-color", "--fail-level", "low"])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_quiet_mode(self) -> None:
        path = write_zip_simple(self.tmp.name)
        code, out = _run(["scan", path, "--no-color", "--quiet"])
        self.assertEqual(code, EXIT_OK)
        self.assertLessEqual(len(out.strip().splitlines()), 2)

    def test_inspect_json_shape(self) -> None:
        path = write_zip_simple(self.tmp.name)
        code, out = _run(["inspect", path, "--no-color", "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["format"], "zip")
        self.assertIn("members", payload)

    def test_plan_command(self) -> None:
        path = write_zip_simple(self.tmp.name)
        dest = os.path.join(self.tmp.name, "plan_dest")
        code, out = _run(["plan", path, "--no-color", "--dest", dest])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Extraction plan", out)

    def test_plan_reports_verdict_line(self) -> None:
        path = write_zip_bomb(self.tmp.name)
        code, out = _run(["plan", path, "--no-color", "--dest", self.tmp.name])
        self.assertIn("verdict", out)
        self.assertIn(code, (EXIT_OK, EXIT_ERROR))

    def test_extract_dry_run_writes_nothing(self) -> None:
        path = write_zip_simple(self.tmp.name)
        dest = os.path.join(self.tmp.name, "extracted")
        code, out = _run(["extract", path, "--no-color", "--dest", dest, "--dry-run"])
        self.assertEqual(code, EXIT_OK)
        self.assertFalse(os.path.exists(dest))

    def test_extract_writes_files(self) -> None:
        path = write_zip_simple(self.tmp.name)
        dest = os.path.join(self.tmp.name, "real")
        code, _ = _run(["extract", path, "--no-color", "--dest", dest])
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(os.path.isfile(os.path.join(dest, "README.md")))

    def test_sniff_multiple_paths(self) -> None:
        a = write_zip_simple(self.tmp.name, name="one.zip")
        b = write_zip_simple(self.tmp.name, name="two.zip")
        code, out = _run(["sniff", a, b, "--no-color"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("one.zip", out)
        self.assertIn("two.zip", out)

    def test_list_rules(self) -> None:
        code, out = _run(["scan", "--list-rules", "--no-color", write_zip_simple(self.tmp.name)])
        self.assertIn("UPG001", out)
        self.assertIn("UPG026", out)


if __name__ == "__main__":
    unittest.main()
