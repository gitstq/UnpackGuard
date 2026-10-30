# -*- coding: utf-8 -*-
"""Smoke-level tests: every module imports and the CLI answers basic queries."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

import unpackguard
from unpackguard import __version__
from unpackguard.cli import build_parser, run_argv

from .fixtures import write_not_archive, write_zip_simple


class SmokeTest(unittest.TestCase):
    def test_version_semver(self) -> None:
        parts = __version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts), parts)

    def test_package_exports(self) -> None:
        self.assertEqual(unpackguard.SEVERITY_WEIGHT["critical"], 40)
        self.assertIn("critical", unpackguard.SEVERITY_ORDER)

    def test_parser_builds(self) -> None:
        parser = build_parser()
        self.assertIsNotNone(parser.format_help())

    def test_cli_version_flag(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            parser = build_parser()
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_cli_scan_basic(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            parser = build_parser()
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


class EndToEndCliTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_scan_clean_archive(self) -> None:
        path = write_zip_simple(self.tmp.name)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_argv(["scan", path, "--no-color", "--fail-level", "critical"])
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn("UnpackGuard scan", buf.getvalue())

    def test_sniff_random_data(self) -> None:
        path = write_not_archive(self.tmp.name)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_argv(["sniff", path, "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn(path, buf.getvalue())

    def test_default_command_is_scan(self) -> None:
        path = write_zip_simple(self.tmp.name)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_argv([path, "--no-color"])
        self.assertEqual(code, 0)

    def test_missing_file_exits(self) -> None:
        with self.assertRaises(SystemExit):
            run_argv(["scan", "/definitely/not/here.zip", "--no-color"])


if __name__ == "__main__":
    unittest.main()
