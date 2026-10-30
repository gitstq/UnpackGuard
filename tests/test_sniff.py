# -*- coding: utf-8 -*-
"""Tests for magic-byte sniffing and filename encoding heuristics."""

from __future__ import annotations

import unittest

from unpackguard.sniff import (
    ARCHIVE_FORMATS,
    CANDIDATE_ENCODINGS,
    decode_member_name,
    format_label,
    guess_encoding,
    is_archive_format,
    looks_utf8,
    sniff_bytes,
    sniff_file,
)

from .fixtures import (
    write_not_archive,
    write_tar_gz,
    write_tar_simple,
    write_zip_simple,
)


class SniffBytesTest(unittest.TestCase):
    def test_zip_local_header(self) -> None:
        self.assertEqual(sniff_bytes(b"PK\x03\x04rest"), "zip")

    def test_empty_zip_eocd(self) -> None:
        self.assertEqual(sniff_bytes(b"PK\x05\x06" + b"\x00" * 16), "zip")

    def test_sevenzip(self) -> None:
        self.assertEqual(sniff_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 8), "7z")

    def test_rar5(self) -> None:
        self.assertEqual(sniff_bytes(b"Rar!\x1a\x07\x01\x00"), "rar5")

    def test_gzip(self) -> None:
        self.assertEqual(sniff_bytes(b"\x1f\x8b\x08\x00rest"), "gzip")

    def test_tar_magic_at_257(self) -> None:
        head = bytearray(512)
        head[257:262] = b"ustar"
        self.assertEqual(sniff_bytes(bytes(head)), "tar")

    def test_unknown(self) -> None:
        self.assertEqual(sniff_bytes(b"just some text here"), "unknown")

    def test_empty_input(self) -> None:
        self.assertEqual(sniff_bytes(b""), "unknown")


class SniffFileTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_detects_real_files(self) -> None:
        self.assertEqual(sniff_file(write_zip_simple(self.tmp.name)), "zip")
        self.assertEqual(sniff_file(write_tar_simple(self.tmp.name)), "tar")
        self.assertEqual(sniff_file(write_tar_gz(self.tmp.name)), "gzip")

    def test_missing_file(self) -> None:
        self.assertEqual(sniff_file("/no/such/file.zip"), "missing")

    def test_random_binary_is_unknown(self) -> None:
        path = write_not_archive(self.tmp.name)
        self.assertIn(sniff_file(path), ("unknown", "zip-partial", "sqlite", "elf"))


class FormatMetaTest(unittest.TestCase):
    def test_archive_formats_contain_core(self) -> None:
        for expected in ("zip", "tar", "7z", "rar5"):
            self.assertIn(expected, ARCHIVE_FORMATS)

    def test_is_archive_format(self) -> None:
        self.assertTrue(is_archive_format("zip"))
        self.assertTrue(is_archive_format("gzip"))
        self.assertFalse(is_archive_format("png"))

    def test_labels_resolve(self) -> None:
        self.assertIn("ZIP", format_label("zip"))
        self.assertEqual(format_label("nope-nope"), "nope-nope")


class EncodingTest(unittest.TestCase):
    def test_looks_utf8(self) -> None:
        self.assertTrue(looks_utf8("中文.txt".encode("utf-8")))
        self.assertTrue(looks_utf8(b"ascii.txt"))
        self.assertFalse(looks_utf8("中文".encode("gb18030")))

    def test_gbk_round_trip(self) -> None:
        raw = "中文合同.txt".encode("gb18030")
        enc = guess_encoding(raw)
        self.assertIn(enc, ("gb18030", "big5", "utf-8", "cp437", "cp1252", "latin-1",
                            "shift_jis", "euc-kr"))
        text, used = decode_member_name(raw, preferred="gb18030")
        self.assertEqual(text, "中文合同.txt")
        self.assertEqual(used, "gb18030")

    def test_declared_utf8_preferred(self) -> None:
        raw = "合同.pdf".encode("utf-8")
        text, enc = decode_member_name(raw, preferred="utf-8")
        self.assertEqual(text, "合同.pdf")
        self.assertEqual(enc, "utf-8")

    def test_cp437_fallback_never_loses_bytes(self) -> None:
        raw = b"\xb2\xe2\xca\xc7.txt"
        text, _ = decode_member_name(raw)
        self.assertTrue(text.endswith(".txt"))
        self.assertGreater(len(text), 0)

    def test_ascii_is_stable(self) -> None:
        text, enc = decode_member_name(b"report.csv")
        self.assertEqual(text, "report.csv")
        self.assertIn(enc, ("utf-8", "gb18030", "cp437", "latin-1", "cp1252"))

    def test_candidate_encodings_are_known(self) -> None:
        for enc in CANDIDATE_ENCODINGS:
            "\xc3\xa9".encode("latin-1").decode(enc, "replace")  # must not raise LookupError


if __name__ == "__main__":
    unittest.main()
