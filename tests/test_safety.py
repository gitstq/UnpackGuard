# -*- coding: utf-8 -*-
"""Tests for the path policy engine -- the zip-slip defence layer."""

from __future__ import annotations

import unittest

from unpackguard.safety import (
    PathPolicy,
    WINDOWS_RESERVED,
    apply_policy,
    is_within,
    normalise_member_name,
    safe_join,
    split_stream_suffix,
)

STRICT = PathPolicy(strip_absolute=False, strip_traversal=False)
LENIENT = PathPolicy()


class HelpersTest(unittest.TestCase):
    def test_normalise_backslashes(self) -> None:
        self.assertEqual(normalise_member_name("a\\b\\c.txt"), "a/b/c.txt")

    def test_split_ads(self) -> None:
        self.assertEqual(split_stream_suffix("notes.txt"), ("notes.txt", None))
        self.assertEqual(split_stream_suffix("notes.txt:ps1"), ("notes.txt", "ps1"))

    def test_is_within(self) -> None:
        self.assertTrue(is_within("/tmp/out", "/tmp/out/a/b.txt"))
        self.assertFalse(is_within("/tmp/out", "/tmp/other/a.txt"))
        self.assertTrue(is_within("/tmp/out", "/tmp/out"))

    def test_reserved_names(self) -> None:
        self.assertIn("CON", WINDOWS_RESERVED)
        self.assertIn("LPT9", WINDOWS_RESERVED)
        self.assertIn("COM1", WINDOWS_RESERVED)


class TraversalTest(unittest.TestCase):
    def test_dotdot_blocked_when_disabled(self) -> None:
        verdict = apply_policy("../../evil.sh", STRICT)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.code, "path-traversal")

    def test_dotdot_stripped_when_allowed(self) -> None:
        verdict = apply_policy("../../evil.sh", LENIENT)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.target, "evil.sh")
        self.assertTrue(verdict.rewritten)

    def test_embedded_traversal(self) -> None:
        verdict = apply_policy("a/b/../../c.txt", STRICT)
        self.assertTrue(verdict.blocked)

    def test_mixed_separators(self) -> None:
        verdict = apply_policy("..\\..\\payload.exe", STRICT)
        self.assertTrue(verdict.blocked, verdict.code)


class AbsolutePathTest(unittest.TestCase):
    def test_posix_absolute_blocked(self) -> None:
        verdict = apply_policy("/etc/cron.d/payload", STRICT)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.code, "absolute-path")

    def test_posix_absolute_rewritten(self) -> None:
        verdict = apply_policy("/etc/cron.d/payload", LENIENT)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.target, "etc/cron.d/payload")

    def test_windows_drive_blocked(self) -> None:
        verdict = apply_policy("C:/Windows/System32/evil.dll", STRICT)
        self.assertTrue(verdict.blocked)

    def test_windows_drive_rewritten(self) -> None:
        verdict = apply_policy("C:/Windows/System32/evil.dll", LENIENT)
        self.assertTrue(verdict.allowed)
        self.assertFalse(verdict.target.startswith(("C:", "/")))

    def test_unc_path(self) -> None:
        verdict = apply_policy("\\\\server\\share\\x.txt", LENIENT)
        self.assertTrue(verdict.allowed)
        # The UNC root is gone: the target is destination-relative, so writing
        # it can never reach the network share it originally named.
        self.assertFalse(verdict.target.startswith("/"))
        self.assertFalse(verdict.target.startswith("//"))

    def test_unc_path_rejected_when_not_stripping(self) -> None:
        verdict = apply_policy("\\\\server\\share\\x.txt", STRICT)
        self.assertTrue(verdict.blocked)
        self.assertIn(verdict.code, ("unc-path", "absolute-path"))


class SanitisationTest(unittest.TestCase):
    def test_ntfs_ads_removed(self) -> None:
        verdict = apply_policy("notes.txt:Payload.ps1", LENIENT)
        self.assertTrue(verdict.allowed)
        self.assertNotIn(":", verdict.target)

    def test_control_chars_blocked(self) -> None:
        verdict = apply_policy("evil\x00.txt", LENIENT)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.code, "control-chars")

    def test_reserved_device_renamed(self) -> None:
        verdict = apply_policy("NUL.txt", LENIENT)
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.rewritten)
        self.assertNotEqual(verdict.target.upper().split("/")[-1], "NUL.TXT")

    def test_windows_illegal_chars(self) -> None:
        verdict = apply_policy('we|rd?name.txt', LENIENT)
        self.assertTrue(verdict.allowed)
        for bad in '<>:"|?*':
            self.assertNotIn(bad, verdict.target)

    def test_trailing_dot_stripped(self) -> None:
        verdict = apply_policy("report.", LENIENT)
        self.assertTrue(verdict.allowed)
        self.assertFalse(verdict.target.endswith("."))


class LinksTest(unittest.TestCase):
    def test_links_blocked_by_default(self) -> None:
        verdict = apply_policy("link", LENIENT, is_link=True)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.code, "link-blocked")

    def test_links_allowed_explicitly(self) -> None:
        policy = PathPolicy(allow_links=True)
        verdict = apply_policy("link", policy, is_link=True)
        self.assertTrue(verdict.allowed)


class ReshapingTest(unittest.TestCase):
    def test_strip_components(self) -> None:
        verdict = apply_policy("pkg-1.2.3/lib/x.py", PathPolicy(strip_components=1))
        self.assertEqual(verdict.target, "lib/x.py")

    def test_flatten(self) -> None:
        verdict = apply_policy("a/b/c.txt", PathPolicy(flatten=True))
        self.assertNotIn("/", verdict.target.rstrip("/"))
        self.assertIn("__b", verdict.target)

    def test_directory_flag(self) -> None:
        verdict = apply_policy("pkg/lib", PathPolicy(), is_dir=True)
        self.assertTrue(verdict.target.endswith("/"))

    def test_empty_name(self) -> None:
        verdict = apply_policy("", LENIENT)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.code, "skip-empty")

    def test_renames_take_precedence(self) -> None:
        policy = PathPolicy(renames=(("bad<name>.txt", "good.txt"),))
        verdict = apply_policy("bad<name>.txt", policy)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.target, "good.txt")


class SafeJoinTest(unittest.TestCase):
    def test_join_ok(self) -> None:
        self.assertEqual(safe_join("/tmp/out", "a/b.txt"), "/tmp/out/a/b.txt")

    def test_join_refuses_escape(self) -> None:
        with self.assertRaises(ValueError):
            safe_join("/tmp/out", "../outside.txt")


if __name__ == "__main__":
    unittest.main()
