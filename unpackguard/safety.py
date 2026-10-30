"""Path policy engine -- decides whether a member may be written where it asks.

The threat model
----------------
A hostile archive can ask an extractor to write outside its destination:

* ``../evil.sh``                       -> parent escape (classic zip-slip)
* ``/etc/cron.d/evil``                 -> absolute POSIX path
* ``C:\\Windows\\System32\\evil.dll``  -> drive-qualified absolute path
* ``notes.txt:evil.ps1``               -> NTFS alternate data stream
* ``symlink -> /etc``                  -> escapes *after* extraction
* ``NUL`` / ``CON`` / ``COM1``         -> reserved Windows device names
* ``..\\..\\payload.exe``              -> wrong separator on POSIX
* two members differing only in case   -> silent overwrite on macOS/Windows

This module normalises member names into a canonical destination-relative
POSIX path and returns verdicts instead of raising, so callers can render
helpful, actionable reports.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PathPolicy",
    "PathVerdict",
    "WINDOWS_RESERVED",
    "apply_policy",
    "normalise_member_name",
    "split_stream_suffix",
    "is_within",
    "safe_join",
]

#: Windows device names are reserved even with an extension (``NUL.txt``).
WINDOWS_RESERVED: Final[frozenset[str]] = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

#: Characters that are illegal in Windows file names.
_ILLEGAL_CHARS: Final[str] = '<>:"|?*'

#: C0 / DEL controls -- never legitimate inside a path component.
_CONTROL_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")
_UNC_RE: Final[re.Pattern[str]] = re.compile(r"^[\\/]{2,}")


def split_stream_suffix(name: str) -> tuple[str, str | None]:
    """Split ``reports.txt:Summary`` into ``("reports.txt", "Summary")``.

    Returns ``(name, None)`` when there is no alternate data stream.
    """
    head, sep, tail = name.partition(":")
    if not sep:
        return name, None
    return head, tail or None


def normalise_member_name(name: str) -> str:
    """Canonicalise separators and Unicode form.

    Backslashes become forward slashes (they are separators in Windows-authored
    archives) and the string is NFKC-normalised so visually identical names are
    treated as the same name.
    """
    cleaned = name.replace("\\", "/")
    try:
        cleaned = unicodedata.normalize("NFKC", cleaned)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        pass
    return cleaned


def is_within(dest_root: str, candidate: str) -> bool:
    """True when *candidate* stays inside *dest_root* (both absolute)."""
    root = posixpath.normpath(dest_root.replace("\\", "/"))
    cand = posixpath.normpath(candidate.replace("\\", "/"))
    if root == cand:
        return True
    prefix = root if root.endswith("/") else root + "/"
    return cand.startswith(prefix)


def safe_join(dest_root: str, relative: str) -> str:
    """Join *relative* under *dest_root* only when it cannot escape."""
    tail = relative.replace("\\", "/").lstrip("/")
    candidate = posixpath.normpath(posixpath.join(dest_root, tail))
    if not is_within(dest_root, candidate):
        raise ValueError(f"refusing path escape: {relative!r}")
    return candidate


@dataclass(frozen=True, slots=True)
class PathPolicy:
    """Tunable path sanitisation policy."""

    #: Rewrite absolute paths instead of rejecting them.
    strip_absolute: bool = True
    #: Drop ``..`` components instead of rejecting them.
    strip_traversal: bool = True
    #: Remove NTFS alternate data stream suffixes.
    strip_ads: bool = True
    #: Replace characters that are illegal on Windows.
    sanitise_windows: bool = True
    #: Allow symlinks / hard links to be created.
    allow_links: bool = False
    #: Number of leading path components to drop.
    strip_components: int = 0
    #: Flatten everything into a single directory.
    flatten: bool = False
    #: Report collisions case-insensitively (macOS / Windows filesystems).
    case_insensitive_fs: bool = False
    #: Authoritative overrides from ``--rename-from/--rename-to``.
    renames: tuple[tuple[str, str], ...] = ()

    def replace(self, **kw: object) -> "PathPolicy":
        data: dict[str, object] = {
            "strip_absolute": self.strip_absolute,
            "strip_traversal": self.strip_traversal,
            "strip_ads": self.strip_ads,
            "sanitise_windows": self.sanitise_windows,
            "allow_links": self.allow_links,
            "strip_components": self.strip_components,
            "flatten": self.flatten,
            "case_insensitive_fs": self.case_insensitive_fs,
            "renames": self.renames,
        }
        data.update(kw)
        return PathPolicy(**data)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class PathVerdict:
    """Result of applying :class:`PathPolicy` to one member name."""

    original: str
    #: Sanitised, destination-relative POSIX path.  Empty when blocked/skipped.
    target: str
    allowed: bool
    code: str = "ok"
    reason: str = ""
    #: True when the policy rewrote the name rather than taking it verbatim.
    rewritten: bool = False

    @property
    def blocked(self) -> bool:
        return not self.allowed


def _strip_components(parts: list[str], count: int) -> list[str]:
    """Drop up to *count* leading real components (like ``tar --strip-components``)."""
    if count <= 0:
        return parts
    kept: list[str] = []
    dropped = 0
    for part in parts:
        if dropped < count and part not in ("", ".", ".."):
            dropped += 1
            continue
        kept.append(part)
    return kept


def _sanitise_component(component: str, policy: PathPolicy) -> tuple[str, bool]:
    """Clean one path component.  Returns ``(component, changed)``."""
    changed = False

    if policy.strip_ads:
        base, sep, tail = component.partition(":")
        if sep:
            component = base
            changed = True
            _ = tail  # stream name intentionally discarded

    if policy.sanitise_windows:
        scrubbed = "".join("_" if ch in _ILLEGAL_CHARS else ch for ch in component)
        if scrubbed != component:
            component, changed = scrubbed, True

    # Windows ignores trailing dots/spaces and silently truncates them.
    stripped = component.rstrip(" .") if component not in ("", ".", "..") else component
    if stripped != component:
        component, changed = stripped, True

    # Reserved device names apply even with an extension.
    stem = component.split(".")[0].upper()
    if stem in WINDOWS_RESERVED:
        component = "_" + component
        changed = True

    if not component:
        component, changed = "_", True

    return component, changed


def apply_policy(
    name: str,
    policy: PathPolicy,
    *,
    is_dir: bool = False,
    is_link: bool = False,
) -> PathVerdict:
    """Return the verdict for extracting *name* under the given policy."""
    original = name

    # Authoritative renames take precedence over every heuristic below.
    renamed_from: str | None = None
    for src, dst in policy.renames:
        if name == src:
            renamed_from = src
            name = dst
            break

    if not name:
        return PathVerdict(original, "", False, "skip-empty", "empty member name")

    cleaned = normalise_member_name(name)

    if _CONTROL_RE.search(cleaned):
        return PathVerdict(
            original, "", False, "control-chars",
            "member name contains control characters",
        )

    rewritten = cleaned != original

    # UNC style \\server\share\...
    if _UNC_RE.match(cleaned):
        if not policy.strip_absolute:
            return PathVerdict(
                original, "", False, "unc-path",
                "UNC path cannot be extracted safely",
            )
        cleaned = cleaned.lstrip("/")
        rewritten = True

    # Drive letter: C:/Windows/... or C:payload.exe
    if _DRIVE_RE.match(cleaned):
        if not policy.strip_absolute:
            return PathVerdict(
                original, "", False, "absolute-path",
                "absolute path outside the destination",
            )
        cleaned = cleaned[2:].lstrip("/")
        rewritten = True

    absolute = cleaned.startswith("/")
    if absolute:
        if not policy.strip_absolute:
            return PathVerdict(
                original, "", False, "absolute-path",
                "absolute path outside the destination",
            )
        cleaned = cleaned.lstrip("/")
        rewritten = True

    trailing = cleaned.endswith("/") or is_dir

    parts = [p for p in cleaned.split("/") if p not in ("", ".")]

    # Check for traversal before we mangle anything.
    if any(p == ".." for p in parts):
        if not policy.strip_traversal:
            return PathVerdict(
                original, "", False, "path-traversal",
                "member escapes the destination via '..'",
            )
        parts = [p for p in parts if p != ".."]
        rewritten = True

    if policy.strip_components:
        parts = _strip_components(parts, policy.strip_components)
        rewritten = True

    sanitised: list[str] = []
    for piece in parts:
        clean_piece, changed = _sanitise_component(piece, policy)
        sanitised.append(clean_piece)
        rewritten = rewritten or changed

    if policy.flatten:
        # Keep only the final component, de-duplicating by suffixing the parent.
        if sanitised:
            tail = sanitised[-1]
            if len(sanitised) > 1:
                parent = sanitised[-2]
                stem, dot, ext = tail.rpartition(".")
                if dot and stem:
                    tail = f"{stem}__{parent}.{ext}"
                else:
                    tail = f"{tail}__{parent}"
            sanitised = [tail]
            rewritten = True
        else:
            return PathVerdict(
                original, "", False, "skip-empty", "nothing left to write",
            )

    if not sanitised:
        return PathVerdict(
            original, "", False, "skip-empty", "nothing left to write",
        )

    target = "/".join(sanitised)
    if trailing:
        target += "/"

    # Belt and braces: nothing may resolve above the destination root.
    norm = posixpath.normpath("/" + target).lstrip("/")
    if trailing:
        norm += "/"
    if norm.startswith("../") or norm == ".." or posixpath.isabs(norm):
        return PathVerdict(
            original, "", False, "path-traversal",
            "member escapes the destination after normalisation",
        )
    if policy.sanitise_windows and any(ch in _ILLEGAL_CHARS for ch in norm):
        return PathVerdict(
            original, "", False, "illegal-chars",
            "member name contains characters illegal on Windows",
        )

    if is_link and not policy.allow_links:
        return PathVerdict(
            original, "", False, "link-blocked",
            "symbolic/hard link blocked by policy",
        )

    if renamed_from is not None:
        rewritten = True

    return PathVerdict(original, norm, True, "ok", "", rewritten)
