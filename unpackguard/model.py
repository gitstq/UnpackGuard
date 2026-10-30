"""Immutable data carriers shared by every UnpackGuard stage."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Sequence

from . import SEVERITY_ORDER

__all__ = [
    "Member",
    "Archive",
    "Finding",
    "ExtractionPlan",
    "SortKey",
    "severity_rank",
    "worst_severity",
    "sum_sizes",
]


@dataclass(slots=True)
class Member:
    """One entry inside an archive (or inside a nested archive)."""

    #: Display name, already re-encoded if a legacy codec was detected.
    name: str
    #: Raw bytes as stored by the writer; kept for lossless re-encoding.
    raw_name: bytes = b""
    #: Codec that produced :attr:`name`.
    encoding: str = "utf-8"
    #: True when the general purpose bit 11 says UTF-8 was declared (ZIP only).
    declared_utf8: bool = False
    is_dir: bool = False
    is_symlink: bool = False
    is_hardlink: bool = False
    link_target: str | None = None
    #: Uncompressed size in bytes.
    size: int = 0
    compressed_size: int = 0
    mode: int = 0
    mtime: float | None = None
    uid: int = 0
    gid: int = 0
    #: Compression method label, e.g. ``deflate`` / ``lzma`` / ``stored``.
    method: str = "stored"
    #: Whether the entry is encrypted (needs a password to read).
    encrypted: bool = False
    #: Detected inner format when this member is itself an archive.
    inner_format: str | None = None
    #: Nesting path, e.g. ``("outer.zip", "inner.tar.gz")``.
    origin: tuple[str, ...] = ()
    #: Sha256 head + size fingerprint (lazily computed, may be empty).
    digest: str = ""

    # -- derived properties -------------------------------------------------

    @property
    def ratio(self) -> float:
        """Compression ratio.  ``1.0`` when nothing could be measured."""
        if self.compressed_size <= 0:
            return float("inf") if self.size > 0 else 1.0
        return self.size / self.compressed_size

    @property
    def basename(self) -> str:
        return os.path.basename(self.name.rstrip("/")) or self.name

    @property
    def depth(self) -> int:
        return len(self.origin)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "raw_name_hex": self.raw_name.hex() if self.raw_name else "",
            "encoding": self.encoding,
            "declared_utf8": self.declared_utf8,
            "is_dir": self.is_dir,
            "is_symlink": self.is_symlink,
            "is_hardlink": self.is_hardlink,
            "link_target": self.link_target,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "ratio": None if self.ratio == float("inf") else round(self.ratio, 3),
            "mode": self.mode,
            "mtime": self.mtime,
            "method": self.method,
            "encrypted": self.encrypted,
            "inner_format": self.inner_format,
            "origin": list(self.origin),
        }


@dataclass(slots=True)
class Archive:
    """A fully enumerated archive."""

    path: str
    #: Container format as reported by magic-byte sniffing (e.g. ``gzip``).
    fmt: str
    #: Which enumeration strategy produced ``members``: ``zip`` / ``tar`` / ``stream``.
    reader: str = "zip"
    members: list[Member] = field(default_factory=list)
    #: Whole-file size on disk.
    file_size: int = 0
    #: Nesting level of this archive (0 for the CLI entry point).
    level: int = 0
    #: Whether the whole container is encrypted / password protected.
    encrypted: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def file_count(self) -> int:
        return sum(1 for m in self.members if not m.is_dir)

    @property
    def total_size(self) -> int:
        return sum_sizes(m.size for m in self.members)

    @property
    def total_compressed_size(self) -> int:
        return sum_sizes(m.compressed_size for m in self.members)

    @property
    def max_depth(self) -> int:
        return max((m.depth for m in self.members), default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.fmt,
            "reader": self.reader,
            "file_size": self.file_size,
            "level": self.level,
            "encrypted": self.encrypted,
            "member_count": self.member_count,
            "file_count": self.file_count,
            "total_size": self.total_size,
            "total_compressed_size": self.total_compressed_size,
            "max_depth": self.max_depth,
            "warnings": list(self.warnings),
            "members": [m.to_dict() for m in self.members],
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A single rule hit."""

    rule: str
    severity: str
    title: str
    detail: str
    member: str | None = None
    #: Suggested remediation shown in ``scan`` output.
    remedy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "member": self.member,
            "remedy": self.remedy,
        }


@dataclass(slots=True)
class ExtractionPlan:
    """Resource budget prediction for an extraction."""

    file_count: int
    dir_count: int
    total_bytes: int
    estimated_on_disk: int
    free_bytes: int
    worst_case_bytes: int
    nested_archives: int
    max_depth: int
    fits: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_count": self.file_count,
            "dir_count": self.dir_count,
            "total_bytes": self.total_bytes,
            "estimated_on_disk": self.estimated_on_disk,
            "free_bytes": self.free_bytes,
            "worst_case_bytes": self.worst_case_bytes,
            "nested_archives": self.nested_archives,
            "max_depth": self.max_depth,
            "fits": self.fits,
            "notes": list(self.notes),
        }


def severity_rank(sev: str) -> int:
    """Map a severity label to a comparable integer."""
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


def worst_severity(findings: Sequence[Finding]) -> str | None:
    """Highest severity present, or ``None`` when there are no findings."""
    if not findings:
        return None
    return max(findings, key=lambda f: severity_rank(f.severity)).severity


def sum_sizes(values: Any) -> int:
    """Sum sizes defensively: some archives report ``None`` or negative sizes."""
    total = 0
    for v in values:
        try:
            iv = int(v)
        except (TypeError, ValueError):
            continue
        if iv > 0:
            total += iv
    return total


SortKey = str
