"""Archive readers built **only** on the Python standard library.

Design notes
------------
* Nothing here writes to disk -- reading is always side-effect free.
* Sizes never come from a single field blindly: every value is clamped, because
  a hostile central directory can declare anything.
* Nested archives are detected by reading a bounded prefix of each member, so
  an inspection never pays the cost of decompressing the whole payload.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import time
import zipfile
import tarfile
from typing import Callable, Iterator

from .model import Archive, Member
from .sniff import decode_member_name, guess_encoding, sniff_bytes

__all__ = [
    "SUPPORTED_READERS",
    "SUPPORTED_EXTRACTORS",
    "open_archive",
    "read_head",
    "iter_nested",
    "ReaderError",
    "HEAD_BYTES",
]

#: Prefix bytes read from each member to detect nested containers.
HEAD_BYTES: int = 4096

#: Formats we can enumerate members for.
SUPPORTED_READERS: frozenset[str] = frozenset(
    {"zip", "tar", "gzip", "bzip2", "xz", "lzma1"}
)

#: Formats we can actually extract from (a subset of the readers).
SUPPORTED_EXTRACTORS: frozenset[str] = frozenset({"zip", "tar"})

#: Formats we recognise but cannot extract (external tooling required).
KNOWN_UNREADABLE: frozenset[str] = frozenset(
    {"7z", "rar4", "rar5", "zstd", "lz4", "cab", "arj", "lzh", "zoo", "ar", "iso9660"}
)


class ReaderError(Exception):
    """Raised when an archive cannot be parsed at all."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_ZIP_METHODS: dict[int, str] = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflate",
    zipfile.ZIP_BZIP2: "bzip2",
    zipfile.ZIP_LZMA: "lzma",
}

try:  # pragma: no cover - depends on Python build
    _ZIP_METHODS[zipfile.ZIP_ZSTANDARD] = "zstd"
except AttributeError:  # pragma: no cover
    pass


def _method_label(kind: int) -> str:
    return _ZIP_METHODS.get(kind, f"method-{kind}")


def _tar_label(ti: tarfile.TarInfo) -> str:
    for predicate, label in (
        (ti.isreg, "file"),
        (ti.isdir, "dir"),
        (ti.issym, "symlink"),
        (ti.islnk, "hardlink"),
        (ti.ischr, "chardev"),
        (ti.isblk, "blockdev"),
        (ti.isfifo, "fifo"),
    ):
        if predicate():
            return label
    return "unknown"


def _size_of(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _zip_time(dt: tuple[int, int, int, int, int, int]) -> float | None:
    try:
        return time.mktime(dt + (0, 0, -1))
    except (ValueError, OverflowError, TypeError):
        return None


def read_head(source: object, length: int = HEAD_BYTES) -> bytes:
    """Read up to *length* bytes from an open member stream, never raising."""
    try:
        data = source.read(length)  # type: ignore[union-attr]
        return data if isinstance(data, (bytes, bytearray)) else b""
    except Exception:
        return b""


def _sniff_nested(handle: object) -> str | None:
    head = read_head(handle)
    if not head:
        return None
    found = sniff_bytes(head)
    return None if found in ("unknown", "zip-partial") else found


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------

def _zip_member(zi: zipfile.ZipInfo, preferred: str | None) -> Member:
    declared_utf8 = bool(zi.flag_bits & 0x800)
    mode = (zi.external_attr >> 16) & 0xFFFF
    is_link = (mode & 0o170000) == 0o120000

    raw = zi.orig_filename
    if not isinstance(raw, bytes):
        # Reading back legacy archives hands us an already-decoded str.  Undo
        # zipfile's lossy guess so the heuristics can work on real bytes: cp437
        # round-trips every byte value, so this is lossless.
        codec = "utf-8" if declared_utf8 else "cp437"
        try:
            raw = raw.encode(codec)
        except UnicodeEncodeError:  # pragma: no cover - defensive
            raw = raw.encode("utf-8", "replace")

    declared_utf8 = bool(zi.flag_bits & 0x800)
    hint = "utf-8" if declared_utf8 else preferred
    name, enc = decode_member_name(raw, preferred=hint)
    if declared_utf8:
        enc = f"{enc} (declared)"

    return Member(
        name=name,
        raw_name=raw,
        encoding=enc,
        declared_utf8=declared_utf8,
        is_dir=zi.is_dir(),
        is_symlink=is_link,
        size=max(0, int(zi.file_size or 0)),
        compressed_size=max(0, int(zi.compress_size or 0)),
        mode=(zi.external_attr >> 16) & 0xFFFF,
        mtime=_zip_time(zi.date_time),
        method=_method_label(zi.compress_type),
        encrypted=bool(zi.flag_bits & 0x1),
    )


def _read_zip(
    path: str, preferred: str | None, probe: bool
) -> Archive:
    archive = Archive(path=path, fmt="zip", reader="zip", file_size=_size_of(path))
    with zipfile.ZipFile(path) as zf:
        entries: list[tuple[Member, zipfile.ZipInfo]] = []
        for zi in zf.infolist():
            try:
                entries.append((_zip_member(zi, preferred), zi))
            except Exception as exc:  # tolerate individually corrupt entries
                archive.warnings.append(f"unreadable entry: {exc}")
        if probe:
            for member, zi in entries:
                if member.is_symlink:
                    # A ZIP symlink stores its target as the member payload.
                    try:
                        with zf.open(zi) as handle:
                            member.link_target = (
                                read_head(handle, 4096).decode("utf-8", "replace") or None
                            )
                    except Exception:
                        member.link_target = None
                    continue
                if member.is_dir or member.encrypted or member.size == 0:
                    continue
                try:
                    with zf.open(zi) as handle:
                        member.inner_format = _sniff_nested(handle)
                except Exception:
                    member.inner_format = None
        archive.members = [m for m, _ in entries]
    archive.encrypted = any(m.encrypted for m in archive.members)
    return archive


# ---------------------------------------------------------------------------
# TAR family
# ---------------------------------------------------------------------------

def _read_tar(path: str, fmt: str, preferred: str | None, probe: bool) -> Archive:
    archive = Archive(path=path, fmt=fmt, reader="tar", file_size=_size_of(path))
    with tarfile.open(path, mode="r:*") as tf:
        entries: list[tuple[Member, tarfile.TarInfo]] = []
        for ti in tf.getmembers():
            raw_name = ti.name.encode("utf-8", "replace")
            name, enc = decode_member_name(raw_name, preferred=preferred)
            member = Member(
                name=name,
                raw_name=raw_name,
                encoding=enc,
                declared_utf8=True,
                is_dir=ti.isdir(),
                is_symlink=ti.issym(),
                is_hardlink=ti.islnk(),
                link_target=(ti.linkname or None) if (ti.issym() or ti.islnk()) else None,
                size=max(0, int(ti.size or 0)),
                compressed_size=0,
                mode=int(ti.mode or 0),
                mtime=float(ti.mtime) if ti.mtime is not None else None,
                uid=int(ti.uid or 0),
                gid=int(ti.gid or 0),
                method=_tar_label(ti),
            )
            entries.append((member, ti))
        if probe:
            for member, ti in entries:
                if not member.is_dir and member.size > 0:
                    try:
                        handle = tf.extractfile(ti)
                        if handle is not None:
                            member.inner_format = _sniff_nested(handle)
                    except Exception:
                        member.inner_format = None
        archive.members = [m for m, _ in entries]
    return archive


# ---------------------------------------------------------------------------
# single-file compression streams
# ---------------------------------------------------------------------------

_STREAM_SUFFIXES: tuple[str, ...] = (
    ".tar.gz", ".tar.bz2", ".tar.xz",
    ".tgz", ".tbz2", ".tbz", ".txz",
    ".gz", ".bz2", ".xz", ".lzma",
)


def _stream_stem(name: str) -> str:
    lowered = name.lower()
    for suffix in _STREAM_SUFFIXES:
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _read_stream(path: str, fmt: str) -> Archive:
    """Treat a single-file compression stream as a virtual one-member archive."""
    opener: Callable[[str], object]
    if fmt == "gzip":
        opener = gzip.open
    elif fmt == "bzip2":
        opener = bz2.open
    elif fmt in ("xz", "lzma1"):
        opener = lzma.open
    else:  # pragma: no cover - guarded by open_archive dispatch
        raise ReaderError(f"no reader for {fmt}")

    archive = Archive(path=path, fmt=fmt, reader="stream", file_size=_size_of(path))
    size = 0
    try:
        with opener(path, "rb") as raw:  # type: ignore[operator]
            stream = io.BufferedReader(raw)  # type: ignore[arg-type]
            while True:
                block = stream.read(1 << 20)
                if not block:
                    break
                size += len(block)
    except Exception as exc:
        archive.warnings.append(f"stream read aborted: {exc}")

    stem = _stream_stem(os.path.basename(path))
    archive.members.append(
        Member(name=stem or "payload", size=size, method=fmt),
    )
    return archive


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def open_archive(
    path: str,
    fmt: str,
    *,
    preferred_encoding: str | None = None,
    probe_nested: bool = True,
) -> Archive:
    """Enumerate every member of *path* (side-effect free)."""
    if fmt == "zip":
        return _read_zip(path, preferred_encoding, probe_nested)
    if fmt in ("tar", "gzip", "bzip2", "xz", "lzma1"):
        # A .tar.gz / .tar.xz is a real multi-member archive; a bare stream is
        # handled by the single-file branch below.
        lowered = path.lower()
        if fmt == "tar" or any(
            lowered.endswith(s) for s in (".tar", ".tar.gz", ".tar.bz2", ".tar.xz",
                                         ".tgz", ".tbz", ".tbz2", ".txz")
        ):
            return _read_tar(path, fmt, preferred_encoding, probe_nested)
        return _read_stream(path, fmt)
    raise ReaderError(
        f"unsupported format {fmt!r}: UnpackGuard reads ZIP, TAR and "
        "gz/bz2/xz streams natively"
    )


def iter_nested(archive: Archive) -> Iterator[Member]:
    """Yield members that are themselves a container of files."""
    for m in archive.members:
        if m.inner_format in SUPPORTED_READERS or m.inner_format in KNOWN_UNREADABLE:
            yield m


def guess_encoding_for(raw: bytes) -> str:
    """Public wrapper so the CLI never imports a private helper."""
    return guess_encoding(raw)
