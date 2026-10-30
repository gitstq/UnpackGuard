"""Magic-bytes based archive format detection.

Why not trust the file extension?  Because attackers rename things, because
``foo.bin`` downloaded from a CI artifact is usually a ZIP, and because a
nested attachment inside an archive *never* has a trustworthy extension.

Everything here is a pure function over the first N bytes of a stream: no I/O
policy, no mutation, no dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "Format",
    "MAGIC_TABLE",
    "SNIFF_LEN",
    "sniff_bytes",
    "sniff_file",
    "is_archive_format",
    "format_label",
    "guess_encoding",
    "CANDIDATE_ENCODINGS",
    "looks_utf8",
    "decode_member_name",
]

#: Bytes read for detection.  Generous enough for ISO-9660 (magic at 32769).
SNIFF_LEN: Final[int] = 64 * 1024


@dataclass(frozen=True, slots=True)
class Format:
    """A recognised container format."""

    id: str
    label: str
    #: ``True`` when the Python standard library can extract it natively.
    readable: bool
    extensions: tuple[str, ...]


def _fmt(fid: str, label: str, readable: bool, *extensions: str) -> Format:
    return Format(fid, label, readable, extensions)


#: Ordered magic table.  Order matters: the first match wins, so the most
#: specific signatures must come before the generic ones.
MAGIC_TABLE: Final[tuple[tuple[bytes, int, Format], ...]] = (
    (b"PK\x03\x04", 0, _fmt("zip", "ZIP archive", True, ".zip", ".jar", ".whl", ".apk", ".docx", ".xlsx", ".pptx")),
    (b"PK\x05\x06", 0, _fmt("zip", "ZIP archive (empty)", True, ".zip")),
    (b"PK\x07\x08", 0, _fmt("zip", "ZIP archive (spanned)", True, ".zip", ".z01")),
    (b"7z\xbc\xaf\x27\x1c", 0, _fmt("7z", "7-Zip archive", False, ".7z")),
    (b"Rar!\x1a\x07\x00", 0, _fmt("rar4", "RAR archive (v4)", False, ".rar")),
    (b"Rar!\x1a\x07\x01\x00", 0, _fmt("rar5", "RAR archive (v5)", False, ".rar")),
    (b"\x1f\x8b", 0, _fmt("gzip", "gzip compressed stream", True, ".gz", ".tgz", ".tar.gz")),
    (b"BZh", 0, _fmt("bzip2", "bzip2 compressed stream", True, ".bz2", ".tbz")),
    (b"\xfd7zXZ\x00", 0, _fmt("xz", "XZ compressed stream", True, ".xz", ".txz")),
    (b"\x28\xb5\x2f\xfd", 0, _fmt("zstd", "Zstandard frame", False, ".zst", ".tzst")),
    (b"\x04\x22\x4d\x18", 0, _fmt("lz4", "LZ4 frame", False, ".lz4")),
    (b"\x5d\x00\x00\x80", 0, _fmt("lzma1", "LZMA alone stream", True, ".lzma")),
    (b"MSCF\x00\x00\x00\x00", 0, _fmt("cab", "Microsoft CAB", False, ".cab")),
    (b"\x60\xea", 0, _fmt("arj", "ARJ archive", False, ".arj")),
    (b"LHA\x20", 0, _fmt("lzh", "LHA/LZH archive", False, ".lzh", ".lha")),
    (b"ZOO\x20", 0, _fmt("zoo", "ZOO archive", False, ".zoo")),
    (b"!<arch>\n", 0, _fmt("ar", "Unix ar archive", False, ".a", ".deb")),
    (b"ustar", 257, _fmt("tar", "POSIX tar archive", True, ".tar")),
    (b"CD001", 32769, _fmt("iso9660", "ISO-9660 disc image", False, ".iso")),
    (b"%PDF-", 0, _fmt("pdf", "PDF document", False, ".pdf")),
    (b"\x89PNG\r\n\x1a\n", 0, _fmt("png", "PNG image", False, ".png")),
    (b"\xff\xd8\xff", 0, _fmt("jpeg", "JPEG image", False, ".jpg", ".jpeg")),
    (b"GIF8", 0, _fmt("gif", "GIF image", False, ".gif")),
    (b"SQLite format 3\x00", 0, _fmt("sqlite", "SQLite database", False, ".db", ".sqlite")),
    (b"\x7fELF", 0, _fmt("elf", "ELF executable", False, "", ".so", ".o")),
    (b"MZ", 0, _fmt("pe", "DOS/PE executable", False, ".exe", ".dll", ".msi")),
    (b"#!/", 0, _fmt("shebang", "Script with shebang", False, ".sh", ".py", ".pl", ".rb")),
    (b"\xca\xfe\xba\xbe", 0, _fmt("fat-mach", "Java class / Mach-O FAT", False, ".class")),
    (b"PK", 0, _fmt("zip-partial", "ZIP-like fragment", False, "")),
)

#: Formats that can contain other files (i.e. real archives / containers).
ARCHIVE_FORMATS: Final[frozenset[str]] = frozenset(
    {"zip", "7z", "rar4", "rar5", "tar", "cab", "arj", "lzh", "zoo", "ar", "iso9660"}
)

#: Compressed *single-stream* formats (these may wrap a tar).
STREAM_FORMATS: Final[frozenset[str]] = frozenset(
    {"gzip", "bzip2", "xz", "zstd", "lz4", "lzma1"}
)


def _matches(head: bytes, magic: bytes, offset: int) -> bool:
    if offset + len(magic) > len(head):
        return False
    return head[offset : offset + len(magic)] == magic


def sniff_bytes(head: bytes) -> str:
    """Return the format id for *head*, or ``"unknown"``.

    >>> sniff_bytes(b"PK\\x03\\x04" + b"\\x00" * 100)
    'zip'
    >>> sniff_bytes(b"hello, world")
    'unknown'
    """
    for magic, offset, fmt in MAGIC_TABLE:
        if _matches(head, magic, offset):
            return fmt.id
    return "unknown"


def sniff_file(path: str, *, read_len: int = SNIFF_LEN) -> str:
    """Detect the format of *path* without extracting anything."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(read_len)
    except OSError:
        return "missing"
    return sniff_bytes(head)


def is_archive_format(fmt: str) -> bool:
    """True when *fmt* denotes something that can hold member entries."""
    return fmt in ARCHIVE_FORMATS or fmt in STREAM_FORMATS


def format_label(fmt: str) -> str:
    """Human readable label for a format id."""
    for _, _, f in MAGIC_TABLE:
        if f.id == fmt:
            return f.label
    return fmt


# ---------------------------------------------------------------------------
# File-name encoding heuristics
# ---------------------------------------------------------------------------

#: Legacy ZIP writers predate Unicode and store DOS/OEM bytes.  Ordered by
#: likelihood for a Chinese/Japanese-heavy corpus.
CANDIDATE_ENCODINGS: Final[tuple[str, ...]] = (
    "gb18030",
    "utf-8",
    "big5",
    "shift_jis",
    "euc-kr",
    "cp437",
    "cp1252",
    "latin-1",
)

#: Byte sequences that betray a mis-decoded (mojibake) name.
_MOJIBAKE_MARKERS: Final[tuple[str, ...]] = (
    "\u00c3", "\u00c2", "\ufffd", "\u2018\u00b0",
)


def looks_utf8(raw: bytes) -> bool:
    """Return True when *raw* decodes cleanly as UTF-8.

    Pure-ASCII strings are reported as such (they decode everywhere) but the
    caller usually wants the declared flag from the entry itself.
    """
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _score_candidate(text: str) -> int:
    """Lower is better.  Penalise replacement chars and mojibake markers."""
    score = 0
    score += text.count("\ufffd") * 100
    score += sum(text.count(m) * 20 for m in _MOJIBAKE_MARKERS)
    for ch in text:
        cp = ord(ch)
        # CJK / kana / hangul are strong signals we picked the right codec.
        if 0x4E00 <= cp <= 0x9FFF or 0x3040 <= cp <= 0x30FF or 0xAC00 <= cp <= 0xD7AF:
            score -= 3
        # C1 control block: usually a Latin-1 misread.
        elif 0x80 <= cp <= 0x9F:
            score += 5
    return score


def guess_encoding(raw: bytes) -> str:
    """Pick the most plausible encoding for legacy archive name bytes."""
    if not raw:
        return "utf-8"
    # UTF-8 is only preferred when bit-11 (language encoding flag) says so, so
    # here we treat a clean UTF-8 decode rather than blindly trusting it.
    best_enc, best_score = "cp437", None
    for enc in CANDIDATE_ENCODINGS:
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        score = _score_candidate(text)
        if best_score is None or score < best_score:
            best_enc, best_score = enc, score
    # A clean UTF-8 decode is authoritative when nothing scored badly.
    if looks_utf8(raw) and (best_score is None or best_score >= 0):
        return "utf-8"
    return best_enc


def decode_member_name(
    raw: bytes, *, preferred: str | None = None
) -> tuple[str, str]:
    """Decode *raw* name bytes.

    Returns ``(decoded_text, encoding_used)``.  *preferred* short-circuits the
    heuristic for explicit ``--encoding`` overrides.  Never raises: a last-resort
    ``errors="replace"`` decode guarantees we keep the entry visible.
    """
    if isinstance(raw, str):
        return raw, preferred or "utf-8"
    order: list[str] = []
    if preferred:
        order.append(preferred)
    guessed = guess_encoding(raw)
    if guessed not in order:
        order.append(guessed)
    for enc in CANDIDATE_ENCODINGS:
        if enc not in order:
            order.append(enc)
    for enc in order:
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8(replace)"
