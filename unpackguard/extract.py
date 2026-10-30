"""Policy-driven extraction.

Unlike ``ZipFile.extractall`` / ``TarFile.extractall`` this writer:

* asks :mod:`unpackguard.safety` for permission before every single write,
* honours byte budgets *while* streaming, so a bomb dies mid-stream instead of
  filling the disk,
* never creates symlinks by default,
* reports every skipped entry rather than silently dropping it,
* can optionally re-open nested archives (``--recursive``).

Nothing is written for members the policy rejects.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Iterator

from .model import Archive, Member
from .plan import free_space, human_bytes
from .safety import PathPolicy, apply_policy, safe_join

__all__ = ["ExtractConfig", "ExtractOutcome", "Extractor", "extract_archive"]

#: Size of each streamed read/write block.
CHUNK: int = 1 << 20

#: Default directory mode when the archive does not carry permissions.
DEFAULT_DIR_MODE: int = 0o755
DEFAULT_FILE_MODE: int = 0o644


@dataclass(slots=True)
class ExtractConfig:
    """Limits applied during extraction."""

    max_total_bytes: int = 0            # 0 == unlimited
    max_files: int = 0                  # 0 == unlimited
    max_file_bytes: int = 0             # 0 == unlimited
    apply_permissions: bool = True
    apply_times: bool = True
    dry_run: bool = False
    overwrite: str = "rename"           # skip | replace | rename
    require_free_bytes: int = 0
    verbose: bool = False

    def replace(self, **kw: object) -> "ExtractConfig":
        data = dict(self.__dict__)
        data.update(kw)
        return ExtractConfig(**data)  # type: ignore[arg-type]


@dataclass(slots=True)
class ExtractOutcome:
    """What actually happened."""

    dest: str
    written: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    bytes_written: int = 0
    directories: int = 0
    aborted: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "dest": self.dest,
            "written": list(self.written),
            "written_bytes": self.bytes_written,
            "directories": self.directories,
            "skipped": [{"member": m, "reason": why} for m, why in self.skipped],
            "errors": [{"member": m, "reason": why} for m, why in self.errors],
            "aborted": self.aborted,
        }


class _Budget:
    """Running counters with hard stops."""

    def __init__(self, config: ExtractConfig) -> None:
        self.config = config
        self.bytes_total = 0
        self.files = 0

    def check_file(self, size: int) -> str | None:
        if self.config.max_files and self.files >= self.config.max_files:
            return f"file budget exhausted (limit {self.config.max_files})"
        if self.config.max_file_bytes and size > self.config.max_file_bytes:
            return f"member exceeds --max-file-size ({human_bytes(size)})"
        return None

    def add(self, size: int) -> str | None:
        self.bytes_total += size
        if self.config.max_total_bytes and self.bytes_total > self.config.max_total_bytes:
            return (
                "total budget exhausted after "
                f"{human_bytes(self.bytes_total)}"
            )
        return None


class Extractor:
    """Extracts one archive under a :class:`PathPolicy`."""

    def __init__(
        self,
        dest: str,
        policy: PathPolicy,
        config: ExtractConfig | None = None,
    ) -> None:
        self.dest = os.path.abspath(dest)
        self.policy = policy
        self.config = config or ExtractConfig()
        self.outcome = ExtractOutcome(dest=self.dest)
        self.budget = _Budget(self.config)

    # -- infra --------------------------------------------------------------

    def ensure_dest(self) -> None:
        if self.config.dry_run:
            return
        os.makedirs(self.dest, exist_ok=True)

    def _target(self, member: Member) -> tuple[str, bool]:
        """Return ``(absolute_target, allowed)`` for a member."""
        raw = member.raw_name.decode("utf-8", "replace") if isinstance(
            member.raw_name, bytes
        ) else (member.raw_name or member.name)
        verdict = apply_policy(
            str(raw), self.policy,
            is_dir=member.is_dir,
            is_link=member.is_symlink or member.is_hardlink,
        )
        if verdict.blocked:
            return "", False
        try:
            return safe_join(self.dest, verdict.target), True
        except ValueError:
            return "", False

    def _mkdir(self, path: str, mode: int) -> None:
        if self.config.dry_run:
            return
        os.makedirs(path, exist_ok=True)
        if self.config.apply_permissions:
            try:
                os.chmod(path, self._dir_mode(mode))
            except OSError:
                pass
        self.outcome.directories += 1

    def _dir_mode(self, mode: int) -> int:
        if not mode:
            return DEFAULT_DIR_MODE
        candidate = mode & 0o7777
        # Always keep owner traversal, otherwise later writes fail.
        return candidate | 0o700 if (candidate & 0o700) else candidate | 0o700

    def _unique(self, path: str) -> str:
        policy = self.config.overwrite
        if policy == "replace" or not os.path.exists(path):
            return path
        if policy == "skip":
            return ""
        stem, dot, ext = path.rpartition(".")
        base, suffix = (stem, dot + ext) if dot else (path, "")
        n = 1
        while True:
            candidate = f"{base}.{n}{suffix}"
            if not os.path.exists(candidate):
                return candidate
            n += 1

    # -- extraction entry points -------------------------------------------

    def run(self, archive: Archive) -> ExtractOutcome:
        if os.path.dirname(self.dest) and not self.config.dry_run:
            os.makedirs(self.dest, exist_ok=True)
        if self.config.require_free_bytes:
            have = free_space(self.dest)
            if have < self.config.require_free_bytes:
                self.outcome.aborted = (
                    "not enough free space: need "
                    f"{human_bytes(self.config.require_free_bytes)}, have {human_bytes(have)}"
                )
                return self.outcome

        if archive.reader == "zip":
            self._run_zip(archive)
        elif archive.reader == "tar":
            self._run_tar(archive)
        else:
            self.outcome.aborted = f"cannot extract format {archive.fmt!r}"
        return self.outcome

    # -- ZIP ----------------------------------------------------------------

    def _run_zip(self, archive: Archive) -> None:
        with zipfile.ZipFile(archive.path) as zf:
            pairs = list(zip(archive.members, zf.infolist()))
            for member, zi in pairs:
                if self.outcome.aborted:
                    break
                self._handle_zip_member(zf, member, zi)

    def _handle_zip_member(
        self, zf: zipfile.ZipFile, member: Member, zi: zipfile.ZipInfo
    ) -> None:
        target, ok = self._target(member)
        if not ok:
            self.outcome.skipped.append((member.name, "rejected by path policy"))
            return
        if member.is_dir:
            self._mkdir(target.rstrip(os.sep) or target, member.mode)
            return
        denial = self.budget.check_file(member.size)
        if denial:
            self.outcome.skipped.append((member.name, denial))
            return

        final = self._unique(target)
        if final == "":
            self.outcome.skipped.append((member.name, "exists and --overwrite=skip"))
            return

        if self.config.dry_run:
            self.outcome.written.append(final)
            self.budget.files += 1
            return

        os.makedirs(os.path.dirname(final) or self.dest, exist_ok=True)
        if member.is_symlink or member.is_hardlink:
            self.outcome.skipped.append((member.name, "links disabled by policy"))
            return

        written = 0
        try:
            with zf.open(zi) as src, open(final, "wb") as dst:
                while True:
                    block = src.read(CHUNK)
                    if not block:
                        break
                    dst.write(block)
                    written += len(block)
                    stop = self.budget.add(len(block))
                    if stop:
                        self.outcome.aborted = stop
                        break
        except Exception as exc:
            self.outcome.errors.append((member.name, f"{type(exc).__name__}: {exc}"))
            return

        self._finalise(final, member, written)
        self.outcome.written.append(final)
        self.outcome.bytes_written += written
        self.budget.files += 1

    # -- TAR ----------------------------------------------------------------

    def _run_tar(self, archive: Archive) -> None:
        with tarfile.open(archive.path, mode="r:*") as tf:
            by_name = {ti.name: ti for ti in tf.getmembers()}
            for member in archive.members:
                if self.outcome.aborted:
                    break
                ti = by_name.get(member.name)
                if ti is None:
                    self.outcome.skipped.append((member.name, "entry vanished"))
                    continue
                self._handle_tar_member(tf, member, ti)

    def _handle_tar_member(
        self, tf: tarfile.TarFile, member: Member, ti: tarfile.TarInfo
    ) -> None:
        target, ok = self._target(member)
        if not ok:
            self.outcome.skipped.append((member.name, "rejected by path policy"))
            return
        if member.is_symlink or member.is_hardlink:
            self.outcome.skipped.append((member.name, "links disabled by policy"))
            return
        if ti.isdir():
            self._mkdir(target.rstrip(os.sep) or target, member.mode)
            return
        if not ti.isreg():
            self.outcome.skipped.append((member.name, f"{member.method} not a regular file"))
            return

        denial = self.budget.check_file(member.size)
        if denial:
            self.outcome.skipped.append((member.name, denial))
            return
        final = self._unique(target)
        if final == "":
            self.outcome.skipped.append((member.name, "exists and --overwrite=skip"))
            return
        if self.config.dry_run:
            self.outcome.written.append(final)
            self.budget.files += 1
            return

        os.makedirs(os.path.dirname(final) or self.dest, exist_ok=True)
        written = 0
        try:
            src = tf.extractfile(ti)
            if src is None:
                self.outcome.skipped.append((member.name, "no payload"))
                return
            with src, open(final, "wb") as dst:
                while True:
                    block = src.read(CHUNK)
                    if not block:
                        break
                    dst.write(block)
                    written += len(block)
                    stop = self.budget.add(len(block))
                    if stop:
                        self.outcome.aborted = stop
                        break
        except Exception as exc:
            self.outcome.errors.append((member.name, f"{type(exc).__name__}: {exc}"))
            return

        self._finalise(final, member, written)
        self.outcome.written.append(final)
        self.outcome.bytes_written += written
        self.budget.files += 1

    # -- post processing -----------------------------------------------------

    def _finalise(self, final: str, member: Member, written: int) -> None:
        if self.config.dry_run:
            return
        if self.config.apply_permissions and member.mode:
            mode = member.mode & 0o777
            if not mode:
                mode = DEFAULT_FILE_MODE
            try:
                os.chmod(final, mode)
            except OSError:
                pass
        elif self.config.apply_permissions:
            try:
                os.chmod(final, DEFAULT_FILE_MODE)
            except OSError:
                pass
        if self.config.apply_times and member.mtime:
            try:
                os.utime(final, (member.mtime, member.mtime))
            except (OSError, OverflowError, ValueError):
                pass
        _ = written


def iter_written(outcome: ExtractOutcome) -> Iterator[str]:
    """Convenience iterator over written paths."""
    yield from outcome.written


def extract_archive(
    archive: Archive,
    dest: str,
    policy: PathPolicy,
    config: ExtractConfig | None = None,
) -> ExtractOutcome:
    """One-shot helper mirroring :meth:`Extractor.run`."""
    return Extractor(dest, policy, config or ExtractConfig()).run(archive)
