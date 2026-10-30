"""Extraction budget forecasting.

``plan`` answers the question every dev asks right before a CI job dies:

    "How much disk do I need, and do I have it?"

The estimate is deliberately pessimistic:

* each file rounds up to a 4 KiB block (the common cluster size),
* each directory carries a 4 KiB inode allowance,
* a worst-case figure adds the size of the archive itself, because most
  extractors keep it next to the output.
"""

from __future__ import annotations

import os
import shutil
from typing import Final

from .model import Archive, ExtractionPlan

__all__ = ["PlanConfig", "PLAN_DEFAULTS", "build_plan", "human_bytes", "free_space"]

#: Allocation unit assumed for adjacency/rounding.
BLOCK: Final = 4096

#: Directory metadata allowance.
DIR_COST: Final = BLOCK

#: Default ``PlanConfig`` values, exposed so callers can render them into docs
#: or build their own config without repeating magic numbers.
PLAN_DEFAULTS: dict[str, object] = {
    "include_archive_size": True,
    "reserve_ratio": 0.05,
}


#: Default settings documented for users and asserted by the test-suite.
PLAN_DEFAULTS: dict[str, object] = {
    "reserve_ratio": 0.05,
    "include_archive_size": True,
    "block_size": BLOCK,
    "dir_cost": DIR_COST,
}


def human_bytes(value: int | float) -> str:
    """Render bytes as a compact human string (binary units).

    >>> human_bytes(2048)
    '2.0 KiB'
    >>> human_bytes(0)
    '0 B'
    """
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "?"
    if n < 0:
        return "-"
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(n)} B"
    return f"{n:.1f} {units[idx]}"


def free_space(target: str) -> int:
    """Free bytes available for *target* (its parent when the path is new)."""
    probe = target
    while not os.path.exists(probe):
        parent = os.path.dirname(os.path.abspath(probe))
        if parent == probe:
            break
        probe = parent
    try:
        return shutil.disk_usage(probe).free
    except OSError:
        return 0


def _ceil_blocks(size: int) -> int:
    if size <= 0:
        return 0
    return ((size + BLOCK - 1) // BLOCK) * BLOCK


class PlanConfig:
    """Simple value object for plan-time knobs."""

    __slots__ = ("include_archive_size", "reserve_ratio")

    def __init__(
        self, include_archive_size: bool = True, reserve_ratio: float = 0.05
    ) -> None:
        self.include_archive_size = include_archive_size
        self.reserve_ratio = reserve_ratio


def build_plan(
    archive: Archive,
    dest: str,
    config: PlanConfig | None = None,
) -> ExtractionPlan:
    """Predict the resource cost of extracting *archive* into *dest*."""
    config = config or PlanConfig()

    files = [m for m in archive.members if not m.is_dir]
    dirs = [m for m in archive.members if m.is_dir]

    total_bytes = sum(max(0, m.size) for m in files)
    nested = [m for m in archive.members if m.inner_format]
    max_depth = archive.max_depth

    estimated = _ceil_blocks(total_bytes) + len(dirs) * DIR_COST
    if config.include_archive_size:
        estimated += _ceil_blocks(archive.file_size)

    worst = estimated + _ceil_blocks(total_bytes)
    if config.include_archive_size:
        worst += _ceil_blocks(archive.file_size)

    free = free_space(dest)
    reserve = int(free * config.reserve_ratio) if config.reserve_ratio else 0
    fits = worst <= max(0, free - reserve)

    notes: list[str] = []
    if total_bytes == 0 and not archive.members:
        notes.append("the archive declares no members at all")
    if nested:
        notes.append(
            f"{len(nested)} member(s) are themselves archives; use --recursive "
            "to include their contents in this budget"
        )
    if archive.file_size and total_bytes:
        try:
            overall = total_bytes / max(1, archive.file_size)
            if overall > 100:
                notes.append(
                    f"overall expansion is {overall:,.0f}x -- verify the source "
                    "looks legitimate"
                )
        except ZeroDivisionError:  # pragma: no cover
            pass
    if max_depth > 3:
        notes.append(f"nesting reaches {max_depth} layers")
    if not fits:
        notes.append(
            f"worst case needs {human_bytes(worst)} but only "
            f"{human_bytes(free)} is free"
        )

    return ExtractionPlan(
        file_count=len(files),
        dir_count=len(dirs),
        total_bytes=total_bytes,
        estimated_on_disk=estimated,
        free_bytes=free,
        worst_case_bytes=worst,
        nested_archives=len(nested),
        max_depth=max_depth,
        fits=fits,
        notes=notes,
    )
