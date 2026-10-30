"""Renderers for the three supported output formats.

``text``   colourised, human friendly tables (default, CI-safe when not a TTY)
``json``   one stable object per command, ideal for piping into ``jq``
``sarif``  SARIF 2.1.0 for GitHub code scanning / CI annotations
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Iterable, Sequence

from . import SEVERITY_ORDER
from .model import Archive, Finding, Member
from .plan import ExtractionPlan, human_bytes
from .rules import ScanResult
from .sniff import format_label

__all__ = [
    "Renderer",
    "render_text",
    "render_json",
    "render_sarif",
    "SEVERITY_GLYPH",
    "SUPPORTS_COLOR",
]

#: Emoji glyphs keep scanning output readable at a glance.
SEVERITY_GLYPH: dict[str, str] = {
    "critical": "\U0001f6a8",
    "high": "\U0001f534",
    "medium": "\U0001f7e1",
    "low": "\U0001f535",
    "info": "\u2139\ufe0f",
}

GRADE_GLYPH: dict[str, str] = {
    "A": "\U0001f7e2",
    "B": "\U0001f7e2",
    "C": "\U0001f7e1",
    "D": "\U0001f7e0",
    "F": "\U0001f534",
}

_COLORS: dict[str, str] = {
    "critical": "\x1b[1;31m",
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[36m",
    "info": "\x1b[90m",
}
_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"


def SUPPORTS_COLOR(stream: object = None) -> bool:
    """True when colours should be emitted."""
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(getattr(stream, "isatty", lambda: False)())
    except Exception:
        return False


class Renderer:
    """Wraps a stream and remembers whether to colourise."""

    def __init__(self, stream: Any = None, *, color: bool | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.color = SUPPORTS_COLOR(self.stream) if color is None else color

    # -- primitives ---------------------------------------------------------

    def emit(self, text: str = "") -> None:
        print(text, file=self.stream)

    def bold(self, text: str) -> str:
        return f"{_BOLD}{text}{_RESET}" if self.color else text

    def dim(self, text: str) -> str:
        return f"{_DIM}{text}{_RESET}" if self.color else text

    def sev(self, severity: str) -> str:
        glyph = SEVERITY_GLYPH.get(severity, "\u2022")
        label = severity.upper()
        if self.color:
            return f"{_COLORS.get(severity, '')}{glyph} {label}{_RESET}"
        return f"{glyph} {label}"

    def rule(self, char: str = "\u2500", width: int = 78) -> str:
        return char * width

    def table(self, rows: Sequence[Sequence[str]], headers: Sequence[str]) -> list[str]:
        """Render a fixed-width table without external dependencies."""
        cols = len(headers)
        widths = [len(h) for h in headers]
        for row in rows:
            for i in range(cols):
                cell = str(row[i] if i < len(row) else "")
                widths[i] = max(widths[i], len(cell))
        out: list[str] = []
        head = "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
        out.append(self.bold(head))
        out.append("  ".join("\u2500" * widths[i] for i in range(cols)))
        for row in rows:
            cells = [str(row[i] if i < len(row) else "") for i in range(cols)]
            out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)))
        return out


# ---------------------------------------------------------------------------
# text renderers
# ---------------------------------------------------------------------------

def render_text_sniff(results: Sequence[tuple[str, str]], r: Renderer) -> None:
    rows = [[path, fmt, format_label(fmt)] for path, fmt in results]
    r.emit(r.bold("Format detection (magic bytes, not file extension)"))
    for line in r.table(rows, ["PATH", "FORMAT", "LABEL"]):
        r.emit(line)


def render_text_members(archive: Archive, limit: int, r: Renderer) -> None:
    r.emit(r.bold(f"Members of {archive.path}"))
    r.emit(
        r.dim(
            f"format={format_label(archive.fmt)}  "
            f"entries={archive.member_count}  "
            f"files={archive.file_count}  "
            f"unpacked={human_bytes(archive.total_size)}"
        )
    )
    rows: list[list[str]] = []
    for m in archive.members[:limit]:
        kind = "dir" if m.is_dir else ("link" if m.is_symlink or m.is_hardlink else "file")
        extra = []
        if m.inner_format:
            extra.append(f"in:{m.inner_format}")
        if m.encrypted:
            extra.append("enc")
        if not m.declared_utf8 and m.encoding:
            extra.append(m.encoding)
        rows.append([
            m.name[:68],
            kind,
            human_bytes(m.size) if not m.is_dir else "-",
            human_bytes(m.compressed_size) if m.compressed_size else "-",
            " ".join(extra) or "-",
        ])
    for line in r.table(rows, ["NAME", "TYPE", "SIZE", "PACKED", "NOTE"]):
        r.emit(line)
    if archive.member_count > limit:
        r.emit(r.dim(f"... {archive.member_count - limit} more (raise --limit)"))


def render_text_plan(plan: ExtractionPlan, dest: str, r: Renderer) -> None:
    r.emit(r.bold(f"Extraction plan -> {dest}"))
    rows = [
        ["files to write", f"{plan.file_count:,}"],
        ["directories to create", f"{plan.dir_count:,}"],
        ["uncompressed size", human_bytes(plan.total_bytes)],
        ["estimated on disk", human_bytes(plan.estimated_on_disk)],
        ["worst case", human_bytes(plan.worst_case_bytes)],
        ["free space", human_bytes(plan.free_bytes)],
        ["nested archives", f"{plan.nested_archives:,}"],
        ["max nesting depth", str(plan.max_depth)],
        ["verdict", "fits \u2705" if plan.fits else "DOES NOT FIT \u274c"],
    ]
    for line in r.table(rows, ["METRIC", "VALUE"]):
        r.emit(line)
    for note in plan.notes:
        r.emit(f"  {SEVERITY_GLYPH['info']} {note}")


def render_text(result: ScanResult, r: Renderer, *, show_members: bool = False) -> None:
    arc = result.archive
    glyph = GRADE_GLYPH.get(result.grade, "\u2022")
    r.emit(r.bold(f"UnpackGuard scan: {arc.path}"))
    r.emit(
        f"  {r.dim('format')}    {format_label(arc.fmt)}\n"
        f"  {r.dim('members')}   {arc.member_count:,} "
        f"({arc.file_count:,} files)\n"
        f"  {r.dim('expands')}   {human_bytes(arc.total_size)}"
    )
    r.emit("")
    r.emit(
        f"  {r.bold('score')}     {result.score}/100  "
        f"grade {glyph} {result.grade}  "
        f"worst={result.worst or 'none'}"
    )

    counts = result.counts()
    tally = "  ".join(
        f"{SEVERITY_GLYPH[s]} {counts.get(s, 0)}" for s in reversed(SEVERITY_ORDER)
    )
    r.emit(f"  {r.dim('findings')} {tally}")
    r.emit("")
    if not result.findings:
        r.emit(f"  \u2705 No findings. This archive looks well behaved.")
        return

    r.emit(r.bold("Findings"))
    current: str | None = None
    for f in result.findings:
        if f.severity != current:
            current = f.severity
            r.emit("")
            r.emit(f"  {r.sev(current)}")
        location = f" [{f.member}]" if f.member else ""
        r.emit(f"    {r.dim(f.rule)}{location}")
        r.emit(f"      {f.detail}")
        if f.remedy:
            r.emit(f"      {r.dim('remedy:')} {f.remedy}")

    if result.blocked_by_policy:
        r.emit("")
        r.emit(r.bold("Blocked by path policy (would not be written)"))
        rows = [[m.name[:60], code, reason] for m, code, reason in result.blocked_by_policy]
        for line in r.table(rows, ["MEMBER", "CODE", "REASON"]):
            r.emit(line)

    if show_members and result.allowed_by_policy:
        r.emit("")
        r.emit(r.bold("Members accepted by policy"))
        members = result.allowed_by_policy[:40]
        rows = [[m.name[:68], human_bytes(m.size)] for m in members]
        for line in r.table(rows, ["TARGET", "SIZE"]):
            r.emit(line)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(payload: Any, r: Renderer) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False), file=r.stream)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_DESCRIPTIONS: dict[str, str] = {}


def render_sarif(result: ScanResult, tool_version: str, r: Renderer) -> None:
    """Emit SARIF 2.1.0 so the findings land in GitHub code scanning."""
    rules_seen: dict[str, dict[str, str]] = {}
    results: list[dict[str, Any]] = []

    for idx, f in enumerate(result.findings):
        rules_seen[f.rule] = {
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.title},
            "help": {"text": f.remedy or f.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "warning")},
        }
        region = {}
        logical: list[dict[str, Any]] = [{"name": f.member or result.archive.path}]
        if f.member:
            region = {"startLine": 1, "snippet": {"text": f.member}}
        results.append(
            {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.detail},
                "ruleIndex": idx,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_uri(result.archive.path)},
                            "region": region or {"startLine": 1},
                        },
                        "logicalLocations": logical,
                    }
                ],
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "UnpackGuard",
                        "version": tool_version,
                        "informationUri": "https://github.com/gitstq/UnpackGuard",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    print(json.dumps(document, indent=2, ensure_ascii=False), file=r.stream)


def _sarif_uri(path: str) -> str:
    return path.replace("\\", "/")


def summarise_findings(findings: Iterable[Finding]) -> str:
    """One-line summary used by CI logs."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if not counts:
        return "no findings"
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts.get(s)]
    return ", ".join(parts)


def member_rows(members: Sequence[Member]) -> list[dict[str, Any]]:
    """Normalise members for JSON output."""
    return [m.to_dict() for m in members]
