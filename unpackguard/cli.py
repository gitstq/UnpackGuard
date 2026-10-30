"""Command line front-end.

Commands
--------
``sniff``     identify the real format from magic bytes
``inspect``   list members without extracting anything
``scan``      audit an archive and print findings (default command)
``plan``      forecast disk usage before you commit
``extract``   write members out, honouring every safety limit

Exit codes
----------
``0`` everything clean, ``1`` runtime/usage error, ``2`` findings at or above
``--fail-level`` (CI friendly), ``3`` nothing could be parsed.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Sequence

from . import SEVERITY_ORDER, __version__
from .extract import ExtractConfig, Extractor
from .model import worst_severity
from .plan import PlanConfig, build_plan, human_bytes
from .reader import SUPPORTED_READERS, open_archive
from .report import (
    Renderer,
    render_json,
    render_sarif,
    render_text,
    render_text_members,
    render_text_plan,
    render_text_sniff,
    summarise_findings,
)
from .rules import ScanConfig, ScanResult, rule_descriptions, scan_archive
from .safety import PathPolicy
from .sniff import format_label, sniff_file

__all__ = ["build_parser", "main", "run_argv"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2
EXIT_UNPARSEABLE = 3

_LEVELS: tuple[str, ...] = ("none",) + tuple(reversed(SEVERITY_ORDER))


def _positive_size(text: str) -> int:
    """Parse ``10M`` / ``1GiB`` / ``2048`` into bytes."""
    raw = text.strip().lower().replace(" ", "")
    multipliers = {
        "kb": 1024, "k": 1024, "kib": 1024,
        "mb": 1024 ** 2, "m": 1024 ** 2, "mib": 1024 ** 2,
        "gb": 1024 ** 3, "g": 1024 ** 3, "gib": 1024 ** 3,
        "tb": 1024 ** 4, "t": 1024 ** 4, "tib": 1024 ** 4,
    }
    for suffix, factor in multipliers.items():
        if raw.endswith(suffix):
            head = raw[: -len(suffix)]
            try:
                return int(float(head) * factor)
            except ValueError:
                break
    try:
        return int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"cannot parse size {text!r}") from exc


def build_parser() -> argparse.ArgumentParser:
    """Construct the full argument parser."""
    parser = argparse.ArgumentParser(
        prog="unpackguard",
        description=(
            "Extract archives as if someone might be attacking you. "
            "Zero dependencies, fully offline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  unpackguard scan download.zip\n"
            "  unpackguard plan big.tar.gz --dest ./out\n"
            "  unpackguard extract drop.zip --dest ./out --max-total-size 1GiB\n"
            "  unpackguard scan drop.zip --json | jq '.findings'\n"
            "  unpackguard scan drop.zip --sarif > unpackguard.sarif\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"unpackguard {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("archive", help="path to the archive to examine")
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    common.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0")
    common.add_argument("--no-color", action="store_true", help="disable colour output")
    common.add_argument("--encoding", default=None,
                        help="force a filename codec (auto, gbk, big5, shift_jis, cp437, utf-8)")
    common.add_argument("--no-probe", action="store_true",
                        help="skip nested-archive detection (faster on huge archives)")
    common.add_argument("-q", "--quiet", action="store_true", help="only print the verdict")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_sniff = sub.add_parser("sniff", parents=[common],
                             help="detect the real format from magic bytes")
    p_sniff.add_argument("more", nargs="*", metavar="ARCHIVE",
                         help="additional paths to detect")

    p_inspect = sub.add_parser("inspect", parents=[common],
                               help="list members without extracting")
    p_inspect.add_argument("--limit", type=int, default=200,
                           help="maximum members to print (default 200)")

    p_scan = sub.add_parser("scan", parents=[common],
                            help="audit an archive for hostile members (default)")
    _add_scan_flags(p_scan)
    p_scan.add_argument("--list-rules", action="store_true",
                        help="print the rule catalogue and exit")
    p_scan.add_argument("--dest", default=".",
                        help="destination used for path-policy evaluation")

    p_plan = sub.add_parser("plan", parents=[common],
                            help="forecast disk usage before extracting")
    p_plan.add_argument("--dest", default=".", help="planned extraction directory")
    p_plan.add_argument("--reserve", type=float, default=0.05,
                        help="share of free space to keep in reserve (default 0.05)")
    p_plan.add_argument("--include-archive-size", action="store_true", default=True,
                        help=argparse.SUPPRESS)

    p_extract = sub.add_parser("extract", parents=[common],
                               help="extract members under the safety policy")
    _add_policy_flags(p_extract)
    _add_scan_flags(p_extract)
    p_extract.add_argument("--dest", "-C", default="./unpacked",
                           help="destination directory (default ./unpacked)")
    p_extract.add_argument("--dry-run", action="store_true",
                           help="show what would be written, write nothing")
    p_extract.add_argument("--overwrite", choices=("skip", "replace", "rename"),
                           default="rename",
                           help="behaviour on existing files (default rename)")
    p_extract.add_argument("--max-total-size", type=_positive_size, default=0,
                           help="abort once this many bytes have been written")
    p_extract.add_argument("--max-file-size", type=_positive_size, default=0,
                           help="skip members larger than this")
    p_extract.add_argument("--max-files", type=int, default=0,
                           help="abort after writing this many files")
    p_extract.add_argument("--no-perms", action="store_true",
                           help="ignore stored permissions")
    p_extract.add_argument("--no-times", action="store_true",
                           help="ignore stored timestamps")
    p_extract.add_argument("--reserve-space", type=_positive_size, default=0,
                           help="require this much free space before starting")

    return parser


def _add_scan_flags(target: argparse.ArgumentParser) -> None:
    group = target.add_argument_group("audit thresholds")
    group.add_argument("--max-ratio", type=float, default=200.0,
                       help="per-member compression ratio limit (default 200)")
    group.add_argument("--max-total-size-scan", type=_positive_size, default=4 * 1024 ** 3,
                       dest="max_total_scan",
                       help="cumulative uncompressed budget (default 4GiB)")
    group.add_argument("--max-members", type=int, default=100_000,
                       help="abort enumerating beyond this many members")
    group.add_argument("--max-depth", type=int, default=3,
                       help="allowed archive nesting depth (default 3)")
    group.add_argument("--huge-member", type=_positive_size, default=512 * 1024 ** 2,
                       help="single-member size warning threshold (default 512MiB)")
    group.add_argument("--fail-level", choices=_LEVELS, default="high",
                       help="exit 2 when findings reach this severity (default high)")


def _add_policy_flags(target: argparse.ArgumentParser) -> None:
    group = target.add_argument_group("path policy")
    group.add_argument("--flat", action="store_true",
                       help="discard directories and flatten everything")
    group.add_argument("--strip", type=int, default=0, metavar="N",
                       help="drop N leading path components")
    group.add_argument("--reject-absolute", action="store_true",
                       help="reject absolute paths / drive-UNC prefixes instead of rewriting them")
    group.add_argument("--reject-traversal", action="store_true",
                       help="reject members containing '..' instead of rewriting them")
    group.add_argument("--allow-links", action="store_true",
                       help="create symbolic and hard links")
    group.add_argument("--no-strip-ads", action="store_true",
                       help="keep NTFS alternate data stream suffixes")
    group.add_argument("--no-sanitise-windows", action="store_true",
                       help="keep characters illegal on Windows")
    group.add_argument("--case-insensitive-fs", action="store_true",
                       help="assume a case-insensitive filesystem")


def _scan_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        max_ratio=max(0.0, args.max_ratio) if getattr(args, "max_ratio", None) else 0.0,
        max_total_bytes=getattr(args, "max_total_scan", 4 * 1024 ** 3),
        max_members=getattr(args, "max_members", 100_000),
        max_depth=getattr(args, "max_depth", 3),
        huge_member_bytes=getattr(args, "huge_member", 512 * 1024 ** 2),
        case_insensitive_fs=getattr(args, "case_insensitive_fs", False),
    )


def _path_policy(args: argparse.Namespace) -> PathPolicy:
    if not hasattr(args, "flat"):
        return PathPolicy()
    return PathPolicy(
        strip_absolute=not getattr(args, "reject_absolute", False),
        strip_traversal=not getattr(args, "reject_traversal", False),
        strip_ads=not args.no_strip_ads,
        sanitise_windows=not args.no_sanitise_windows,
        allow_links=args.allow_links,
        strip_components=args.strip,
        flatten=args.flat,
        case_insensitive_fs=args.case_insensitive_fs,
    )


def _load(path: str, args: argparse.Namespace) -> tuple[Any, str]:
    fmt = sniff_file(path)
    if fmt == "missing":
        raise SystemExit(f"unpackguard: cannot read {path!r}")
    if fmt not in SUPPORTED_READERS:
        raise SystemExit(
            f"unpackguard: {path!r} looks like {format_label(fmt)} which has no "
            "standard-library reader; convert it or use vendor tooling first"
        )
    enc = args.encoding
    if enc == "auto":
        enc = None
    return open_archive(path, fmt, preferred_encoding=enc,
                        probe_nested=not args.no_probe), fmt


def _renderer(args: argparse.Namespace) -> Renderer:
    return Renderer(color=not args.no_color)


def _should_fail(result: ScanResult, level: str) -> bool:
    if level == "none":
        return False
    worst = result.worst
    if worst is None:
        return False
    order = list(SEVERITY_ORDER)
    return order.index(worst) >= order.index(level)


def _do_sniff(args: argparse.Namespace, r: Renderer) -> int:
    paths = [args.archive, *getattr(args, "more", [])]
    pairs = [(p, sniff_file(p)) for p in paths]
    if args.json:
        render_json(
            [{"path": p, "format": f, "label": format_label(f)} for p, f in pairs], r
        )
        return EXIT_OK
    render_text_sniff(pairs, r)
    unsupported = [p for p, f in pairs if f not in SUPPORTED_READERS]
    if unsupported:
        r.emit("")
        r.emit(r.dim(" unsupported: " + ", ".join(unsupported)))
    return EXIT_OK


def _do_inspect(args: argparse.Namespace, r: Renderer) -> int:
    archive, _ = _load(args.archive, args)
    if args.json:
        render_json(archive.to_dict(), r)
        return EXIT_OK
    render_text_members(archive, args.limit, r)
    return EXIT_OK


def _do_scan(args: argparse.Namespace, r: Renderer) -> int:
    if getattr(args, "list_rules", False):
        if args.json:
            render_json(rule_descriptions(), r)
        else:
            r.emit(r.bold("UnpackGuard rule catalogue"))
            for line in r.table(
                [[name, desc] for d in rule_descriptions()
                 for name, desc in ((d["rule"], d["description"]),)],
                ["RULE", "DESCRIPTION"],
            ):
                r.emit(line)
        return EXIT_OK

    archive, _ = _load(args.archive, args)
    result = scan_archive(archive, _scan_config(args), _path_policy(args))
    if args.sarif:
        render_sarif(result, __version__, r)
        return EXIT_FINDINGS if _should_fail(result, args.fail_level) else EXIT_OK
    if args.json:
        render_json(result.to_dict(), r)
        return EXIT_FINDINGS if _should_fail(result, args.fail_level) else EXIT_OK
    if args.quiet:
        r.emit(
            f"{archive.path}: score={result.score} grade={result.grade} "
            f"({summarise_findings(result.findings)})"
        )
    else:
        render_text(result, r, show_members=False)
    return EXIT_FINDINGS if _should_fail(result, args.fail_level) else EXIT_OK


def _do_plan(args: argparse.Namespace, r: Renderer) -> int:
    archive, _ = _load(args.archive, args)
    plan = build_plan(
        archive, args.dest,
        PlanConfig(reserve_ratio=max(0.0, args.reserve)),
    )
    if args.json:
        render_json(plan.to_dict(), r)
        return EXIT_OK if plan.fits else EXIT_ERROR
    render_text_plan(plan, args.dest, r)
    return EXIT_OK if plan.fits else EXIT_ERROR


def _do_extract(args: argparse.Namespace, r: Renderer) -> int:
    archive, _ = _load(args.archive, args)
    if archive.reader not in ("zip", "tar"):
        raise SystemExit(
            f"unpackguard: {archive.fmt!r} streams have no member to extract; "
            "use `zcat` semantics via the library instead"
        )
    policy = _path_policy(args)
    config = ExtractConfig(
        max_total_bytes=args.max_total_size,
        max_files=args.max_files,
        max_file_bytes=args.max_file_size,
        apply_permissions=not args.no_perms,
        apply_times=not args.no_times,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
        require_free_bytes=args.reserve_space,
        verbose=not args.quiet,
    )
    extractor = Extractor(args.dest, policy, config)
    outcome = extractor.run(archive)

    if args.json:
        render_json(outcome.to_dict(), r)
    elif args.quiet:
        r.emit(
            f"wrote {len(outcome.written)} files "
            f"({human_bytes(outcome.bytes_written)}) to {outcome.dest}"
        )
        if outcome.aborted:
            r.emit(f"aborted: {outcome.aborted}")
    else:
        r.emit(r.bold(f"Extracted -> {os.path.abspath(args.dest)}"))
        r.emit(
            f"  files written : {len(outcome.written):,}\n"
            f"  bytes written : {human_bytes(outcome.bytes_written)}\n"
            f"  dirs created  : {outcome.directories:,}\n"
            f"  skipped       : {len(outcome.skipped):,}\n"
            f"  errors        : {len(outcome.errors):,}"
        )
        if args.dry_run:
            r.emit(r.dim("  dry run -- nothing was written"))
        for m, why in outcome.skipped[:20]:
            r.emit(f"    {r.dim('skip')} {m}: {why}")
        if len(outcome.skipped) > 20:
            r.emit(r.dim(f"    ... {len(outcome.skipped) - 20} more skipped"))
        for m, why in outcome.errors[:10]:
            r.emit(f"    {r.sev('high')} {m}: {why}")
        if outcome.aborted:
            r.emit(f"  {r.sev('medium')} aborted: {outcome.aborted}")

    if outcome.errors or outcome.aborted:
        return EXIT_ERROR
    return EXIT_OK


_DISPATCH = {
    "sniff": _do_sniff,
    "inspect": _do_inspect,
    "scan": _do_scan,
    "plan": _do_plan,
    "extract": _do_extract,
}


def run_argv(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; returns a process exit code.

    When no subcommand is given the default is ``scan`` -- the safest possible
    thing to do with an archive you have not inspected yet.
    """
    raw_args: list[str] = list(argv) if argv is not None else list(sys.argv[1:])
    commands = tuple(_DISPATCH)
    if raw_args and not raw_args[0].startswith("-") and raw_args[0] not in commands:
        raw_args = ["scan", *raw_args]

    parser = build_parser()
    args = parser.parse_args(raw_args)
    if not getattr(args, "archive", None):
        parser.print_help()
        return EXIT_ERROR

    _ensure_defaults(parser, args)
    renderer = _renderer(args)
    handler = _DISPATCH.get(args.command)
    if handler is None:  # pragma: no cover - argparse prevents this
        parser.print_help()
        return EXIT_ERROR
    return handler(args, renderer)


def _ensure_defaults(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Fill attributes that only exist on sibling subparsers."""
    defaults = {
        "limit": 200,
        "max_ratio": 200.0,
        "max_total_scan": 4 * 1024 ** 3,
        "max_members": 100_000,
        "max_depth": 3,
        "huge_member": 512 * 1024 ** 2,
        "fail_level": "high",
        "list_rules": False,
        "dest": ".",
        "reserve": 0.05,
        "dry_run": False,
        "overwrite": "rename",
        "max_total_size": 0,
        "max_file_size": 0,
        "max_files": 0,
        "no_perms": False,
        "no_times": False,
        "reserve_space": 0,
        "more": [],
        "flat": False,
        "strip": 0,
        "reject_absolute": False,
        "reject_traversal": False,
        "allow_links": False,
        "no_strip_ads": False,
        "no_sanitise_windows": False,
        "case_insensitive_fs": False,
    }
    for key, value in defaults.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    _ = parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point installed by ``pyproject.toml``."""
    try:
        return run_argv(argv)
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:  # pragma: no cover
        return EXIT_OK
