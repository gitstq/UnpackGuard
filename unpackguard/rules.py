"""The UnpackGuard audit rule set and risk scoring.

Every check is a small, pure function of a :class:`~unpackguard.model.Member`
plus a frozen :class:`ScanConfig`.  Rules never touch the filesystem, which
means ``scan`` is completely side-effect free and safe to run on untrusted
input -- including in CI.

Rule catalogue
--------------
===========  ==================================================  ==========
Rule         Meaning                                             Severity
===========  ==================================================  ==========
UPG001       ``..`` parent traversal (zip-slip)                  critical
UPG002       POSIX absolute path                                 high
UPG003       Windows drive / UNC path                            high
UPG004       NTFS alternate data stream                          high
UPG005       symbolic or hard link                               high
UPG006       link target escapes the destination                 critical
UPG007       reserved Windows device name                        medium
UPG008       control characters in the name                      high
UPG009       path outlives normalisation to ``..``               critical
UPG010       member compression ratio above threshold            high
UPG011       cumulative uncompressed size above budget           high
UPG012       archive nesting deeper than allowed                 medium
UPG013       executable / script payload                         medium
UPG014       sensitive location (``.git``, ``.ssh``, keys)        high
UPG015       legacy / mojibake filename encoding                 low
UPG016       duplicate member names                              medium
UPG017       case-insensitive collision                          medium
UPG018       setuid / setgid bit set                             high
UPG019       world-writable entry                                low
UPG020       encrypted member cannot be audited                  medium
UPG021       implausible timestamp                               low
UPG022       special file (fifo / device node)                   medium
UPG023       secret-looking filename                             medium
UPG024       bidi / zero-width characters in the name            high
UPG025       misleading extension (double / right-to-left)       medium
UPG026       trailing dot or space (Windows truncation)          low
===========  ==================================================  ==========
"""

from __future__ import annotations

import os
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterable

from . import SEVERITY_WEIGHT
from .model import Archive, Finding, Member, worst_severity
from .safety import PathPolicy, apply_policy

__all__ = [
    "ScanConfig",
    "ScanResult",
    "RULE_INDEX",
    "scan_archive",
    "rule_descriptions",
]

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Thresholds driving the rule set.  Immutable so results are reproducible."""

    #: Per-member compression ratio above which we cry bomb.
    max_ratio: float = 200.0
    #: Cumulative uncompressed budget.  ``0`` disables the check.
    max_total_bytes: int = 4 * 1024 ** 3
    #: Maximum number of members tolerated.
    max_members: int = 100_000
    #: Maximum nesting of archives inside archives.
    max_depth: int = 3
    #: Floor for the "single member is huge" heuristic.
    huge_member_bytes: int = 512 * 1024 ** 2
    #: Emit low-severity informational findings too.
    include_info: bool = True
    #: Case-insensitive filesystem assumption (macOS / Windows).
    case_insensitive_fs: bool = False

    def replace(self, **kw: object) -> "ScanConfig":
        data = dict(self.__dict__)
        data.update(kw)
        return ScanConfig(**data)  # type: ignore[arg-type]


@dataclass(slots=True)
class ScanResult:
    """Outcome of a scan."""

    archive: Archive
    findings: list[Finding]
    score: int
    grade: str
    allowed_by_policy: list[Member]
    blocked_by_policy: list[tuple[Member, str, str]]

    @property
    def worst(self) -> str | None:
        return worst_severity(self.findings)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, object]:
        return {
            "archive": self.archive.path,
            "format": self.archive.fmt,
            "score": self.score,
            "grade": self.grade,
            "worst": self.worst,
            "counts": self.counts(),
            "blocked": [
                {"member": m.name, "code": code, "reason": reason}
                for m, code, reason in self.blocked_by_policy
            ],
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# character-level helpers
# ---------------------------------------------------------------------------

_BIDI_ZW_RANGES: tuple[tuple[int, int], ...] = (
    (0x202A, 0x202E),  # LRE RLO PDF etc.
    (0x2066, 0x2069),  # isolates
    (0x200E, 0x200F),  # LRM / RLM
    (0x200B, 0x200D),  # zero width space/joiners
    (0xFEFF, 0xFEFF),  # BOM inside a name
)

_EXEC_EXT: frozenset[str] = frozenset(
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
        ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".app", ".dmg", ".pkg",
        ".deb", ".rpm", ".so", ".dylib", ".bin", ".run", ".sh", ".jar", ".class",
        ".pyc", ".pyz", ".elf", ".apk", ".ipa", ".hta", ".lnk", ".scpt",
    }
)

_SECRET_NAMES: frozenset[str] = frozenset(
    {
        ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd",
        ".netrc", ".npmrc", ".pypirc", "credentials", "secrets.yaml",
        "secrets.yml", ".aws/credentials", "kubeconfig", "shadow", "passwd",
        "master.key", "application.properties", ".git-credentials",
    }
)

_SENSITIVE_PREFIXES: tuple[str, ...] = (
    ".git/", ".ssh/", ".aws/", ".gnupg/", ".kube/", ".docker/", ".config/gcloud/",
)

#: extensions that look harmless but execute anyway
_DOUBLE_EXT_RE: re.Pattern[str] = re.compile(
    r"\.(tar|zip|gz|bz2|xz|7z|rar|pdf|png|jpg|jpeg|gif|txt|md|docx|xlsx)\."
    r"(exe|scr|bat|cmd|ps1|js|vbs|jar|sh|com|lnk|hta)$",
    re.IGNORECASE,
)


_DRIVE_PREFIX_RE: Final = re.compile(r"^[A-Za-z]:")


def _split_ads(name: str) -> tuple[str, str | None]:
    """Return ``(base, stream)`` for NTFS alternate data streams.

    Unlike a naive ``partition(":")`` this ignores the Windows drive-letter
    colon, so ``C:/Windows/evil.dll`` is not mistaken for a stream.
    """
    candidate = name
    if _DRIVE_PREFIX_RE.match(candidate):
        candidate = candidate[2:]
    head, sep, tail = candidate.partition(":")
    if not sep:
        return name, None
    return head, tail or None


def has_sneaky_char(name: str) -> tuple[bool, bool]:
    """Return ``(has_bidi_or_zw, has_confusable)``."""
    bidi = False
    confusable = False
    has_latin = any("LATIN" in unicodedata.name(ch, "") for ch in name)
    for ch in name:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in _BIDI_ZW_RANGES):
            bidi = True
        try:
            nm = unicodedata.name(ch)
        except ValueError:
            continue
        if has_latin and ("CYRILLIC" in nm or "GREEK" in nm or "ARMENIAN" in nm):
            confusable = True
    return bidi, confusable


def _extension(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def _is_exec_like(member: Member) -> bool:
    if member.is_symlink or member.is_hardlink:
        return False
    if _extension(member.name) in _EXEC_EXT:
        return True
    return False


def _mode_bits(member: Member) -> tuple[bool, bool]:
    setid = bool(member.mode & 0o6000)
    world_writable = bool(member.mode & 0o002)
    return setid, world_writable


# ---------------------------------------------------------------------------
# the rule catalogue
# ---------------------------------------------------------------------------

RULE_INDEX: dict[str, str] = {
    "UPG001": "parent-directory traversal ('..') in member path",
    "UPG002": "absolute POSIX path in member name",
    "UPG003": "Windows drive letter or UNC path",
    "UPG004": "NTFS alternate data stream suffix",
    "UPG005": "symbolic or hard link member",
    "UPG006": "link target escapes the destination",
    "UPG007": "reserved Windows device name",
    "UPG008": "control characters in member name",
    "UPG009": "member resolves outside the destination after normalisation",
    "UPG010": "member compression ratio exceeds the configured threshold",
    "UPG011": "cumulative uncompressed size exceeds the configured budget",
    "UPG012": "archive nesting deeper than the configured maximum",
    "UPG013": "executable or script payload included",
    "UPG014": "member targets a sensitive location",
    "UPG015": "legacy / mojibake filename encoding detected",
    "UPG016": "duplicate member names",
    "UPG017": "case-insensitive filename collision",
    "UPG018": "setuid / setgid permission bit set",
    "UPG019": "world-writable entry",
    "UPG020": "encrypted member could not be audited",
    "UPG021": "implausible modification timestamp",
    "UPG022": "special file (fifo / character or block device)",
    "UPG023": "secret-looking filename",
    "UPG024": "bidi control or zero-width character in the name",
    "UPG025": "misleading double extension",
    "UPG026": "trailing dot or space (truncated on Windows)",
}


def rule_descriptions() -> list[dict[str, str]]:
    """Machine-readable rule catalogue (used by ``scan --list-rules``)."""
    return [{"rule": k, "description": v} for k, v in RULE_INDEX.items()]


def _f(
    rule: str, severity: str, detail: str, member: str | None = None, remedy: str = ""
) -> Finding:
    return Finding(rule, severity, RULE_INDEX[rule], detail, member, remedy)


# ---------------------------------------------------------------------------
# scan driver
# ---------------------------------------------------------------------------

def scan_archive(
    archive: Archive,
    config: ScanConfig,
    policy: PathPolicy | None = None,
) -> ScanResult:
    """Run every rule against *archive* and return findings + a 0-100 score."""
    policy = policy or PathPolicy()
    findings: list[Finding] = []
    allowed: list[Member] = []
    blocked: list[tuple[Member, str, str]] = []

    seen: dict[str, int] = {}
    seen_ci: dict[str, str] = {}
    cumulative = 0
    cumulative_flagged = False

    for member in archive.members:
        name = member.name

        # ---- structural / path related -------------------------------------
        raw = member.raw_name.decode("utf-8", "replace") if isinstance(
            member.raw_name, bytes
        ) else str(member.raw_name or name)

        verdict = apply_policy(
            raw, policy, is_dir=member.is_dir,
            is_link=member.is_symlink or member.is_hardlink,
        )
        if verdict.blocked:
            blocked.append((member, verdict.code, verdict.reason))
        else:
            allowed.append(member)

        if verdict.code in ("path-traversal", "unc-path"):
            findings.append(_f(
                "UPG001", "critical",
                f"{name!r} escapes the destination with '..'", name,
                "extract with --strip-traversal or reject the archive",
            ))
        if ".." in raw.replace("\\", "/").split("/"):
            findings.append(_f(
                "UPG001", "critical",
                f"{name!r} contains a '..' component", name,
                "reject or extract with --no-traversal dropped components",
            ))
        if verdict.code == "absolute-path" and raw.startswith("/"):
            findings.append(_f(
                "UPG002", "high", f"{name!r} is an absolute POSIX path", name,
                "extract with --strip-absolute to rewrite it under the destination",
            ))
        if verdict.code in ("absolute-path", "unc-path"):
            findings.append(_f(
                "UPG003", "high",
                f"{name!r} is drive-qualified or a UNC path", name,
                "never extract such archives on Windows without --strip-absolute",
            ))
        head, ads = _split_ads(raw)
        if ads:
            findings.append(_f(
                "UPG004", "high",
                f"{name!r} carries NTFS stream ': {ads}'", name,
                "strip ADS with --strip-ads before writing to Windows targets",
            ))
        if member.is_symlink or member.is_hardlink:
            kind = "symlink" if member.is_symlink else "hard link"
            findings.append(_f(
                "UPG005", "high", f"{name!r} is a {kind}", name,
                "only enable links with --allow-links when you trust the source",
            ))
            target = member.link_target or ""
            if target.startswith("/") or ".." in target.split("/"):
                findings.append(_f(
                    "UPG006", "critical",
                    f"link {name!r} points at {target!r} outside the destination",
                    name, "reject: this escapes any sandbox after extraction",
                ))
        if any(ch in raw for ch in ('<', '>', '"', '|', '?', '*')):
            findings.append(_f(
                "UPG007", "medium",
                f"{name!r} uses characters reserved by Windows", name,
                "sanitise with --sanitise-windows",
            ))
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
            findings.append(_f(
                "UPG008", "high",
                f"{name!r} contains control characters", name,
                "reject: control characters poison logs and shell pipelines",
            ))
        norm = posixpath.normpath("/" + raw.lstrip("/")).lstrip("/")
        if norm.startswith("../"):
            findings.append(_f(
                "UPG009", "critical",
                f"{name!r} still escapes after normalisation", name,
                "reject the archive",
            ))

        reserved_stem = posixpath.basename(raw).split(".")[0].upper()
        if reserved_stem in (
            {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)}
            | {f"LPT{i}" for i in range(1, 10)}
        ):
            findings.append(_f(
                "UPG007", "medium",
                f"{name!r} uses a reserved Windows device name", name,
                "rename or drop with --sanitise-windows",
            ))

        # ---- size / bomb related -------------------------------------------
        cumulative += max(0, member.size)
        ratio = member.ratio
        if config.max_ratio and ratio != float("inf") and ratio > config.max_ratio:
            findings.append(_f(
                "UPG010", "high",
                f"{name!r} expands {ratio:,.0f}x ({member.compressed_size:,} B on "
                f"disk -> {member.size:,} B)",
                name, "classic zip-bomb signature; raise --max-ratio only knowingly",
            ))
        elif member.size >= config.huge_member_bytes:
            findings.append(_f(
                "UPG010", "medium",
                f"{name!r} expands to {member.size:,} bytes", name,
                "verify available disk with `plan` before extracting",
            ))
        if config.max_total_bytes and not cumulative_flagged and cumulative > config.max_total_bytes:
            findings.append(_f(
                "UPG011", "high",
                f"archive expands to {cumulative:,} bytes, over the "
                f"{config.max_total_bytes:,} byte budget", None,
                "raise --max-total-size or plan for more free space",
            ))
            cumulative_flagged = True
        if member.depth > config.max_depth:
            findings.append(_f(
                "UPG012", "medium",
                f"{name!r} sits {member.depth} archive layers deep", name,
                "nested bombs hide here; cap with --max-depth",
            ))
        if member.inner_format:
            findings.append(_f(
                "UPG012", "low",
                f"{name!r} is itself a {member.inner_format} archive", name,
                "use --recursive if you intend to unpack it too",
            ))

        # ---- content nature -------------------------------------------------
        if _is_exec_like(member) and not member.is_dir:
            findings.append(_f(
                "UPG013", "medium",
                f"{name!r} is an executable payload", name,
                "review before running anything you just extracted",
            ))
        lowered = name.lower()
        if lowered.startswith(_SENSITIVE_PREFIXES):
            findings.append(_f(
                "UPG014", "high",
                f"{name!r} writes into a sensitive directory", name,
                "unexpected in a distributable archive",
            ))
        if posixpath.basename(name) in _SECRET_NAMES:
            findings.append(_f(
                "UPG023", "medium",
                f"{name!r} looks like a credential file", name,
                "credentials should never ship inside an archive",
            ))
        if member.encoding.startswith(("gb18030", "big5", "shift_jis", "cp437", "cp1252")):
            findings.append(_f(
                "UPG015", "low",
                f"{name!r} decoded as {member.encoding} (legacy codec)", name,
                "pass --encoding auto (default) or --encoding gbk to force repairs",
            ))
        if member.encrypted:
            findings.append(_f(
                "UPG020", "medium",
                f"{name!r} is password protected and cannot be audited", name,
                "scan encrypted members manually once decrypted",
            ))

        # ---- metadata -------------------------------------------------------
        setid, world_writable = _mode_bits(member)
        if setid:
            findings.append(_f(
                "UPG018", "high",
                f"{name!r} sets mode {member.mode:04o} (setuid/setgid)", name,
                "setuid bits are a privilege escalation vector",
            ))
        if world_writable and config.include_info:
            findings.append(_f(
                "UPG019", "low",
                f"{name!r} is world-writable (mode {member.mode:04o})", name,
                "use --no-perms to ignore stored permissions",
            ))
        if member.mtime is not None and (member.mtime <= 0 or member.mtime > 4_102_444_800):
            findings.append(_f(
                "UPG021", "low",
                f"{name!r} has an implausible timestamp ({member.mtime!r})", name,
                "harmless but often a sign of a hand-crafted archive",
            ))
        if member.method in ("chardev", "blockdev", "fifo"):
            findings.append(_f(
                "UPG022", "medium",
                f"{name!r} is a {member.method} node", name,
                "device nodes should not appear in distributable archives",
            ))

        bidi, confusable = has_sneaky_char(name)
        if bidi:
            findings.append(_f(
                "UPG024", "high",
                f"{name!r} contains invisible bidi / zero-width characters", name,
                "Trojan-Source style spoofing; reject or rename before trusting it",
            ))
        if confusable:
            findings.append(_f(
                "UPG024", "medium",
                f"{name!r} mixes look-alike scripts (homoglyphs)", name,
                "visually indistinguishable from another file",
            ))
        if _DOUBLE_EXT_RE.search(name):
            findings.append(_f(
                "UPG025", "medium",
                f"{name!r} hides an executable behind a document extension", name,
                "Windows hides the real extension by default",
            ))
        base = posixpath.basename(name)
        if base not in ("", ".", "..") and base != base.rstrip(" ."):
            findings.append(_f(
                "UPG026", "low",
                f"{name!r} ends with a dot or space, truncated on Windows", name,
                "sanitise with --sanitise-windows",
            ))

        # ---- duplicates ------------------------------------------------------
        key = name.rstrip("/")
        seen[key] = seen.get(key, 0) + 1
        if seen[key] == 2:
            findings.append(_f(
                "UPG016", "medium",
                f"{name!r} appears more than once in the archive", name,
                "later entries silently win; tools disagree on which",
            ))
        ci_key = key.lower()
        if ci_key in seen_ci and seen_ci[ci_key] != key:
            findings.append(_f(
                "UPG017",
                "medium" if config.case_insensitive_fs else "low",
                f"{name!r} collides with {seen_ci[ci_key]!r} on "
                "case-insensitive filesystems", name,
                "one of the two will be lost on macOS / Windows",
            ))
        else:
            seen_ci[ci_key] = key

    # ---- archive level checks ----------------------------------------------
    if config.max_members and archive.member_count > config.max_members:
        findings.append(_f(
            "UPG011", "high",
            f"archive declares {archive.member_count:,} members, more than the "
            f"{config.max_members:,} limit", None,
            "raise --max-files if this is legitimate",
        ))
    if not archive.members:
        findings.append(_f(
            "UPG015", "info", "archive contains no members", None,
            "empty archives are usually a broken upload",
        ))

    if not config.include_info:
        findings = [f for f in findings if f.severity != "info"]

    findings.sort(key=lambda f: (-_rank(f.severity), f.rule, f.member or ""))
    score = _score_of(findings)
    return ScanResult(archive, findings, score, _grade(score), allowed, blocked)


def _rank(sev: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 0)


def _score_of(findings: Iterable[Finding]) -> int:
    """Deduct per finding, capped per rule so one rule cannot dominate."""
    total = 0
    per_rule: dict[str, int] = {}
    for f in findings:
        weight = SEVERITY_WEIGHT.get(f.severity, 0)
        cap = weight * 3
        used = per_rule.get(f.rule, 0)
        applied = min(weight, max(0, cap - used))
        per_rule[f.rule] = used + applied
        total += applied
    return max(0, 100 - total)


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


#: Convenience: expose the callable type used by plugin-style rules (unused but
#: documented so third parties can see the expected signature).
RuleFn = Callable[[Member, ScanConfig], Finding | None]
