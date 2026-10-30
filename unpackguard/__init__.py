"""UnpackGuard -- 压缩包安全解压与审计引擎。

UnpackGuard is a zero-dependency, offline-first toolkit that inspects, audits
and *safely* extracts ZIP / TAR-family archives.  Everything runs on the Python
standard library only: no network calls, no third-party packages, no telemetry.

Sub-packages / modules
----------------------
``sniff``    magic-bytes based archive format detection (extension agnostic)
``model``    immutable data carriers (Member, Archive, Finding, Plan)
``safety``   path policy engine (zip-slip, absolute paths, reserved names, links)
``rules``    the audit rule set (UPG001..UPG0xx) and risk scoring
``reader``   archive readers built on ``zipfile`` / ``tarfile``
``plan``     extraction budget: size estimation, disk headroom, worst case
``report``   text / JSON / SARIF renderers
``extract``  policy-enforcing extraction writer
``cli``      command line front-end
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "SEVERITY_ORDER",
    "SEVERITY_WEIGHT",
    "__summary__",
]

#: Canonical ordering from the most benign to the most dangerous severity.
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

#: Deduction applied to the 100-point safety score for every finding.
SEVERITY_WEIGHT: dict[str, int] = {
    "info": 0,
    "low": 2,
    "medium": 8,
    "high": 20,
    "critical": 40,
}

__summary__ = (
    "UnpackGuard - zero-dependency, offline-first archive safety auditing "
    "and policy-driven extraction engine."
)
