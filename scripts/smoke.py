#!/usr/bin/env python3
"""End-to-end smoke test: build archives, then exercise every subcommand.

Runs with zero third-party dependencies, exactly the way CI does it:

    python scripts/smoke.py

Exits non-zero when any command misbehaves.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from tests.fixtures import (  # noqa: E402
    write_zip_bomb,
    write_zip_legacy_names,
    write_zip_mixed_attacks,
    write_zip_simple,
    write_zip_traversal,
)


def _run(args: list[str], expect: int, label: str) -> bool:
    proc = subprocess.run(
        [sys.executable, "-m", "unpackguard", *args, "--no-color"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    ok = proc.returncode == expect
    print(f"[{'ok' if ok else 'FAIL'}] {label}: exit={proc.returncode} (want {expect})")
    if not ok:
        print(proc.stdout[-1500:])
        print(proc.stderr[-1500:])
    return ok


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        checks = [
            (["scan", write_zip_simple(tmp)], 0, "scan clean archive"),
            (["scan", write_zip_mixed_attacks(tmp), "--fail-level", "low"], 2, "scan hostile archive"),
            (["inspect", write_zip_legacy_names(tmp)], 0, "inspect legacy names"),
            (["plan", write_zip_bomb(tmp), "--dest", tmp], 0, "plan toxic ratio"),
            (["extract", write_zip_traversal(tmp), "--dest", os.path.join(tmp, "out")], 0, "extract traversal"),
            (["sniff", write_zip_simple(tmp, name="a.zip"), write_zip_bomb(tmp, name="b.zip")], 0, "sniff multiple"),
            (["scan", "--list-rules", write_zip_simple(tmp)], 0, "list rules"),
        ]
        results = [_run(args, expect, label) for args, expect, label in checks]
        print(f"\n{sum(results)}/{len(results)} checks passed")
        return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
