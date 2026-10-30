#!/usr/bin/env python3
"""Assert the CLI's exit codes, which is the contract CI gating depends on.

Usage::

    python scripts/check_exit_codes.py

The contract
------------
``0`` clean scan, ``1`` findings present, ``2`` the scan itself broke.

Keeping 2 distinct from 1 is the part that matters. If a crashed scan reported
the same status as a clean one, a broken build would silently read as a passing
one — the classic CI footgun, and the reason this gets its own check rather than
being folded into the test suite.

Also asserts ``--fail-on`` respects its threshold, since that is what users set
in their pipelines.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import contextlib  # noqa: E402
import io  # noqa: E402

from quillback.cli import main as cli_main  # noqa: E402
from quillback.models import ScanReport, Severity  # noqa: E402
from quillback.runner import run_scan  # noqa: E402
from quillback.demo import HardenedSupportAgent, VulnerableSupportAgent  # noqa: E402


def main() -> int:
    failures: list[str] = []

    def run_cli(argv: list[str]) -> int:
        """Invoke the CLI with its stdout swallowed.

        The JSON and terminal renderers write the whole report, which would bury
        this script's own output. Only the exit status is under test here.
        """
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            return cli_main(argv)

    def check(label: str, got: int, want: int) -> None:
        status = "ok " if got == want else "FAIL"
        print(f"  {status} {label:<52} exit {got} (expected {want})")
        if got != want:
            failures.append(f"{label}: exit {got}, expected {want}")

    print("exit-code contract")

    # Scan the vulnerable demo: findings exist, so 1.
    check(
        "scan --demo (findings present)",
        run_cli(["scan", "--demo", "--quiet", "--format", "json"]),
        1,
    )

    # --fail-on none must never fail the build, even with findings.
    check(
        "scan --demo --fail-on none",
        run_cli(["scan", "--demo", "--quiet", "--format", "json", "--fail-on", "none"]),
        0,
    )

    # A bad target is a broken scan, not a clean one.
    check(
        "scan --target does.not:Exist",
        run_cli(["scan", "--target", "does.not:Exist", "--quiet", "--format", "json"]),
        2,
    )

    # A malformed --target spec is a usage error, also 2.
    check(
        "scan --target malformed",
        run_cli(["scan", "--target", "no-colon-here", "--quiet", "--format", "json"]),
        2,
    )

    print("\nthreshold behaviour")

    vuln = run_scan(VulnerableSupportAgent())
    hard = run_scan(HardenedSupportAgent())

    def exit_for(report: ScanReport, fail_on: str) -> int:
        """Recompute the CLI's exit decision for a report."""
        from quillback.cli import _exit_code

        return _exit_code(report, fail_on)

    has_critical = any(f.severity is Severity.CRITICAL for f in vuln.findings)
    if not has_critical:
        failures.append("the vulnerable agent should produce a critical finding")

    check("vulnerable, --fail-on critical", exit_for(vuln, "critical"), 1)
    check("hardened,   --fail-on any", exit_for(hard, "any"), 0)
    check("hardened,   --fail-on critical", exit_for(hard, "critical"), 0)

    # A scan with a raised attack must report 2 regardless of findings, so that
    # an incomplete scan can never be mistaken for a clean one.
    broken = ScanReport(target="synthetic")
    from quillback.models import AttackResult

    broken.results.append(AttackResult(attack_id="test/x", error="boom"))
    check("scan with a raised attack", exit_for(broken, "any"), 2)

    if failures:
        print(f"\nFAILED — {len(failures)} problem(s)")
        for f in failures:
            print(f"  ✗ {f}")
        return 1

    print("\nOK — exit codes behave as documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
