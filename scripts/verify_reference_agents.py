#!/usr/bin/env python3
"""Assert that the attack library still detects what it claims to detect.

Run this after changing any attack, any payload, or the ``Scaffold`` interface::

    python scripts/verify_reference_agents.py

Why this exists
---------------
A red-team tool has two failure modes, and only one of them is obvious.

An attack that stops detecting is invisible. Nothing crashes, no test fails, the
scan simply reports fewer findings — and a quieter report looks like progress.
The only way to catch it is to assert against a target *known* to be vulnerable.

An attack that starts detecting things it should not is worse. False positives
do not break a build; they teach reviewers to skim, and after that nothing the
tool says is believed. The only way to catch it is to assert against a target
known to be clean.

So both directions are asserted here, and CI runs this on every commit. The
numbers below are expectations, not hardcoded magic: they are re-derived from
the reference agents each run and compared against a recorded floor.

Exit codes: 0 clean, 1 assertion failed, 2 the scan itself broke.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from a fresh checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quillback.demo import HardenedSupportAgent, VulnerableSupportAgent  # noqa: E402
from quillback.models import ScanReport, Severity  # noqa: E402
from quillback.registry import all_attacks  # noqa: E402
from quillback.runner import run_scan  # noqa: E402

#: Minimum distinct attacks that must fire on the vulnerable agent. A floor
#: rather than an exact count, so adding an attack does not require editing this
#: file — but *losing* one does fail.
MIN_DETECTING_ATTACKS = 16

#: Minimum findings on the vulnerable agent.
MIN_FINDINGS = 15

#: Categories that must be covered. Kept in sync with the library; if you add
#: attacks for a new ASI category, add it here so a regression is caught.
REQUIRED_CATEGORIES = frozenset({"ASI01", "ASI02", "ASI03", "ASI04", "ASI06", "ASI07"})


def main() -> int:
    failures: list[str] = []

    vuln = run_scan(VulnerableSupportAgent())
    hard = run_scan(HardenedSupportAgent())

    for label, report in (("vulnerable", vuln), ("hardened", hard)):
        for r in report.failed_attacks:
            failures.append(f"[{label}] attack raised: {r.attack_id}: {r.error}")

    # -- direction 1: detection still works ---------------------------------
    detecting = {f.attack_id for f in vuln.findings}
    print(f"vulnerable agent : {len(vuln.findings):>3} findings from "
          f"{len(detecting):>2} distinct attacks")

    counts = vuln.by_severity
    print("                   " + ", ".join(
        f"{n} {s.value}" for s, n in counts.items() if n
    ) or "                   none")

    if len(vuln.findings) < MIN_FINDINGS:
        failures.append(
            f"vulnerable agent produced {len(vuln.findings)} findings, "
            f"expected at least {MIN_FINDINGS} — attacks have stopped detecting"
        )
    if len(detecting) < MIN_DETECTING_ATTACKS:
        silent = sorted(
            a.id for a in all_attacks()
            if a.id not in detecting
            and not any(r.attack_id == a.id and r.skipped for r in vuln.results)
        )
        failures.append(
            f"only {len(detecting)} distinct attacks fired, expected at least "
            f"{MIN_DETECTING_ATTACKS}. Silent: {silent}"
        )

    missing_cats = REQUIRED_CATEGORIES - vuln.covered_categories
    if missing_cats:
        failures.append(f"ASI categories no longer covered: {sorted(missing_cats)}")

    # -- direction 2: no false positives ------------------------------------
    print(f"hardened agent   : {len(hard.findings):>3} findings")
    for f in hard.findings:
        failures.append(
            f"false positive on the hardened agent: {f.attack_id} — {f.title}"
        )

    # -- determinism ---------------------------------------------------------
    again = run_scan(VulnerableSupportAgent())
    if _shape(vuln) != _shape(again):
        failures.append("two scans of the same target produced different findings")

    if failures:
        print("\nFAILED")
        for f in failures:
            print(f"  ✗ {f}")
        return 2 if any("raised" in f for f in failures) else 1

    print(
        f"\nOK — {len(detecting)} attacks detect, 0 false positives, "
        f"{len(REQUIRED_CATEGORIES)} ASI categories covered, output deterministic"
    )
    return 0


def _shape(report: ScanReport) -> list[tuple[str, ...]]:
    """A comparable fingerprint of a report, ignoring timing and ordering."""
    return sorted(
        (f.attack_id, f.asi, f.severity.value, f.title) for f in report.findings
    )


if __name__ == "__main__":
    sys.exit(main())
