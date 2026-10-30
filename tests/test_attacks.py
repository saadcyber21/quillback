"""The contract every attack must satisfy.

Two properties, asserted for the whole library in one pass:

1. **It fires on the vulnerable reference agent.** An attack that cannot
   demonstrate a real detection is dead weight and gives false confidence in
   coverage numbers.
2. **It stays silent on the hardened reference agent.** An attack that fires
   regardless of controls is a false-positive generator, which is worse than no
   attack — it teaches reviewers to ignore the report.

Any attack satisfying neither is unfinished. This is the test to run after
adding one.
"""

from __future__ import annotations

from quillback.demo import HardenedSupportAgent, VulnerableSupportAgent
from quillback.models import Severity
from quillback.registry import all_attacks
from quillback.runner import run_scan


def test_every_attack_fires_on_the_vulnerable_agent() -> None:
    """Each attack must produce at least one finding, or justify a skip."""
    report = run_scan(VulnerableSupportAgent())

    silent = []
    errored = []
    for result in report.results:
        if result.error:
            errored.append(f"{result.attack_id}: {result.error}")
        elif not result.skipped and not result.findings:
            silent.append(result.attack_id)

    assert not errored, "attacks raised:\n  " + "\n  ".join(errored)
    assert not silent, (
        "these attacks produced no findings against the deliberately vulnerable "
        "reference agent, so they demonstrate nothing:\n  " + "\n  ".join(silent)
    )


def test_no_attack_fires_on_the_hardened_agent() -> None:
    """Zero findings on the hardened variant, by attack id.

    Reported per-id rather than as a total, because "3 findings remain" tells
    you nothing actionable while "these 3 attacks still fire" does.
    """
    report = run_scan(HardenedSupportAgent())

    remaining = {}
    for finding in report.findings:
        remaining.setdefault(finding.attack_id, []).append(finding.title)

    assert not remaining, (
        "these attacks still fire against the hardened agent — either the "
        "control is incomplete or the attack has a false positive:\n"
        + "".join(
            f"  {attack_id}\n" + "".join(f"      - {t}\n" for t in titles)
            for attack_id, titles in sorted(remaining.items())
        )
    )


def test_no_attack_errors_on_either_variant() -> None:
    """An exception inside an attack is a bug, not a finding."""
    for label, agent in (
        ("vulnerable", VulnerableSupportAgent()),
        ("hardened", HardenedSupportAgent()),
    ):
        report = run_scan(agent)
        errors = [f"{r.attack_id}: {r.error}" for r in report.failed_attacks]
        assert not errors, f"{label} variant raised:\n  " + "\n  ".join(errors)


def test_attacks_are_deterministic() -> None:
    """Two scans of the same target must produce identical findings.

    This is the property the whole tool is sold on. If it ever breaks, the CI
    gating story collapses, so it gets an explicit test rather than being
    assumed.
    """
    first = run_scan(VulnerableSupportAgent())
    second = run_scan(VulnerableSupportAgent())

    def key(f):
        return (f.attack_id, f.asi, f.severity.value, f.title)

    assert sorted(map(key, first.findings)) == sorted(map(key, second.findings)), (
        "scan output differed between two runs of the same target"
    )


def test_attack_library_is_internally_consistent() -> None:
    """Unique ids, valid ASI codes, non-empty descriptions."""
    from quillback.asi import BY_CODE

    ids = [a.id for a in all_attacks()]
    assert len(ids) == len(set(ids)), f"duplicate attack ids: {[i for i in ids if ids.count(i) > 1]}"

    for attack in all_attacks():
        assert attack.asi in BY_CODE, f"{attack.id}: unknown ASI {attack.asi!r}"
        assert attack.name, f"{attack.id}: missing name"
        assert len(attack.description) > 40, (
            f"{attack.id}: description too short to be useful in a report"
        )
        assert attack.severity in Severity, f"{attack.id}: invalid severity"


def test_every_attack_declares_its_required_hooks() -> None:
    """``requires`` must name real Scaffold hooks.

    A typo here makes an attack skip forever with a confusing reason, which is
    exactly the kind of silent failure worth catching at import time.
    """
    from quillback.scaffold import Scaffold

    valid = {n for n in dir(Scaffold) if not n.startswith("_")}
    for attack in all_attacks():
        unknown = [h for h in attack.requires if h not in valid]
        assert not unknown, f"{attack.id}: requires unknown hook(s) {unknown}"
