"""Tests for SARIF output.

SARIF is worth testing properly because it is the integration that gets this
tool into a repository's GitHub Security tab, and GitHub rejects malformed
documents silently-ish — you upload, nothing appears, and you lose an afternoon.

These tests check the structural invariants GitHub actually enforces rather than
validating against the full JSON schema, which would need a dependency.
"""

from __future__ import annotations

import json

from quillback.demo import HardenedSupportAgent, VulnerableSupportAgent
from quillback.registry import all_attacks
from quillback.runner import run_scan
from quillback.sarif import dumps, to_sarif


def test_sarif_document_has_required_top_level_shape() -> None:
    doc = to_sarif(run_scan(VulnerableSupportAgent()))

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1

    run = doc["runs"][0]
    assert "tool" in run and "driver" in run["tool"]
    assert "results" in run
    assert "invocations" in run


def test_every_rule_declared_even_when_it_produced_nothing() -> None:
    """GitHub shows '0 results' for declared rules, silence for undeclared ones.

    Without this, a fixed finding disappears instead of visibly resolving, and
    nobody can tell whether the control worked or the attack stopped running.
    """
    doc = to_sarif(run_scan(HardenedSupportAgent()))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}

    assert rule_ids == {a.id for a in all_attacks()}, (
        "rule set must match the attack library exactly"
    )
    assert doc["runs"][0]["results"] == [], "hardened target should produce no results"


def test_results_reference_declared_rules() -> None:
    doc = to_sarif(run_scan(VulnerableSupportAgent()))
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}

    assert run["results"], "the vulnerable target should produce results"
    for result in run["results"]:
        assert result["ruleId"] in rule_ids, (
            f"result references undeclared rule {result['ruleId']!r}"
        )


def test_levels_are_valid_sarif_values() -> None:
    doc = to_sarif(run_scan(VulnerableSupportAgent()))
    valid = {"none", "note", "warning", "error"}

    for result in doc["runs"][0]["results"]:
        assert result["level"] in valid, f"invalid SARIF level {result['level']!r}"


def test_severities_carry_numeric_security_severity() -> None:
    """GitHub's UI sorts and filters on this property."""
    doc = to_sarif(run_scan(VulnerableSupportAgent()))

    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        value = rule["properties"]["security-severity"]
        assert isinstance(value, str) and value, f"{rule['id']}: missing security-severity"
        float(value)  # must parse as a number


def test_asi_mapping_and_tags_present_on_rules() -> None:
    doc = to_sarif(run_scan(VulnerableSupportAgent()))

    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        tags = rule["properties"]["tags"]
        assert any(t.startswith("owasp-asi:ASI") for t in tags), (
            f"{rule['id']}: no OWASP ASI tag"
        )


def test_results_carry_evidence_and_stable_fingerprints() -> None:
    """Evidence makes a finding actionable; fingerprints make it dedupe."""
    doc = to_sarif(run_scan(VulnerableSupportAgent()))
    results = doc["runs"][0]["results"]

    fingerprints = set()
    for result in results:
        props = result["properties"]
        assert props["evidence"], f"{result['ruleId']}: no evidence in SARIF output"
        assert props["payload"], f"{result['ruleId']}: no payload recorded"
        assert props["owasp-asi"].startswith("ASI")

        fp = result["partialFingerprints"]["primaryLocationLineHash"]
        assert len(fp) == 32
        fingerprints.add(fp)

    # Two distinct findings should not collapse into one via a weak fingerprint.
    assert len(fingerprints) == len(results), (
        "fingerprint collision: distinct findings would dedupe into one"
    )


def test_fingerprints_are_stable_across_runs() -> None:
    """Dedup only works if the same finding hashes the same every time."""
    first = to_sarif(run_scan(VulnerableSupportAgent()))["runs"][0]["results"]
    second = to_sarif(run_scan(VulnerableSupportAgent()))["runs"][0]["results"]

    fp = lambda rs: sorted(r["partialFingerprints"]["primaryLocationLineHash"] for r in rs)
    assert fp(first) == fp(second), "fingerprints changed between identical scans"


def test_every_result_has_a_physical_location() -> None:
    """GitHub code scanning rejects the whole file without one.

    Regression test. The exporter originally emitted only logicalLocations,
    which is valid SARIF and reads as sufficient. The upload then succeeded and
    the analysis failed server-side with 'expected a physical location' repeated
    per result, so the symptom was an empty Security tab and a red step with no
    useful message. The project's own validator passed the document, because it
    checked the spec rather than what the consumer enforces.
    """
    doc = to_sarif(run_scan(VulnerableSupportAgent()))

    for result in doc["runs"][0]["results"]:
        locations = result.get("locations") or []
        physical = [
            loc for loc in locations if loc.get("physicalLocation")
        ]
        assert physical, f"{result['ruleId']}: no physical location"

        pl = physical[0]["physicalLocation"]
        assert pl["artifactLocation"]["uri"], f"{result['ruleId']}: no artifact uri"
        start = pl["region"]["startLine"]
        assert isinstance(start, int) and start >= 1, (
            f"{result['ruleId']}: startLine must be a positive int, got {start!r}"
        )


def test_findings_are_anchored_to_a_real_file() -> None:
    """The default location must be the target's own source file.

    Anchoring to a synthetic path would upload fine and then point a reviewer at
    a file that does not exist, which is worse than no location.
    """
    from pathlib import Path

    report = run_scan(VulnerableSupportAgent())
    for finding in report.findings:
        assert finding.location, f"{finding.attack_id}: no location"
        assert Path(finding.location).exists(), (
            f"{finding.attack_id}: location {finding.location!r} is not a real file"
        )


def test_validator_script_rejects_a_missing_physical_location(tmp_path=None) -> None:
    """The standalone validator must catch what GitHub catches."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    doc = to_sarif(run_scan(VulnerableSupportAgent()))
    del doc["runs"][0]["results"][0]["locations"]

    bad = root / "broken.sarif.tmp"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    try:
        proc = subprocess.run(
            [sys.executable, str(root / "scripts" / "validate_sarif.py"), str(bad)],
            capture_output=True, text=True,
        )
        assert proc.returncode == 1, (
            f"validator accepted a document code scanning would reject:\n{proc.stdout}"
        )
        assert "physical location" in proc.stdout
    finally:
        bad.unlink(missing_ok=True)


def test_sarif_serialises_to_valid_json() -> None:
    text = dumps(run_scan(VulnerableSupportAgent()))
    parsed = json.loads(text)  # must not raise
    assert parsed["version"] == "2.1.0"


def test_empty_scan_still_produces_valid_document() -> None:
    """CI uploads SARIF on clean runs too, so this must not be a special case."""
    doc = json.loads(dumps(run_scan(HardenedSupportAgent())))

    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_run_properties_report_coverage_and_blind_spots() -> None:
    doc = to_sarif(run_scan(VulnerableSupportAgent()))
    props = doc["runs"][0]["properties"]

    assert "categoriesTested" in props
    assert "categoriesUntested" in props
    assert props["target"], "target name must be recorded"
    # ASI05/08/09/10 have no attacks yet, so they must be reported as untested
    # rather than silently omitted. Overstating coverage is the failure mode
    # this guards against.
    assert set(props["categoriesUntested"]), (
        "expected some ASI categories to be reported as untested"
    )
