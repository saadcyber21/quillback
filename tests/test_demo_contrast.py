"""Tests for the report renderers.

Thin on purpose. The renderers have no logic worth unit-testing beyond "does
not crash" and "does not silently drop information", and the second of those is
the one that matters: a report that omits a blind spot is worse than no report,
because it reads as complete.
"""

from __future__ import annotations

import io
import json

from quillback.asi import ASI, uncovered
from quillback.demo import HardenedSupportAgent, VulnerableSupportAgent
from quillback.report import render_json, render_markdown, render_terminal
from quillback.runner import run_scan


def test_terminal_report_renders_without_error() -> None:
    buf = io.StringIO()
    render_terminal(run_scan(VulnerableSupportAgent()), stream=buf, verbose=True)
    out = buf.getvalue()

    assert "quillback scan" in out
    assert "Evidence chain" in out
    assert "OWASP ASI 2026 coverage" in out


def test_terminal_report_names_every_asi_category() -> None:
    """All ten categories must appear, including the untested ones."""
    buf = io.StringIO()
    render_terminal(run_scan(VulnerableSupportAgent()), stream=buf, verbose=True)
    out = buf.getvalue()

    for category in ASI:
        assert category.code in out, f"{category.code} missing from terminal report"


def test_terminal_report_states_blind_spots_explicitly() -> None:
    """Untested categories must be labelled as such, never implied safe."""
    report = run_scan(VulnerableSupportAgent())
    gaps = uncovered(report.covered_categories)
    assert gaps, "expected the library to leave some ASI categories uncovered"

    buf = io.StringIO()
    render_terminal(report, stream=buf)
    out = buf.getvalue()

    assert "not covered" in out
    assert "Blind spots" in out
    for code in gaps:
        assert code in out


def test_clean_scan_says_so_clearly() -> None:
    buf = io.StringIO()
    render_terminal(run_scan(HardenedSupportAgent()), stream=buf)
    out = buf.getvalue()

    assert "No findings" in out


def test_markdown_report_is_well_formed() -> None:
    md = render_markdown(run_scan(VulnerableSupportAgent()))

    assert md.startswith("# quillback scan")
    assert "## Summary" in md
    assert "## Detail" in md
    assert "## OWASP ASI 2026 coverage" in md
    # Every table row must have a consistent column count, or GitHub renders
    # it as garbage.
    for line in md.splitlines():
        if line.startswith("|") and "---" not in line:
            assert line.count("|") >= 4, f"malformed table row: {line}"


def test_summary_table_rows_are_consistent() -> None:
    """The summary table must have exactly four columns on every row.

    Scoped to the summary section only — the coverage table below it has three
    columns, and an earlier version of this test wrongly asserted one shape
    across both, failing on a correct document.
    """
    md = render_markdown(run_scan(VulnerableSupportAgent()))

    section = md.split("## Summary", 1)[1].split("## Detail", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("|")]

    assert len(rows) > 1, "expected a header plus at least one data row"
    for row in rows:
        # Four columns means five pipes (leading and trailing included).
        assert row.count("|") == 5, f"row has wrong column count: {row}"


def test_coverage_table_rows_are_consistent() -> None:
    md = render_markdown(run_scan(VulnerableSupportAgent()))

    section = md.split("## OWASP ASI 2026 coverage", 1)[1]
    rows = [ln for ln in section.splitlines() if ln.startswith("|")]

    assert len(rows) >= len(ASI) + 1, "every ASI category needs a coverage row"
    for row in rows:
        assert row.count("|") == 4, f"row has wrong column count: {row}"


def test_pipe_in_a_title_cannot_break_the_table() -> None:
    """Guard the escaping itself, with a synthetic title containing a pipe."""
    from quillback.models import Finding, Severity, Step
    from quillback.report import _md_escape

    assert _md_escape("a | b") == "a \\| b"

    finding = Finding(
        attack_id="test/pipe",
        title="bad | title",
        severity=Severity.HIGH,
        asi="ASI01",
        description="d",
        payload="p",
        recommendation="r",
        evidence=[Step(kind="inject", detail="x")],
    )
    assert "\\|" in _md_escape(finding.title)


def test_json_report_round_trips() -> None:
    report = run_scan(VulnerableSupportAgent())
    data = json.loads(render_json(report))

    assert data["target"]
    assert data["counts"]
    assert len(data["findings"]) == len(report.findings)
    assert data["exit_code"] == report.exit_code

    for finding in data["findings"]:
        assert finding["severity"] in {"critical", "high", "medium", "low"}
        assert finding["asi"].startswith("ASI")
        assert finding["recommendation"]
        assert finding["evidence"]


def test_json_report_lists_untested_categories() -> None:
    data = json.loads(render_json(run_scan(VulnerableSupportAgent())))

    assert data["categories_untested"], "blind spots must be reported, not omitted"
    assert set(data["categories_tested"]).isdisjoint(data["categories_untested"])


def test_no_renderer_crashes_on_an_empty_scan() -> None:
    """Clean runs still need a report; CI renders on every commit."""
    report = run_scan(HardenedSupportAgent())

    buf = io.StringIO()
    render_terminal(report, stream=buf)
    assert render_markdown(report)
    assert json.loads(render_json(report))
