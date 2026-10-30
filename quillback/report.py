"""Report renderers: terminal, Markdown, JSON.

Terminal output is written for a security reviewer, not for a developer running
tests. That means: worst findings first, the evidence chain inline, and a
coverage line that makes blind spots obvious. A report that only lists what
failed quietly implies everything else was tested, which is usually false.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import Any, TextIO

from .asi import BY_CODE, uncovered
from .models import Finding, ScanReport, Severity

#: Colour only when the stream is a TTY and NO_COLOR is not set. Respecting
#: NO_COLOR (https://no-color.org) is a small thing that people notice.
_COLOR_OK = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR_OK else text


_SEV_STYLE = {
    Severity.CRITICAL: ("91", "CRITICAL"),
    Severity.HIGH: ("91", "HIGH"),
    Severity.MEDIUM: ("93", "MEDIUM"),
    Severity.LOW: ("96", "LOW"),
}


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------


def render_terminal(report: ScanReport, stream: TextIO | None = None, verbose: bool = False) -> None:
    out = stream or sys.stdout
    w = out.write

    w(f"\n{_c('1', 'quillback')} scan — {_c('1', report.target)}\n")
    w(f"{'─' * 72}\n")

    counts = report.by_severity
    total = len(report.findings)

    if total == 0:
        w(f"\n{_c('92', '✓ No findings.')} ")
        w(
            f"{len(report.results) - len(report.skipped)} attacks ran, "
            f"{len(report.skipped)} skipped.\n"
        )
    else:
        w(f"\n{_c('1;91', f'{total} finding' + ('s' if total != 1 else ''))}  ")
        w(
            "  ".join(
                f"{_c(_SEV_STYLE[s][0], f'{n} {s.value}')}"
                for s, n in counts.items()
                if n
            )
            + "\n"
        )

    for finding in report.sorted_findings:
        _render_finding(finding, w, verbose)

    _render_coverage(report, w)
    _render_skipped(report, w, verbose)

    if report.failed_attacks:
        w(f"\n{_c('91', 'Scan errors')}\n")
        for r in report.failed_attacks:
            w(f"  ! {r.attack_id}: {r.error}\n")
        w("  Findings above may be incomplete. Exit code 2.\n")

    w(f"\n{'─' * 72}\n")


def _render_finding(finding: Finding, w, verbose: bool) -> None:
    code, label = _SEV_STYLE[finding.severity]
    category = BY_CODE[finding.asi]
    cwe = finding.effective_cwe
    cwe_str = f" · CWE-{cwe}" if cwe else ""

    w(f"\n{_c(code, _c('1', f'[{label}]'))} {_c('1', finding.title)}\n")
    w(f"  {_c('2', f'{finding.asi} {category.name}{cwe_str} · {finding.attack_id}')}\n")
    w(f"  {_wrap(finding.description, 72, 2)}\n")

    w(f"\n  {_c('1', 'Evidence chain')}\n")
    for i, step in enumerate(finding.evidence, 1):
        w(f"    {_c('2', f'{i}.')} [{step.kind}] {step.detail}\n")

    w(f"\n  {_c('1', 'Payload')}\n")
    w(f"    {_c('2', _wrap(_clip(finding.payload, 240), 72, 4))}\n")

    w(f"\n  {_c('92', _c('1', 'Fix'))}\n")
    w(f"    {_wrap(finding.recommendation, 72, 4)}\n")


def _render_coverage(report: ScanReport, w) -> None:
    tested = report.covered_categories
    missing = uncovered(tested)

    w(f"\n{_c('1', 'OWASP ASI 2026 coverage')}\n")
    for code, category in BY_CODE.items():
        if code in tested:
            n = report.by_asi.get(code, 0)
            if n:
                mark = _c("91", f"✗ {n} finding{'s' if n != 1 else ''}")
            else:
                mark = _c("92", "✓ tested, no findings")
        elif code in missing:
            mark = _c("93", "— not covered by this scan")
        else:
            mark = _c("2", "—")
        w(f"  {code}  {category.name:<40} {mark}\n")

    if missing:
        w(
            f"\n  {_c('93', 'Blind spots:')} {', '.join(missing)}. "
            "No finding here means untested, not safe.\n"
        )


def _render_skipped(report: ScanReport, w, verbose: bool) -> None:
    if not report.skipped:
        return
    if not verbose:
        msg = (
            f"{len(report.skipped)} attacks skipped — the target does not "
            "implement those hooks. Re-run with -v for details."
        )
        w(f"\n{_c('2', msg)}\n")
        return
    w(f"\n{_c('2', 'Skipped attacks')}\n")
    for r in report.skipped:
        w(f"  {_c('2', '·')} {r.attack_id}: {r.skip_reason}\n")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(report: ScanReport) -> str:
    """Markdown report, suitable for pasting into an issue or a pentest report."""
    lines: list[str] = []
    counts = report.by_severity

    lines.append(f"# quillback scan — {report.target}\n")
    lines.append(
        f"Run at {report.started_at.strftime('%Y-%m-%d %H:%M UTC')} · "
        f"quillback {report.quillback_version}\n"
    )
    lines.append(f"**{len(report.findings)} finding(s)** — ")
    lines.append(
        ", ".join(f"{n} {s.value}" for s, n in counts.items() if n) or "none"
    )
    lines.append("\n\n")

    if report.findings:
        lines.append("## Summary\n\n")
        lines.append("| Severity | ASI | Finding | Attack |\n|---|---|---|---|\n")
        for f in report.sorted_findings:
            lines.append(
                f"| {f.severity.value.upper()} | {f.asi} | "
                f"{_md_escape(f.title)} | `{f.attack_id}` |\n"
            )
        lines.append("\n")

        lines.append("## Detail\n\n")
        for f in report.sorted_findings:
            lines.append(f"### {f.severity.value.upper()} — {f.title}\n\n")
            lines.append(f"**{f.asi} {BY_CODE[f.asi].name}**")
            if f.effective_cwe:
                lines.append(f" · CWE-{f.effective_cwe}")
            lines.append(f" · `{f.attack_id}`\n\n")
            lines.append(f"{f.description}\n\n")
            lines.append("**Evidence**\n\n")
            for i, s in enumerate(f.evidence, 1):
                lines.append(f"{i}. `{s.kind}` — {s.detail}\n")
            lines.append("\n**Payload**\n\n```\n")
            lines.append(_clip(f.payload, 1200))
            lines.append("\n```\n\n**Remediation**\n\n")
            lines.append(f"{f.recommendation}\n\n")

    lines.append("## OWASP ASI 2026 coverage\n\n")
    lines.append("| Category | Name | Result |\n|---|---|---|\n")
    tested = report.covered_categories
    for code, cat in BY_CODE.items():
        if code in tested:
            n = report.by_asi.get(code, 0)
            result = f"❌ {n} finding(s)" if n else "✅ tested, clean"
        else:
            result = "⚪ not covered"
        lines.append(f"| {code} | {cat.name} | {result} |\n")

    if report.skipped:
        lines.append("\n## Skipped attacks\n\n")
        for r in report.skipped:
            lines.append(f"- `{r.attack_id}` — {r.skip_reason}\n")

    return "".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(report: ScanReport) -> str:
    """Machine-readable dump. Mirrors the dataclasses with no cleverness."""
    return json.dumps(_report_dict(report), indent=2, default=str)


def _report_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "target": report.target,
        "version": report.quillback_version,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat() if report.finished_at else None,
        "exit_code": report.exit_code,
        "counts": {s.value: n for s, n in report.by_severity.items()},
        "by_asi": report.by_asi,
        "categories_tested": sorted(report.covered_categories),
        "categories_untested": uncovered(report.covered_categories),
        "findings": [_finding_dict(f) for f in report.sorted_findings],
        "skipped": [
            {"id": r.attack_id, "reason": r.skip_reason} for r in report.skipped
        ],
        "errors": [{"id": r.attack_id, "error": r.error} for r in report.failed_attacks],
    }


def _finding_dict(f: Finding) -> dict[str, Any]:
    d = asdict(f)
    d["severity"] = f.severity.value
    d["tags"] = sorted(f.tags)
    d["cwe"] = f.effective_cwe
    d["call_chain"] = f.call_chain
    d["asi_name"] = BY_CODE[f.asi].name
    return d


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _wrap(text: str, width: int, indent: int) -> str:
    """Naive word wrap preserving the leading indent on continuation lines."""
    import textwrap

    return textwrap.fill(
        text,
        width=width,
        initial_indent=" " * indent if indent else "",
        subsequent_indent=" " * indent,
        break_long_words=False,
        break_on_hyphens=False,
    ).lstrip()


def _clip(text: str, limit: int) -> str:
    text = text.replace("\n", " ⏎ ")
    return text if len(text) <= limit else text[:limit] + " …"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")
