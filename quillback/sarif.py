"""SARIF 2.1.0 output.

Why SARIF and not just JSON
---------------------------
GitHub code scanning ingests SARIF natively. Uploading this file puts findings
in the repository's Security tab, next to CodeQL and Semgrep results, with
severity, CWE and a permalink to the rule. For a security tool that is the
single highest-value integration available, and it costs about a hundred lines.

We implement the subset that GitHub actually consumes rather than the whole
spec: one tool with a rule per attack, results with level/partialFingerprints,
and properties carrying the OWASP ASI mapping.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .asi import BY_CODE, get as asi_get
from .models import Finding, ScanReport, sarif_level
from .registry import all_attacks

SARIF_SCHEMA = (
    "https://json.schemastore.org/sarif-2.1.0.json"
)
SARIF_VERSION = "2.1.0"


def to_sarif(report: ScanReport) -> dict[str, Any]:
    """Convert a scan report into a SARIF document."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": _driver()},
                "results": [_result(f) for f in report.sorted_findings],
                "invocations": [_invocation(report)],
                "properties": _run_properties(report),
            }
        ],
    }


def dumps(report: ScanReport, indent: int | None = 2) -> str:
    return json.dumps(to_sarif(report), indent=indent, sort_keys=False)


# ---------------------------------------------------------------------------


def _driver() -> dict[str, Any]:
    """Tool metadata plus one reportingDescriptor per attack.

    Declaring rules up front — even ones that produced no results — is what lets
    GitHub show "0 results" for a rule rather than treating it as absent, so a
    fixed finding visibly disappears instead of silently vanishing.
    """
    from . import __version__

    rules = []
    for attack in all_attacks():
        category = asi_get(attack.asi)
        rule: dict[str, Any] = {
            "id": attack.id,
            "name": _pascal(attack.id),
            "shortDescription": {"text": attack.name},
            "fullDescription": {"text": attack.description},
            "helpUri": (
                "https://genai.owasp.org/resource/"
                "owasp-top-10-for-agentic-applications-for-2026/"
            ),
            "properties": {
                "security-severity": _cvss_like(attack.severity.value),
                "tags": sorted(attack.tags | {f"owasp-asi:{attack.asi}"}),
                "precision": "high",
            },
        }
        if category.cwe:
            rule["relationships"] = [
                {
                    "target": {
                        "id": str(category.cwe),
                        "toolComponent": {"name": "CWE", "guid": _CWE_GUID},
                    },
                    "kinds": ["superset"],
                }
            ]
        rules.append(rule)

    return {
        "name": "quillback",
        "fullName": "quillback — offline AI agent scaffold red-team harness",
        "version": __version__,
        "informationUri": "https://github.com/saadcyber21/quillback",
        "rules": rules,
    }


#: Fixed GUID for the CWE tool component. SARIF relationships need a stable
#: identifier; this is the conventional placeholder value used by exporters.
_CWE_GUID = "b3b10f39-0d3a-4a5d-9c9d-0e8a5f0d0f4c"


def _result(finding: Finding) -> dict[str, Any]:
    category = asi_get(finding.asi)
    cwe = finding.effective_cwe

    result: dict[str, Any] = {
        "ruleId": finding.attack_id,
        "level": sarif_level(finding.severity),
        "message": {
            "text": (
                f"{finding.title}\n\n"
                f"{finding.description}\n\n"
                f"OWASP {finding.asi}: {category.name}\n"
                f"Remediation: {finding.recommendation}"
            )
        },
        # quillback findings are behavioural, not tied to a source line. A
        # single logical location keeps GitHub happy without inventing a
        # filename that does not exist.
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": finding.asi,
                        "kind": "module",
                        "fullyQualifiedName": f"{finding.asi}:{category.name}",
                    }
                ]
            }
        ],
        "properties": {
            "severity": finding.severity.value,
            "owasp-asi": finding.asi,
            "owasp-asi-name": category.name,
            "tags": sorted(finding.tags),
            "payload": finding.payload[:2000],
            "evidence": [_step_dict(s) for s in finding.evidence],
        },
    }

    if cwe:
        result["taxa"] = [
            {
                "id": str(cwe),
                "toolComponent": {"name": "CWE", "guid": _CWE_GUID},
            }
        ]

    # A stable fingerprint lets GitHub dedupe across runs so the same finding
    # does not reopen as new every commit.
    result["partialFingerprints"] = {
        "primaryLocationLineHash": _fingerprint(finding)
    }
    return result


def _step_dict(step: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": step.kind, "detail": step.detail}
    if step.tool_call is not None:
        out["tool"] = step.tool_call.tool
        out["allowed"] = step.tool_call.allowed
        out["origin"] = step.tool_call.origin
        if step.tool_call.deny_reason:
            out["deny_reason"] = step.tool_call.deny_reason
    return out


def _invocation(report: ScanReport) -> dict[str, Any]:
    return {
        "executionSuccessful": not report.failed_attacks,
        "startTimeUtc": report.started_at.isoformat(),
        "endTimeUtc": (
            report.finished_at.isoformat() if report.finished_at else None
        ),
        "toolExecutionNotifications": [
            {
                "level": "error",
                "message": {"text": f"{r.attack_id}: {r.error}"},
            }
            for r in report.failed_attacks
        ],
    }


def _run_properties(report: ScanReport) -> dict[str, Any]:
    counts = report.by_severity
    return {
        "target": report.target,
        "findings": len(report.findings),
        "bySeverity": {s.value: n for s, n in counts.items()},
        "categoriesTested": sorted(report.covered_categories),
        "categoriesUntested": [
            code
            for code in sorted(BY_CODE)
            if code not in report.covered_categories
        ],
        "attacksSkipped": [
            {"id": r.attack_id, "reason": r.skip_reason} for r in report.skipped
        ],
    }


def _fingerprint(finding: Finding) -> str:
    """Stable hash of the *identity* of a finding, not its incidental detail.

    Deliberately excludes argument values and timestamps: those change between
    runs and would defeat deduplication.

    It does include the evidence chain's detail text. An earlier version hashed
    only ``(attack_id, asi, title, call_chain)``, which collided when one attack
    emitted several findings of the same shape — for instance two different
    documents both containing invisible characters. Colliding fingerprints make
    GitHub merge distinct findings into one, silently hiding the second.
    """
    basis = "|".join(
        [
            finding.attack_id,
            finding.asi,
            finding.title,
            "->".join(finding.call_chain),
            ">>".join(s.detail for s in finding.evidence),
        ]
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def _pascal(attack_id: str) -> str:
    """Turn 'asi01/indirect-injection-to-x' into a SARIF-friendly rule name."""
    tail = attack_id.split("/", 1)[-1]
    return "".join(part.capitalize() for part in tail.replace("_", "-").split("-"))


def _cvss_like(severity: str) -> str:
    """Numeric security-severity string, GitHub's expected format.

    These are indicative values chosen to sort our severities consistently with
    CodeQL's scale. We do not claim a real CVSS vector — computing one would
    require environmental assumptions we cannot make.
    """
    return {
        "critical": "9.8",
        "high": "8.0",
        "medium": "6.0",
        "low": "3.5",
    }[severity]
