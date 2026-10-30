#!/usr/bin/env python3
"""Validate a SARIF document against the invariants GitHub code scanning enforces.

Usage::

    python scripts/validate_sarif.py results.sarif

Why this is a script and not an inline CI step
----------------------------------------------
It started as a heredoc inside the workflow and broke twice: first because
``run: python - <<'PY'`` is a YAML multi-line *plain* scalar, which may not
contain blank lines or ``": "`` sequences, so the document failed to parse; then
because the terminator was indented inside a block scalar, so bash never saw it
and executed the Python as shell.

Both failures looked like CI problems and were really "logic living in YAML".
Anything with control flow belongs in a file that can be run and tested locally.

This deliberately does not validate against the full JSON schema — that would
need a dependency, and quillback has none. It checks the properties GitHub
actually rejects or silently drops on.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

VALID_LEVELS = {"none", "note", "warning", "error"}


def validate(path: Path) -> list[str]:
    """Return a list of problems. Empty means valid."""
    problems: list[str] = []

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"{path}: file does not exist"]
    except json.JSONDecodeError as exc:
        return [f"{path}: not valid JSON — {exc}"]

    if doc.get("version") != "2.1.0":
        problems.append(f"version must be 2.1.0, got {doc.get('version')!r}")
    if "$schema" not in doc:
        problems.append("missing $schema")

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non-empty list")
        return problems

    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    rules = driver.get("rules") or []
    if not rules:
        problems.append("no rules declared — findings would be unattributable")

    rule_ids = {r.get("id") for r in rules}
    if None in rule_ids:
        problems.append("a rule is missing an id")

    for rule in rules:
        sev = rule.get("properties", {}).get("security-severity")
        if not sev:
            problems.append(f"rule {rule.get('id')!r}: missing security-severity")
        else:
            try:
                float(sev)
            except (TypeError, ValueError):
                problems.append(
                    f"rule {rule.get('id')!r}: security-severity {sev!r} is not numeric"
                )

    results = run.get("results") or []
    fingerprints: dict[str, str] = {}
    locations_seen: set[str] = set()
    for i, res in enumerate(results):
        rid = res.get("ruleId")
        if rid not in rule_ids:
            problems.append(f"result[{i}] references undeclared rule {rid!r}")
        if res.get("level") not in VALID_LEVELS:
            problems.append(f"result[{i}] has invalid level {res.get('level')!r}")
        if not res.get("message", {}).get("text"):
            problems.append(f"result[{i}] has no message text")

        # Code scanning requires a physical location on every result. Without
        # one the upload still succeeds and the analysis fails server-side, so
        # the only symptom is an empty Security tab. This check exists because
        # the exporter shipped a version that omitted it and this validator
        # waved it through.
        locations = res.get("locations") or []
        physical = [
            loc for loc in locations if isinstance(loc, dict) and loc.get("physicalLocation")
        ]
        if not physical:
            problems.append(
                f"result[{i}] ({rid}) has no physical location — code scanning "
                f"rejects the whole file with 'expected a physical location'"
            )
        else:
            uri = (
                physical[0]["physicalLocation"]
                .get("artifactLocation", {})
                .get("uri")
            )
            if not uri:
                problems.append(f"result[{i}] ({rid}): physical location has no artifact uri")
            region = physical[0]["physicalLocation"].get("region") or {}
            if not isinstance(region.get("startLine"), int) or region["startLine"] < 1:
                problems.append(
                    f"result[{i}] ({rid}): region.startLine must be a positive integer"
                )

        fp = (res.get("partialFingerprints") or {}).get("primaryLocationLineHash")
        if not fp:
            problems.append(f"result[{i}] has no fingerprint — it will not dedupe")
        elif fp in fingerprints:
            # Colliding fingerprints make GitHub merge two distinct findings
            # into one, silently hiding the second.
            problems.append(
                f"result[{i}] fingerprint collides with the finding for "
                f"{fingerprints[fp]!r}; distinct findings would be merged"
            )
        else:
            fingerprints[fp] = rid

    invocations = run.get("invocations") or []
    if not invocations:
        problems.append("no invocations block — GitHub expects run metadata")

    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(f"usage: {Path(argv[0]).name} <sarif-file>", file=sys.stderr)
        return 2

    path = Path(argv[0])
    problems = validate(path)

    if problems:
        print(f"INVALID {path} — {len(problems)} problem(s)")
        for p in problems:
            print(f"  ✗ {p}")
        return 1

    doc = json.loads(path.read_text(encoding="utf-8"))
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    print(
        f"valid SARIF 2.1.0 — {len(results)} result(s) against {len(rules)} "
        f"declared rule(s), {len({r['partialFingerprints']['primaryLocationLineHash'] for r in results})} unique fingerprint(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
