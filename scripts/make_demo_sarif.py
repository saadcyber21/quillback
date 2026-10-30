#!/usr/bin/env python3
"""Generate a SARIF report from the bundled demo target and assert it is usable.

Usage::

    python scripts/make_demo_sarif.py results.sarif

Separated from the workflow because ``scan`` exits 1 when findings exist — which
is correct behaviour for a CI gate, but wrong for a step whose job is to
*produce a document* about a target that is deliberately vulnerable. Wrapping
the exit code inline in YAML is what produced two broken builds of this repo.

Exit 0 when a non-empty, parseable SARIF document was written from a scan that
found things. Exit 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quillback.demo import VulnerableSupportAgent  # noqa: E402
from quillback.runner import run_scan  # noqa: E402
from quillback.sarif import dumps  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(f"usage: {Path(argv[0]).name} <output.sarif>", file=sys.stderr)
        return 2

    out = Path(argv[0])
    report = run_scan(VulnerableSupportAgent())

    # A scan that errored produced an incomplete document. Uploading that to the
    # Security tab would show fewer findings than reality, which is worse than
    # showing nothing.
    if report.failed_attacks:
        for r in report.failed_attacks:
            print(f"  ✗ attack raised: {r.attack_id}: {r.error}")
        return 1

    if not report.findings:
        print("  ✗ the deliberately vulnerable agent produced no findings")
        return 1

    text = dumps(report)
    out.write_text(text, encoding="utf-8")

    # Confirm what we wrote parses back, rather than trusting the serialiser.
    try:
        doc = json.loads(out.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"  ✗ wrote {out} but it does not parse: {exc}")
        return 1

    n_results = len(doc["runs"][0]["results"])
    n_rules = len(doc["runs"][0]["tool"]["driver"]["rules"])
    print(
        f"wrote {out} — {out.stat().st_size:,} bytes, "
        f"{n_results} result(s), {n_rules} rule(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
