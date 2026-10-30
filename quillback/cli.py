"""Command-line interface.

Subcommands
-----------
``scan``     run the attack library against a target
``attacks``  list the library, with ASI mapping and required hooks
``demo``     scan the bundled vulnerable agent and the hardened variant, then
             print the contrast. This is the command to run first.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import Any

from . import __version__
from .asi import BY_CODE
from .models import Severity, ScanReport
from .registry import all_attacks, coverage_summary, select
from .report import render_json, render_markdown, render_terminal
from .runner import ScanAborted, run_scan
from .sarif import dumps as sarif_dumps
from .scaffold import Scaffold


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="quillback",
        description=(
            "Offline red-team harness for AI agent scaffolds. "
            "No API keys, no tokens, deterministic."
        ),
    )
    parser.add_argument("--version", action="version", version=f"quillback {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- scan ---------------------------------------------------------------
    p_scan = sub.add_parser("scan", help="scan a target scaffold")
    target_group = p_scan.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        metavar="MODULE:ATTR",
        help="import path to a Scaffold subclass or instance, e.g. myapp.sec:MyAgent",
    )
    target_group.add_argument(
        "--demo",
        action="store_true",
        help="scan the bundled deliberately-vulnerable reference agent",
    )
    p_scan.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "sarif"),
        default="terminal",
    )
    p_scan.add_argument("--out", metavar="FILE", help="write the report to FILE instead of stdout")
    p_scan.add_argument("--asi", nargs="*", metavar="CODE", help="only run attacks for these ASI categories")
    p_scan.add_argument("--tag", nargs="*", metavar="TAG", help="only run attacks carrying these tags")
    p_scan.add_argument("--attack", nargs="*", metavar="ID", help="only run these attack ids")
    p_scan.add_argument("--exclude", nargs="*", metavar="ID", help="skip these attack ids")
    p_scan.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        help="ignore attacks below this severity",
    )
    p_scan.add_argument("-v", "--verbose", action="store_true", help="show skipped attacks and reasons")
    p_scan.add_argument("--quiet", action="store_true", help="suppress progress output")
    p_scan.add_argument(
        "--fail-on",
        choices=("any", "critical", "high", "medium", "none"),
        default="any",
        help="exit non-zero when findings reach this level (default: any)",
    )

    # -- attacks ------------------------------------------------------------
    p_attacks = sub.add_parser("attacks", help="list the attack library")
    p_attacks.add_argument("--asi", metavar="CODE", help="filter to one ASI category")
    p_attacks.add_argument("--json", action="store_true", help="machine-readable output")

    # -- demo ---------------------------------------------------------------
    sub.add_parser(
        "demo",
        help="scan the vulnerable reference agent, then the hardened one, and compare",
    )

    args = parser.parse_args(argv)

    if args.command == "attacks":
        return _cmd_attacks(args)
    if args.command == "demo":
        return _cmd_demo()
    return _cmd_scan(args)


# ---------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        scaffold = _load_target(args)
    except ScanAborted as exc:
        print(f"quillback: {exc}", file=sys.stderr)
        return 2

    attacks = select(
        ids=args.attack,
        tags=args.tag,
        asi=[a.upper() for a in (args.asi or [])],
        exclude=args.exclude,
        min_severity=Severity(args.min_severity) if args.min_severity else None,
    )
    if not attacks:
        print("quillback: filters matched no attacks.", file=sys.stderr)
        return 2

    def progress(attack, index, total):
        if not args.quiet and args.format == "terminal":
            sys.stderr.write(f"\r  [{index}/{total}] {attack.id:<52}")
            sys.stderr.flush()

    try:
        report = run_scan(scaffold, attacks, progress=progress)
    except ScanAborted as exc:
        print(f"\nquillback: {exc}", file=sys.stderr)
        return 2

    if not args.quiet and args.format == "terminal":
        sys.stderr.write("\r" + " " * 70 + "\r")

    _VERBOSE["v"] = bool(args.verbose)
    body = _render(report, args.format)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body)
        if not args.quiet:
            print(f"wrote {args.format} report to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(body)

    return _exit_code(report, args.fail_on)


def _render(report: ScanReport, fmt: str) -> str:
    if fmt == "json":
        return render_json(report) + "\n"
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "sarif":
        return sarif_dumps(report) + "\n"

    # Terminal rendering writes directly so it can stream colour codes; capture
    # into a buffer so --out still works.
    import io

    buf = io.StringIO()
    render_terminal(report, stream=buf, verbose=_VERBOSE.get("v", False))
    return buf.getvalue()


#: --verbose is consumed by the renderer, which does not take the argparse
#: namespace. Storing it here avoids threading it through every call.
_VERBOSE: dict[str, bool] = {}


def _load_target(args: argparse.Namespace) -> Scaffold:
    if args.demo:
        from .demo import VulnerableSupportAgent

        return VulnerableSupportAgent()

    if ":" not in args.target:
        raise ScanAborted(
            f"--target must look like 'package.module:ClassName', got {args.target!r}"
        )
    module_name, attr = args.target.rsplit(":", 1)

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ScanAborted(f"could not import {module_name!r}: {exc}") from exc

    try:
        obj = getattr(module, attr)
    except AttributeError:
        raise ScanAborted(f"{module_name!r} has no attribute {attr!r}") from None

    # Accept a class or an already-constructed instance.
    if isinstance(obj, type):
        if not issubclass(obj, Scaffold):
            raise ScanAborted(
                f"{attr} is a class but not a quillback.Scaffold subclass"
            )
        try:
            obj = obj()
        except TypeError as exc:
            raise ScanAborted(
                f"{attr} could not be instantiated without arguments: {exc}. "
                "Pass an already-constructed instance instead."
            ) from exc

    if not isinstance(obj, Scaffold):
        raise ScanAborted(f"{attr} is not a quillback.Scaffold (got {type(obj).__name__})")
    return obj


def _exit_code(report: ScanReport, fail_on: str) -> int:
    """Translate a report into a CI-friendly exit status.

    0 = nothing to fail on, 1 = findings at or above the threshold,
    2 = the scan itself broke. Keeping 2 distinct matters: a crashed scan must
    never be mistaken for a clean one, which is the classic CI footgun.
    """
    if report.failed_attacks:
        return 2
    if fail_on == "none":
        return 0

    floor = {
        "any": Severity.LOW,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }[fail_on]

    for finding in report.findings:
        # Lower rank == more severe, so "at or above the threshold" means the
        # finding's rank is <= the floor's rank.
        if finding.severity.rank <= floor.rank:
            return 1
    return 0


def _cmd_attacks(args: argparse.Namespace) -> int:
    attacks = all_attacks()
    if args.asi:
        code = args.asi.upper()
        if code not in BY_CODE:
            print(f"quillback: unknown ASI category {code!r}", file=sys.stderr)
            return 2
        attacks = [a for a in attacks if a.asi == code]

    if args.json:
        import json

        print(
            json.dumps(
                [
                    {
                        "id": a.id,
                        "name": a.name,
                        "asi": a.asi,
                        "asi_name": BY_CODE[a.asi].name,
                        "severity": a.severity.value,
                        "tags": sorted(a.tags),
                        "requires": list(a.requires),
                        "description": a.description,
                    }
                    for a in attacks
                ],
                indent=2,
            )
        )
        return 0

    current = None
    for a in sorted(attacks, key=lambda x: (x.asi, x.id)):
        if a.asi != current:
            current = a.asi
            print(f"\n{a.asi} — {BY_CODE[a.asi].name}")
        print(f"  [{a.severity.value.upper():<8}] {a.id}")
        print(f"             {a.name}")
        print(f"             needs: {', '.join(a.requires) or '—'}")

    counts = coverage_summary()
    print(f"\n{len(attacks)} attacks across {len(counts)} ASI categories: ", end="")
    print(", ".join(f"{k}={v}" for k, v in counts.items()))
    untested = [c for c in BY_CODE if c not in counts]
    if untested:
        print(f"No attacks yet for: {', '.join(untested)}")
    return 0


def _cmd_demo() -> int:
    """Run the contrast that justifies the whole tool."""
    from .demo import HardenedSupportAgent, VulnerableSupportAgent

    print("=" * 72)
    print("quillback demo — the same agent, before and after the controls")
    print("=" * 72)

    reports: dict[str, ScanReport] = {}
    for label, cls in (("vulnerable", VulnerableSupportAgent), ("hardened", HardenedSupportAgent)):
        print(f"\n>>> scanning {label} variant ({cls.__name__})")
        reports[label] = run_scan(cls())
        counts = reports[label].by_severity
        active = [
            f"{n} {s.value}" for s, n in counts.items() if n
        ]
        print(f"    {len(reports[label].findings)} findings — {', '.join(active) or 'none'}")

    vuln, hard = reports["vulnerable"], reports["hardened"]

    print("\n" + "=" * 72)
    print("contrast")
    print("=" * 72)
    fixed = {f.attack_id for f in vuln.findings} - {f.attack_id for f in hard.findings}
    remaining = {f.attack_id for f in hard.findings}

    for attack_id in sorted(fixed):
        print(f"  ✓ controlled   {attack_id}")
    for attack_id in sorted(remaining):
        print(f"  ✗ still open   {attack_id}")

    print(
        f"\n{len(fixed)} of {len({f.attack_id for f in vuln.findings})} distinct "
        "weaknesses were closed by the hardened variant.\n"
        "If a hardened control still produces a finding, either the control is "
        "incomplete or the attack has a false positive — both are bugs worth "
        "filing.\n"
    )

    print("=" * 72)
    print("full report for the vulnerable variant")
    print("=" * 72)
    render_terminal(vuln, verbose=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
