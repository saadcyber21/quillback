"""The scan runner: executes attacks against a scaffold and collects results.

Two properties are load-bearing here:

**Isolation.** Every attack gets a fresh ``Trace`` via ``Recorder.reset``. An
attack that leaves state behind would make later attacks non-deterministic, and
non-determinism is the one thing this tool cannot afford — the whole pitch is
that CI can gate on it.

**Containment.** An attack that raises is recorded as an error, not allowed to
abort the scan. One broken attack should cost you one attack, not the report.
That is why the exit code distinguishes 1 (findings) from 2 (scan broke).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Iterable

from . import __version__
from .attacks.base import Attack
from .models import AttackResult, ScanReport
from .registry import all_attacks
from .scaffold import Recorder, Scaffold

#: Called before each attack, so a CLI can render progress. Kept optional:
#: the runner must work with no reporting layer attached.
ProgressHook = Callable[[Attack, int, int], None]


class ScanAborted(Exception):
    """Raised when the target itself cannot be used."""


def target_artifact(scaffold: Scaffold) -> str | None:
    """Repo-relative path of the file defining ``scaffold``'s class.

    Used as the default physical location for findings. It is a real file, it
    is where the scaffold's own logic lives, and it is the right place to send a
    reviewer for anything the permission gate or planner got wrong.
    """
    module = sys.modules.get(type(scaffold).__module__)
    path = getattr(module, "__file__", None)
    if not path:
        return None
    try:
        return str(Path(path).resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        # Outside the working directory (e.g. an installed package). Fall back
        # to the dotted module path so the location is still stable and unique.
        return type(scaffold).__module__.replace(".", "/") + ".py"


def run_scan(
    scaffold: Scaffold,
    attacks: Iterable[Attack] | None = None,
    progress: ProgressHook | None = None,
    fail_fast: bool = False,
) -> ScanReport:
    """Run ``attacks`` (default: the whole library) against ``scaffold``.

    Parameters
    ----------
    scaffold:
        The target. Must be a :class:`~quillback.scaffold.Scaffold` instance.
    attacks:
        Subset to run. ``None`` means everything registered.
    progress:
        Optional ``(attack, index, total)`` callback for live output.
    fail_fast:
        Stop after the first attack that raises. Off by default; on when
        developing an attack and you want the traceback immediately.
    """
    if not isinstance(scaffold, Scaffold):
        raise ScanAborted(
            f"Target must be a quillback.Scaffold subclass, got {type(scaffold).__name__}. "
            "See the README section 'Wrapping your own agent'."
        )

    selected = list(attacks) if attacks is not None else list(all_attacks())
    if not selected:
        raise ScanAborted("Attack selection resolved to nothing — check your filters.")

    report = ScanReport(
        target=f"{scaffold.name} ({type(scaffold).__module__}.{type(scaffold).__name__})",
        quillback_version=__version__,
    )
    rec = Recorder(scaffold)
    total = len(selected)

    for index, attack in enumerate(selected, start=1):
        if progress:
            progress(attack, index, total)

        started = time.perf_counter()

        # Capability check first, so a target missing a hook yields a clean
        # skip with a useful reason instead of an exception.
        missing = [h for h in attack.requires if not _implements(scaffold, h)]
        if missing:
            report.results.append(
                AttackResult(
                    attack_id=attack.id,
                    skipped=True,
                    skip_reason=f"target does not implement: {', '.join(missing)}",
                    duration_ms=_ms(started),
                )
            )
            continue

        try:
            rec.reset()
            findings = attack.run(rec)
        except Exception as exc:  # noqa: BLE001 - containment is the point
            report.results.append(
                AttackResult(
                    attack_id=attack.id,
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=_ms(started),
                )
            )
            if fail_fast:
                raise
            continue

        default_location = target_artifact(scaffold)
        for finding in findings:
            if not finding.location:
                finding.location = default_location

        report.results.append(
            AttackResult(
                attack_id=attack.id,
                findings=list(findings),
                duration_ms=_ms(started),
            )
        )
        report.findings.extend(findings)

    report.finished_at = _now()
    return report


def _implements(scaffold: Scaffold, hook: str) -> bool:
    """True if the target overrides ``hook`` from the base class.

    We compare the bound function against the base implementation rather than
    calling it, because calling it would run user code during a capability
    check — and a hook with side effects would then fire twice.
    """
    base = getattr(Scaffold, hook, None)
    impl = getattr(type(scaffold), hook, None)
    return impl is not None and impl is not base


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
