"""Registry: look up attacks by id, tag or ASI category.

Kept separate from ``attacks/__init__.py`` so that reporting and CLI code can
query the library without importing every attack module into their namespace.
"""

from __future__ import annotations

from typing import Iterable

from .attacks import ALL_ATTACKS
from .attacks.base import Attack
from .models import Severity

_BY_ID: dict[str, Attack] = {a.id: a for a in ALL_ATTACKS}


def _validate() -> None:
    """Fail loudly at import if the library is internally inconsistent.

    These conditions are all authoring mistakes. Detecting them at import time
    means a broken attack library cannot ship, rather than producing a
    half-silent scan weeks later.
    """
    if len(_BY_ID) != len(ALL_ATTACKS):
        seen: set[str] = set()
        dupes = []
        for a in ALL_ATTACKS:
            if a.id in seen:
                dupes.append(a.id)
            seen.add(a.id)
        raise ValueError(f"Duplicate attack ids: {sorted(set(dupes))}")

    for a in ALL_ATTACKS:
        if not isinstance(a.severity, Severity):
            raise ValueError(f"Attack {a.id!r} has an invalid severity")
        # asi validity is already enforced by Finding, but attacks declare it
        # independently, so check here too.
        from .asi import BY_CODE

        if a.asi not in BY_CODE:
            raise ValueError(f"Attack {a.id!r} declares unknown ASI category {a.asi!r}")


_validate()


def all_attacks() -> tuple[Attack, ...]:
    return ALL_ATTACKS


def get(attack_id: str) -> Attack:
    try:
        return _BY_ID[attack_id]
    except KeyError:
        raise KeyError(
            f"Unknown attack {attack_id!r}. Run 'quillback attacks' to list them."
        ) from None


def attack_category(attack_id: str) -> str:
    """ASI code for an attack id. Used by the report for coverage maths."""
    return _BY_ID[attack_id].asi


def select(
    ids: Iterable[str] | None = None,
    tags: Iterable[str] | None = None,
    asi: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    min_severity: Severity | None = None,
) -> list[Attack]:
    """Filter the library.

    Filters are AND-ed; values within a filter are OR-ed. ``exclude`` removes
    last, so it always wins — useful for skipping a known-flaky attack in CI
    without editing config.
    """
    excluded = set(exclude or ())
    tag_set = set(tags or ())
    asi_set = {a.upper() for a in (asi or ())}

    severity_floor = None
    if min_severity is not None:
        severity_floor = min_severity.rank

    chosen: list[Attack] = []
    for attack in ALL_ATTACKS:
        if attack.id in excluded:
            continue
        if ids and attack.id not in set(ids):
            continue
        if tag_set and not (attack.tags & tag_set):
            continue
        if asi_set and attack.asi not in asi_set:
            continue
        if severity_floor is not None and attack.severity.rank > severity_floor:
            continue
        chosen.append(attack)
    return chosen


def coverage_summary() -> dict[str, int]:
    """How many attacks exist per ASI category. Used by the report."""
    counts: dict[str, int] = {}
    for a in ALL_ATTACKS:
        counts[a.asi] = counts.get(a.asi, 0) + 1
    return dict(sorted(counts.items()))
