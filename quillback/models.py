"""Core data types shared across the harness.

Everything here is a plain dataclass with no third-party imports. That is a
deliberate constraint, not laziness: ``quillback`` installs with zero
dependencies so it can be dropped into a CI runner or a locked-down AppSec
pipeline without a dependency review. Pydantic would be nicer to write, but it
would also be the first thing a security team has to approve.

Conventions
-----------
* IDs are kebab-case and globally unique (``indirect-injection/read-doc-then-refund``).
* Severity uses the four levels below. There is no "informational" tier — if a
  finding is not worth acting on it should not be emitted.
* Every ``Finding`` must carry enough evidence that a reviewer can reproduce it
  without re-running the scan. That means the payload, the call chain and the
  reasoning, not just a label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """Impact rating for a finding.

    Subclasses ``str`` so it serialises to JSON/SARIF without a custom encoder
    and compares naturally against the strings used in config files.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    # Rank used for sorting worst-first. Kept as a property rather than relying
    # on enum ordering so the declaration order above stays readable.
    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


#: SARIF wants a numeric-ish level. Mapping keeps our vocabulary richer than
#: SARIF's while still emitting something valid.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def sarif_level(severity: Severity) -> str:
    return _SARIF_LEVEL[severity]


@dataclass(frozen=True)
class Tool:
    """A tool the agent can invoke.

    ``dangerous`` is a *declaration by the target*, not a judgement by
    quillback. It lets an agent author mark the tools that would be genuinely
    bad to call with attacker-chosen arguments, so attacks can aim at them.
    If a target marks nothing dangerous, attacks fall back to the ``sensitive``
    tags below.
    """

    name: str
    description: str = ""
    #: JSON-schema-ish parameter names. Kept as a simple list on purpose —
    #: full JSON Schema parsing would drag in a dependency for little gain.
    parameters: tuple[str, ...] = ()
    #: Free-form capability tags, e.g. {"network", "write", "money", "exec"}.
    tags: frozenset[str] = frozenset()
    #: True if calling this with attacker-controlled arguments is a real problem.
    dangerous: bool = False
    #: True if invoking it should require a human in the loop.
    requires_approval: bool = False

    def __post_init__(self) -> None:
        # Normalise tags so callers can pass a plain list or set without
        # worrying about type. frozen=True means we must use object.__setattr__.
        object.__setattr__(self, "tags", frozenset(self.tags))
        object.__setattr__(self, "parameters", tuple(self.parameters))


@dataclass
class ToolCall:
    """A tool invocation the scaffold permitted, recorded by the harness.

    This is the primary evidence object. ``allowed`` records the *decision*,
    ``deny_reason`` records why it was refused. Both matter: a tool that was
    correctly denied still tells you the attack reached your permission layer,
    which is worth knowing.
    """

    tool: str
    arguments: dict[str, object] = field(default_factory=dict)
    #: Trust level of the context that produced this call, e.g. "untrusted_doc".
    origin: str = "user"
    allowed: bool = True
    deny_reason: str | None = None
    #: Position in the chain, zero-indexed.
    step: int = 0

    @property
    def blocked(self) -> bool:
        return not self.allowed


@dataclass
class Step:
    """One hop in an attack's execution trace.

    Kept separate from ``ToolCall`` because a step can also be a memory write,
    a retrieval, or a message crossing an agent boundary — things that are not
    tool invocations but are still part of the causal chain a reviewer needs.
    """

    kind: str  # "inject" | "retrieve" | "tool_call" | "memory_write" | "message" | "approval"
    detail: str
    tool_call: ToolCall | None = None


@dataclass
class Finding:
    """A single confirmed weakness.

    Invariants enforced in ``__post_init__``:
      * ``evidence`` must be non-empty. A finding with no evidence is not
        actionable and is almost certainly a bug in an attack.
      * ``asi`` must be a valid category code. Checked against the registry so
        typos fail at construction, not at report time.
    """

    attack_id: str
    title: str
    severity: Severity
    asi: str
    description: str
    #: The hostile input that triggered it.
    payload: str
    #: What the target should change. Concrete, not "improve validation".
    recommendation: str
    #: Ordered trace of what happened.
    evidence: list[Step] = field(default_factory=list)
    #: CWE override; falls back to the ASI category's mapping.
    cwe: int | None = None
    #: Free-form tags for filtering, e.g. {"rag", "finance"}.
    tags: frozenset[str] = frozenset()
    #: Where to point a reviewer, as a repo-relative artifact URI.
    #:
    #: Set by the runner from the target's defining source file when the attack
    #: does not name one itself. Not optional in practice: GitHub code scanning
    #: rejects any result without a physical location, so a finding with no
    #: location cannot be uploaded at all.
    location: str | None = None
    #: Line within ``location`` when the finding is tied to a specific line.
    line: int | None = None

    def __post_init__(self) -> None:
        # Import here rather than at module level: asi.py does not import
        # models.py today, but a lazy import keeps that independence guaranteed.
        from .asi import get as _asi_get

        _asi_get(self.asi)  # raises KeyError with a helpful message if invalid

        if not self.evidence:
            raise ValueError(
                f"Finding {self.attack_id!r} has no evidence. Every finding must "
                "carry a reproducible trace — an unverifiable claim is worse "
                "than no claim, because it teaches reviewers to ignore the report."
            )

        object.__setattr__(self, "tags", frozenset(self.tags))
        if isinstance(self.severity, str):
            object.__setattr__(self, "severity", Severity(self.severity))

    @property
    def effective_cwe(self) -> int | None:
        """CWE to report: explicit override, else the ASI category's mapping."""
        if self.cwe is not None:
            return self.cwe
        from .asi import cwe_of

        return cwe_of(self.asi)

    @property
    def call_chain(self) -> list[str]:
        """Human-readable chain of tool invocations, for report output."""
        return [
            f"{s.tool_call.tool}({'allowed' if s.tool_call.allowed else 'DENIED'})"
            for s in self.evidence
            if s.tool_call is not None
        ]


@dataclass
class AttackResult:
    """Outcome of running one attack against one scaffold."""

    attack_id: str
    findings: list[Finding] = field(default_factory=list)
    #: True if the attack could not run at all (e.g. target lacks the hook).
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class ScanReport:
    """Everything produced by one scan. The single object reports consume."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    results: list[AttackResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    quillback_version: str = "unknown"

    # -- aggregation helpers ------------------------------------------------

    @property
    def by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def by_asi(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.asi] = counts.get(f.asi, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def covered_categories(self) -> set[str]:
        """ASI categories that were *tested*, whether or not they failed.

        Distinct from ``by_asi`` (which only counts failures). A category with
        zero findings because all attacks were blocked is a good result and
        should show as covered.
        """
        from .registry import attack_category

        return {
            attack_category(r.attack_id)
            for r in self.results
            if not r.skipped and r.error is None
        }

    @property
    def skipped(self) -> list[AttackResult]:
        return [r for r in self.results if r.skipped]

    @property
    def failed_attacks(self) -> list[AttackResult]:
        return [r for r in self.results if r.error is not None]

    @property
    def sorted_findings(self) -> list[Finding]:
        """Worst first, then by ASI code, then by id for stable output."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.asi, f.attack_id),
        )

    @property
    def exit_code(self) -> int:
        """Process exit status, so CI can gate on it.

        0 = clean, 1 = findings present, 2 = the scan itself broke. Returning 2
        distinctly matters: a crashed scan must not be mistaken for a passing one.
        """
        if self.failed_attacks:
            return 2
        return 1 if self.findings else 0
