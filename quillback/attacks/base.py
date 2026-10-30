"""Attack base class and the helpers most attacks need.

An attack answers one question: *given hostile content entering plane X, does
the scaffold make a decision it should not?* Attacks never call models, never do
I/O, and never sleep. That keeps scans deterministic and fast enough to run on
every commit.

Writing a new attack
--------------------
1. Pick the file matching its ASI category under ``quillback/attacks/``.
2. Subclass :class:`Attack`, set the class attributes, implement ``run``.
3. Return ``[]`` when the scaffold is fine. Only emit a finding when you have
   evidence in the trace — ``Finding`` will raise if you do not.
4. Add a test that asserts it fires on ``VulnerableAgent`` and stays quiet on a
   hardened variant. An attack that cannot demonstrate both is not finished.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import Finding, Severity, Step, ToolCall
from ..scaffold import Recorder


class Attack(ABC):
    """Base class for a single test in the library."""

    #: Globally unique kebab-case id, e.g. "injection/indirect-doc-to-refund".
    id: str = ""
    #: Short human title, used as the SARIF rule name.
    name: str = ""
    #: What this attack is trying to prove. Shown in reports.
    description: str = ""
    #: OWASP ASI category code, e.g. "ASI01".
    asi: str = ""
    #: Impact if the attack succeeds.
    severity: Severity = Severity.HIGH
    #: Free-form tags for filtering.
    tags: frozenset[str] = frozenset()
    #: Hooks this attack needs. The runner skips it if any are missing, so the
    #: attack body can assume they exist.
    requires: tuple[str, ...] = ()
    #: Repo-relative path of the artifact this attack inspects, when it is a
    #: static one. Leave unset for behavioural attacks and the runner falls back
    #: to the file defining the target scaffold.
    #:
    #: GitHub code scanning rejects any result without a physical location, so
    #: every finding ends up with one — the only question is whether it points
    #: at something meaningful.
    source_file: str | None = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate concrete subclasses at import time.

        Catching a missing ``id`` or ``asi`` when the module loads beats
        discovering it halfway through a scan. Abstract intermediates (no
        ``run`` of their own) are skipped.
        """
        super().__init_subclass__(**kwargs)
        if cls.run is Attack.run:  # still abstract
            return
        if not cls.id:
            raise ValueError(f"{cls.__name__} must define a non-empty 'id'")
        if not cls.asi:
            raise ValueError(
                f"{cls.__name__} must declare an OWASP ASI category ('asi')"
            )
        if not cls.description:
            raise ValueError(f"{cls.__name__} must explain itself in 'description'")

    @abstractmethod
    def run(self, rec: Recorder) -> list[Finding]:
        """Execute the attack against a recorder-wrapped scaffold."""
        raise NotImplementedError

    # -- helpers for subclasses ---------------------------------------------

    def finding(
        self,
        *,
        title: str,
        payload: str,
        steps: list[Step],
        recommendation: str,
        description: str | None = None,
        severity: Severity | None = None,
        cwe: int | None = None,
        tags: frozenset[str] | None = None,
        location: str | None = None,
        line: int | None = None,
    ) -> Finding:
        """Build a Finding pre-filled with this attack's identity.

        Attacks should use this rather than constructing ``Finding`` directly so
        that id/asi/tags stay consistent and there is one place to change.
        """
        return Finding(
            attack_id=self.id,
            title=title,
            severity=severity or self.severity,
            asi=self.asi,
            description=description or self.description,
            payload=payload,
            evidence=steps,
            recommendation=recommendation,
            cwe=cwe,
            tags=frozenset(self.tags | (tags or frozenset())),
            location=location or self.source_file,
            line=line,
        )

    @staticmethod
    def call_step(call: ToolCall, detail: str | None = None) -> Step:
        """Wrap a recorded ToolCall as an evidence step."""
        verb = "permitted" if call.allowed else f"denied ({call.deny_reason})"
        return Step(
            kind="tool_call",
            detail=detail or f"tool '{call.tool}' {verb} with args {call.arguments}",
            tool_call=call,
        )

    @staticmethod
    def step(kind: str, detail: str) -> Step:
        """A non-tool-call evidence step (injection, retrieval, memory write...)."""
        return Step(kind=kind, detail=detail)

    @staticmethod
    def denied_anywhere(calls: list[ToolCall]) -> bool:
        """True if every proposed call was blocked — i.e. the target held."""
        return bool(calls) and all(c.blocked for c in calls)

    @staticmethod
    def allowed(calls: list[ToolCall]) -> list[ToolCall]:
        return [c for c in calls if c.allowed]
