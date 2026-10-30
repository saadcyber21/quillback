"""The OWASP Top 10 for Agentic Applications (2026) as a typed registry.

Why this module exists
----------------------
Findings from a red-team tool are only useful if a reviewer can tell *what kind*
of risk they represent and *how bad* it is. OWASP published a peer-reviewed top
ten for agentic systems in December 2025 (the "ASI" list). Aligning to it means:

  * a security reviewer instantly recognises the categories,
  * findings can be aggregated into a coverage report ("you have no tests for
    ASI07 at all" is a much more useful sentence than "3 findings"),
  * and the project speaks the same language as the wider AppSec community.

The source list: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Each entry also carries a CWE where a reasonable mapping exists. CWE is what
SARIF consumers (GitHub's code scanning, in particular) expect, so having both
lets us emit standards-shaped output. Where no honest CWE mapping exists we say
so with ``None`` rather than inventing one — a wrong mapping is worse than none.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AsiCategory:
    """One row of the OWASP ASI 2026 top ten."""

    #: Stable identifier, e.g. "ASI01". Safe to use in code and filenames.
    code: str
    #: Human-readable risk name as published by OWASP.
    name: str
    #: One-paragraph description of the failure mode, in plain English.
    summary: str
    #: Nearest CWE, or None when there is no defensible mapping.
    cwe: int | None


# ---------------------------------------------------------------------------
# The list itself.
#
# Ordered as published. Keep the order stable: reports sort by it, and people
# comparing output between versions should not see rows jump around.
# ---------------------------------------------------------------------------

ASI: tuple[AsiCategory, ...] = (
    AsiCategory(
        code="ASI01",
        name="Agent Goal Hijack",
        summary=(
            "Attackers manipulate an agent's goals, plans or decision paths via "
            "direct or indirect instruction injection, so the agent pursues an "
            "objective nobody authorised. Includes instructions hidden in "
            "retrieved documents, tool outputs and web content."
        ),
        cwe=77,  # Command injection: the injected instruction IS the command.
    ),
    AsiCategory(
        code="ASI02",
        name="Tool Misuse & Exploitation",
        summary=(
            "An agent abuses tools it legitimately has access to: recursive "
            "call loops, dangerous compositions, budget exhaustion, or state "
            "leaking between tool contexts. Permissions are valid; the "
            "behaviour is still harmful."
        ),
        cwe=841,  # Improper enforcement of behavioural workflow.
    ),
    AsiCategory(
        code="ASI03",
        name="Agent Identity & Privilege Abuse",
        summary=(
            "Delegated authority, ambiguous identity or unchecked trust "
            "assumptions lead to unauthorised actions: impersonation, "
            "privilege inheritance along a call chain, or role bypass."
        ),
        cwe=269,  # Improper privilege management.
    ),
    AsiCategory(
        code="ASI04",
        name="Agentic Supply Chain Compromise",
        summary=(
            "Compromise of externally sourced agents, tools, schemas or "
            "prompts that the agent dynamically trusts. Includes misleading "
            "tool descriptions and manipulated schemas."
        ),
        cwe=829,  # Inclusion of functionality from untrusted control sphere.
    ),
    AsiCategory(
        code="ASI05",
        name="Unexpected Code Execution",
        summary=(
            "An agent executes code it was not meant to, typically because "
            "untrusted content reached an interpreter, template engine or "
            "shell-backed tool without sanitisation."
        ),
        cwe=94,  # Improper control of generation of code.
    ),
    AsiCategory(
        code="ASI06",
        name="Memory & Context Poisoning",
        summary=(
            "Hostile content is persisted into long-term memory or carried "
            "across context boundaries, so it influences later sessions that "
            "never saw the original attack."
        ),
        cwe=502,  # Deserialization of untrusted data is the closest analogue.
    ),
    AsiCategory(
        code="ASI07",
        name="Insecure Inter-Agent Communication",
        summary=(
            "Messages between agents are unauthenticated, unsigned or "
            "unvalidated, letting one agent impersonate another or smuggle "
            "instructions across a trust boundary."
        ),
        cwe=345,  # Insufficient verification of data authenticity.
    ),
    AsiCategory(
        code="ASI08",
        name="Cascading Agent Failures",
        summary=(
            "One compromised or failing agent propagates damage through a "
            "multi-agent system, with no circuit breaker or blast-radius "
            "control between steps."
        ),
        cwe=None,  # Genuinely no good CWE fit; do not invent one.
    ),
    AsiCategory(
        code="ASI09",
        name="Human-Agent Trust Exploitation",
        summary=(
            "Attackers exploit the fact that humans over-trust agent output: "
            "fabricated confidence, suppressed warnings, or approval prompts "
            "framed so the human rubber-stamps them."
        ),
        cwe=451,  # User interface misrepresentation of critical information.
    ),
    AsiCategory(
        code="ASI10",
        name="Rogue Agents",
        summary=(
            "An agent operates outside its intended constraints — self-"
            "modifying its instructions, exceeding its mandate, or continuing "
            "to act after it should have stopped."
        ),
        cwe=284,  # Improper access control.
    ),
)


# Look-up tables built once at import time. Building these inline in a loop
# would be O(n) per lookup and, more importantly, harder to read.
BY_CODE: dict[str, AsiCategory] = {c.code: c for c in ASI}

#: Which categories have at least one attack implemented. Computed lazily by
#: the runner so this module stays free of import cycles.
_ALL_CODES: frozenset[str] = frozenset(BY_CODE)


def get(code: str) -> AsiCategory:
    """Return the category for ``code``, raising a clear error if unknown.

    A typo in an attack's category tag should fail loudly at scan time with a
    helpful message, not silently produce an unmapped finding.
    """
    try:
        return BY_CODE[code]
    except KeyError:
        known = ", ".join(sorted(BY_CODE))
        raise KeyError(
            f"Unknown OWASP ASI category {code!r}. Valid codes are: {known}"
        ) from None


def cwe_of(code: str) -> int | None:
    """Convenience accessor for the CWE mapping of a category."""
    return get(code).cwe


def uncovered(codes: set[str]) -> list[str]:
    """ASI categories with no findings or attacks in a given run.

    Used by the report to surface blind spots. "You tested 4 of 10 categories"
    is actionable in a way that a raw finding count is not.
    """
    return sorted(_ALL_CODES - set(codes))
