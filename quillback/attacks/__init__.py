"""Attack library for quillback.

Attacks are grouped by OWASP ASI category so the mapping stays obvious when
reading the source. Importing this package registers every attack with the
registry via the decorators at the bottom of ``registry.py`` — there is no
manual list to forget to update.

Adding an attack
----------------
1. Write a subclass of :class:`~quillback.attacks.base.Attack` in the module
   matching its ASI category (create a new module if none fits).
2. Import that module here.
3. Add it to ``_ALL`` below.
4. Write a test proving it fires on the vulnerable demo agent and stays silent
   on a hardened variant.

Step 4 is not optional. An attack that only ever fires is a false-positive
generator, and an attack that never fires is dead weight. Both destroy trust in
the report faster than a missing feature would.
"""

from __future__ import annotations

from . import identity, injection, memory, supplychain, toolmisuse
from .base import Attack
from .identity import (
    ApprovalBypassOnGatedTool,
    CrossOriginTrustInheritance,
    PrivilegeEscalationByClaim,
)
from .injection import (
    HiddenInstructionInRetrievedContent,
    IndirectInjectionToDangerousTool,
    InstructionLeakIntoOutboundMessage,
    SystemPromptLacksInjectionBoundary,
)
from .memory import (
    HostileContentPersistedToMemory,
    MemoryNamespaceIsolationFailure,
    UnboundedMemoryGrowth,
)
from .supplychain import (
    FakeSystemEventInMessageChannel,
    ForgedSenderAccepted,
    NoDepthLimitOnDelegation,
    ToolDescriptionContainsInstructions,
    ToolScopeWiderThanDeclared,
)
from .toolmisuse import (
    NoToolCallBudget,
    UnsafeToolComposition,
    UnsanitisedArgumentReachesTool,
)

#: Every attack, in the order they run. Ordered by ASI code so reports read
#: top-to-bottom the same way the OWASP list does.
_ALL: tuple[type[Attack], ...] = (
    # ASI01 — Agent Goal Hijack
    IndirectInjectionToDangerousTool,
    HiddenInstructionInRetrievedContent,
    SystemPromptLacksInjectionBoundary,
    InstructionLeakIntoOutboundMessage,
    # ASI02 — Tool Misuse & Exploitation
    NoToolCallBudget,
    UnsafeToolComposition,
    UnsanitisedArgumentReachesTool,
    # ASI03 — Agent Identity & Privilege Abuse
    PrivilegeEscalationByClaim,
    ApprovalBypassOnGatedTool,
    CrossOriginTrustInheritance,
    # ASI04 — Agentic Supply Chain Compromise
    ToolDescriptionContainsInstructions,
    ToolScopeWiderThanDeclared,
    # ASI06 — Memory & Context Poisoning
    HostileContentPersistedToMemory,
    MemoryNamespaceIsolationFailure,
    UnboundedMemoryGrowth,
    # ASI07 — Insecure Inter-Agent Communication
    ForgedSenderAccepted,
    FakeSystemEventInMessageChannel,
    NoDepthLimitOnDelegation,
)

ALL_ATTACKS: tuple[Attack, ...] = tuple(cls() for cls in _ALL)

__all__ = [
    "Attack",
    "ALL_ATTACKS",
    "identity",
    "injection",
    "memory",
    "supplychain",
    "toolmisuse",
]
