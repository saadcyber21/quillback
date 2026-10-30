"""The target interface: how an agent exposes its control surface to quillback.

Design notes (read this before writing an attack)
-------------------------------------------------
The central idea is that we never ask a model what it would do. Instead we ask
the *scaffold* — the code around the model — to make its own decisions, and we
record them. Concretely:

1. An attack fabricates hostile content and hands it to one of the scaffold's
   data planes (``retrieve``, ``memory_get``, ``receive_message``, ...).
2. The scaffold's own logic runs: it plans, it calls ``check_permission``, it
   writes memory, it forwards messages.
3. The recorder captures every decision.
4. The attack inspects the recording and emits findings for the decisions that
   were wrong.

That is why this is deterministic and needs no API key: step 2 is your code, not
an inference call. For scaffolds whose planning genuinely *is* an LLM call, the
target can stub the planner with a canned transcript — see ``planned_calls``.

Capability detection
--------------------
Every hook defaults to returning ``NOT_IMPLEMENTED``. Attacks must check for
that and skip cleanly when the target does not implement a plane. A scan that
skips 6 attacks and reports 4 real findings is more useful than one that crashes
on the first missing method.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Tool, ToolCall

#: Sentinel meaning "this scaffold does not implement that hook".
#: A distinct object rather than None, because None is a legitimate value for
#: several of these methods (e.g. check_permission returns None to mean "allow").
NOT_IMPLEMENTED = object()


def is_unsupported(value: Any) -> bool:
    """True if a scaffold hook returned the not-implemented sentinel."""
    return value is NOT_IMPLEMENTED


class Scaffold:
    """Base class for a target agent.

    Override only the hooks your agent actually has. The defaults are all
    "unsupported", which makes dependent attacks skip rather than fail.
    """

    #: Display name used in reports. Override it.
    name: str = "unnamed-scaffold"

    #: Trust level attached to content arriving from the user. Attacks compare
    #: against this to detect trust-boundary crossings.
    user_origin: str = "user"

    # -- static artefacts (the part that lives in your repo) -----------------

    def system_prompt(self) -> Any:
        """Return the system prompt as a string."""
        return NOT_IMPLEMENTED

    def tools(self) -> Any:
        """Return the tool registry as a list[Tool]."""
        return NOT_IMPLEMENTED

    def policy(self) -> Any:
        """Return a dict of declared policy limits, if the agent has any.

        Recognised keys (all optional):
          ``max_tool_calls``  int   budget per turn
          ``max_depth``       int   nesting depth for agent-to-agent delegation
          ``deny_tags``       set   capability tags that must never be invoked
          ``human_approval``  set   tool names requiring a human decision
        """
        return NOT_IMPLEMENTED

    # -- runtime decision points --------------------------------------------

    def check_permission(
        self, tool_name: str, arguments: dict[str, Any], context: dict[str, Any]
    ) -> Any:
        """Authorisation gate.

        Return ``None`` to allow the call, or a string reason to deny it.
        ``context`` carries at least ``{"origin": <trust level>, "step": <int>}``
        and may carry whatever else the attack supplied.
        """
        return NOT_IMPLEMENTED

    def planned_calls(self, injected: str, context: dict[str, Any]) -> Any:
        """What tool calls would the agent make after seeing ``injected``?

        Return ``list[ToolCall]``. This is the hook that stands in for the
        model: a target whose planner is an LLM can replay a canned transcript
        here, or implement a rule-based planner, and the scan stays offline.
        """
        return NOT_IMPLEMENTED

    # -- data planes an attacker can write into ------------------------------

    def retrieve(self, query: str, namespace: str = "documents") -> Any:
        """Return retrieved content as a list[str] (RAG, web fetch, file read)."""
        return NOT_IMPLEMENTED

    def memory_append(self, namespace: str, key: str, value: Any) -> Any:
        """Persist a value to long-term memory. Return None on success."""
        return NOT_IMPLEMENTED

    def memory_get(self, namespace: str, key: str) -> Any:
        """Read back from long-term memory."""
        return NOT_IMPLEMENTED

    def send_message(self, recipient: str, content: str) -> Any:
        """Emit a message to another agent.

        Return ``None`` if the message was emitted, or a **string reason** if it
        was refused. The reason is recorded as evidence, so a refusal shows up
        in the report as a control working rather than as a silent gap.

        Do not signal refusal by returning ``None`` and dropping the message:
        the harness cannot distinguish that from success, and your control
        becomes invisible to every attack that depends on it.
        """
        return NOT_IMPLEMENTED

    def receive_message(self, sender: str, content: str) -> Any:
        """Ingest a message from another agent.

        Return ``None`` if accepted, or a **string reason** if rejected. Same
        rule as :meth:`send_message` — refusals must be observable.
        """
        return NOT_IMPLEMENTED

    def delegation_depth(self) -> Any:
        """Return the current delegation chain depth as an int.

        ``0`` means this agent was invoked directly. ``n`` means the request
        reached it through *n* agent-to-agent hops. A scaffold that cannot
        answer this has no way to bound a delegation chain, which is the
        mechanism behind cascading failures (ASI08).

        This is a *reported* value rather than something the harness infers by
        counting messages, because counting outbound sends measures fan-out, not
        depth — and conflating the two produces a finding that is technically
        true and practically meaningless.
        """
        return NOT_IMPLEMENTED


# ---------------------------------------------------------------------------
# The recording harness
# ---------------------------------------------------------------------------


@dataclass
class Trace:
    """Everything a scaffold did during one attack.

    Populated by :class:`Recorder`. Attacks read it; they never mutate it.
    """

    tool_calls: list[ToolCall] = field(default_factory=list)
    memory_writes: list[tuple[str, str, Any]] = field(default_factory=list)
    memory_reads: list[tuple[str, str]] = field(default_factory=list)
    messages_sent: list[tuple[str, str]] = field(default_factory=list)
    messages_received: list[tuple[str, str]] = field(default_factory=list)
    #: Outbound messages the target refused, as (recipient, reason).
    messages_refused: list[tuple[str, str]] = field(default_factory=list)
    #: Inbound messages the target rejected, as (sender, reason).
    messages_rejected: list[tuple[str, str]] = field(default_factory=list)
    retrievals: list[tuple[str, str, Any]] = field(default_factory=list)
    #: What the target actually holds after a write, read back through the
    #: target's own getter. Distinct from ``memory_writes`` — see below.
    memory_readback: dict[tuple[str, str], Any] = field(default_factory=dict)
    #: Writes the target actively rejected by raising. Evidence of a working
    #: control, not of a vulnerability.
    memory_rejections: list[tuple[str, str, str]] = field(default_factory=list)
    #: Hooks the target did not implement, so an attack can explain a skip.
    unsupported: set[str] = field(default_factory=set)

    def reset(self) -> None:
        self.tool_calls.clear()
        self.memory_writes.clear()
        self.memory_reads.clear()
        self.messages_sent.clear()
        self.messages_received.clear()
        self.messages_refused.clear()
        self.messages_rejected.clear()
        self.retrievals.clear()
        self.memory_readback.clear()
        self.memory_rejections.clear()

    @property
    def allowed_calls(self) -> list[ToolCall]:
        return [c for c in self.tool_calls if c.allowed]

    @property
    def denied_calls(self) -> list[ToolCall]:
        return [c for c in self.tool_calls if c.blocked]

    def calls_to(self, tool_name: str) -> list[ToolCall]:
        return [c for c in self.tool_calls if c.tool == tool_name]

    def allowed_with_tag(self, tag: str, tools: list[Tool]) -> list[ToolCall]:
        """Allowed calls whose tool carries ``tag``. Used to find money/exec/network."""
        tagged = {t.name for t in tools if tag in t.tags}
        return [c for c in self.allowed_calls if c.tool in tagged]

    def payload_reached(self, payload: str) -> bool:
        """True if hostile text left the scaffold through an outbound channel.

        Covers the two planes that genuinely egress: inter-agent messages and
        durable memory. For memory this checks ``memory_readback`` — what the
        target actually holds — and **not** ``memory_writes``, which only
        records what the harness asked it to store.

        That distinction is load-bearing. Checking the write request would
        report a finding against a target that correctly sanitises on the way
        in, because the request still contained the payload. An attack that
        reports what it tried rather than what happened is worse than no attack
        at all: it trains reviewers to distrust the report.
        """
        needle = payload.strip()
        if not needle:
            return False
        for _r, content in self.messages_sent:
            if needle in content:
                return True
        for value in self.memory_readback.values():
            if isinstance(value, str) and needle in value:
                return True
        return False

    def memory_persisted(self, namespace: str, key: str, payload: str) -> bool:
        """Did ``payload`` survive into the target's durable store?

        Reads back through ``memory_readback`` when available and falls back to
        an explicit ``memory_get`` result recorded by the harness. Returns False
        when the target rejected or sanitised the write — which is the correct
        outcome and must not be reported.
        """
        needle = payload.strip()
        if not needle:
            return False
        for (ns, k), value in self.memory_readback.items():
            if ns == namespace and k == key and isinstance(value, str):
                if needle in value:
                    return True
        return False


class Recorder:
    """Wraps a :class:`Scaffold`, recording every decision into a :class:`Trace`.

    Usage inside an attack::

        rec = Recorder(target)
        rec.reset(origin="untrusted_document")
        rec.planned_calls(hostile_text)
        if rec.trace.allowed_calls:
            ...emit finding...

    The recorder is deliberately thin. It does not add policy, does not filter,
    and does not interpret — interpretation belongs in attacks so it stays
    testable and reviewable.
    """

    def __init__(self, scaffold: Scaffold) -> None:
        self.scaffold = scaffold
        self.trace = Trace()
        self._tools: list[Tool] | None = None
        self._origin = "user"
        self._step = 0

    # -- lifecycle ----------------------------------------------------------

    def reset(self, origin: str = "user") -> None:
        """Start a fresh trace. Always call this at the top of an attack."""
        self.trace.reset()
        self.trace.unsupported.clear()
        self._origin = origin
        self._step = 0

    @property
    def origin(self) -> str:
        return self._origin

    def context(self, **extra: Any) -> dict[str, Any]:
        """Build the context dict passed to ``check_permission``."""
        ctx: dict[str, Any] = {"origin": self._origin, "step": self._step}
        ctx.update(extra)
        return ctx

    # -- static accessors with caching --------------------------------------

    def tools(self) -> list[Tool]:
        """The target's tool registry, or ``[]`` if unsupported. Cached."""
        if self._tools is None:
            raw = self.scaffold.tools()
            self._tools = [] if is_unsupported(raw) else list(raw)
            if is_unsupported(raw):
                self.trace.unsupported.add("tools")
        return self._tools

    def tool_named(self, name: str) -> Tool | None:
        for t in self.tools():
            if t.name == name:
                return t
        return None

    def system_prompt(self) -> str | None:
        raw = self.scaffold.system_prompt()
        if is_unsupported(raw):
            self.trace.unsupported.add("system_prompt")
            return None
        return str(raw)

    def policy(self) -> dict[str, Any]:
        raw = self.scaffold.policy()
        if is_unsupported(raw):
            self.trace.unsupported.add("policy")
            return {}
        return dict(raw)

    def supports(self, hook: str) -> bool:
        """True if the target implements ``hook``.

        Attacks use this to skip cleanly. Checking up front is friendlier than
        calling and inspecting the sentinel, and it keeps attack bodies short.
        """
        raw = getattr(self.scaffold, hook)()
        return not is_unsupported(raw)

    # -- recorded invocations -----------------------------------------------

    def check_permission(
        self, tool_name: str, arguments: dict[str, Any], **ctx_extra: Any
    ) -> tuple[bool, str | None]:
        """Ask the scaffold whether a call is allowed, and record the answer.

        Returns ``(allowed, deny_reason)``. If the target has no permission
        hook at all, the call is treated as **allowed** — that is the honest
        interpretation, since nothing stopped it.
        """
        ctx = self.context(**ctx_extra)
        decision = self.scaffold.check_permission(tool_name, arguments, ctx)

        if is_unsupported(decision):
            self.trace.unsupported.add("check_permission")
            allowed, reason = True, None
        else:
            # Any non-None, non-empty return is treated as a denial reason.
            allowed = decision is None
            reason = None if allowed else str(decision)

        call = ToolCall(
            tool=tool_name,
            arguments=dict(arguments),
            origin=self._origin,
            allowed=allowed,
            deny_reason=reason,
            step=self._step,
        )
        self.trace.tool_calls.append(call)
        self._step += 1
        return allowed, reason

    def planned_calls(
        self, injected: str, **ctx_extra: Any
    ) -> list[ToolCall]:
        """Run the scaffold's planner on hostile input and adjudicate each call.

        The planner proposes; ``check_permission`` disposes. Every proposed call
        is passed through the permission gate and recorded, whether allowed or
        denied. Returns the calls the planner proposed (with decisions applied).
        """
        raw = self.scaffold.planned_calls(injected, self.context(**ctx_extra))
        if is_unsupported(raw):
            self.trace.unsupported.add("planned_calls")
            return []

        adjudicated: list[ToolCall] = []
        for proposed in raw:
            allowed, reason = self.check_permission(
                proposed.tool, dict(proposed.arguments), **ctx_extra
            )
            # The recorder created its own ToolCall with correct origin/step,
            # so take that one rather than mutating the planner's copy.
            adjudicated.append(self.trace.tool_calls[-1])
            del allowed, reason  # decisions are on the recorded call
        return adjudicated

    def retrieve(self, query: str, namespace: str = "documents") -> list[str]:
        raw = self.scaffold.retrieve(query, namespace)
        if is_unsupported(raw):
            self.trace.unsupported.add("retrieve")
            return []
        out = list(raw)
        self.trace.retrievals.append((namespace, query, out))
        return out

    def memory_append(self, namespace: str, key: str, value: Any) -> None:
        """Record the *attempted* write, then capture what actually stuck.

        ``trace.memory_writes`` is the harness's own log of what it asked for —
        useful evidence that the attack reached the memory plane, but not proof
        of persistence. ``trace.memory_readback`` is the target's answer, and is
        what attacks must check before claiming a poisoning finding.
        """
        # A target that *raises* on an oversized or hostile write is refusing
        # it, which is correct behaviour and must not abort the scan. Record the
        # refusal as evidence instead of propagating the exception.
        try:
            result = self.scaffold.memory_append(namespace, key, value)
        except Exception as exc:  # noqa: BLE001 - refusal is a valid outcome
            self.trace.memory_writes.append((namespace, key, value))
            self.trace.memory_rejections.append((namespace, key, f"{type(exc).__name__}: {exc}"))
            return
        if is_unsupported(result):
            self.trace.unsupported.add("memory_append")
            return
        self.trace.memory_writes.append((namespace, key, value))

        # Read back immediately, through the target's own getter. If the target
        # sanitises, caps or rejects on write, the readback shows the real state.
        # A getter that raises is treated as "not persisted" rather than an
        # error: refusing the read is a valid hardened behaviour.
        try:
            stored = self.scaffold.memory_get(namespace, key)
        except Exception:  # noqa: BLE001 - refusal is acceptable behaviour
            stored = None
        if not is_unsupported(stored):
            self.trace.memory_readback[(namespace, key)] = stored

    def memory_get(self, namespace: str, key: str) -> Any:
        raw = self.scaffold.memory_get(namespace, key)
        if is_unsupported(raw):
            self.trace.unsupported.add("memory_get")
            return None
        self.trace.memory_reads.append((namespace, key))
        return raw

    def send_message(self, recipient: str, content: str) -> str | None:
        """Ask the scaffold to emit a message; record only what it accepts.

        Returns the refusal reason, or ``None`` if the message was sent.

        The ordering here is the whole point: the append to ``messages_sent``
        happens *after* the scaffold has agreed to emit. Recording the attempt
        first — which an earlier version of this harness did — makes a target
        that correctly drops hostile content look like one that forwarded it.
        """
        result = self.scaffold.send_message(recipient, content)
        if is_unsupported(result):
            self.trace.unsupported.add("send_message")
            return None
        if result is not None:
            self.trace.messages_refused.append((recipient, str(result)))
            return str(result)
        self.trace.messages_sent.append((recipient, content))
        return None

    def receive_message(self, sender: str, content: str) -> Any:
        """Deliver an inbound message; record only what the scaffold accepts."""
        result = self.scaffold.receive_message(sender, content)
        if is_unsupported(result):
            self.trace.unsupported.add("receive_message")
            return None
        if isinstance(result, str) and result:
            self.trace.messages_rejected.append((sender, result))
            return None
        self.trace.messages_received.append((sender, content))
        return result

    def delegation_depth(self) -> int | None:
        """Current delegation depth as reported by the scaffold, or None.

        ``None`` means the target does not implement the hook. Callers should
        treat that as "depth is untracked" rather than "depth is zero" — the
        distinction is the whole finding.
        """
        raw = self.scaffold.delegation_depth()
        if is_unsupported(raw):
            self.trace.unsupported.add("delegation_depth")
            return None
        return int(raw)
