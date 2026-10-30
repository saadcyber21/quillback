"""Tests for the runner and the recording harness.

These cover the two bugs that were actually found while building quillback, and
which are easy to reintroduce:

* the harness recording what it *attempted* rather than what the target *did*
  (found twice — once for memory writes, once for outbound messages)
* a target that refuses an action by silently returning None, making the refusal
  invisible to every attack

Both are interface-level mistakes, so they get interface-level tests.
"""

from __future__ import annotations

from quillback.models import Severity, Tool, ToolCall
from quillback.runner import ScanAborted, run_scan, _implements
from quillback.scaffold import Recorder, Scaffold


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class MinimalScaffold(Scaffold):
    """Implements nothing. Every attack should skip, none should crash."""

    name = "minimal"


class RefusingScaffold(Scaffold):
    """Refuses everything, and says so with a reason string."""

    name = "refusing"

    def tools(self):
        return [Tool(name="do_thing", parameters=("x",), tags=frozenset({"write"}))]

    def check_permission(self, tool_name, arguments, context):
        return "denied by policy"

    def send_message(self, recipient, content):
        return "refused: content untrusted"

    def receive_message(self, sender, content):
        return "rejected: unsigned"

    def memory_append(self, namespace, key, value):
        # Refusing by raising is also legitimate and must not abort the scan.
        raise PermissionError("memory writes disabled")

    def memory_get(self, namespace, key):
        return None


class PermissiveScaffold(Scaffold):
    """Allows everything — the shape of most real first drafts."""

    name = "permissive"

    def tools(self):
        return [
            Tool(name="read_doc", parameters=("q",), tags=frozenset({"read"})),
            Tool(name="send_money", parameters=("to", "amount"),
                 tags=frozenset({"money"}), dangerous=True, requires_approval=True),
        ]

    def check_permission(self, tool_name, arguments, context):
        return None

    def planned_calls(self, injected, context):
        origin = context.get("origin", "user")
        return [
            ToolCall(tool=t.name, arguments={}, origin=origin)
            for t in self.tools()
            if t.name in injected
        ]

    def retrieve(self, query, namespace="documents"):
        return ["some retrieved text"]

    def memory_append(self, namespace, key, value):
        self._store = getattr(self, "_store", {})
        self._store[(namespace, key)] = value

    def memory_get(self, namespace, key):
        return getattr(self, "_store", {}).get((namespace, key))

    def send_message(self, recipient, content):
        self._out = getattr(self, "_out", [])
        self._out.append((recipient, content))

    def receive_message(self, sender, content):
        return None


# ---------------------------------------------------------------------------
# Capability detection and skipping
# ---------------------------------------------------------------------------


def test_minimal_target_skips_everything_without_erroring() -> None:
    report = run_scan(MinimalScaffold())

    assert report.findings == [], "a target implementing nothing should yield no findings"
    assert not report.failed_attacks, (
        f"attacks raised on an empty target: {[r.error for r in report.failed_attacks]}"
    )
    assert len(report.skipped) > 0, "every attack should have skipped"
    for r in report.skipped:
        assert r.skip_reason, f"{r.attack_id} skipped with no explanation"


def test_implements_detects_overrides_not_call_them() -> None:
    """``_implements`` must not invoke the hook.

    Calling a hook during a capability check would run target code twice, and a
    hook with side effects would corrupt the scan.
    """
    assert _implements(PermissiveScaffold(), "tools") is True
    assert _implements(MinimalScaffold(), "tools") is False
    assert _implements(MinimalScaffold(), "nonexistent_hook") is False


# ---------------------------------------------------------------------------
# Recording what happened, not what was attempted
# ---------------------------------------------------------------------------


def test_refused_message_is_not_recorded_as_sent() -> None:
    """Regression: the harness used to log the attempt before the decision."""
    rec = Recorder(RefusingScaffold())
    rec.reset()

    reason = rec.send_message("peer", "hostile content")

    assert reason == "refused: content untrusted"
    assert rec.trace.messages_sent == [], (
        "a message the target refused must not appear in messages_sent; "
        "attacks read that list as proof of egress"
    )
    assert rec.trace.messages_refused == [("peer", "refused: content untrusted")]


def test_rejected_inbound_message_is_not_recorded_as_received() -> None:
    rec = Recorder(RefusingScaffold())
    rec.reset()

    rec.receive_message("attacker", "signed: false")

    assert rec.trace.messages_received == []
    assert len(rec.trace.messages_rejected) == 1


def test_memory_rejection_does_not_abort_the_scan() -> None:
    """A target that raises on a write is refusing it, not breaking."""
    rec = Recorder(RefusingScaffold())
    rec.reset()

    rec.memory_append("ns", "key", "value")  # must not raise

    assert len(rec.trace.memory_rejections) == 1
    assert rec.trace.memory_readback == {}, "nothing was stored, so readback is empty"


def test_memory_readback_reflects_the_target_not_the_request() -> None:
    """Regression: findings must be based on what the target persisted."""

    class SanitisingScaffold(PermissiveScaffold):
        name = "sanitising"

        def memory_append(self, namespace, key, value):
            # Stores something different from what it was given.
            super().memory_append(namespace, key, "SANITISED")

    rec = Recorder(SanitisingScaffold())
    rec.reset()
    rec.memory_append("ns", "key", "HOSTILE-PAYLOAD")

    assert rec.trace.memory_writes[0][2] == "HOSTILE-PAYLOAD", (
        "memory_writes should record the attempt, as evidence the plane was reached"
    )
    assert rec.trace.memory_readback[("ns", "key")] == "SANITISED", (
        "memory_readback must show what the target actually holds"
    )
    assert rec.trace.memory_persisted("ns", "key", "HOSTILE-PAYLOAD") is False
    assert rec.trace.memory_persisted("ns", "key", "SANITISED") is True


def test_permissive_target_does_persist_and_egress() -> None:
    """The mirror of the two tests above — controls must not be assumed."""
    rec = Recorder(PermissiveScaffold())
    rec.reset()

    rec.memory_append("ns", "key", "HOSTILE-PAYLOAD")
    rec.send_message("peer", "HOSTILE-PAYLOAD")

    assert rec.trace.memory_persisted("ns", "key", "HOSTILE-PAYLOAD") is True
    assert rec.trace.payload_reached("HOSTILE-PAYLOAD") is True
    assert rec.trace.messages_sent == [("peer", "HOSTILE-PAYLOAD")]


# ---------------------------------------------------------------------------
# Runner behaviour
# ---------------------------------------------------------------------------


def test_runner_rejects_non_scaffold_target() -> None:
    try:
        run_scan(object())  # type: ignore[arg-type]
    except ScanAborted as exc:
        assert "Scaffold" in str(exc)
    else:
        raise AssertionError("run_scan should reject a non-Scaffold target")


def test_runner_rejects_empty_attack_selection() -> None:
    try:
        run_scan(PermissiveScaffold(), attacks=[])
    except ScanAborted as exc:
        assert "nothing" in str(exc)
    else:
        raise AssertionError("an empty selection should be an error, not a clean scan")


def test_broken_attack_does_not_abort_the_scan() -> None:
    """One exploding attack costs one attack, not the report."""
    from quillback.attacks.base import Attack

    class RealExplosion(Attack):
        id = "test/explodes"
        name = "Exploding test attack"
        asi = "ASI01"
        severity = Severity.LOW
        description = "A test attack that always raises, to verify containment."
        requires = ()

        def run(self, rec):
            raise RuntimeError("deliberate failure")

    report = run_scan(PermissiveScaffold(), attacks=[RealExplosion()])

    assert len(report.failed_attacks) == 1
    assert "deliberate failure" in report.failed_attacks[0].error
    assert report.exit_code == 2, "a broken scan must not report as clean"


def test_exit_codes_distinguish_clean_found_and_broken() -> None:
    clean = run_scan(HardenedTarget())
    assert clean.exit_code == 0, f"expected clean scan, got findings: {[f.title for f in clean.findings]}"

    found = run_scan(PermissiveScaffold())
    assert found.findings, "the permissive target should produce findings"
    assert found.exit_code == 1


def test_registry_filters_work() -> None:
    from quillback.registry import select

    by_asi = select(asi=["ASI01"])
    assert by_asi, "expected ASI01 attacks to exist"
    assert all(a.asi == "ASI01" for a in by_asi)

    excluded_id = by_asi[0].id
    remaining = select(asi=["ASI01"], exclude=[excluded_id])
    assert all(a.id != excluded_id for a in remaining)
    assert len(remaining) == len(by_asi) - 1

    assert select(ids=["does-not-exist"]) == []


def test_finding_requires_evidence() -> None:
    """A finding with no trace is not actionable and must not construct."""
    from quillback.models import Finding

    try:
        Finding(
            attack_id="test/x",
            title="no evidence",
            severity=Severity.HIGH,
            asi="ASI01",
            description="d",
            payload="p",
            recommendation="r",
            evidence=[],
        )
    except ValueError as exc:
        assert "evidence" in str(exc)
    else:
        raise AssertionError("Finding should reject an empty evidence chain")


def test_finding_rejects_unknown_asi_code() -> None:
    from quillback.models import Finding, Step

    try:
        Finding(
            attack_id="test/x",
            title="t",
            severity=Severity.HIGH,
            asi="ASI99",
            description="d",
            payload="p",
            recommendation="r",
            evidence=[Step(kind="inject", detail="x")],
        )
    except KeyError as exc:
        assert "ASI99" in str(exc)
    else:
        raise AssertionError("Finding should reject an unknown ASI category")


# A genuinely clean target, used to assert exit code 0.
from quillback.demo import HardenedSupportAgent as HardenedTarget  # noqa: E402
