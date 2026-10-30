# quillback

**Offline red-team harness for AI agent scaffolds. No API keys. No tokens. Deterministic.**

> Named after the quillback porcupine — nothing fancy, just a lot of spines and
> excellent posture when something gets too close.

---

## The problem

Existing AI red-teaming tools — [garak](https://github.com/NVIDIA/garak),
[PyRIT](https://github.com/Azure/PyRIT), [promptfoo](https://github.com/promptfoo/promptfoo),
[deepteam](https://github.com/confident-ai/deepteam) — all point attacks at a
**live model**. That means:

- You need an API key and you pay per run
- Results are non-deterministic, so CI is flaky
- You are testing the model, which you did not write and cannot fix
- The attack surface that you *actually own* — your system prompt, your tool
  schemas, your permission gates, your memory store — is barely covered

## The idea

Your agent's **scaffold** is static. It lives in your repository. The system
prompt is a string. The tool definitions are JSON. The permission logic is
code. The memory store has an interface.

`quillback` attacks the scaffold, not the model. It does this by wrapping your
agent in a **recording harness**: hostile payloads are injected into the data
planes your agent trusts (retrieved documents, tool outputs, memory, inter-agent
messages), and the harness observes which tools your permission layer would have
allowed, what got persisted to memory, and what leaked across trust boundaries.

No inference. No randomness. Same input, same findings, every time — which means
it can gate a pull request.

## Findings are mapped to OWASP ASI 2026

Every finding carries a mapping to the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
(ASI01–ASI10) and to a CWE where one applies. Reports export to **SARIF 2.1.0**,
so findings appear natively in your repository's GitHub Security tab.

## Quick start

```bash
# Scan the bundled deliberately-vulnerable demo agent
python -m quillback scan --demo

# Scan your own agent
python -m quillback scan --target myapp.security:my_scaffold

# Emit SARIF for CI
python -m quillback scan --demo --format sarif --out results.sarif

# See what's in the attack library
python -m quillback attacks
```

## Wrapping your own agent

Subclass `Scaffold` and point the hooks at your real code. Only override what
you have; everything has a safe default.

```python
from quillback import Scaffold, Tool

class MyAgent(Scaffold):
    name = "support-agent"

    def system_prompt(self) -> str:
        return MY_SYSTEM_PROMPT

    def tools(self) -> list[Tool]:
        return load_my_tool_registry()

    def check_permission(self, tool_name, arguments, context):
        # Your real authorisation logic. Return None to allow,
        # or a string reason to deny.
        return my_guard(tool_name, arguments, context)

    def memory_append(self, namespace, key, value) -> None:
        my_memory.write(namespace, key, value)

    def retrieve(self, query, namespace="documents"):
        return my_rag.search(query, namespace)
```

Then register it somewhere importable and scan it:

```bash
python -m quillback scan --target myapp.security:MyAgent
```

## Status

This is early. The architecture, the ASI mapping, the runner, the SARIF export
and a working attack set are in place. See [ROADMAP.md](ROADMAP.md) for what is
next, and be blunt in issues about what is missing.

## Is this a scanner or a red team?

Neither, precisely. It is closer to a **fuzzer with a policy oracle**. It will
not tell you whether a model can be jailbroken into writing malware. It will
tell you that your permission gate lets a payload arriving inside a retrieved
PDF trigger `refund_customer` without human approval, and it will show you the
exact call chain that got there.

## Responsible use

The attack payloads in this repository are designed to test **your own**
systems. They are deliberately generic and contain no working exploits against
third-party services. Do not point this at systems you do not have written
authorisation to test — the same rule as every other security tool.

## Licence

MIT. See [LICENSE](LICENSE).
