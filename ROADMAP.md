# Roadmap

Honest status. What is here works and is tested; what is missing is listed
because pretending otherwise would waste your time.

## Done (v0.1.0)

- **18 attacks** across ASI01, ASI02, ASI03, ASI04, ASI06, ASI07
- **OWASP ASI 2026** mapping and CWE relationships on every finding
- **SARIF 2.1.0** export, GitHub code-scanning compatible
- Terminal, Markdown and JSON reports, with an explicit coverage section that
  names blind spots instead of implying full coverage
- **Reference targets**: a deliberately vulnerable support agent and a hardened
  variant, with a test asserting every attack fires on the former and stays
  silent on the latter
- **CI**: matrix across Python 3.10–3.13, plus two regression gates — one
  asserting the vulnerable agent still fails, one asserting the hardened agent
  stays clean
- **GitHub Action** scaffold (`action.yml`)
- Zero runtime dependencies

## Next, roughly in order

### 1. Close the coverage gaps
No attacks yet for **ASI05** (unexpected code execution), **ASI08** (cascading
failures), **ASI09** (human-agent trust exploitation) or **ASI10** (rogue
agents). The report says so loudly, which is correct, but four uncovered
categories out of ten is a real limitation. ASI09 is the most interesting — it
is about a human approving something they should not have, which needs a model
of the approval prompt rather than of the permission gate.

### 2. Real framework adapters
Right now you write a `Scaffold` subclass by hand. The adoption blocker is that
this takes an afternoon. Adapters that introspect an existing agent would make
it take a minute:
- LangGraph / LangChain
- CrewAI
- OpenAI Agents SDK / Assistants
- MCP servers — read `tools/list` and treat the descriptions as the artefact
  under test. This one is probably the highest-value target in the list, because
  MCP servers are exactly the runtime-fetched supply chain ASI04 describes.

### 3. Static analysis of agent configs without any adapter
Parse `.cursor/rules`, `CLAUDE.md`, `AGENTS.md`, MCP `config.json` and tool
schemas straight off disk. No integration required, works on any repository, and
it is the mode that makes the GitHub Action genuinely useful to a stranger —
they point it at a repo and get findings without writing a line of Python.

### 4. Baseline and diff
Store a baseline of accepted findings so CI only fails on *new* ones. Without
this, adopting the tool on an existing agent means either fixing everything
first or ignoring the build. This is the single biggest adoption blocker after
the adapters.

### 5. Multi-turn and stateful attack sequences
Every current attack is one hop. Real compromises are usually three: poison
memory in session one, have it retrieved in session two, act on it in session
three. This needs a session abstraction on `Scaffold`, which is an interface
change — hence it is not first.

## Deliberately not planned

- **Attacks that require a live model.** That is garak's and PyRIT's job, and
  they do it well. Adding it here would mean API keys, cost and non-determinism,
  which is the entire thing this tool refuses to be.
- **A CVSS score per finding.** Computing one honestly requires environmental
  assumptions we cannot make about someone else's deployment. The SARIF export
  carries indicative `security-severity` values for sorting, and they are
  labelled as such.
- **A web UI.** A terminal tool that runs in CI reaches more people than a
  dashboard that needs hosting.

## Things I would want told to me before contributing

- Every attack needs a test proving it fires on the vulnerable agent **and**
  stays silent on the hardened one. One half of that is easy to fake; both
  halves together are what make a finding worth reading.
- Detection must be based on what the target *did*, not on what the harness
  *attempted*. Two bugs of exactly this shape were found during initial
  development, and both produced confident, completely wrong findings.
- Refusals must be observable. A scaffold that silently drops a message is
  indistinguishable from one that forwarded it, which is why the message hooks
  return a reason string.
- Do not key a control to a specific payload string. The hardened reference
  agent initially sanitised by matching quillback's own canary. It passed the
  demo and was worthless.
