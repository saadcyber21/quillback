# Changelog

## 0.1.0 — 2026-10-30

First release.

- 18 attacks across OWASP ASI 2026 categories ASI01, ASI02, ASI03, ASI04,
  ASI06, ASI07, each mapped to a CWE where one applies.
- Recording harness over five trust planes: retrieved documents, tool outputs,
  memory, inter-agent messages, system prompt.
- SARIF 2.1.0 export; findings land natively in GitHub code scanning. The
  repository scans itself: 19 live findings in its own Security tab.
- Reference-agent contrast asserted in CI on every commit: 19 findings on the
  deliberately-vulnerable agent, 0 on the hardened variant. Both directions,
  or the build fails.
- Zero runtime dependencies; deterministic — same input, same findings.
- Declared blind spots printed on every run: ASI05, ASI08, ASI09, ASI10 have
  no attacks yet. See ROADMAP.md.
