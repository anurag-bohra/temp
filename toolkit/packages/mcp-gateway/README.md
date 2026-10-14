# @rtk/mcp-gateway
MCP stdio server that sits in front of an upstream MCP server (default: REA) and **enforces** what REA only advertises: tool filtering by `@rtk/effects` profile (denied tools are neither advertised nor callable), path-argument allow-roots, untrusted-output envelope + control/bidi/ANSI stripping + size caps + prompt-injection detection (matched text is withheld from metadata: only length and hash are reported), and a tamper-evident hash-chained audit log (`verifyAuditLog`).
```json
{ "mcpServers": { "rea-gated": { "command": "node", "args": ["/path/to/toolkit/packages/mcp-gateway/bin/rtk-gateway.ts"],
  "env": { "RTK_PROFILE": "static-analysis", "RTK_ALLOWED_ROOTS": "/samples", "RTK_AUDIT_LOG": "/var/log/rtk-audit.jsonl",
           "RTK_UPSTREAM_COMMAND": "node /path/to/rea/scripts/rea.mjs mcp", "RTK_UPSTREAM_ENV_ALLOW": "GHIDRA_INSTALL_DIR,PATH,HOME" } } } }
```
**Verified (tests, 19):** unit tests for policy/sanitize/audit plus **5 live tests against the real REA server**: execution/device tools hidden and refused, out-of-root path refused, analysis output wrapped, a binary whose strings say "IGNORE PREVIOUS INSTRUCTIONS …" (opened through Ghidra) appears only inside the envelope and is flagged, audit chain verifies and detects tampering.
**Limits:** wrapping/detection reduce but cannot eliminate prompt-injection risk; policy depends on declared effects (see audit-gap overlay); `ask` verdicts are refused unless approved via `RTK_APPROVE`; CLI (non-MCP) use of REA is not covered.
