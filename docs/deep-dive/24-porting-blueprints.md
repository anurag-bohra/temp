# 24 — Porting blueprints: sub-tools that can be lifted out of REA

Each blueprint lists the REA source units to take, dependencies, and what to rebuild. Seams were assessed by chapter writers (Porting notes sections in each chapter); the import graph of `src/` is cyclic in places (application↔artifacts, process↔artifacts — [02](02-architecture-and-module-map.md)), so extraction means copying a unit plus its transitive imports, not a clean package cut. Licence is MIT (package.json); third-party notices are in `THIRD_PARTY_NOTICES.md`.

| # | Sub-tool | Take from REA | Depends on | Rebuild | Malware use |
|---|---|---|---|---|---|
| 1 | **Tool-effects audit + annotation deriver** | `ToolEffects`, `TOOL_EFFECTS`, derived annotations ([03](03-mcp-server-runtime-and-contracts.md) §11) | none | your own tool list | Gate which agent tools may touch a sample vs detonate |
| 2 | **Evidence record + ledger + bundle** | Evidence zod schema, `EvidenceLedger`, bundle canonicalization ([10](10-evidence-model-ledger-unknowns-bundles.md)) | zod | persistence (ledger is in-memory) | Portable analyst report with provenance |
| 3 | **Unknowns tracker** | Unknown lifecycle + authority/confidence/environment resolution rules ([10](10-evidence-model-ledger-unknowns-bundles.md)) | Evidence model | storage | Hypothesis tracking; VM-required unknowns |
| 4 | **MCP server scaffold** | `createServer`, contract-driven registration, admission, progress, error projection, result delivery ([03](03-mcp-server-runtime-and-contracts.md)) | MCP SDK | your tools | Host any malware tooling behind typed contracts |
| 5 | **Provider router (deterministic, no fallback)** | `AnalysisProviderRegistry`, `SessionProviderRouter` ([06](06-provider-layer-and-session-routing.md)) | provider interface | adapters | Swap Ghidra/IDA/Hopper per sample |
| 6 | **Ghidra headless read-only bridge** | `src/ghidra`, `bridge/ghidra/*.java` ([08](08-ghidra-provider.md)) | Ghidra + JDK | — | Decompile/xrefs for samples without a GUI |
| 7 | **Hopper bridge** | `src/hopper`, `bridge/hopper_bridge.py` ([07](07-hopper-provider.md)) | Hopper (licensed) | — | macOS/Linux decompile |
| 8 | **Prompts + skill pack** | six prompts and the skill ([12](12-ai-layer-prompts-and-skills.md), part b) | REA tool names | retarget to your tools | Analyst-steering skill; ch12 includes proposed malware agent/skill definitions |
| 9 | **JS/Electron static analyzer** | `src/domain/javascript`, `src/application/javascript` ([16](16-javascript-electron-analysis.md)) | Node worker, wakaru | — | Trojanized desktop-app review |
| 10 | **.NET static analyzer** | `src/dotnet`, `src/domain/managed` | none (static) | — | Loader/stager triage |
| 11 | **Archive/format inspectors** | `src/artifacts`, `src/native/parsers` ([14](14-filetypes-native-apple-archives.md)) | — | harden extraction for hostile input | Package unpacking and inventory |
| 12 | **Browser/CDP observer** | `src/browser` ([17](17-browser-and-web-observation.md)) | Chrome | run in disposable profile | Malicious-page behaviour |
| 13 | **Process-capture harness** | `src/process` ([18 not written in this pass]) | PTY, OS | **must add VM sandbox** | Detonation logging |

Hard to lift (ch03 writer): `src/process` (imports `src/artifacts`) and the `application`/`artifacts` split. Easy: items 1, 2, 4.
