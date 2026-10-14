# rea-toolkit (independent implementations of the 13 porting blueprints + triage layer)

Defensive malware-triage / vulnerability-research toolkit designed in `../docs/deep-dive/24-porting-blueprints.md`. TypeScript run directly by Node 22 (type stripping); `npm install && npm test`; `npx tsc --noEmit -p tsconfig.json` is clean at the last run.

## Status at last run (tests per package; nothing here is a product, all verified only on the benign demo samples)
| Package | Blueprint | Tests (pass/fail/skip) | State |
|---|---|---|---|
| `evidence` | 02 Evidence/ledger/bundle | 6/0/0 | Done. Reproduces all 26 real REA Evidence IDs; REA's exported bundle round-trips byte-identically |
| `effects` | 01 ToolEffects + policy | 6/0/0 | Done. Annotations derived = advertised for all 207 REA tools; policy profiles + verified audit-gap overlay |
| `unknowns` | 03 Unknown registry | 7/0/0 | Done. REA-compatible ids/digests (verified on a real REA unknown); lifecycle + evidence-qualified resolution |
| `provider-router` | 05 registry/router | 13/0/0 | Done (no lazy load, snapshot cache, or cancellation) |
| `ghidra-bridge` | 06 Ghidra bridge | 14/0/0 | Done for x86-64 ELF on Linux; matches REA's Ghidra results on the same samples; `xrefs` limited to strings and direct calls |
| `hopper-bridge` | 07 Hopper bridge | 12/0/0 | **Skeleton, unverified against real Hopper** (fake-server tests only) |
| `prompts-skills` | 08 prompts + skills | 8/0/0 | Done. REA's six prompts render byte-identically to real REA output; two toolkit skills + four prompts; additive installer |
| `js-analyzer` | 09 JS/Electron analyzer | 17/0/0 | Built by an implementer that was stopped before its final report: README/limitations may be incomplete — review before relying on it |
| `dotnet-analyzer` | 10 .NET analyzer | 8/0/0 | Built; implementer stopped during README/final checks — review |
| `artifacts` | 11 archive inspector/extractor | 31/0/0 | Built (zip/tar/asar, quotas, anomaly tests); implementer stopped — review |
| `browser-observer` | 12 browser observer | 19/0/0 | Built; runs Chromium as root with `--no-sandbox` (see its limitations) — review |
| `sandbox` | 13 sandboxed runner | 14/0/1 | Built; isolation is process/namespace level, never a VM; implementer stopped — review |
| `mcp-gateway` | policy/untrusted-output gateway | 12/**2 failing** | **Incomplete**: 2 tests fail (the live-REA integration tests were not finished when the implementer was stopped) |
| `triage` | 14 triage layer | 19/0/0 | Core done: identify, ELF/PE parsers, IOC normaliser, facts from REA + toolkit Evidence, 35 rules, scoring, YARA wrapper, STIX/MISP/CSV/Markdown exporters, SQLite case store, CLI. **Not yet wired** to js-analyzer, dotnet-analyzer, artifacts (recursive extraction), ghidra-bridge, sandbox: only the built-in static analyzers and YARA run in the pipeline |

## Known gaps (next steps)
1. Fix the 2 failing `mcp-gateway` tests and review its README; run it in front of a real REA.
2. Register `js-analyzer`, `dotnet-analyzer`, `artifacts`, `ghidra-bridge`, `sandbox` as triage analyzers with Evidence-to-Facts adapters (`registerAnalyzer`, `registerFactsAdapter` in `@rtk/triage`).
3. Independent review of the packages whose implementers were stopped early.
4. `hopper-bridge` needs a real Hopper to verify.
