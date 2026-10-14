# REA (morluto/rea v6.4.0) deep-dive — master index

Source: https://github.com/morluto/rea (HEAD `f75b1a4`, shallow clone, built locally; `tool-specs/` and `catalog/` were generated from the built source). Goal: understand capabilities, MCP server, calling mechanisms, prompts and skills; assess defensive malware-analysis use; enable porting sub-tools.

## Start here (your main ask — complete)
| Chapter | Abstract |
|---|---|
| [01-capabilities-and-calling-overview.md](01-capabilities-and-calling-overview.md) | One-page map: 207 tools / 18 families, calling mechanisms, prompts and skill, with diagrams |
| [03-mcp-server-runtime-and-contracts.md](03-mcp-server-runtime-and-contracts.md) | MCP server internals, tool contracts, admission, result delivery, effects audit (207 rows), error contract, live transcripts, sequence diagrams |
| [12-ai-layer-prompts-and-skills.md](12-ai-layer-prompts-and-skills.md) | Six guided prompts (verbatim + rendered), completion, chaining, sequence diagrams, porting to malware agents |
| [12 part b](12-ai-layer-prompts-and-skills-part-b-bundled-skill-verbatim.md) | Bundled skill `SKILL.md` + 6 references, verbatim |
| [12 part c](12-ai-layer-prompts-and-skills-part-c-repo-skills-and-llm-text.md) | Repo skills, AGENTS.md, tool-design, RE-tools guide, verbatim |
| [26-tool-usage-in-context-malware-analyst-view.md](26-tool-usage-in-context-malware-analyst-view.md) | **Per-flow usage**: when each tool is called, what is extracted, how it is used next, caveats; real outputs from runs on demo samples (RUN vs DOC labelled); 8 flow diagrams |
| [25-capabilities-reference.md](25-capabilities-reference.md) | **Every capability in detail**: 18 families, 207 tools with verbatim agent-facing descriptions, tier, providers, CLI mapping, requirements, malware-analysis use; provider list |
| [13-tool-catalog-index.md](13-tool-catalog-index.md), [catalog/](catalog/), [tool-specs/](tool-specs/) | All 207 tools: verbatim input schemas (catalog), full specs incl. output schemas (tool-specs), effects matrix |

## Supporting chapters (written)
| Chapter | Abstract | Status |
|---|---|---|
| [02-architecture-and-module-map.md](02-architecture-and-module-map.md) | Architecture, module map, env vars, build/runtime | complete |
| [10-evidence-model-ledger-unknowns-bundles.md](10-evidence-model-ledger-unknowns-bundles.md) | Evidence schema, ledger, unknowns, bundles | complete |
| [11-comparison-snapshots-analysis-view-reconstruction.md](11-comparison-snapshots-analysis-view-reconstruction.md) | Comparison, snapshots, analysis view, reconstruction | complete; 2 parts read from source only |
| [23-defensive-malware-analysis-playbook.md](23-defensive-malware-analysis-playbook.md) | Risk tiers, 8 scenario tool-chains, sequence diagram, reuse plan, gaps | complete synthesis |
| [24-porting-blueprints.md](24-porting-blueprints.md) | 13 liftable sub-tools with deps | concise synthesis |

## Chapters written by early-stopped writers (complete-looking, not spot-checked)
04 CLI reference, 05 setup/clients, 06 provider layer, 07 Hopper, 08 Ghidra, 14 native/Apple/archive formats, 16 JS/Electron, 17 browser/web — each ends with its Porting notes section; citations not independently re-verified. See [29-pending-and-status.md](29-pending-and-status.md).

## Added after review requests
| Chapter | Abstract |
|---|---|
| [27-manual-test-log.md](27-manual-test-log.md) | Every manual test: environment, setup problems, samples, 11 test cases with real values, reproducibility, what was not tested; [manual-tests/](manual-tests/) holds script, samples, raw outputs |
| [28-vulnerability-research-with-rea.md](28-vulnerability-research-with-rea.md) | Vuln-research flows: hardening triage, crash triage from a core, patch diffing, Electron attack surface, EVM selectors, source-to-sink; RUN vs DOC labelled |
| [29-pending-and-status.md](29-pending-and-status.md) | Completion matrix, prioritised pending list, known discrepancies |
| [30-subsystem-primers-and-architecture-glue.md](30-subsystem-primers-and-architecture-glue.md) | Short primers for subsystems without deep chapters + architecture/execution-authority diagrams |

## Not written as deep dives
09, 15, 18, 19, 20, 21, 22 — only primers in [30](30-subsystem-primers-and-architecture-glue.md); tools are still fully described in [25](25-capabilities-reference.md).

## Discrepancies found (code vs docs)
- Attached CLAUDE.md predates the code (Hopper/Ghidra only vs 47 providers).
- `docs/architecture.mermaid` omits 14 `src/` dirs and implies a DAG; the real import graph is cyclic ([02](02-architecture-and-module-map.md)).
- `compare_bundles` summary counters for added/removed are never non-zero; several pipelines keep own status enums ([11](11-comparison-snapshots-analysis-view-reconstruction.md)).
- Effects audit misses `start_frida_session`, `start_gdb_session`, `observe_web_execution` as foreign-code executors ([03](03-mcp-server-runtime-and-contracts.md)).
