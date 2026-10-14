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
| [26-tool-usage-in-context-malware-analyst-view.md](26-tool-usage-in-context-malware-analyst-view.md) | **Per-flow usage**: when each tool is called, what is extracted, how it is used next, caveats; real outputs from runs on demo samples (RUN vs DOC labelled); 11 flow diagrams |
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

## Partial chapters (writers stopped early to save credits — treat as incomplete, unverified tail)
| Chapter | Note |
|---|---|
| [04-cli-reference.md](04-cli-reference.md) | Likely missing family tables / side-effect tail; check before relying |
| [05-setup-doctor-update-uninstall-clients.md](05-setup-doctor-update-uninstall-clients.md) | May be truncated |
| [06-provider-layer-and-session-routing.md](06-provider-layer-and-session-routing.md), [07-hopper-provider.md](07-hopper-provider.md), [08-ghidra-provider.md](08-ghidra-provider.md) | Provider layer, Hopper, Ghidra |
| [14-filetypes-native-apple-archives.md](14-filetypes-native-apple-archives.md) | Native/Apple/archive formats |
| [16-javascript-electron-analysis.md](16-javascript-electron-analysis.md), [17-browser-and-web-observation.md](17-browser-and-web-observation.md) | JS/Electron, browser |

## Not written
25 is now the capabilities reference (no gaps chapter). Missing: 09 (IDA/Cutter/Rizin/GDB/objdump), 15 (.NET/firmware/WASM/EVM/misc formats), 18 (process capture/Frida), 19 (Android), 20 (pcap/signals), 21 (security model), 22 (end-to-end workflows; see 23 §6 and 12 §12.11 instead) — covered only by the tool catalog and the brief mentions above. Resume these if needed.

## Discrepancies found (code vs docs)
- Attached CLAUDE.md predates the code (Hopper/Ghidra only vs 47 providers).
- `docs/architecture.mermaid` omits 14 `src/` dirs and implies a DAG; the real import graph is cyclic ([02](02-architecture-and-module-map.md)).
- `compare_bundles` summary counters for added/removed are never non-zero; several pipelines keep own status enums ([11](11-comparison-snapshots-analysis-view-reconstruction.md)).
- Effects audit misses `start_frida_session`, `start_gdb_session`, `observe_web_execution` as foreign-code executors ([03](03-mcp-server-runtime-and-contracts.md)).
