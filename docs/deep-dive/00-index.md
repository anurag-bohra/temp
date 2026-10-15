# REA (morluto/rea v6.4.0 / commit f75b1a4) deep-dive — master index

Source: https://github.com/morluto/rea (analysed commit `f75b1a4`; upstream has since moved to 6.5.0 — see [29](29-pending-and-status.md)). Goal: understand capabilities, MCP server, calling mechanisms, prompts and skills; assess defensive malware-analysis and vulnerability-research use; enable porting sub-tools. Status and open items: **[29-pending-and-status.md](29-pending-and-status.md)**.

## Start here
| Chapter | Abstract |
|---|---|
| [01-capabilities-and-calling-overview.md](01-capabilities-and-calling-overview.md) | One-page map: 207 tools / 18 families, calling mechanisms, prompts and skill, diagrams |
| [26-tool-usage-in-context-malware-analyst-view.md](26-tool-usage-in-context-malware-analyst-view.md) | Per-flow usage: when each tool is called, what is extracted, how it is used, caveats; real outputs (RUN) |
| [22-end-to-end-workflows.md](22-end-to-end-workflows.md) | Atlas of 16 workflows with tool chains and verification level |
| [23-defensive-malware-analysis-playbook.md](23-defensive-malware-analysis-playbook.md) | Risk tiers, scenario chains, reuse plan, lab-round findings |
| [28-vulnerability-research-with-rea.md](28-vulnerability-research-with-rea.md) | Hardening triage, crash root cause (core → Ghidra), patch diff, Electron surface, EVM |

## Architecture and server
[02](02-architecture-and-module-map.md) architecture/modules/env vars · [03](03-mcp-server-runtime-and-contracts.md) MCP server, contracts, effects audit · [31](31-mcp-and-prompts-deep-dive.md) **MCP + prompts in depth (wire level, rendering, completion)** · [32](32-file-type-analysis-atlas.md) **per-file-type analysis flow diagrams** · [30](30-subsystem-primers-and-architecture-glue.md) architecture-glue diagrams · [04](04-cli-reference.md) CLI (153 commands) · [05](05-setup-doctor-update-uninstall-clients.md) setup/doctor/25 clients

## Providers and formats
[06](06-provider-layer-and-session-routing.md) provider layer · [07](07-hopper-provider.md) Hopper · [08](08-ghidra-provider.md) Ghidra · [09](09-other-native-providers.md) IDA/Cutter/Rizin/GDB/objdump/pwntools/JEB/macOS/Windows · [14](14-filetypes-native-apple-archives.md) native/Apple/archives · [15](15-filetypes-managed-firmware-wasm-evm-misc.md) .NET/firmware/Go/Rust/SQLite/WASM/EVM/Flutter/Harmony · [16](16-javascript-electron-analysis.md) JS/Electron · [17](17-browser-and-web-observation.md) browser/web · [18](18-process-capture-and-instrumentation.md) + [part b](18-process-capture-and-instrumentation-part-b.md) process capture, LLDB, Frida · [19](19-android-mobile.md) Android/ADB/JEB/Flutter/Harmony · [20](20-network-and-signal-captures.md) pcap/packets/HAR/SAZ/qlog/sigrok

## Evidence, AI layer, security
[10](10-evidence-model-ledger-unknowns-bundles.md) Evidence/ledger/Unknowns/bundles · [11](11-comparison-snapshots-analysis-view-reconstruction.md) comparison/snapshots/analysis views/reconstruction · [12](12-ai-layer-prompts-and-skills.md) six prompts + completion + chaining + diagrams ([part b](12-ai-layer-prompts-and-skills-part-b-bundled-skill-verbatim.md) skill and references verbatim, [part c](12-ai-layer-prompts-and-skills-part-c-repo-skills-and-llm-text.md) repo skills/AGENTS.md/tool-design verbatim) · [21](21-security-model.md) security model, threat model, prompt-injection test, 207-tool effects table

## Catalog and reference
[13](13-tool-catalog-index.md) effects matrix · [25](25-capabilities-reference.md) every capability, tier, providers, malware use · [catalog/](catalog/) verbatim input schemas by family · [tool-specs/](tool-specs/) per-tool JSON (input + output schemas)

## Tests, prototypes, porting
[27](27-manual-test-log.md) manual test log (Part 1 static, Part 2 lab) · [manual-tests/](manual-tests/) (`run-all.sh`, `run-lab.sh`, MCP driver, samples, transcripts, raw outputs) · [prototype/rea-triage](prototype/rea-triage/README.md) IOC + rule layer prototype · [24](24-porting-blueprints.md) porting blueprints with measured dependency closures · [verification/](verification/) claim-level verification logs for chapters 02–08, 14, 16, 17

## Reading order for the stated goals
1. Understand REA: 01 → 02 → 03 → 12 → 25.
2. Malware analysis: 26 → 23 → 22 → 21 → 15/16/18/19/20 as needed → 27 for evidence of what was actually run.
3. Vulnerability research: 28 → 26 A1 → 09/14 → 11.
4. Porting: 24 → 03 → 10 → prototype → 29 (open items).
