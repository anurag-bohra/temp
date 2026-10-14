# 29 — What is pending, unverified, or known-imperfect

Status date: end of this session. Everything is committed to branch `claude/sweet-edison-8y1kkl`.

## 1. Completion matrix
| Area | Document | State |
|---|---|---|
| Capabilities overview, calling mechanisms, diagrams | [01](01-capabilities-and-calling-overview.md) | done |
| Architecture, modules, env vars | [02](02-architecture-and-module-map.md) | done (writer completed; 14 diagrams validated by writer) |
| MCP server, contracts, effects audit | [03](03-mcp-server-runtime-and-contracts.md) | done, includes live stdio transcripts |
| CLI reference (153 commands) | [04](04-cli-reference.md) | written; ends with Porting notes; sections 4.1–4.10 present. Writer was stopped near the end → flag lists per command not spot-checked |
| Setup/doctor/update/uninstall/25 clients | [05](05-setup-doctor-update-uninstall-clients.md) | written; ends with Porting notes; not spot-checked |
| Provider layer, Hopper, Ghidra | [06](06-provider-layer-and-session-routing.md), [07](07-hopper-provider.md), [08](08-ghidra-provider.md) | written; end with Porting notes; ch06 sections 1–10 present; Hopper/Ghidra not run (no engines) |
| Evidence, comparison, AI layer (prompts + skills verbatim) | [10](10-evidence-model-ledger-unknowns-bundles.md), [11](11-comparison-snapshots-analysis-view-reconstruction.md), [12](12-ai-layer-prompts-and-skills.md) + parts b, c | done; two items in 11 read from source only |
| Tool catalog (207) | [13](13-tool-catalog-index.md), [25](25-capabilities-reference.md), `catalog/`, `tool-specs/` | done (generated) |
| File types native/Apple/archives | [14](14-filetypes-native-apple-archives.md) | written; ends with Porting notes; not spot-checked |
| JS/Electron; browser/web | [16](16-javascript-electron-analysis.md), [17](17-browser-and-web-observation.md) | written; end with Porting notes; JS flow additionally verified by RUN tests |
| Malware playbook, usage in context, vuln research, manual tests | [23](23-defensive-malware-analysis-playbook.md), [26](26-tool-usage-in-context-malware-analyst-view.md), [28](28-vulnerability-research-with-rea.md), [27](27-manual-test-log.md) | done; flows labelled RUN vs DOC |
| Porting blueprints | [24](24-porting-blueprints.md) | concise; one table, not a design per sub-tool |
| Former chapters 09, 15, 18, 19, 20, 21, 22 | primers in [30](30-subsystem-primers-and-architecture-glue.md) | **pending as deep dives** (summary-level only; not code-verified) |

## 2. Pending work items (prioritised for the stated goals)
| # | Item | Why it matters | Effort |
|---|---|---|---|
| P1 | Run **deep-provider flow B** with a real Ghidra (or Hopper/IDA) and replace DOC rows in [26] with real outputs (`open_binary`, `binary_overview`, `analyze_function`, `trace_call_path`, `trace_native_values`) | Core of native malware/vuln work is currently description-based | Install Ghidra+JDK in a lab; ~1 session |
| P2 | Exercise MCP prompts end-to-end with a real MCP client + LLM (the six prompts) and record transcripts | Prompt flows were rendered and diagrammed, not driven live | small |
| P3 | Run lab-only tier-D tools in an isolated VM: `capture_process_scenario`, Frida, GDB/Rizin | Detonation/dynamic confirmation is unverified | needs VM |
| P4 | Write deep chapters 09, 15, 18, 19, 20, 21 (code-level) | Only primers exist | 6 chapters |
| P5 | Test remaining static tools with prerequisites: .NET (`inspect_managed_*`), Android (JADX/Apktool + APK), pcap (tshark), WASM (WABT), firmware (Binwalk/Unblob), `inspect_pe_resources`, `inspect_signature`, SQLite (Node ≥ 24.15) | List in [27] §6 | per-tool installs |
| P6 | Spot-check chapters 04, 05, 14, 16, 17 against code (writers were stopped early to save credits) | Citations (`file:line`) not independently re-verified | medium |
| P7 | Build the malware-specific layer REA lacks: YARA/IOC extraction, unpacking, case store, STIX/MISP export, enforcement of `untrusted_content` | Needed for the "port to our tools" goal | design + build |
| P8 | Per-sub-tool design docs for the 13 blueprints in [24] (interfaces, repo seams, effort) | User wants to "create multiple sub-tools directly from the doc" | per blueprint |
| P9 | Validate Mermaid diagrams in my chapters (01, 23, 26, 28, 30) with a renderer; chapter-02/03 diagrams were validated by their writer with mermaid 10.9.3 | I did not render mine | small |
| P10 | Retest on newer REA (this is HEAD `f75b1a4`, v6.4.0; project changes quickly) | Counts (207 tools, 47 providers, 25 clients) will drift; regenerate `catalog/` with the scripts | small |

## 3. Known discrepancies and weaknesses to remember (found by me or the writers)
- **Attached CLAUDE.md is outdated** vs code (Hopper/Ghidra only; real: 47 providers, 207 tools, 18 families).
- `docs/architecture.mermaid` omits 14 `src/` directories; real import graph has cycles (application↔artifacts, process↔artifacts) — only some boundaries enforced (`scripts/lib/module-boundaries.mjs`).
- Effects audit gaps: `start_frida_session`, `start_gdb_session`, `observe_web_execution` not flagged `executesForeignCode`; only 6 tools carry `readOnlyHint` (Evidence recording counts as a session mutation).
- `compare_bundles` added/removed counters never non-zero; `verify_unknown_resolution` description over-claims (it reads the head; validation happens on append/import); several comparison pipelines keep their own status enums despite docs calling the 3-value set canonical.
- Evidence field naming: `parent_evidence_id` and `retention` are not envelope fields (analysis-view result / bundle summary only).
- `trace_crash.document` still says "Open Hopper document".
- `docs/mcp-contracts.md` says errors omit `structuredContent` — true on the wire only (private carrier stripped).
- **Observed in my runs:** `exec` command and `request` endpoint remain `null` (dynamic); `eval`/`Buffer` are generic expression nodes; JS comparison reports edited modules as removed+added; `nx_indicator:null` and `relro:null` mean "no indicator", not a negative proof; binary hashes are not rebuild-stable.
- Build quirks: `npm run build:cached` failed in this container after `npm ci --ignore-scripts` (missing `node_modules/.package-lock.json`); the CLI requires the bundle step ([27] §2). Default `tools/list` is ~3.09 MB (≈215 KB with output schemas off and compact inputs) — relevant for agent token budgets.
- The 207/47/25 counts and all RUN results are for the checked-out commit only.

## 4. Scope reminders
No real malware was handled; samples are benign. The vulnerability-research chapter stays at triage/analysis level and does not include exploitation steps; REA itself excludes exploit-payload automation and protection-defeat workflows (`CONTRIBUTING.md`).
