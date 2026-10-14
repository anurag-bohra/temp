# 29 — Status, verification summary, what is still pending, known discrepancies

Status date: end of the "complete all pending" round. Everything is committed to branch `claude/sweet-edison-8y1kkl`. Commit analysed: `morluto/rea` `f75b1a4` (package.json 6.4.0; its CHANGELOG already documents 6.5.0). Upstream HEAD at check time: `eab789a` (6.5.0) — 18 non-test `src/` files differ, all in managed-member comparison plus the generated version file ([27](27-manual-test-log.md) L14).

## 1. Completion matrix (all chapters now exist)
| Area | Documents | State |
|---|---|---|
| Overview, capabilities, calling mechanisms, diagrams | [01](01-capabilities-and-calling-overview.md), [25](25-capabilities-reference.md), [13](13-tool-catalog-index.md), `catalog/`, `tool-specs/` | done (catalog generated from the built source) |
| Architecture, MCP server, contracts, effects audit | [02](02-architecture-and-module-map.md), [03](03-mcp-server-runtime-and-contracts.md), [30](30-subsystem-primers-and-architecture-glue.md) | done, fact-checked |
| CLI, setup/doctor/update/uninstall/25 clients | [04](04-cli-reference.md), [05](05-setup-doctor-update-uninstall-clients.md) | done, fact-checked |
| Providers: layer, Hopper, Ghidra, others | [06](06-provider-layer-and-session-routing.md), [07](07-hopper-provider.md), [08](08-ghidra-provider.md), [09](09-other-native-providers.md) | done; 06–08 fact-checked, 08 re-tested with real Ghidra; 09 written with its own runs |
| Evidence, comparison, AI layer (prompts + skills verbatim) | [10](10-evidence-model-ledger-unknowns-bundles.md), [11](11-comparison-snapshots-analysis-view-reconstruction.md), [12](12-ai-layer-prompts-and-skills.md) + parts b, c | done; not independently fact-checked (see R3) |
| File types | [14](14-filetypes-native-apple-archives.md), [15](15-filetypes-managed-firmware-wasm-evm-misc.md) | done; 14 fact-checked |
| JS/Electron, browser | [16](16-javascript-electron-analysis.md), [17](17-browser-and-web-observation.md) | done, fact-checked, browser tools RUN |
| Process capture/Frida, Android/ADB/JEB, network/signals, security model | [18](18-process-capture-and-instrumentation.md) (+[part b](18-process-capture-and-instrumentation-part-b.md)), [19](19-android-mobile.md), [20](20-network-and-signal-captures.md), [21](21-security-model.md) | done with RUN evidence (see R3 for independent check) |
| Workflows, malware playbook, vuln research | [22](22-end-to-end-workflows.md), [23](23-defensive-malware-analysis-playbook.md), [26](26-tool-usage-in-context-malware-analyst-view.md), [28](28-vulnerability-research-with-rea.md) | done; RUN/DOC labelled |
| Manual tests | [27](27-manual-test-log.md), [manual-tests/](manual-tests/) | done: Part 1 (static, 11 tests) + Part 2 (lab, L1–L14); both scripts re-run successfully (31 s and 79 s) |
| Porting | [24](24-porting-blueprints.md), [prototype/](prototype/) | per-blueprint designs with measured dependency closures; one prototype built (rea-triage) |

## 2. The original pending list — outcome
| # | Item | Outcome |
|---|---|---|
| P1 | Run the deep native flow with a real engine | **Done** with Ghidra 12.1.4: `open_binary`, `binary_overview`, `list_strings`, `xrefs`, `analyze_function`, `batch_decompile`, `inspect_native_api`, `trace_call_path`, `trace_native_values`, `set_address_name`, bundle export — [27] L1, [26] A1, [28] V2 |
| P2 | Exercise MCP prompts end-to-end | **Done at protocol level** (no LLM): `prompts/list`, six `prompts/get`, `completion/complete` — [27] L2. LLM-in-the-loop behaviour **not** tested (R2) |
| P3 | Run tier-D tools in an isolated VM | **Done in this disposable container with benign demos**: `capture_process_scenario`, comparison, Frida attach and spawn, GDB session (chapter-09 writer), setsid-escapee cleanup (chapter-18 writer). Rizin/Cutter debuggers not run (not installed). No real malware was executed anywhere |
| P4 | Deep chapters 09, 15, 18, 19, 20, 21 | **Written** (about 600 KB total) |
| P5 | Test remaining tools with prerequisites | **Done** for .NET, Android (JADX), pcap/packet/HAR/SAZ/qlog, WASM (+compare), firmware regions, PE resources, SQLite, EVM, Rust (cargo-auditable), Go, YARA. **Not run:** Unblob extraction, Apktool, sigrok, native mitmproxy, Hopper, IDA, Rizin/Cutter, JEB, real adb, Wakaru, macOS-only observers, Mach-O `inspect_signature` |
| P6 | Semantic check of claims in earlier chapters | **Done for chapters 02, 03, 04, 05, 06, 07, 08, 14, 16, 17**: 454 claims checked, **54 corrected in place**, the rest confirmed or marked unverifiable; logs in [verification/](verification/). Chapters 10, 11, 12 and the new 09, 15, 18–21 were produced by writers who ran code, but were **not independently re-verified** (R3) |
| P7 | Malware-specific layer REA lacks | **Prototype built and run** ([prototype/rea-triage](prototype/rea-triage/README.md)): 11 findings and 8 IOCs from real Evidence; YARA demo. Not a product (R4) |
| P8 | Per-sub-tool design docs | **Done** in [24](24-porting-blueprints.md) with measured closures (e.g. ToolEffects = 1 file; MCP scaffold = 1,190 files) |
| P9 | Validate Mermaid | **Done**: all 121 diagrams parse (mermaid 10.9.3). Visual layout not inspected (R8) |
| P10 | Retest on newer REA | **Done as a drift check** (upstream 6.5.0, 18 non-test files differ); catalogs not regenerated against `eab789a` (R6) |

## 3. Verification summary (what "checked" means here)
- Mermaid: 121/121 blocks parse.
- Citations: 1,051 `file:line` citations in chapters 02–30; every file exists and every range is within the file (1 overshoot fixed). A claim-level check was done by the fact-check agents for the chapters listed in P6 (their logs include evidence per claim).
- Real runs: Part 1 (11 tests) and Part 2 (14 tests) in [27]; transcripts and raw outputs committed; `run-all.sh` and `run-lab.sh` reproduce them (binary hashes differ per rebuild; two identical process captures compare as `changed`).
- **Not** verified: LLM behaviour, Windows/macOS, anything listed under "Not run" in P5, the visual rendering of diagrams.

## 4. Still pending (genuinely open)
| # | Item | Why it is open |
|---|---|---|
| R1 | Hopper, IDA, Rizin, Cutter, JEB, Apktool, Unblob, sigrok, native mitmproxy, real adb device, Wakaru, macOS/Windows hosts | Not installable/available here (licences, hardware, OS). Chapters describe them from code/docs; labelled DOC |
| R2 | Behaviour of a real LLM agent with the six prompts and the skill (does it follow the routing, does it resist prompt injection from tool output?) | Needs an agent client; this environment tested the server side only. REA applies no text-level mitigation ([21]) |
| R3 | Independent claim-level re-verification of chapters 09, 10, 11, 12, 15, 18, 19, 20, 21, 23, 24, 26, 28 | Their authors ran code but nobody else checked; budget used for 02–08, 14, 16, 17 first |
| R4 | A real malware-triage layer: fix rule R-EXEC-001 (resolve .NET call targets via `member_refs`), scan pseudocode/WASM data/dex strings, STIX/MISP export, case store, enforcement of the `untrusted_content` marker | Prototype only |
| R5 | Implementations of blueprints 01–13 (designs exist, code does not) | Out of scope of documentation work |
| R6 | Regenerate `catalog/` and `tool-specs/` against upstream `eab789a` and diff `managedWorkflowToolContracts.ts` | New release appeared during the session |
| R7 | Windows- and macOS-specific behaviour (Windows Ghidra P0, Hopper on macOS, lldb tracer, native UI) | No such hosts |
| R8 | Visual QA of rendered diagrams and the 17 MB doc set (tool-specs are ~8 MB of JSON) | Only syntax-validated |

## 5. Known discrepancies and weaknesses (code vs docs, and things to remember)
- The attached CLAUDE.md predates the code (Hopper/Ghidra only vs 47 providers, 207 tools, 25 clients).
- `docs/architecture.mermaid` omits 14 `src/` directories; real import graph has cycles ([02]).
- **Effects audit:** `close_frida_session` resumes a paused spawn and a failed `start_frida_session` also resumes it, neither flagged `executesForeignCode`; `observe_web_execution` classified by wording; ADB install/start/stop flagged `mutatesDevice` only; `inspect_sqlite_database` and `inspect_evm_interface` flagged `launchesProcess`/`writesFilesystem` although the helper is REA's own Node worker ([21], [09]). 11 of 207 tools have `mutatesSession:false`; 6 carry `readOnlyHint` ([06]).
- **Chromium launched by REA runs with its sandbox disabled by default** (Playwright adds `--no-sandbox`) — corrected from an earlier wrong statement ([17]).
- **Prompt injection:** no mitigation beyond `_meta.provenance.untrusted_content` and server instructions; some results (bundle export, `record_unknown`) unmarked; CLI unmarked ([21]).
- `compare_bundles` added/removed counters never non-zero; several comparison pipelines keep their own status enums ([11]).
- Managed member diff ignores `ldstr` literals; WASM interface diff ignores data segments/bodies ([15]).
- `compare_process_captures` advertises command-shim/HTTP/WebSocket comparison the code does not implement; identical real captures can never compare `unchanged` ([18]).
- `inspect_packet_capture` has no redaction while `inspect_pcap_capture` strips URI userinfo; `capture_start/end` null with capinfos 4.2.2 ([20]).
- JADX jar sha256 pin is advisory ([19]); JEB rejects `localhost` while IDA accepts it ([09]); `debug-with-gdb --help` shows `--inferior-tty` optional but it is required ([09]).
- Version pins are fail-closed: WABT 1.0.42, Binwalk 3.1.x, Ghidra 12.1.x, pwntools 4.15.0 (apt versions rejected/failed — [27]).
- Doc/build quirks: `npm run build:cached` fails after `npm ci --ignore-scripts`; CLI needs the bundle step; `rea update` example now fails on a source checkout; default `tools/list` ≈ 3.09 MB.
- Observed behaviours worth knowing: dynamic arguments stay `null` (`exec` command, request endpoint); `eval`/`Buffer` are generic expression nodes; JS version diff reports edited modules as removed+added; `nx_indicator`/`relro` null mean "no indicator", not a negative proof.

## 6. Scope reminders
No real malware was handled; all samples are benign demos with inert indicators (`example.invalid`, TEST-NET). The vulnerability chapter stays at triage/analysis level. REA itself excludes exploit-payload automation, packer/anti-debug-evasion and DRM-bypass workflows (`CONTRIBUTING.md`).


## 7. Update: toolkit implementations (blueprints 01-14) — completed
Code is in [`/toolkit`](../../toolkit/README.md): 14 packages, **201 tests pass, 0 fail**, typecheck clean. The earlier gaps are closed: `mcp-gateway` is complete (19 tests, 5 of them live against the real REA server, including an injection test through Ghidra) and the triage pipeline now runs the JS, .NET, archive (recursive), Ghidra (opt-in) and sandbox (policy-gated, opt-in) analyzers with Evidence-to-Facts adapters (27 tests). Remaining: `hopper-bridge` is an unverified skeleton; five analyzer packages (`js-analyzer`, `dotnet-analyzer`, `artifacts`, `browser-observer`, `sandbox`) were not independently reviewed; no real malware or real LLM agent was used. This closes R4 and R5 above as far as a prototype-quality implementation goes.
