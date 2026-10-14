# Verification log: chapters 02, 03, 16, 17

Repo under test: `/home/user/morluto/rea` (HEAD f75b1a4, `dist/` built). Verdicts: CONFIRMED / CORRECTED / UNVERIFIABLE. "RUN" = executed in the lab (scratchpad `v/` directory: jsapp, jsapp2, a self-built `app.asar`, a tampered copy, a fabricated ELF with the fuse sentinel, headless Chromium 141 at `/opt/pw-browsers/chromium-1194/chrome-linux/chrome` on 127.0.0.1:9222 plus `python3 -m http.server` on 8765). Wakaru is not installed; Electron is not installed.

Mermaid: `check.mjs` run on all four files after edits: 02 = 8 blocks, 03 = 6, 16 = 6, 17 = 4, 0 failures (no change needed).

## Chapter 16 (javascript / Electron)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | Resource defaults heap 1024 / timeout 300000 / nodes 100000 / 20000 / max 1,000,000 | CONFIRMED | `javascriptAnalysisResourceControls.ts:6-14` | none |
| 2 | `max_heap_mb` 128..16384, `analysis_timeout_ms` 1..2147483647, nodes 1..1000000 | CONFIRMED | same file `:43-80` | none |
| 3 | `analyzeJavaScriptApplicationInputSchema` verbatim | CONFIRMED | `javascriptApplicationAnalysis.ts:27-33` identical | none |
| 4 | Result shape block verbatim | CORRECTED | source has `limitations: z.array(z.string().min(1))` | edited verbatim block |
| 5 | analyze evidence: predicate `rea.javascript-application-analysis`, `derived`, authority `shipped-artifact` | CONFIRMED | `JavaScriptApplicationEvidence.ts:73-86`; RUN output same | none |
| 6 | `summary` keys (browser_windows ... ipc{...}) and `statistics` keys | CONFIRMED | RUN on jsapp: all keys present exactly as listed | none |
| 7 | Tool effects flags for the 13 tools in 16.3 (`-S-------i`, `-SFP------`, `-SF-------`, `-SFP-----i`, `-SFPN----i`) | CONFIRMED | `toolEffects.ts:178-190,650-668` and catalog effects for 6 sampled tools | none |
| 8 | Worker spawn: private root, `UV_THREADPOOL_SIZE=1`, NODE_OPTIONS deleted, argv `--max-old-space-size`, `--max-semi-space-size=8`, `--v8-pool-size=1`, `--expose-gc`, `--stack_size=2048` | CONFIRMED | `JavaScriptAnalysisWorker.ts:451-482` | none |
| 9 | Worker protocol defaults (8 MiB checkpoint, 64 KiB frames) | CONFIRMED | `JavaScriptAnalysisWorkerProtocol.ts:11-16` | none |
| 10 | Static checkpoint written `flag: "wx", mode: 0o600`; gc between jobs | CONFIRMED | `JavaScriptAnalysisWorkerServer.ts:87,132-133` | none |
| 11 | Bun on Windows Job Object limit = heap + 512 MiB; elsewhere none | CONFIRMED | `JavaScriptWorkerMemoryLimit.ts:14-45` | none |
| 12 | ASAR header cap 16 MiB | CONFIRMED | `AsarHeader.ts:7` `MAX_ASAR_HEADER_BYTES` | none |
| 13 | Graph node kinds / relations (incl. 7 `managed-*`) verbatim | CONFIRMED | `javascriptApplicationGraphSchemas.ts:15-72`; 7 managed kinds counted | none |
| 14 | Semantic node kinds / families / relations verbatim | CONFIRMED | `javascriptSemanticGraphSchemas.ts:37-128` spot-compared | none |
| 15 | File-count table: domain/javascript 199 incl. tests, application/javascript 66, `src/javascript` 24 files, `src/electron` 4 | CORRECTED | `find`: 199 / 66 confirmed; `src/javascript/{analysis,sourceMaps,recovery}` = 20 non-test (29 with tests); `src/electron` = 3 non-test (4 with test) | edited both cells |
| 16 | Progress phases "match" the 3 phases in `JavaScriptApplicationService.ts:57-106` | CORRECTED | RUN stderr shows 13 distinct `rea_progress` phases | caption rewritten to list the real phase set |
| 17 | `package.json` maps `#javascript-analysis-worker`; engines range; dependency versions (zod 4.4.3, canonicalize 3.0.0, @babel 8.0.4, @electron/asar 4.2.0, trace-mapping 0.3.31, pino) | CONFIRMED | `package.json:37-39,44-46,315-353` | none |
| 18 | Wakaru pin: version 1.14.0, revision, `^1.13.0`, RECOVERY_LIMITS | CONFIRMED | `WakaruRelease.ts` verbatim | none |
| 19 | prlimit argv (`--as --fsize --core=0 --cpu=120 --`), env `TMPDIR/RAYON_NUM_THREADS/NO_COLOR`, host environment inherited, mode map structural/heuristic/inspection -> strict/auto/inspect, Wakaru flags | CONFIRMED | `WakaruCommand.ts:118-134`, `WakaruExecution.ts:30-34,80-92` | none |
| 20 | Default `/usr/bin/prlimit` and `REA_JAVASCRIPT_PRLIMIT_COMMAND` absolute | CONFIRMED | `WakaruCommand.ts:84-88` | none |
| 21 | `recover_javascript_sources` fails unless `REA_WAKARU_COMMAND` set; "Not installed by REA; checked only at call time" | CONFIRMED (RUN, negative) | CLI returned `capability_unavailable` with the documented remediation text; `/usr/bin/prlimit` exists. Success path not runnable | none (documented in 16.17) |
| 22 | Fuse constants (sentinel, state bytes 0x30/0x31/0x72, 9 names) | CONFIRMED | `electronFuses.ts:7-29` | none |
| 23 | Fuse implications table (fuse 3, 0, 4, 5) and ASAR-integrity outcome unknown on ELF | CONFIRMED (RUN) | fabricated ELF with sentinel: `node_cli_inspect_arguments honored`, `electron_run_as_node not_honored`, `embedded_asar_integrity_validation unknown` | none |
| 24 | Reader limits (1 GiB, 256 KiB, 32 sentinels, 1 MiB PE offset) | CONFIRMED | `ElectronFuseReader.ts:24-29` | none |
| 25 | No sentinel => state unknown, not disabled | CONFIRMED (RUN) | ELF `c/t`: `sentinel_count 0`, `runtime_implications []`, limitation text | none |
| 26 | Source-map limits (4 MiB, 32 MiB, 262144, 64, 192 MiB, 20 s) | CONFIRMED | `webSourceLocation.ts:113-123` | none |
| 27 | ASAR integrity default `fail` returns logical path, declared vs calculated SHA-256 | CONFIRMED (RUN) | tampered ASAR: `artifact_integrity_mismatch`, `details{logical_path,declared_sha256,calculated_sha256,unpacked}` | none |
| 28 | `record-and-continue`: coverage partial, contradicted path listed in limitations | CONFIRMED (RUN) | coverage `partial`; limitation "Artifact integrity metadata contradicts observed bytes at src/net.js" | none |
| 29 | "every graph fact is then `observed-untrusted`" | CORRECTED | RUN: string `observed-untrusted` occurs 0 times in graph; it is `trust` on `integrity_contradictions[]`; node evidence keeps `artifact-bytes/observed`, `ast-static-analysis/observed`, `static-relationship-inference/inferred` | rewrote 16.8 text twice (bullet and malware note) |
| 30 | Unpacked entries are not an integrity exemption | CONFIRMED | `AsarArtifactReader.ts:34-39` doc comment (cite said 36-41; class starts at 40) | none |
| 31 | `trace_application_feature`: `inferred` / `analyst-inference`, seed matching default (exact, string => contains), `match: null` default | CONFIRMED (RUN) | RUN trace Evidence `rea.application-feature-trace`, `inferred`, `analyst-inference`; `featureSeedMatchMode` source | none |
| 32 | Feature-trace/compare/semantic tools consume retained Evidence over MCP | CONFIRMED (RUN) | MCP client: analyze summary -> `inspect_analysis_view` and `trace_application_feature` with `{kind:"retained-evidence"}` accepted | none |
| 33 | `compare_application_versions` result shape / statuses | CONFIRMED (RUN) | summary `unchanged/added/removed/changed/unknown` keys; `items` with `matching`, `graph` | none |
| 34 | Source-path selection: unselected files outside scope, coverage partial | CONFIRMED (RUN, partly) | `source_selection {requested_paths, unselected_files: 4}`, 1 JS file parsed; coverage status field was not printed (graph coverage key is `status`, not `state`) | none |
| 35 | Function/line anchors `reconcileJavaScriptRuntime` `:37`, `reconcileJavaScriptRuntimeEvidence :20`, `buildJavaScriptNativeHandoffs :12`, `featureSeedMatchMode :14-18` | CONFIRMED | grep | none |
| 36 | `reconcile_javascript_runtime` rules | UNVERIFIABLE | not executed (needs runtime Evidence); doc-only | marked DOC in 16.17 |
| 37 | Docs-quoted bounds (wrapper expansion 1M/128, expression 256/1 MiB, transfer 512 MiB..2 GiB, Bun note) | CONFIRMED | `docs/javascript-artifact-reconstruction.md:336-338,421-428,486-513` | none |
| 38 | `analysis_input`/Wakaru success layout (`inputs/ modules/ reports/ manifest.json`) | UNVERIFIABLE | Wakaru absent | none |

## Chapter 17 (browser / web observation)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | Provider identities (`rea-cdp-browser` v2, `rea-cdp-electron` v1, `rea-playwright-browser-scenario` v1, `rea-playwright-electron-active` v1) | CONFIRMED | `providerIdentities.ts:4-30`; RUN shows `rea-cdp-browser` v2 | none |
| 2 | Effects/annotations table for all 20 tools | CONFIRMED | catalog flag-string + annotations for each of 20 tools identical to the table | none |
| 3 | 20 tools across families browser 12 / electron 6 / javascript-runtime 2 (+ static three counted under electron) | CONFIRMED | `product-catalog.json` families | none |
| 4 | Loopback endpoint rules (127.0.0.1/::1, explicit port, no creds/path/query, localhost rejected) | CONFIRMED (RUN) | `browserObservation.ts:44-94`; CLI rejected `http://localhost:9222` and `http://127.0.0.1` | none |
| 5 | Discovery 8 MiB / 10 s, no redirects | CONFIRMED | `CdpEndpoint.ts:33-37` | none |
| 6 | `WEB_RUNTIME_LIMITS` block verbatim; 64 MiB ws maxPayload default, ceiling 0x7fffffff | CONFIRMED | `webRuntime.ts:89-95`, `CdpConnection.ts:8-85` | none |
| 7 | CDP method inventory; no `Runtime.evaluate`/`Page.navigate`/`Input.*`/`Fetch.*` | CONFIRMED | grep of quoted `Domain.method` literals in non-test `Cdp*.ts` + `execution/*.ts` returned exactly the listed methods (plus events); none of the forbidden ones | none |
| 8 | V8 provider sends exactly `Runtime.enable` and `Debugger.enable` | CONFIRMED | `V8InspectorProvider.ts:79,191-192` | none |
| 9 | WebMCP: only `WebMCP.enable` + events; `invokeTool` never called | CONFIRMED | `CdpWebMcpDiscovery.ts:50-51` | none |
| 10 | Default windows: inspect 500, session 10000, WebMCP 100, execution 10000 | CONFIRMED | `browserObservation.ts:177`, `browserSession.ts:15`, `webMcpDiscovery.ts:17`, `webExecution.ts:13` | none |
| 11 | Passive inspect: no prior activity, scripts still visible, storage values redacted but names/fingerprints available | CONFIRMED (RUN) | `network.requests []`, `prior_activity_available false`, scripts present with source; `local_storage_keys ["k"]`, `value_sha256`, `values_redacted true` | none |
| 12 | `observe_web_execution` arms precise coverage, resets counters, disables optimized execution | CONFIRMED (RUN) | `instrumentation` object in result | none |
| 13 | Event-listener inspection returns callback locations | CONFIRMED (RUN) | `click` listener with script id/url/line/column, `execution: unknown` | none |
| 14 | `export_web_scripts` -> manifest + `files/` tree into an absent dir; exported tree analyzable | CONFIRMED (RUN) | `exp/manifest.json`, `exp/files/origins/<sha>/app.js`; analyze -> directory, 1 file | none |
| 15 | `trace_web_module_imports` needs absolute `REA_BROWSER_EXECUTABLE`; flags; `REA_BROWSER_NO_SANDBOX` | CORRECTED | flags/env confirmed at `NativeModuleResolver.ts:80,116-132`; RUN showed a no-import script traces without the env var; and Playwright adds `--no-sandbox` anyway | qualified the requirement "for literal imports"; noted redundancy of the env var |
| 16 | Scenario launch uses `launchPersistentContext` with temp profile, allowlisted env (13 names), `acceptDownloads:false`, no REA-added `--no-sandbox` on desktop, "Chromium's own sandbox applies" | CORRECTED (significant) | REA args confirmed (`PlaywrightScenarioBrowser.ts:257-280,489-520`) but `chromium.js:291-292` in playwright-core 1.58.2 pushes `--no-sandbox` unless `chromiumSandbox === true`; REA never sets it (`grep chromiumSandbox src` = none); RUN launched as root | rewrote 17.5.2 bullet, 17.9 table row, 17.11 env row, added note in malware-lab paragraph |
| 17 | Scenario environment defaults (1280x720, en-US, UTC, light, reduce, service workers block) and `headless` default true | CONFIRMED (RUN) | `browserScenarioValues.ts:93-126`; echoed in RUN parameters | none |
| 18 | Scenario action/locator/capture enums | CONFIRMED | `browserScenarioValues.ts`, `browserScenarioCaptureValues.ts:123-132` spot-checked | none |
| 19 | Owned scenario cleanup: owned process terminated, temp profile removed | CONFIRMED (RUN) | `cleanup: terminated-owned-process`; no `rea-browser-scenario-*` dir left in `/tmp` | none |
| 20 | Scenario network events keep header names only (header values off by default) | CONFIRMED (RUN) | `header_names: [...]`, no values | none |
| 21 | Electron active input schema, env allowlist (8 names + Windows set + `REA_PROCESS_RUN_ID`), 60 s startup, `-r hook` args | CONFIRMED | `electronActiveObservation.ts:36-88`, `PlaywrightElectronActiveProvider.ts:41,99-107,365-405` | none |
| 22 | Hook scripts total 1068 lines | CONFIRMED | `wc -l`: 392 + 676 | none |
| 23 | Untrusted-content marker `_meta.provenance.untrusted_content` and server instructions | CONFIRMED (RUN) | `toolResultEncoding.ts:20-46`, `createServer.ts:145-147`; MCP `list_browser_targets` result `_meta` = `{provenance:{untrusted_content:true,source:"analysis_target"}}` | none |
| 24 | Secrets from env vars via `BrowserScenarioSecrets.resolve` | CONFIRMED | `BrowserScenarioSecrets.ts:259-272` | none |
| 25 | Source-map/export limits (32 MiB manifest / 16 MiB source / 4 MiB map, 20 s) | CONFIRMED | `webScriptToolContracts.ts:47` | none |
| 26 | "Only six tools accept a browser socket" | CONFIRMED | `docs/browser-observation.md:140-143` | none |
| 27 | `docs/browser-observation.md:67-76` quotation and non-goals quotation | CONFIRMED | text matches (non-goals at ~347-349) | none |
| 28 | File counts: Cdp ~40, Playwright ~22, execution 13, history 22, domain browser/web ~45, inspector 5 | CORRECTED | `find`: Cdp 43 (34 non-test), Playwright 23 (12), execution 13 (12), history 23 (17), domain 55 (42), inspector 5 non-test (9 total) | replaced approximations with exact numbers |
| 29 | Dependencies ws 8.21.0, playwright-core 1.58.2, parse5, har-schema, ajv, jsonc-parser, lossless-json, zip.js, xmldom | CONFIRMED | `package.json:323-351` | none |
| 30 | Env vars `REA_BROWSER_EXECUTABLE`, `REA_BROWSER_NO_SANDBOX`, `REA_ELECTRON_EXECUTABLE`, `REA_MITMDUMP_COMMAND` (mitmdump 12.2.3) | CONFIRMED | `NativeModuleResolver.ts`, `docs/electron-observation.md:82`, `MitmproxyCaptureAdapter.ts:10,21`, `CaptureRelease.ts:29` | none |
| 31 | Real-browser coverage "Linux x64 / Chrome 153 / Node 24" | CONFIRMED (docs) / note | `docs/web-runtime.md:57-58`; lab used Chromium 141, tools worked | added to 17.13 |
| 32 | Electron active scenario, passive Electron, V8 Inspector runtime behaviour | UNVERIFIABLE | no Electron or `--inspect` target available | marked DOC in 17.13 |
| 33 | `capture_browser_scenario` network "no origin allowlist / interception" | CONFIRMED (docs) | `docs/browser-scenario-contract.md:9-23` | none |

## Chapter 02 (architecture)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | `environmentSchema` block `environment.ts:23-78` verbatim | CONFIRMED | `diff` of block vs `sed -n 23,78p` = identical | none |
| 2 | `AppConfig` interface | CONFIRMED | `types.ts:8-28` | none |
| 3 | Startup-timeout defaults 330000 / 120000 / 120000, schema regex and max 2147483647 | CONFIRMED | `providerStartupTimeout.ts` | none |
| 4 | `REA_MCP_MAX_RESPONSE_BYTES` min 10 MiB, SDK default 10 MiB, 1024 reserved | CONFIRMED | `mcpResponseBudget.ts`, SDK `:7159`, `toolResult.ts:49-50` | none |
| 5 | Input-schema compact budget 13 KiB | CONFIRMED | `mcpInputSchemaProfile.ts` | none |
| 6 | IDA config max 64 KiB | CONFIRMED | `IdaConfiguration.ts:61-64` (65_536) | none |
| 7 | `REA_GHIDRA_NATIVEAOT_JAR` "Linux x86-64 only" | CORRECTED | adapter gates host = linux and target format elf/pe, arch x86_64, not managed (`NativeAotAdapter.ts:8-27`) | clarified row |
| 8 | Ghidra language-id regex, disabled analyzers (<=32, <=120, pattern) | CONFIRMED | `ghidraLanguageOverride.ts:16-22`, `ghidraDisabledAnalyzers.ts:3-11` | none |
| 9 | Cross-field rule compiler spec requires language id | CONFIRMED | `parseConfig.ts` / `environment.ts:135-149` | none |
| 10 | Hopper launcher default selection per platform | CONFIRMED | `parseConfig.ts:25-40,83-88` | none |
| 11 | `HOPPER_TARGET_KIND` default executable; `HOPPER_LOADER_ARGS_JSON` default `[]` | CONFIRMED | `environment.ts:72-73`, `parsers.ts:17-27` | none |
| 12 | Provider-local defaults: `REA_PWNTOOLS_MAX_INPUT_BYTES` 32 MiB / max 1 GiB, `REA_PWNDBG_GDB` `/usr/bin/gdb`, `REA_GDB_COMMAND` gdb, `REA_RIZIN_COMMAND` rizin, `REA_OBJDUMP_COMMAND` objdump, prlimit commands `/usr/bin/prlimit` (tshark, sigrok, firmware, wakaru, evm), `REA_JEB_MCP_URL` 127.0.0.1:8425, Ghidra heap `2G` | CONFIRMED | grep of each cited line (`PwntoolsRelease.ts:13`, `PwntoolsInputLimit.ts:8`, `PwndbgCoreContext.ts:68-70`, `GdbSessionManager.ts:349`, `reverseEngineering.ts:20,30`, `*Provider.ts` lines, `JebMcpEndpoint.ts:7`, `GhidraJavaLaunch.ts:178`) | none |
| 13 | `REA_CUTTER_BRIDGE_DIR` default and Windows LOCALAPPDATA variant | CONFIRMED | `CutterBridgeClient.ts:254-255,281-285` | none |
| 14 | `REA_BUILD_COMMIT`, `REA_PACKAGE_VERSION` (no consumer in `src/`), `REA_PROCESS_RUN_ID` | CONFIRMED | `serverIdentity.ts:68`, `scripts/rea.mjs:13`, grep over src, `ProviderProcess.ts:205` | none |
| 15 | JVM option variables "cleared" | CORRECTED | `GhidraInstallation.ts:616-624` blanks `_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `GHIDRA_JAVA_OPTIONS`; launcher then sets provider-owned values on Windows | row rewritten |
| 16 | Completeness of the env table | CONFIRMED | all `REA_*` identifiers in non-test `src/**/*.ts` appear in ch02 (only `REA_WORKFLOW_PROVIDER`, `REA_X11_DIAGNOSTIC` are not, and neither is an environment variable read) | none |
| 17 | Per-directory file and line counts for 41 `src/` dirs (e.g. domain 408/93,011, application 249/49,743, browser 94/20,889) | CONFIRMED | `find`/`xargs cat` script: every row matches | none |
| 18 | Totals: 1,418 non-test files, ~298.9k lines, 460 colocated tests, 19 root `.ts`, 368 scripts, 813 tests | CONFIRMED | 1418 / 298905 / 460 / 19 / 368 / 813 | none |
| 19 | Sub-counts: domain/javascript 131, application/javascript 55, domain/{apple 15, native 23, process 15, analysisView 22, managed 13}, native/pwntools 9, history 17, execution 12 | CONFIRMED | `find` | none |
| 20 | `artifacts/apple` 9 files | CORRECTED | 11 non-test files | edited |
| 21 | Import-graph edge counts (contracts->domain 208, application->artifacts 38, server->composition 27, browser->application 31, etc.) | CONFIRMED (within regex tolerance) | independent edge counter reproduced ~60 numbers; differences only application->domain 1091 vs 1080, application->process 22 vs 21, ghidra->domain 123 vs 119; `domain` has zero outgoing edges | none (tolerance noted) |
| 22 | Bridge file sizes (hopper 1173, ReaGhidraBridge 4878 + 8 helpers ~700, cutter 816, jadx 368, mitm 384, swift 374, nativeaot ~360) | CONFIRMED | `wc -l` (helpers 696; swift 339+35; nativeaot 361) | none |
| 23 | Toolchain: node engines, `.nvmrc 24.18.0`, `.npmrc engine-strict`, TypeScript 7.0.2, oxlint 1.87.0, oxfmt 0.72.0, rolldown 1.2.12, incur 0.6.1, mcp 2.3.1, frida 17.23.2 | CONFIRMED | `package.json`, `.nvmrc`, `.npmrc` | none |
| 24 | tsconfig flags; `tsconfig.build.json` includes/excludes | CONFIRMED | `tsconfig.json`, `tsconfig.build.json` | none |
| 25 | Turbo graph (compile depends on metadata:check; artifacts:* depend on compile; managed-evidence depends on skills; test:run deps + cache false) and cache 7d/500MB | CONFIRMED | `turbo.json` queried | none |
| 26 | npm script lines (compile `:293`, build `:109`, build:cached `:124`) | CONFIRMED | `package.json` | none |
| 27 | Test project file counts (composition 21, conformance 105, evaluation 13, boundary 653, acceptance 91, process-global 24, fixtures 197, support 23) | CONFIRMED | `find tests/...` | none |
| 28 | Dispatcher routing (mcp, mcp doctor, missing-runtime message) | CONFIRMED | `scripts/rea.mjs:9-53` | none |
| 29 | "`dist/` lacks `dist/mcp` and `dist/cli-runtime`; `scripts/rea.mjs` reports runtime missing" | CORRECTED | both dirs now exist (mtime 12:20 today), CLI and MCP via `scripts/rea.mjs` run fine | finding paragraph marked superseded |
| 30 | Main-process messages, `RuntimeDependencies`, `MCP_STARTUP_POLICY` blocks verbatim | CONFIRMED | `messages.ts`, `types.ts:3-11`, `mcpStartupPolicy.ts:8-17` | none |
| 31 | Composition factory names/lines (binary.ts@19/40/46, directAnalysis.ts@17/68, auxiliary@19, optional@24, reverseEngineering@14/49, jeb@13) | CONFIRMED | grep | none |
| 32 | `snapshotEnvironment` Windows upper-casing and first-sorted-key rule | CONFIRMED | `snapshotEnvironment.ts:1-16` | none |
| 33 | Boundary rules table in 2.2 | UNVERIFIABLE (not re-read) | `scripts/lib/module-boundaries.mjs` not re-inspected beyond existence; `tests/evaluation/moduleBoundaries.test.ts` noted by the chapter | none |
| 34 | "tools/list returned 207 tools / 3,087,977 bytes" | CONFIRMED (approx) | RUN via SDK client: 207 tools; `JSON.stringify(listTools())` = 3,087,943 bytes (framing differences account for the delta) | none |

## Chapter 03 (MCP server runtime and contracts)

| # | Claim | Verdict | Evidence | Fix |
|---|---|---|---|---|
| 1 | Full `TOOL_EFFECTS` audit table: all 207 rows (kind, 10 effect flags, derived RO/DEST/OPEN) | CONFIRMED | script parsed the 207 markdown rows and compared with `.cache/mcp-tool-catalog.json` effects/annotations/kind: 0 mismatches, 0 unlisted tools | none |
| 2 | Summary stats (196 mutatesSession, 82 launchesProcess, 58 accessesNetwork, 46 writesFilesystem, 30 mutatesTarget, 15 mayDiscardData, 15 executesForeignCode, 7 changesUiState, 6 mutatesDevice, 40 non-idempotent, 31 destructive, 99 openWorld, 6 readOnly) | CONFIRMED | recomputed from catalog: identical | none |
| 3 | Exact member lists for executesForeignCode (15), mutatesDevice (6), mutatesTarget (30), mayDiscardData (15), the 6 readOnly tools; `launchesProcess` without foreign code = 67 | CONFIRMED | computed sets match the listed names | none |
| 4 | `ToolEffects` / annotations code blocks verbatim; cites `:1-30`, `:714-737` | CORRECTED (cites only) | text identical but first block spans 1-31 and second starts at the doc comment on 713 | cites fixed |
| 5 | `annotationsFromEffects` rule | CONFIRMED | `toolEffects.ts:713-737` | none |
| 6 | Kind counts (official-proxy 41, enhanced 14, native-provider 32, artifact 16, managed 3, android 5, apktool 2, flutter 2, jeb 4, adb 24, firmware 2, pcap 2, browser 12, electron 5, runtime 2, application 20, session 21) | CONFIRMED | catalog `kind` histogram | none |
| 7 | `TOOL_CONTRACTS` is the concatenation of 36 arrays in the listed order; `toolContract` throws `Missing tool contract` | CONFIRMED | `toolContracts.ts:39-94` | none |
| 8 | 20 error codes and the retryable set | CONFIRMED | `error-contract.schema.json` code consts (20, same names); `RETRYABLE_CODES` at `analysisErrorProjection.ts:537-544` | none |
| 9 | Exhaustive over 27 tags | CONFIRMED | `analysisErrorBase.ts:4-33` union has 27 members | none |
| 10 | Server tool list is 207 and tools/list works | CONFIRMED (RUN) | MCP client: 207 | none |
| 11 | Response budget minus 1024 reserved; classes `ToolResultDelivery`, `EvidenceMcpServer`, `ErrorEvidenceTransport` locations | CONFIRMED | `toolResult.ts:47-52`, `EvidenceMcpServer.ts:107,193` | none |
| 12 | Untrusted-content marker shape | CONFIRMED (RUN) | MCP result `_meta.provenance = {untrusted_content: true, source: "analysis_target"}` | none |
| 13 | Startup-policy constants (also ch02) and the claim that budgets are not enforced at runtime | CONFIRMED (constants) / UNVERIFIABLE (non-enforcement grep not repeated) | `mcpStartupPolicy.ts:8-17` | none |
| 14 | Instructions text split fixed-target vs session server | CONFIRMED | `createServer.ts:139-142,268-269` (chapter cites `:253-283`) | none |
