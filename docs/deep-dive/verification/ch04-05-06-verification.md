# Verification log: chapters 04, 05, 06

Verified 2026-10-14 against `/home/user/morluto/rea` (HEAD f75b1a4, v6.4.0, `dist/` and `dist/cli-runtime/` present). Method: code reading with line checks; real runs of `node scripts/rea.mjs <cmd> --help|--schema|--json` (isolated `HOME` for setup/doctor/uninstall/update); programmatic comparison of the chapter 04 command tables with `--schema` of all 154 command rows and with `.cache/mcp-tool-catalog.json`; programmatic comparison of the chapter 06 provider table with `docs/public/product-catalog.json` and the catalog; Mermaid validator `scratchpad/mv/check.mjs` (04: 3 blocks, 05: 7, 06: 5, all pass).

Totals (claim rows below; each row may bundle a small family of identical checks):

| Chapter | CONFIRMED | CORRECTED | UNVERIFIABLE |
|---|---|---|---|
| 04 CLI reference | 43 | 7 | 4 |
| 05 Setup/doctor/update/uninstall/clients | 35 | 7 | 5 |
| 06 Provider layer and routing | 34 | 6 | 2 |

## Chapter 04

| # | Claim | Verdict | Evidence | Fix applied |
|---|---|---|---|---|
| 1 | 153 canonical CLI commands, `CLI_COMMAND_NAMES` line 160, alias `compare-bundles` line 163 | CONFIRMED | `src/cliCommandNames.ts:2-163`; script counted 153 entries | none |
| 2 | `product-catalog.json` `.cli.primary_count: 153`; every catalog command appears in the 4.8 tables | CONFIRMED | `e.mjs`: 153 catalog commands all present, 154 rows incl. alias | none |
| 3 | 65 MCP operations without a dedicated CLI twin | CONFIRMED | `cliCommandNames.ts:189-257` (65 entries) | none |
| 4 | `rea providers --json` reports `catalog.counts.cli_commands=153, mcp_tools=207, mcp_prompts=6` | CORRECTED | `rea providers --json`: counts are at `server_identity.catalog.counts`; no top-level `catalog` | text fixed |
| 5 | Framework incur 0.6.1; `Cli.create` at `src/cli.ts:88-97` | CONFIRMED | `package.json:336`, `node_modules/incur/package.json`, `cli.ts:88-96` | none |
| 6 | `scripts/rea.mjs` dispatch: `--mcp`/`mcp` intercept, `mcp doctor`, missing-build message, win32/Termux shims, line ranges | CONFIRMED | `scripts/rea.mjs:13-98` | none |
| 7 | `bin` maps `rea` and `rea-agents`; engines `^22.19.0 \|\| ^24.11.0 \|\| >=26.0.0` | CONFIRMED | `package.json:40-46` | none |
| 8 | Verification note: `dist/cli-runtime/` absent, `rea.mjs` prints "compiled runtime is missing", harness used instead | CORRECTED | `dist/cli-runtime/{cli,cliOutput,cliResultOutput,mcpDoctor}.js` exist; `node scripts/rea.mjs --version` = 6.4.0 | note rewritten |
| 9 | Invalid `REA_LOG_LEVEL`: stderr message, exit 1 | CONFIRMED (RUN) | `REA_LOG_LEVEL=bogus rea providers` -> stderr text, exit 1 | none |
| 10 | CLI default log level is silent when unset | CONFIRMED | `src/cli.ts:80-87` | none |
| 11 | `--token-limit` with `--json` rejected as `UNSUPPORTED_OUTPUT_COMBINATION`, exit 1, JSON on stdout | CONFIRMED (RUN) | `rea providers --json --token-limit 10` | none |
| 12 | Unclosed `[` slice in `--filter-output` rejected up front | CONFIRMED (RUN) | returns `INVALID_OUTPUT_FILTER`, exit 1 | none |
| 13 | Fully filtered structured output renders `{}` | CONFIRMED (RUN) | `--filter-output nothing.here --json` -> `{}` exit 0 | none |
| 14 | `--full-output` envelope `{ok,data,meta:{command,duration}}` | CONFIRMED (RUN) | observed | none |
| 15 | `--token-count` prints estimated count instead of result | CONFIRMED (RUN) | prints `5985` | none |
| 16 | `--llms` manifest `incur.v1`; global flags list; `--update` present | CONFIRMED (RUN) | `rea --llms --format json`, `rea --help` | none |
| 17 | `rea mcp add` flags and incur-owned `completions` | CONFIRMED (RUN) | `rea mcp add --help` (`--agent`, `--command/-c`, `--no-global`) | none |
| 18 | Exit 130/143 via `withCommandCancellation` | CONFIRMED | `src/cli/commandCancellation.ts:9-32` | none |
| 19 | Setup status to exit mapping (`planned/cancelled/ready` 0; `needs_confirmation/needs_human` 1) | CONFIRMED | `SetupTypes.ts:122-139` | none |
| 20 | Doctor `healthy === false` -> exit 1 | CONFIRMED (RUN) | `rea doctor --json` exit 1 on empty host | none |
| 21 | Failure classification (`analysisCliErrorEnvelopeSchema`, `healthy === false`), errors on stdout with exit 1 | CONFIRMED (RUN) | `cliLogging.ts:18-59,98-101`; `decompile /nonexistent/x main --json` exit 1 | none |
| 22 | `cleanup_incomplete` rewrap on close failure | CONFIRMED | `DirectAnalysisCleanup.ts:47,65` | none |
| 23 | Failure example shape for `decompile /nonexistent/x main` (`target_unavailable`) | CONFIRMED (RUN) | exact fields observed | none |
| 24 | `rea analyze` with no engine: `provider_unavailable`, `candidate_ids ["ghidra","hopper","ida"]`, `rejections[].code not_configured`, `details.operation "current_document"` | CONFIRMED (RUN) | `rea analyze samples/c/t --json` | none |
| 25 | 19 commands take `inputJson` (list of 18 + `observe-native-calls`) | CONFIRMED | `--schema` of all commands: 19 with `inputJson` positional | none |
| 26 | `parseCliJsonInput` `input_reason` values `invalid-json`/`read-failed`/`too-large`; `invalid_format` expected JSON | CONFIRMED | `src/cliJsonInput.ts:14-57,131-154` | none |
| 27 | `nativeOpenOptionFields` verbatim block | CORRECTED | `src/cli/options.ts:40-45`: source has no trailing comments | label added: comments are the document's own |
| 28 | `createBinarySession` verbatim block `composition/binary.ts:21-37` | CORRECTED | real signature has typed params and different wrapping | labelled "condensed" |
| 29 | `createManagedBinarySession`/`createArtifactBinarySession` use empty registry + one auxiliary | CONFIRMED | `composition/binary.ts:40-57` | none |
| 30 | Composed workflows list (`binary_overview`, `inspect_native_api`, `inspect_native_dispatch_metadata`, `trace_feature`, `trace_native_values`, `trace_native_ui_action`); `binary_overview` calls `list_segments/procedures/strings` | CONFIRMED | `DirectAnalysis.ts:421-430,612-620`; `EnhancedTools.ts:626-631` | none |
| 31 | `--snapshot` accepted by 10 listed commands | CONFIRMED | `--schema` scan: analyze, decompile, function, inspect, inspect-native-api, inspect-native-dispatch-metadata, instructions, search, trace, xrefs | none |
| 32 | `capabilities` and `providers` identical apart from `started_at`; provider id lists; effect vocabulary | CONFIRMED (RUN) | structural compare = identical; ids `native-macos, rea-artifact-graph, rea-dotnet-static, sqlite` / `ghidra, hopper, ida` | none |
| 33 | `instructions` is `read_function_instructions` | CONFIRMED | `cliCommandNames.ts:171`, `--schema` | none |
| 34 | Evidence enums (`confidence`, `authority`, `isolation`) | CONFIRMED | `src/domain/evidence.ts:108-114,134-135` | none |
| 35 | `inspect-analysis-view` "14 kinds" while listing 13 names | CORRECTED | tool description enumerates producer operations, command description lists 13 families | now "13 named families" |
| 36 | Per-family counts (4,20,2,1,6,8,7,9,8,7,5,37,16,18,6) sum to 153+alias; ADB 24 | CONFIRMED | row counts per section; 24 `*adb*` rows | none |
| 37 | All positional args / required markers / option names / `=defaults` for 154 rows | CONFIRMED | `t.mjs`: 0 mismatches except 4 rows where `--schema` default is `null` | legend note added |
| 38 | MCP twin names and Eff letters for all rows | CONFIRMED | `e.mjs`: 0 mismatches vs catalog `effects` | none |
| 39 | `idempotent`/`mutatesSession` omitted because "every observation mutates the session ledger" | CORRECTED | catalog: `mutatesSession` false for 11 tools (list in text) | legend corrected |
| 40 | 25 catalog tools have `requiresSession: true` | CONFIRMED | catalog count 25 | none |
| 41 | Frida: exactly one of `--script/--scriptFile`, `durationMs` 0..60000 default 1000, attach needs positive PID, remote options exclusive with `--deviceId` | CONFIRMED | `src/cli/fridaCommands.ts:140-296` | none |
| 42 | `cutter-command` takes UUID session + integer generation | CONFIRMED | `src/cli/cutterCommands.ts:28-42` | none |
| 43 | `inspect-with-objdump` operation enum; `list-objdump-architectures` uses `architectures` | CONFIRMED | catalog inputSchema for `inspect_with_objdump` | none |
| 44 | Flag case "camelCase" for most families | CORRECTED | `--help` shows kebab (`--max-depth`); schema keys camelCase; both accepted (setup `--installHopper`/`--install-hopper`) | note added |
| 45 | `compare-bundles` is an incur alias | CONFIRMED | `cliEvidenceCommands.ts:51` | none |
| 46 | `setup` is `outputPolicy: "agent-only"` | CONFIRMED | `setupCommands.ts:52` | none |
| 47 | `docs/cli.md` quoted line ranges (3-5, 23-38, 135-161, 142-143, 157-159, 170-208, 177-179, 275-277, 286-290, 303-304, 308-314, 316-320, 322-331, 333-339) | CONFIRMED | each range read | none |
| 48 | REA monkey-patches `Cli.toCommands` WeakMap (`cliResultOutput.ts:44`, `omittableDefaults.ts:11`) | CONFIRMED | grep | none |
| 49 | Dependency list (tokenx, semver, write-file-atomic, stream-json/chain, pino, @clack/prompts, zod, jsonc-parser...) | CONFIRMED | `package.json` | none |
| 50 | `bridge/pwntools/recorded_crash*.py`, `bridge/pwndbg/*` shipped in `files` | CONFIRMED | `package.json:48-100` | none |
| 51 | Worked evidence-import/export/compare/inspect-evidence-bundle transcript (bundle created via library) | UNVERIFIABLE | needs a bundle fixture created outside the CLI; not re-run | none |
| 52 | `jsonParts` streaming of very large JSON; `--token-count` string-size guard | UNVERIFIABLE | would need a multi-hundred-MB result | none |
| 53 | incur `--update` path unrelated to REA's updater (INFERRED) | UNVERIFIABLE | not executed; flag existence confirmed | none |
| 54 | Windows/Termux shims, Windows historical-source `unsupported_host` | UNVERIFIABLE | Linux host only | none |

## Chapter 05

| # | Claim | Verdict | Evidence | Fix applied |
|---|---|---|---|---|
| 1 | `setup` flags and defaults (`--yes/-y`, `--installHopper=false`, `--client[]`, `--skillClient[]`, `--allDetected`, `--skill`, `--dryRun`, `--accessible`) | CONFIRMED (RUN) | `setup --help`; `setupCommands.ts:45-89` | kebab spelling note added (see 40) |
| 2 | `doctor` flags; `DOCTOR_PROVIDER_IDS = ["hopper","ghidra","ida","jadx"]` | CONFIRMED | `setupCommands.ts:105-136`; `DoctorProviderIds.ts:2` | none |
| 3 | `uninstall --purgeData`; `update` takes no options | CONFIRMED | `setupCommands.ts:143-190` | none |
| 4 | `SetupOptions`, `SetupResult`, `SetupAction`, `ClientConfigurationResult`, `SetupHost` line ranges and fields | CONFIRMED | `SetupTypes.ts:28,65,104,169,184` | none |
| 5 | 15 `SetupFailureCode` values, `SetupInstallFailure.ts:4-19` | CONFIRMED | exact list | none |
| 6 | Flag-to-option derivation (`interactive`, `approved`, `structured`, `proposeHopper`, explicit scope, `installSkill`, `readinessScope`) | CONFIRMED | `setupCommands.ts:255-320` | none |
| 7 | 25 client definitions, ids and formats match catalog; definition line ranges 487-709 | CONFIRMED | `product-catalog.json .setup_clients`; per-client start lines identical | none |
| 8 | Per-client config paths, override env vars, skill roots, entry shapes (spot-check of all 25 rows) | CONFIRMED | `SupportedClients.ts:485-712`; Commandcode and Droid have no override env (confirmed) | none |
| 9 | Server-table key per format (`mcp_servers`, `mcp`/`mcp.servers`, `servers`, `mcpServers`) | CONFIRMED | `ClientConfigurationDocument.ts:80-96,190-205` (zcode nested `mcp.servers`) | none |
| 10 | `clientRegistrationEntry` verbatim (all dialects), DSH entry shape | CONFIRMED | `ClientConfigurationDocument.ts:1437-1512`; `DshCordisPatch.ts:424-438` | none |
| 11 | Codex/Grok `startup_timeout_sec=30`; Kimi 30000/120000 | CONFIRMED (RUN for Codex) | `mcpStartupPolicy.ts:9-11`; setup wrote `startup_timeout_sec = 30` | none |
| 12 | `PRODUCT_IDENTITY.registrationPackageSpecifier = rea-agents@<version>` | CONFIRMED | `src/identity.ts:10` (chapter said :11) | none |
| 13 | npx/bunx pinned command, `cmd.exe /d /c` on Windows; absolute entrypoint registration | CONFIRMED | `ClientRegistrationIdentity.ts`; `SetupHost.ts:62-73`; run registered `[".../scripts/rea.mjs","mcp"]` | none |
| 14 | Provider env propagated (`GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `REA_IDA_MCP_CONFIG`, JADX vars, `REA_JEB_MCP_URL`, `HOPPER_LAUNCHER_PATH`) | CONFIRMED | `GhidraDoctor.ts`, `IdaDoctor.ts:24`, `JadxDoctor.ts:38-52`, `doctorRuntime.ts:17-26` | none |
| 15 | User env overrides `REA_MCP_*` accepted by config schema | CONFIRMED | `config/environment.ts:25-27` | none |
| 16 | Setup idempotence: first run `ready`/`configured_codex`/backup `config.toml.rea.backup`; second `plannedActions: []` | CONFIRMED (RUN) | re-ran in scratch HOME; unrelated `model="x"` preserved | none |
| 17 | `setup --client codex --dry-run` yields `planned`, action `configure_client:codex`, operation `update`, backupPath | CONFIRMED (RUN) | observed | none |
| 18 | `--installHopper` + `--dry-run` adds `install_hopper` action | CONFIRMED (RUN) | actions `[install_hopper, configure_client:codex, install_skill]` | none |
| 19 | Approval prompt "Apply these N changes?"; needs_confirmation remediation text | CONFIRMED | `interactiveSetup.ts:61`; `Setup.ts:295` | none |
| 20 | Final remediation after Hopper install "Open Hopper, choose its demo mode..." | CONFIRMED | `Setup.ts:515` | none |
| 21 | Skill: exactly seven managed files | CONFIRMED | `SetupSkill.ts:22-30` | none |
| 22 | Authored skill 341 + references = 1,103 lines, `metadata.version "42"` | CONFIRMED | `wc -l`; `SKILL.md:5` | none |
| 23 | Generator runs in `build`/`build:cached` via `artifacts:skills`; `files` ships `skills` | CONFIRMED | `package.json:76,109,124,296` | none |
| 24 | `skills/` not generated in checkout; `setup --skill --yes` -> `needs_human`, `skill_install_failed`, ENOENT | CONFIRMED (RUN) | `ls skills` fails; observed result | none |
| 25 | Hopper macOS: metadata URL, `https://www.hopperapp.com:443/downloader/public/` prefix, SHA-1 compare, 100,000,000 bytes, 120 s | CONFIRMED | `MacHopper.ts:28-29,336`; `HopperDownload.ts:2,9` | none |
| 26 | Hopper publisher bundle id and team id | CONFIRMED | `hopperPublisher.ts:10-11` | none |
| 27 | Linux Hopper: three pinned 6.4.2 records, `pkexec` unless root, dependency package list | CONFIRMED | `LinuxHopper.ts:30-40,459-493` | none |
| 28 | `doctor` node check (Bun by compat version) and host check (macOS >=12, Linux apt/dnf/pacman, win32 x64) | CONFIRMED | `DoctorDiagnostics.ts:98-148` | none |
| 29 | Doctor check order | CORRECTED | `DoctorDiagnostics.ts:28-56`: node, host, hopper, hopper-version, providers, ilspy, hopper-demo-runtime, target | text fixed (demo-runtime moved) |
| 30 | Audit-wide health = core checks + configured providers + one available engine | CORRECTED | `Doctor.ts:211-235,285-310`: identity checks (non-aligned skill, non-aligned/manual registrations) are core; fresh HOME shows `skill:identity ok:false` | clarified |
| 31 | Explicit scope: `rea doctor --client codex --json` exit 0 on engine-less host; scope_checks `[node, registration:codex]` | CONFIRMED (RUN) | observed `healthy:true, environment_healthy:false`, exit 0 | none |
| 32 | `DoctorCheck` classification enum | CONFIRMED | `Doctor.ts:50-66` | none |
| 33 | Update command pinned and script-free (`--ignore-scripts`); Bun >=1.2.17 | CONFIRMED | `Update.ts:100,107`; `UpdateRuntime.ts:324-328` | none |
| 34 | Update worked example (`status current`, latest 6.4.0, exit 0) | CORRECTED | re-run: latest is now 6.5.0 -> `failed`, `unknown-install-method`, exit 1 | example updated, time-sensitivity noted |
| 35 | Uninstall worked example: 22 other clients skipped | CORRECTED | run: 27 items = 25 clients (codex removed, 24 skipped incl. grok_bot) + skill + analysis_engine retained; so 23 others; JSON key is `items[]` | fixed |
| 36 | Uninstall retains foreign config content, backup left (`model="x"` kept, `.rea.backup` stays) | CONFIRMED (RUN) | observed | none |
| 37 | MCP startup budgets 15 s / 5 s / 20 s / 30 s, stderr 64 KiB | CONFIRMED | `mcpStartupPolicy.ts:12-19` | none |
| 38 | `install.sh`: Darwin/Linux only, Node gate, `--prefix ~/.local` on Linux | CONFIRMED | `install.sh:113-148` | none |
| 39 | `install.sh` starts setup only if `/dev/tty` usable | CORRECTED | `install.sh:173` also requires `-t 1` and `-t 2` | text fixed |
| 40 | Flag spellings (`--installHopper` etc.) | CORRECTED | `--help` prints kebab; both accepted (RUN) | note added |
| 41 | 5.14 item 2: `dist/cli-runtime` absent | CORRECTED | directory exists now | marked resolved |
| 42 | `rea mcp add` flags | CONFIRMED (RUN) | `mcp add --help` | none |
| 43 | macOS Hopper install (hdiutil/codesign/ditto), `sw_vers`, brew probe | UNVERIFIABLE | Linux host | none |
| 44 | Windows MSIX resolution rules and `processView: redirected` refusal | UNVERIFIABLE | needs Windows | none |
| 45 | Gemini policy blocks, OpenCode layering, ZCode fallback copying | UNVERIFIABLE | read, not executed; no clients installed | none |
| 46 | `docs/installation.md` "npm 6.4.0 accepted dry-run for 17 client IDs (checked 2026-10-11)" | UNVERIFIABLE | doc statement exists (`installation.md:399`); registry not re-queried | none |
| 47 | Client-verification lanes (`verify:*-client`) | UNVERIFIABLE | require native clients | none |

## Chapter 06

| # | Claim | Verdict | Evidence | Fix applied |
|---|---|---|---|---|
| 1 | Six session-bound providers: deep `hopper, ghidra, ida`; auxiliary `rea-artifact-graph, native-macos, rea-dotnet-static` | CONFIRMED | `composition/binary.ts:24-36`; `auxiliaryAnalysisProviders.ts:19-53` | none |
| 2 | 47 providers in catalog | CONFIRMED | `product-catalog.json providers.length` = 47 | none |
| 3 | Provider table: id, name, catalog version, op count for all 47 rows | CONFIRMED | script compare: 0 mismatches; every catalog id present | none |
| 4 | MCP tool-kind column for every provider | CONFIRMED | script compare vs `.cache/mcp-tool-catalog.json` kinds: 0 mismatches | none |
| 5 | EXECUTES set: frida (3), gnu.gdb, cutter, rizin, rizin.debugger, native-macos (2), two Playwright providers | CONFIRMED | catalog `executesForeignCode` | none |
| 6 | Hopper 36 ops incl. 6 editing ops; Ghidra 29 ops incl. 3 edits | CONFIRMED | catalog `mutatesTarget` | none |
| 7 | Tool counts: 41 official-proxy, 14 enhanced | CONFIRMED | catalog kinds | none |
| 8 | `AnalysisProvider.ts` ranges (23-62, 81-120, 122-190, 192-241, 243-293) | CONFIRMED | line check | none |
| 9 | `PROVIDER_REJECTION_CODES` (13 values) and selector regex/refine | CONFIRMED | `providerSelection.ts:1-33` | none |
| 10 | Registry file sizes (453/138/205/227/154/989) and `binary/` total 6,216 lines | CONFIRMED | `wc -l` | none |
| 11 | Registry constructor invariants (valid id, unique, provenance, no duplicate op, code-point sort) | CONFIRMED | `AnalysisProviderRegistry.ts:80-124` | none |
| 12 | `select`: abort check, invalid request, all-unsupported shortcut, concrete order registered->supported->available, auto ambiguity | CONFIRMED | `AnalysisProviderRegistry.ts:151-260,328` | none |
| 13 | `ProviderSelectionFailureReason` 5 values; ambiguity user message | CONFIRMED | `providerSelectionError.ts:8-13,79-80` | none |
| 14 | Evaluation outcomes (`version_unresolved`, "Provider profile resolution threw", null profile message) | CONFIRMED | `AnalysisProviderEvaluation.ts:51,85,130` | none |
| 15 | `AnalysisProviderBinding` verbatim; `selectedResult` 368-398 with `structuredClone` | CONFIRMED | `AnalysisProviderRegistry.ts:47-62,368-398` | none |
| 16 | `unboundOperationError` target_unsupported vs provider_unavailable | CONFIRMED | `AnalysisProviderRegistry.ts:204-221` | none |
| 17 | Router invariants (unique ids, disjoint aux, deep vs aux overlap) and route/resolve/initialRoute/emptyClient ranges | CONFIRMED | `SessionProviderRouter.ts:24-143,181-205` | none |
| 18 | Composite id `composite:<sorted ids joined by +>`, name, `version:null` | CONFIRMED | `CompositeProvider.ts:19-28` | none |
| 19 | Composite lazy `clientFor`, profile passed only to matching provider, health probes instantiated children only | CONFIRMED | `CompositeProvider.ts:80-110,160-175` | none |
| 20 | Lazy provider: `client_closed`, cache cleared on load rejection | CONFIRMED | `LazyAnalysisProvider.ts:68,112,140-141` | none |
| 21 | Auxiliary operation tables (artifact 6+hidden inventory, native-macos 8+dispatch=9, dotnet 3) | CONFIRMED | catalog and `rea providers` capability groups (9 ops for native-macos) | none |
| 22 | `createManagedBinarySession`/`createArtifactBinarySession` | CONFIRMED | `composition/binary.ts:40-57` | none |
| 23 | `BinarySession` function ranges (serialize, drain, open, external mutation, execute, restore, wait) | CONFIRMED | line check | none |
| 24 | Ghidra external-mutation refusal text | CONFIRMED | `BinarySession.ts:414` | none |
| 25 | Snapshot cacheability rule verbatim; `STATEFUL_OPERATIONS`, `CURSOR_DEFAULT_OPERATIONS`, ceiling 10,000 | CORRECTED (cite only) | `AnalysisSnapshotCache.ts:43-85` | cited range corrected 67-77 -> 70-85 |
| 26 | IDA declares `cachePolicy "live"`; Ghidra reads declare `"snapshot"`; IDA `procedure_callers` unavailable on headless/native | CONFIRMED | `IdaProviderCapabilities.ts:78-86`; `GhidraProviderCapabilities.ts:176-184` | none |
| 27 | `ENHANCED_REQUIREMENTS` verbatim | CORRECTED (cite only) | `CapabilityInventory.ts:103-132` | range corrected 105-135 -> 103-132 |
| 28 | `toolUnavailabilityReason` six values; `AvailabilityPolicy` 21 fields | CONFIRMED | `toolOutputSchemaPrimitives.ts:368-375`; `CapabilityInventory.ts:45-67` | none |
| 29 | `mutatesSession` is true for every tool, hence every `readOnlyHint` false | CORRECTED | catalog: 11 tools false, 6 with `readOnlyHint:true` | text corrected |
| 30 | `rea-javascript-application-workflows` is the only provider with a read-only tool | CORRECTED | also `gnu.gdb` (`gdb_session_status`) and `frida` (`frida_session_status`) | text corrected |
| 31 | `open_binary` description contains "no failure fallback"; ghidra doc quote | CONFIRMED | catalog; `docs/ghidra-provider.md:22` | none |
| 32 | Provider env var names/defaults (`REA_ADB_PATH`, `REA_GDB_COMMAND`/`REA_RIZIN_COMMAND`/`REA_OBJDUMP_COMMAND` defaults, JEB default URL `http://127.0.0.1:8425/mcp`, Cutter bridge dir default) | CONFIRMED | `CutterBridgeClient.ts:285`; `JebMcpEndpoint.ts:7`; `reverseEngineering.ts:20,30`; every `REA_*` token in chapters 04-06 greps to a source file | none |
| 33 | Global env table: `REA_ANALYSIS_PROVIDER` default `auto`, schema lines 24-77 | CONFIRMED | `environment.ts:24-77` | none |
| 34 | `REA_LOG_LEVEL` default `info` | CORRECTED (completed) | schema default `info`; CLI uses `silent` when unset (`cli.ts:80-87`) | table cell qualified |
| 35 | Status projection ranges (`BinarySessionStatus.ts:42-110`, `providerCapabilitySets` 188-244, `availabilityFor` 273-300, `registerSessionStatusTool.ts:60-145`) | CORRECTED | actual 36-109, 213-281, 290-314, 42-130 | cites fixed |
| 36 | `NativeMacOSProvider.ts` 1172 lines, metadata 57 lines, `OWNED_PROCESS_OPERATIONS` effects | CONFIRMED | `wc -l`; `NativeMacOSProviderMetadata.ts:14,43-46` | none |
| 37 | `BinarySession` sub-file line counts table (all 15 files) | CONFIRMED | `wc -l` | none |
| 38 | `createServer.ts` registration ranges 439-758 / 831-904; `registerOfficialTools.ts:78-98` Evidence creation | CONFIRMED | sampled boundary lines | none |
| 39 | Sequence diagrams 7.1/7.2 call chains | CONFIRMED | consistent with `BinarySession.open/#execute`, `registerOfficialTools.ts` | none |
| 40 | IDA doc quote and worked JSON sequence | CONFIRMED | `docs/ida-provider.md:5,128` | none |
| 41 | Ambiguity worked example (`candidateIds ["ghidra","hopper","ida"]`, `ida` rejected `not_configured`) | UNVERIFIABLE | needs two engines installed; behaviour follows from code (12) | none |
| 42 | Unbound `.zip` example returns `target_unsupported` for `list_procedures` | UNVERIFIABLE | MCP session not driven here; consistent with `unboundOperationError` | none |
