# 24 — Porting blueprints: sub-tools that can be lifted out of REA (with measured dependency closure and per-blueprint designs)

Replaces the earlier one-table version. Goal: let a team create separate sub-tools from REA. Method: for each candidate I computed the **transitive import closure** of its root source files (script: [prototype/closure.mjs](prototype/closure.mjs); regex over `import`/`export … from`/`import()` statements in `src/**/*.ts`, excluding `*.test.ts`/`*.fixture.ts`, relative imports only, external packages listed separately). Commit analysed: `f75b1a4`. Licence: MIT (`package.json`); see `THIRD_PARTY_NOTICES.md`.

## 1. Measured closure (objective coupling data)
| # | Blueprint | Root files | Transitive files | LOC | Main source dirs pulled in | npm packages pulled in |
|---|---|---|---:|---:|---|---|
| 01 | ToolEffects + derived annotations | `contracts/toolEffects.ts` | 1 | 777 | contracts:1 | — |
| 02 | Evidence record + ledger + bundle | `domain/evidence.ts`, `domain/evidenceBundle.ts`, `application/investigation/EvidenceLedger.ts` | 72 | 14,297 | domain:70, application:2 | @jridgewell/trace-mapping, canonicalize, zod |
| 03 | Unknown registry | `domain/residualUnknown.ts`, `application/investigation/InvestigationRecords.ts` | 204 | 43,683 | domain:167, contracts:21, process:9, application:6 | @jridgewell/trace-mapping, canonicalize, diff, zod |
| 04 | MCP server scaffold | `server/createServer.ts` | 1190 | 253,794 | domain:377, application:219, server:90, contracts:75 | @babel/parser, @babel/types, @electron/asar, @jridgewell/trace-mapping, @lydell/node-pty, @modelcontextprotocol/client, @modelcontextprotocol/server, @xmldom/xmldom, @xterm/addon-serialize, @xterm/headless, @zip.js/zip.js, canonicalize, diff, electron, frida, jsonc-parser, parse5, pino, playwright-core, plist, semver, smol-toml, stream-chain, stream-json, write-file-atomic, ws, yaml, zod |
| 05 | Provider registry + session router | `application/binary/AnalysisProviderRegistry.ts`, `application/binary/SessionProviderRouter.ts`, `application/binary/BinarySession.ts` | 285 | 59,240 | domain:200, application:29, contracts:23, process:14 | @jridgewell/trace-mapping, @xmldom/xmldom, canonicalize, diff, plist, stream-chain, stream-json, zod |
| 06 | Ghidra headless bridge | `ghidra/GhidraProvider.ts` | 283 | 60,987 | domain:186, ghidra:41, process:21, contracts:21 | @jridgewell/trace-mapping, @xmldom/xmldom, canonicalize, diff, pino, write-file-atomic, zod |
| 07 | Hopper bridge | `hopper/HopperProvider.ts` | 253 | 52,335 | domain:182, hopper:21, contracts:21, process:18 | @jridgewell/trace-mapping, canonicalize, diff, pino, write-file-atomic, zod |
| 08 | Prompts (contracts + registration) | `contracts/promptContracts.ts`, `server/registerPrompts.ts`, `server/promptCompletion.ts` | 430 | 91,730 | domain:303, contracts:75, application:14, process:13 | @babel/parser, @babel/types, @jridgewell/trace-mapping, @modelcontextprotocol/server, canonicalize, diff, electron, stream-chain, stream-json, zod |
| 09 | JS/Electron analyzer (boundary analysis) | `application/javascript/ElectronBoundaryAnalysis.ts` | 39 | 7,850 | domain:35, application:4 | @jridgewell/trace-mapping, canonicalize, zod |
| 10 | .NET static provider | `dotnet/ManagedStaticProvider.ts` | 287 | 60,156 | domain:199, dotnet:26, contracts:21, process:13 | @jridgewell/trace-mapping, @xmldom/xmldom, canonicalize, diff, plist, zod |
| 11 | Artifact graph provider | `artifacts/ArtifactProvider.ts` | 280 | 60,322 | domain:187, artifacts:41, contracts:21, process:16 | @electron/asar, @jridgewell/trace-mapping, @xmldom/xmldom, @zip.js/zip.js, canonicalize, diff, plist, zod |
| 12 | CDP browser provider | `browser/CdpBrowserProvider.ts` | 311 | 74,789 | domain:243, browser:32, contracts:21, process:9 | @babel/parser, @babel/types, @jridgewell/trace-mapping, canonicalize, diff, electron, ws, zod |
| 13 | Process supervision (OwnedCommand) | `process/OwnedCommand.ts` | 80 | 16,828 | domain:64, process:12, windows:2, config:1 | @jridgewell/trace-mapping, canonicalize, zod |

**How to read this:** the numbers are an **upper bound** — file-level closure follows every import including type-only imports, and almost every file imports the large `src/domain` layer, so a lift that copies the closure drags most of `domain`. A real extraction should (a) copy only the root plus the symbols it uses and re-declare the types (cheap for 01, 02, 09, 13), or (b) take the whole closure as a vendored library (feasible for 02, 09, 13, impractical for 04). Observed pattern worth remembering: **01 (1 file, 777 LOC) is trivially liftable; 02, 09 and 13 are 39–80 files; everything that goes through the MCP server, provider router or a provider adapter pulls 250–1,200 files** because `application`, `contracts` and `domain` are mutually entangled ([02](02-architecture-and-module-map.md): the import graph has cycles; only a few boundaries are enforced).

## 2. Recommended extraction order
1. **01 ToolEffects** (hours) → 2. **09 JS/Electron analyzer** (days) → 3. **02 Evidence/ledger/bundle** (days) → 4. **13 process supervision** (days, but add your own sandbox) → 5. **03 Unknowns** → 6. **08 prompts/skill (text only, no code lift)** → then provider-bound items (05–07, 10–12) only if you need REA's exact semantics; otherwise **re-implement against the same contracts** using [catalog/](catalog/) and [tool-specs/](tool-specs/) as the spec.

## 3. Blueprint designs
Each blueprint: **Goal / Lift / Interface / Re-implement / Effort / Risks / Malware & vuln use / Verify**. Effort: S ≤ 1 week, M 1–3 weeks, L > 3 weeks for one engineer (my estimate from closure size and observed coupling, **INFERRED**).

### 01 — Tool effects audit + derived annotations
- **Goal:** a per-tool, reviewable statement of what a tool can do, from which MCP annotations are *derived* (never hand-set). Use to gate which agent tools may touch a sample vs detonate it.
- **Lift:** `src/contracts/toolEffects.ts` (verified standalone: no relative imports).
- **Interface (verbatim from source):**
```ts
export interface ToolEffects {
  readonly mutatesTarget: boolean;
  readonly mutatesSession: boolean;   // additive Evidence, navigation, unknown updates
  readonly writesFilesystem: boolean;
  readonly launchesProcess: boolean;
  readonly accessesNetwork: boolean;
  readonly changesUiState: boolean;
  readonly mayDiscardData: boolean;
  readonly executesForeignCode: boolean; // runs code REA does not own: target, caller-chosen executable, app under test
  readonly mutatesDevice: boolean;       // changes an attached Android device
  readonly idempotent: boolean;
}
```
- **Re-implement:** your own tool table (`TOOL_EFFECTS` has 207 REA entries); add a **policy engine** that maps effects → allow/deny per environment (REA only advertises; it does not enforce). Fix known audit gaps when copying: `start_frida_session`, `start_gdb_session`, `observe_web_execution` are not flagged `executesForeignCode`.
- **Effort:** S. **Risks:** annotations are hints for clients; a malicious server could lie — enforce in your gateway. **Use:** tier A–E gating in [23](23-defensive-malware-analysis-playbook.md). **Verify:** assert derived annotations equal advertised ones for all tools (the ch03 writer did this for 207/207).

### 02 — Evidence record, ledger, canonical bundle
- **Goal:** a provenance-carrying result envelope and a deterministic exportable case file.
- **Lift:** `src/domain/evidence.ts`, `evidenceBundle.ts`, `src/application/investigation/EvidenceLedger.ts` (closure 72 files — take the closure as a vendored lib, or re-declare the zod schema).
- **Interface (observed on real output):** `{evidence_id, subject{name,digest{sha256},local_path,format,architecture}, provider{id,name,version}, analysis_profile, predicate_type, operation, parameters, raw_result, normalized_result, confidence: observed|derived|inferred, authority: shipped-artifact|controlled-replay|historical-reference|external-service|analyst-inference, environment{id,platform,architecture,isolation}|null, limitations[], relationship_coverage, locations[], evidence_links[]}`; `evidence_id` is deterministic (identical re-runs dedupe — observed). Bundle export: canonical, byte-stable ordering (`canonicalize` package).
- **Re-implement:** persistence (the ledger is in-memory per connection), signing/attestation if you need chain-of-custody, a store (SQLite/object store) keyed by `evidence_id`.
- **Effort:** M. **Risks:** large records (JS app Evidence 559 KB for 6 files; real apps hundreds of MB) need the summary/paging pattern. **Use:** analyst report artifact; vendor-reproducible findings. **Verify:** export twice → identical bytes; import → `compare_bundles` shows no difference (note the known counter bug in [11](11-comparison-snapshots-analysis-view-reconstruction.md)).

### 03 — Unknowns registry (hypothesis tracking)
- **Goal:** first-class "not yet proven" items with required evidence authority/confidence/environment; closing requires matching Evidence.
- **Lift:** `src/domain/residualUnknown.ts` + `src/application/investigation/InvestigationRecords.ts` (closure 204 files; prefer re-implementing from the contract).
- **Interface (observed `record_unknown` output):** `{unknown_id, revision, previous_revision_digest, scope_digest, question, status: open|…, severity, domain, supporting_evidence_ids[], contradicting_evidence_ids[], required_authority, required_confidence, required_environment, recommended_probes[{operation,rationale}], relationships[]}`; `update_unknown` needs `expected_revision` (optimistic concurrency).
- **Re-implement:** storage + UI; keep the rule "a verified resolution must be backed by Evidence meeting the unknown's required authority/confidence/environment" (verified by the ch10 writer: static string-search Evidence was rejected for `controlled-replay`).
- **Effort:** M. **Risks:** REA's own captures carry `environment.isolation: "process"`, so a "VM-required" Unknown cannot be closed by REA captures — add your VM provider as an Evidence source. **Use:** hypothesis ledger for triage and vuln research. **Verify:** revision conflicts, scope digest equals sample SHA-256 (seen in L1).

### 04 — MCP server scaffold (contract-driven registration, admission, progress, error projection)
- **Goal:** host your own tools behind typed contracts with audited effects and structured errors.
- **Lift:** **do not lift code**: closure 1,190 files / 254K LOC. Instead re-implement the pattern documented in [03](03-mcp-server-runtime-and-contracts.md): `ToolContract` (name, effects, input/output zod → JSON Schema 2020-12), registration pipeline, admission against the active target, progress reporter, error projection with `remediation`, result delivery with `_meta.provenance.untrusted_content`.
- **Re-implement:** everything above on `@modelcontextprotocol/server`. **Effort:** M–L. **Risks:** `tools/list` size (REA's default 3.09 MB; ≈215 KB with output schemas off + compact inputs) — design for token budgets. **Use:** a malware-analysis MCP gateway that adds *enforced* policy (REA only labels untrusted content). **Verify:** run REA's own MCP schema conformance idea: validate advertised schemas under Ajv 2020.

### 05 — Provider registry + session router (deterministic, no fallback)
- **Goal:** bind exactly one deep analysis engine per target and never silently switch.
- **Lift:** `application/binary/{AnalysisProviderRegistry,SessionProviderRouter,BinarySession}.ts` (285 files). Prefer re-implementing from [06](06-provider-layer-and-session-routing.md): sorted candidates, `auto` selection rule, immutable binding recorded in `analysis_provider_binding`, auxiliary providers routed disjointly.
- **Effort:** M. **Risks:** parallel samples need parallel sessions (one binding per session). **Use:** swap Ghidra/IDA/Hopper per sample while keeping Evidence comparable (note profiles differ).

### 06 — Ghidra headless read-only bridge
- **Goal:** programmatic decompile/xrefs/strings/CFG without a GUI, on an ephemeral database.
- **Lift:** `bridge/ghidra/*.java` (the scripts run inside `analyzeHeadless`) + `src/ghidra/*` client/startup/wire (closure 283 files, mostly shared domain types). Protocol details in [08](08-ghidra-provider.md); private socket + per-session capability token.
- **Re-implement:** the Node-side client in your language; keep the "socket exposed only after auto-analysis completes" handshake.
- **Effort:** M–L. **Risks:** first analysis is slow (observed 15–19 s for a 16 KB ELF; docs allow up to 330 s default startup), needs Ghidra 12.1.x + JDK 21, one session at a time per client. **Use:** the engine behind flow B in [26](26-tool-usage-in-context-malware-analyst-view.md). **Verify:** REA's lab results in [27](27-manual-test-log.md) L1 are a ready acceptance test (`binary_overview`, `list_strings`, `xrefs`, `analyze_function` on a known ELF).

### 07 — Hopper bridge
- Same shape as 06: `bridge/hopper_bridge.py` + `src/hopper/*` (253 files closure). **Effort:** M–L; licence-bound (commercial Hopper); macOS/Linux; declines saved `.hop` on macOS. Not run in this lab (DOC only).

### 08 — Prompts + skill pack (text, near-zero code)
- **Goal:** steer any agent with the six workflows and the routing skill.
- **Lift:** the prompt texts and `SKILL.md` + 6 references are **plain text** ([12](12-ai-layer-prompts-and-skills.md), parts b/c). The code that renders/registers them (closure 430 files) is not needed: re-implement rendering as "objective + quoted JSON context + optional starting points + evidence discipline" (seen in real output).
- **Effort:** S. **Risks:** tool names must exist in your server; change the skill's routing table to your tool set. **Use:** ship a malware-triage skill that keeps observation/inference/unknown discipline; proposed definitions in ch12 "Porting the AI layer".

### 09 — JavaScript/Electron static analyzer
- **Goal:** AST-based application graph (modules, imports, Electron main/preload/renderer, IPC, contextBridge) + semantic graph (calls, data-flow, child-process, request, timer) with explicit unknowns.
- **Lift:** `application/javascript/ElectronBoundaryAnalysis.ts` closure = **39 files / 7.9K LOC** (best ratio). The full analysis worker is `composition/javascriptAnalysisWorkerProcess.ts` (larger; see [16](16-javascript-electron-analysis.md)). Parsers: `@babel/parser`, `@jridgewell/trace-mapping`.
- **Interface:** `analyze-javascript-application <dir|asar> --json` Evidence; views via `inspect_analysis_view`; traces via `trace_application_feature`; compare via `compare_application_versions` (all RUN in [26]/[28]).
- **Re-implement:** a **sink classifier** (REA labels `eval`/`Buffer` only as generic expressions), IOC extraction (see prototype), deobfuscation. **Effort:** S–M. **Risks:** large outputs; dynamic arguments stay `null`. **Use:** trojanized Electron/npm review; Electron vuln surface ([28] V4).

### 10 — .NET static analyzer
- `dotnet/ManagedStaticProvider.ts` closure 287 files / 60K LOC (domain-heavy). Parses PE/CLI metadata, CIL, `#US` literals, P/Invoke, no loading. RUN results in [27] L3. **Effort:** M (re-implement metadata reading with e.g. `System.Reflection.Metadata` or `dnlib` and keep REA's output shape). **Use:** stager/loader triage; call-edge + literal extraction proved sufficient to see the C2 URL, `Process.Start`, `VirtualAlloc` P/Invoke.

### 11 — Artifact graph / format inspectors
- `artifacts/ArtifactProvider.ts` closure 280 files; npm: `@zip.js/zip.js`, `@electron/asar`, `plist`, `@xmldom/xmldom`. Key behaviours to keep: integrity policy `fail`, path-traversal/symlink-escape rejection and fresh-temp extraction ("never overwrites, verifies cleanup"). **Effort:** M. **Risks for malware use:** add size/depth/ratio quotas (zip-bomb) and a sandboxed scratch mount; REA's quotas are documented in [14](14-filetypes-native-apple-archives.md).

### 12 — CDP browser provider
- `browser/CdpBrowserProvider.ts` closure 311 files; Playwright/CDP; passive observation vs scenario driving; consent and loopback-only rules in [17](17-browser-and-web-observation.md). **Effort:** L. **Risks:** drives a live browser (tier D) — run in a disposable profile; the Chromium REA launches runs with its sandbox disabled by default (Playwright adds `--no-sandbox`; chapter 17 verification).

### 13 — Process supervision / capture
- `process/OwnedCommand.ts` closure 80 files / 16.8K LOC; owned process groups, run tokens, identity (PID + path is not ownership), cleanup verification; PTY capture in `src/process/capture/`. **Effort:** M. **Must add:** a real sandbox (REA: "This is not a sandbox"). **Observed:** the comparison of identical runs reports `changed` (see [27] L10) — decide your own normalization before building diff-based detection on it.

### 14 — Malware triage layer (new component, not in REA) — prototype exists
- **Goal:** turn Evidence into IOCs, rule hits and a report with Evidence-ID provenance.
- **Prototype:** [prototype/rea-triage](prototype/rea-triage/README.md): single-file Node script + `rules.json` + YARA demo; real run produced 11 findings and 8 IOCs from 10 Evidence inputs (L13). Known gap: .NET call edges expose member names only, so `Process::Start` did not match.
- **Design for v1:** (1) ingest adapters per Evidence `operation` (as in the script); (2) IOC normaliser (defang, dedupe, TLD/IP allow-lists, base64/hex decoding, URL parsing); (3) rule engine = YARA for bytes + JSON rules for Evidence facts, ATT&CK mapping table; (4) enrichment hooks (TI lookups off by default); (5) exporters (STIX 2.1 bundle, MISP event, CSV); (6) case store keyed by sample SHA-256 + `evidence_id`; (7) enforcement shim implementing the `untrusted_content` policy (strip/quote tool text before it reaches an LLM). **Effort:** M for v1. **Verify:** golden tests = the manual-test samples in [manual-tests/samples](manual-tests/samples/).

## 4. Cross-cutting porting hazards
- **Provider version pinning is fail-closed** (WABT 1.0.42, Binwalk 3.1.x, Ghidra 12.1.x, pwntools 4.15.0): your port must carry the same pin table or you will silently accept unvalidated parsers. Observed rejections: L5/L8.
- **Everything is Evidence-shaped**: if you replace the envelope, you lose cross-tool comparison and bundle compatibility.
- **Entangled layers**: plan on re-implementing against the contracts ([tool-specs/](tool-specs/)) rather than copying code, except for the small closures (01, 02, 09, 13).
- **Policy scope**: REA excludes exploit-payload automation, packer-defeat and anti-debug-evasion workflows (`CONTRIBUTING.md`); a port that adds them is a separate product with its own review.
