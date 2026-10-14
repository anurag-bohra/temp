# @rtk/js-analyzer

AST-based static analysis of JavaScript / Electron applications. Input: a directory, a single file, or an `.asar`
(extracted to a temp dir with `@electron/asar`, removed afterwards). Parsing: `@babel/parser`; own walker (no
`@babel/traverse`). Nothing is ever executed. Output is an `@rtk/evidence` record (`createEvidence`).

```ts
import { analyzeJavaScriptApplication, compareJavaScriptApplications } from "@rtk/js-analyzer";
const ev  = await analyzeJavaScriptApplication(path, { maxFileBytes, maxFiles, timeBudgetMs, maxAstDepth, includeNodeModules });
const delta = compareJavaScriptApplications(evA, evB);   // security delta, Evidence "compare_javascript_applications"
```
CLI: `node bin/rtk-js.ts analyze <path>` / `node bin/rtk-js.ts compare <A> <B>` (A/B: a path, or a saved evidence `.json`); JSON on stdout.

Provider `rtk-js-analyzer`, operation `analyze_javascript_application`, predicate `rtk.javascript-application-analysis`,
confidence `derived`, authority `shipped-artifact`, subject sha256 = file sha256 / asar sha256 / digest of the sorted
`(path, sha256, size)` inventory for directories.

## normalized_result
- `files[]` path, sha256, bytes, kind, `parse_status` (`ok`, `parse-error` + message/loc, `json-ok|json-error`, `skipped-non-js`, `skipped-too-large`, `skipped-time-budget`, `partial-depth-limit`, `partial-budget-exceeded`, ...). Oversized files are still hashed.
- `modules[]` per file: imports/requires/dynamic imports with specifier and resolution `resolved|builtin|electron|external|unresolved|dynamic`.
- `electron`: `main_entry` (package.json `main`), `windows[]` (file, loc, `webPreferences` for nodeIntegration, contextIsolation, sandbox, webSecurity, ... each a literal, `"dynamic"` or `"unset"`), `preloads[]`, `context_bridge[]` (api, members, file, loc), `ipc[]` (channel literal or `"dynamic"`, kind handle|on|invoke|send, side, `sender_validation` boolean for main-side handlers), `loads[]` (loadFile/loadURL).
- `sinks[]` kinds `child-process | eval | function-constructor | vm | network-request | fs-write | base64-decode | dynamic-require | timer | native-addon`, each with api, argument `{kind literal|identifier|dynamic|function, value?, resolved_value?, expression?}` and optional `taint {source network-response|ipc-argument|env|fs-read, path[], channel?, guarded?, guard?}`; `base64-decode` sinks carry `decoded_preview` when the argument resolves to a literal.
- `iocs[]` URLs/IPv4 from string literals, with base64/hex layers decoded recursively (depth 3): value, encoding chain, file, line/column.
- `flows[]` taint source -> sink with path, `guarded` flag; `summary` counters.
- `limitations` always lists the heuristics below; `locations` points at windows, sinks and IOCs.

## How taint works (and where it stops)
Name-based, intra-file, closure-aware: callback parameters are seeded (ipc handler params after `event`; the response of
`http(s).request/get` callbacks; `fetch(...).then(cb)`; `fs.readFile` callbacks; `process.env.*`; `fs.readFileSync(...)`), taint propagates
through assignments (`d += c`), declarations/destructuring, calls (args and receiver), template/binary/conditional
expressions, and closures (a variable assigned in one callback is seen in a sibling callback later in source order).
An equality / allowlist-membership check (`!ALLOWED.has(cmd)` with early throw/return, or in the `if` body) marks the flow
`guarded` (heuristic: sufficiency is not judged). `startsWith`-style checks are NOT treated as guards.
`sender_validation` = the handler (or a same-file helper it passes the event to, depth 2) reads `event.senderFrame|sender` `.url|.origin|.getURL()|...`
and compares it (===, !==, startsWith, includes, has, test, ...). Computed values are never guessed: they are `"dynamic"`.

## Verification (tests in `test/analyzer.test.ts`, 17 tests, no skips)
Fixtures `test/fixtures/jsapp` (v1) and `jsapp2` (patched) are copies of the benign demo apps; the REA cross-check uses a reduced copy
of REA's real output `T1-js-v1.json` (`test/fixtures/rea-T1-js-v1.reduced.json`), so nothing depends on the lab paths.
- v1 `nodeIntegration:true` -> v2 `false` + `contextIsolation:true` + `sandbox:true`; sender validation false -> true for `run-task`.
- v1 flows ipc-argument -> `child_process.exec` and network-response -> `eval`; base64 literal decoded to `https://c2.example.invalid/task` as IOC with file/line; v2 exec flow reported as guarded.
- `compare(v1,v2)`: improved items (nodeIntegration, contextIsolation, sandbox, sender validation, exec flow); zero regressions; reverse direction regresses; identical inputs give an empty delta.
- Agreement with REA: 1 browser window, 1 context-bridge API (`api`, member `run`), literal main-side channel `run-task`, 1 main handler, nodeIntegration literal true, preload `preload.js`. REA leaves exec command / request endpoint null and does not classify eval/base64; this package does (asserted).
- ASAR built in the test with `@electron/asar` (subject digest = asar sha256, temp extraction removed); single-file input; parse failures and non-JS files; size limit, time budget, AST depth limit and file-count limit each produce explicit limitations; dynamic constructs (`new BrowserWindow(opts)`, `...spread`, `ipcMain.on(name)`, `require(name)`) stay `"dynamic"`; sender-validation and guard heuristics (positive and negative cases); env/fs-read/fetch taint; hex and double-base64 IOCs; CLI.

## Not implemented / not verified
- No cross-file or cross-module data flow, no object-field/array sensitivity, no interprocedural taint beyond sender-validation helpers; obfuscated, minified-and-packed, or eval-generated code is not unpacked.
- `XMLHttpRequest.open` and `WebSocket` via aliases are only partly covered; no TypeScript/ESM-bundler specific handling (`.ts` files are skipped).
- HTML/JSON are not scanned for IOCs; IPv4 matching can hit version strings.
- Malicious asar path-traversal rejection exists in `files.ts` (entry names with `/`, `\`, `..`) but is not exercised by a test.
- Results on real-world large apps (performance, false-positive rate) were not measured; only the demo apps and synthetic cases above.
