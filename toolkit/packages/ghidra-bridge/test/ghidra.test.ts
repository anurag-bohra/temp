import { test, before } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeBinary, GhidraProvider, GhidraTimeoutError, GhidraNotFoundError, resolveInstallDir, processGroupMembers, sha256File, ProcedureNotFoundError } from "../src/index.ts";
import type { GhidraSnapshot } from "../src/index.ts";
import { Registry, BinarySession } from "@rtk/provider-router";
import { parseEvidence } from "@rtk/evidence";

const SCRATCH = "/tmp/claude-0/-home-user-temp/b1154f5f-19b6-591b-8a67-cb57e20a5c77/scratchpad";
const T = `${SCRATCH}/samples/c/t`;
const WEAK = `${SCRATCH}/samples/vuln/weak`;
const T2 = "/home/user/temp/docs/deep-dive/manual-tests/mcp-transcripts/t2.json";
const haveGhidra = resolveInstallDir() !== null;
const skipReason = !haveGhidra ? "Ghidra not installed" : (!existsSync(T) || !existsSync(WEAK)) ? "sample binaries missing" : false;

let snapT: GhidraSnapshot, snapWeak: GhidraSnapshot, hashT = "";
let provT: GhidraProvider, provWeak: GhidraProvider;
const ev = async (p: GhidraProvider, op: string, args: Record<string, unknown> = {}) => parseEvidence(JSON.parse(JSON.stringify(await p.call(op, args)))) as any;

before(async () => {
  if (skipReason) return;
  hashT = await sha256File(T);
  const sha = async (f: string) => ({ path: f, sha256: await sha256File(f) });
  const wt = await sha(T), ww = await sha(WEAK);
  provT = new GhidraProvider(); await provT.open(wt as any); snapT = provT.snapshot()!;
  provWeak = new GhidraProvider(); await provWeak.open(ww as any); snapWeak = provWeak.snapshot()!;
});

test("t: finds main and check; overview", { skip: skipReason }, async () => {
  const names = (await ev(provT, "list_procedures")).normalized_result.procedures.map((p: any) => p.name);
  assert.ok(names.includes("main") && names.includes("check"));
  const o = await ev(provT, "binary_overview");
  assert.equal(o.provider.id, "rtk-ghidra-bridge");
  assert.equal(o.subject.digest.sha256, hashT);
  assert.equal(o.normalized_result.format, "Executable and Linking Format (ELF)");
  assert.equal(o.normalized_result.image_base, "0x100000");
});

test("t: string 198.51.100.7 with xref from main; xrefs op; strings search literal+regex", { skip: skipReason }, async () => {
  const s = await ev(provT, "search_strings", { pattern: "198.51.100.7" });
  assert.equal(s.normalized_result.matches[0].address, "0x102004");
  assert.ok(s.normalized_result.matches[0].xrefs.some((x: any) => x.function === "main"));
  const r = await ev(provT, "search_strings", { pattern: "^198\\.51\\.\\d+\\.\\d+$", mode: "regex" });
  assert.equal(r.normalized_result.total_matches, 1);
  await assert.rejects(provT.call("search_strings", { pattern: "(", mode: "regex" }), /invalid regex/);
  const l = await ev(provT, "list_strings", { min_length: 5 });
  assert.ok(l.normalized_result.strings.some((x: any) => x.value === "/bin/sh -c id"));
  const x = await ev(provT, "xrefs", { address: "0x102004" });
  assert.deepEqual(x.normalized_result.references.map((r: any) => r.from), ["0x1012da", "0x104010"]);
});

test("t: check pseudocode contains ptrace; callers/callees; analyze_function", { skip: skipReason }, async () => {
  const p = await ev(provT, "procedure_pseudo_code", { procedure: "check" });
  assert.match(p.normalized_result.pseudo_code, /ptrace/);
  assert.equal(p.confidence, "derived");
  assert.deepEqual((await ev(provT, "procedure_callers", { procedure: "check" })).normalized_result.callers.map((c: any) => c.name), ["main"]);
  assert.ok((await ev(provT, "procedure_callees", { procedure: "main" })).normalized_result.callees.some((c: any) => c.name === "check"));
  const a = (await ev(provT, "analyze_function", { procedure: "main" })).normalized_result;
  assert.equal(a.identity.name, "main");
  assert.deepEqual(a.body, [{ start: "0x10125b", end: "0x101339" }]);
  assert.ok(a.referenced_strings.some((s: any) => s.value === "198.51.100.7"));
  assert.ok(a.imports_used.some((i: any) => i.name === "connect"));
  assert.match(a.pseudo_code, /connect/);
  const info = (await ev(provT, "procedure_info", { procedure: "0x101230" })).normalized_result.procedure; // address inside check
  assert.equal(info.name, "check");
});

test("t: trace_call_path main->check reached; check->main not reachable forward; backward works", { skip: skipReason }, async () => {
  const r = (await ev(provT, "trace_call_path", { start: "main", goal: "check" })).normalized_result;
  assert.equal(r.goal_status, "reached");
  assert.deepEqual(r.path.map((p: any) => p.name), ["main", "check"]);
  const back = (await ev(provT, "trace_call_path", { start: "check", goal: "main", direction: "backward" })).normalized_result;
  assert.equal(back.goal_status, "reached");
  const no = (await ev(provT, "trace_call_path", { start: "check", goal: "main" })).normalized_result;
  assert.notEqual(no.goal_status, "reached");
});

test("weak: greet pseudocode contains strcpy and a 32-byte local", { skip: skipReason }, async () => {
  const a = (await ev(provWeak, "analyze_function", { procedure: "greet" })).normalized_result;
  assert.match(a.pseudo_code, /strcpy/);
  assert.match(a.pseudo_code, /char local_\w+ \[32\]/);
  assert.ok(a.decompiler_locals.some((l: any) => l.size === 32 && l.type === "char[32]"));
  assert.ok(a.imports_used.some((i: any) => i.name === "strcpy"));
  assert.ok(snapWeak.functions.some((f) => f.name === "main"));
});

test("unknown procedure gives a clear error", { skip: skipReason }, async () => {
  await assert.rejects(provT.call("procedure_info", { procedure: "no_such_fn" }), (e: any) => e instanceof ProcedureNotFoundError && /Unknown procedure: "no_such_fn"/.test(e.message));
  await assert.rejects(provT.call("procedure_info", { procedure: "0xdeadbeef" }), ProcedureNotFoundError);
  await assert.rejects(provT.call("procedure_info", {}), /procedure is required/);
});

test("CROSS-CHECK against REA's Ghidra results (t2.json)", { skip: skipReason || (!existsSync(T2) && "REA transcript missing") }, async () => {
  const steps = JSON.parse(readFileSync(T2, "utf8")) as any[];
  const res = (step: string) => JSON.parse(steps.find((s) => s.step === step).result.content[0].text);
  const reaProc = res("resolve_containing_procedure").normalized_result.procedure;
  assert.equal(reaProc.address, "0x10125b");
  const main = snapT.functions.find((f) => f.name === "main")!;
  assert.equal(main.entry, reaProc.address);
  assert.deepEqual(main.body, reaProc.body.ranges);
  assert.equal(snapT.functions.find((f) => f.name === "check")!.entry, "0x101229");
  const reaStr = res("search_strings").normalized_result[0];
  const mine = snapT.strings.find((s) => s.value === reaStr.value)!;
  assert.equal(mine.address, reaStr.address);
  assert.deepEqual(mine.xrefs.map((x) => x.from).sort(), [...res("xrefs").normalized_result].sort());
  assert.deepEqual(main.callers.map((c) => c.entry), []);
  assert.deepEqual(snapT.functions.find((f) => f.name === "check")!.callers.map((c) => c.entry), res("procedure_callers").normalized_result);
  assert.equal(snapT.source.sha256, res("open_binary").result.sha256);
});

test("original file hash unchanged and no temp state left", { skip: skipReason }, async () => {
  assert.equal(await sha256File(T), hashT);
  assert.equal(snapT.source.sha256, hashT);
  assert.deepEqual(readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-ghidra-")), []);
});

test("tiny timeout: group killed, no strays, temp dir and copy removed, copy was 0600", { skip: skipReason }, async () => {
  let workDir = "", pid = 0, copyMode = 0, dirMode = 0;
  const t0 = Date.now();
  await assert.rejects(analyzeBinary(T, {
    timeoutMs: 1500,
    onStart: (i) => {
      workDir = i.workDir; pid = i.pid;
      dirMode = statSync(i.workDir).mode & 0o777;
      copyMode = statSync(join(i.workDir, "in", "t")).mode & 0o777;
    },
  }), GhidraTimeoutError);
  assert.ok(Date.now() - t0 < 15000, "returned promptly");
  assert.equal(copyMode, 0o600);
  assert.equal(dirMode, 0o700);
  assert.ok(pid > 0);
  assert.deepEqual(processGroupMembers(pid), []);
  assert.equal(existsSync(workDir), false);
  const ps = (await import("node:child_process")).execFileSync("ps", ["-eo", "args"], { encoding: "utf8" });
  assert.equal(ps.split("\n").some((l) => l.includes(workDir) && workDir !== ""), false);
  assert.equal(await sha256File(T), hashT);
});

test("missing Ghidra install is a clear error", async () => {
  await assert.rejects(analyzeBinary(T, { installDir: "/nonexistent/ghidra" }), GhidraNotFoundError);
  const p = new GhidraProvider({ installDir: "/nonexistent/ghidra" });
  assert.equal(p.supports({ path: T, sha256: "a".repeat(64) }).status, "unavailable");
});

test("failure path (non-binary input) cleans up and reports a failure", { skip: skipReason }, async () => {
  const f = join(SCRATCH, "rtk-notbinary.txt");
  (await import("node:fs")).writeFileSync(f, "plain text, not an executable\n");
  try {
    await assert.rejects(analyzeBinary(f, { timeoutMs: 120000 }), /analyzeHeadless failed|snapshot/);
  } finally { (await import("node:fs")).rmSync(f, { force: true }); }
  assert.deepEqual(readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-ghidra-")), []);
});

test("provider works under the provider-router (binding + evidence)", { skip: skipReason }, async () => {
  const sha256 = await sha256File(T);
  const s = new BinarySession(new Registry([() => new GhidraProvider()]));
  const { binding, evidence } = await s.open({ path: T, sha256, name: "t" }, { provider: "ghidra" });
  assert.equal(binding.provider_id, "ghidra");
  assert.equal(evidence.operation, "bind_provider");
  const e = (await s.call("trace_call_path", { start: "main", goal: "check" })) as any;
  assert.equal(e.provider.id, "rtk-ghidra-bridge");
  assert.equal(e.normalized_result.goal_status, "reached");
  await s.close();
});

// ---- synthetic call-graph tests (no Ghidra needed)
function fakeSnap(): GhidraSnapshot {
  const fn = (entry: string, name: string, callees: string[], indirect = false, external = false) => ({
    entry, name, external, thunk: false, thunk_target: null, signature: name + "()", calling_convention: null, namespace: "Global",
    body: external ? [] : [{ start: entry, end: "0x" + (BigInt(entry) + 15n).toString(16) }], callers: [] as any[], callees: callees.map((c) => ({ entry: c, name: c })),
    call_sites: [], has_unresolved_indirect_calls: indirect, locals: [],
  });
  const fns = [fn("0x10", "a", ["0x20"]), fn("0x20", "b", ["0x30"]), fn("0x30", "c", []), fn("0x40", "d", ["0x30"], true), fn("0x50", "iso", [])];
  for (const f of fns) for (const c of f.callees) { const t = fns.find((x) => x.entry === c.entry)!; t.callers.push({ entry: f.entry, name: f.name }); c.name = t.name; }
  return {
    schema: "rtk-ghidra-snapshot/1", ghidra_version: "x", program: { name: "fake", format: "ELF", language_id: "x", processor: "x", endian: "little", pointer_size: 8, compiler_spec: "gcc", image_base: "0x0", executable_sha256: null, entry_points: [] },
    memory_blocks: [], functions: fns as any, strings: [], strings_truncated: false, externals: [], symbols: [], symbols_truncated: false, decompiled: [], decompile_ms: 0, warnings: [],
    source: { path: "/fake", sha256: "f".repeat(64), size: 1, elapsed_ms: 0, options: {} },
  };
}
test("trace_call_path goal_status semantics on a synthetic graph", async () => {
  const p = new GhidraProvider({ installDir: "/nonexistent", analyze: async () => fakeSnap() });
  await p.open({ path: "/fake", sha256: "f".repeat(64) });
  const st = async (a: Record<string, unknown>) => ((await p.call("trace_call_path", a)) as any).normalized_result;
  assert.deepEqual((await st({ start: "a", goal: "c" })).path.map((x: any) => x.name), ["a", "b", "c"]);
  assert.equal((await st({ start: "a", goal: "c", max_depth: 1 })).goal_status, "unknown"); // depth-limited
  assert.equal((await st({ start: "a", goal: "iso" })).goal_status, "not-reached"); // closed world, no indirect calls visited
  assert.equal((await st({ start: "d", goal: "iso" })).goal_status, "unknown"); // d has an unresolved indirect call
  assert.equal((await st({ start: "c", goal: "a", direction: "backward" })).goal_status, "reached");
  assert.equal((await st({ start: "iso", goal: "a", direction: "backward" })).goal_status, "unknown"); // d's indirect call could reach anything
  await assert.rejects(p.call("trace_call_path", { start: "a", goal: "zzz" }), ProcedureNotFoundError);
  await assert.rejects(p.call("trace_call_path", { start: "a", goal: "c", direction: "sideways" }), /direction/);
  await p.close();
  await assert.rejects(p.call("list_procedures"), /not open/);
});

test("provider rejects an analysed file whose hash differs from the target", async () => {
  const p = new GhidraProvider({ installDir: "/nonexistent", analyze: async () => fakeSnap() });
  await assert.rejects(p.open({ path: "/fake", sha256: "e".repeat(64) }), /does not match target/);
});
