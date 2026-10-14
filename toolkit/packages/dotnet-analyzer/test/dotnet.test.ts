import { test, before } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, truncateSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compareManagedAssemblies, deriveIndicators, dotnetAvailable, dotnetEnv, inspectManagedAssembly, managedResultOf, NotManagedError } from "../src/index.ts";
import type { ManagedResult } from "../src/index.ts";
import { parseEvidence } from "@rtk/evidence";

const SCRATCH = "/tmp/claude-0/-home-user-temp/b1154f5f-19b6-591b-8a67-cb57e20a5c77/scratchpad/samples";
const DN_SRC = join(SCRATCH, "dn");
const PREBUILT = join(DN_SRC, "out/Stager.dll");
const DEMO_EXE = join(SCRATCH, "pe/demo.exe");
const REA_JSON = "/home/user/temp/docs/deep-dive/manual-tests/outputs/lab-dn-members.json";
const SKIP = !dotnetAvailable() ? "dotnet SDK not available" : !existsSync(join(DN_SRC, "Program.cs")) ? "dn sample sources not available" : false;

const work = SKIP ? "" : mkdtempSync(join(tmpdir(), "rtk-dn-test-"));
function build(name: string, patch?: (src: string) => string): string {
  const dir = join(work, name); mkdirSync(dir, { recursive: true });
  const src = readFileSync(join(DN_SRC, "Program.cs"), "utf8");
  writeFileSync(join(dir, "Program.cs"), patch ? patch(src) : src);
  copyFileSync(join(DN_SRC, "Stager.csproj"), join(dir, "Stager.csproj"));
  const r = spawnSync("dotnet", ["build", "-c", "Release", "-o", join(dir, "out"), "--nologo", "-v", "q"], { cwd: dir, env: dotnetEnv(), encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  return join(dir, "out", "Stager.dll");
}
let base: string, litVariant: string, pinvVariant: string;
before(() => {
  if (SKIP) return;
  base = build("base");
  litVariant = build("lit", (s) => s.replace("stage2", "stage9")); // same length: IL bytes identical, only #US heap differs
  pinvVariant = build("pinv", (s) => s.replace("uint t, uint p); }", 'uint t, uint p); [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr f, IntPtr p, uint fl, IntPtr id); }'));
});

test("Stager.dll: identity, literals attributed to Loader.Main, edges, P/Invoke, indicators", { skip: SKIP }, async () => {
  const ev = await inspectManagedAssembly(base);
  parseEvidence(JSON.parse(JSON.stringify(ev)));
  assert.equal(ev.operation, "inspect_managed_assembly"); assert.equal(ev.provider.id, "rtk-dotnet-analyzer");
  const r = managedResultOf(ev);
  assert.equal(r.identity.name, "Stager"); assert.match(r.identity.mvid, /^[0-9a-f-]{36}$/u);
  assert.equal(r.target_framework, ".NETCoreApp,Version=v8.0");
  assert.ok(r.assembly_references.some((a) => a.name === "System.Net.Http"));
  assert.deepEqual(r.module_references, ["kernel32.dll"]);
  const main = r.methods.find((m) => m.full_name.startsWith("Demo.Stager.Loader::Main"))!;
  assert.deepEqual(main.literals, ["https://c2.example.invalid/stage2", "cmd.exe", "/c "]);
  assert.match(main.il_sha256!, /^[0-9a-f]{64}$/u); assert.ok(main.il_length > 0);
  assert.ok(r.user_string_literals.some((l) => l.value === "cmd.exe"));
  assert.ok(r.call_edges.some((e) => e.caller.startsWith("Demo.Stager.Loader::Main") && e.target.startsWith("System.Diagnostics.Process::Start(")));
  assert.ok(r.call_edges.some((e) => e.caller.startsWith("Demo.Stager.Loader::Decode") && e.target_type === "System.Convert" && e.target_name === "FromBase64String"));
  const pi = r.pinvokes.find((p) => p.entry_point === "VirtualAlloc")!;
  assert.equal(pi.dll, "kernel32.dll"); assert.match(pi.declaring_method, /^Demo\.Stager\.Native::VirtualAlloc\(/u);
  const ids = new Set(r.indicators.map((i) => i.id));
  for (const id of ["process-start", "http-client", "base64-decode", "pinvoke-virtualalloc"]) assert.ok(ids.has(id), id);
  assert.ok(r.indicators.find((i) => i.id === "process-start")!.method.startsWith("Demo.Stager.Loader::Main"));
  assert.ok(r.indicators.find((i) => i.id === "base64-decode")!.method.startsWith("Demo.Stager.Loader::Decode"));
});

test("cross-check against REA's inspect_managed_members output (same literals, same call targets, same methods)", { skip: SKIP || !existsSync(REA_JSON) || !existsSync(PREBUILT) }, async () => {
  const rea = JSON.parse(readFileSync(REA_JSON, "utf8")).normalized_result;
  const r = managedResultOf(await inspectManagedAssembly(PREBUILT)); // the very binary REA analysed (rebuilds get a new MVID)
  assert.deepEqual(r.user_string_literals.map((l) => l.value), rea.user_strings.literals.map((l: { value: string }) => l.value));
  assert.deepEqual(r.user_string_literals.map((l) => l.token), rea.user_strings.literals.map((l: { token: string }) => l.token));
  const mine = r.methods.map((m) => `${m.declaring_type}.${m.name}`).sort();
  assert.deepEqual(mine, rea.methods.map((m: { declaring_type: string; name: string }) => `${m.declaring_type}.${m.name}`).sort());
  const norm = (caller: string, opcode: string, ty: string, name: string) => `${caller.replace(/\(.*$/u, "").replace("::", ".")} ${opcode} ${ty} ${name}`;
  const a = r.call_edges.map((e) => norm(e.caller, e.opcode, e.target_type!.replace(/<.*$/u, ""), e.target_name!)).sort();
  const b = rea.call_edges.map((e: { caller: string; opcode: string; target_declaring_type: string; target_name: string }) => norm(e.caller, e.opcode, e.target_declaring_type, e.target_name)).sort();
  assert.deepEqual(a, b);
  assert.equal(r.identity.mvid, rea.module.mvid); assert.equal(r.artifact.sha256, rea.artifact.sha256);
  assert.equal(r.pinvokes.length, 1);
});

test("literal-only change: compare() flags it; IL-hash-only comparison calls the method unchanged", { skip: SKIP }, async () => {
  const a = await inspectManagedAssembly(base), b = await inspectManagedAssembly(litVariant);
  const ra = managedResultOf(a), rb = managedResultOf(b);
  const key = (r: ManagedResult) => r.methods.find((m) => m.full_name.startsWith("Demo.Stager.Loader::Main"))!;
  // demonstrate: IL hashes equal, so an IL-hash-only diff (like REA's compare-managed-members) sees nothing in Main
  assert.equal(key(ra).il_sha256, key(rb).il_sha256);
  assert.notEqual(ra.artifact.sha256, rb.artifact.sha256);
  const ilOnlyChanged = ra.methods.filter((m) => rb.methods.find((n) => n.full_name === m.full_name)!.il_sha256 !== m.il_sha256);
  assert.equal(ilOnlyChanged.length, 0, "IL-hash-only comparison reports no changed methods");
  const cmp = compareManagedAssemblies(a, b);
  const n = cmp.normalized_result as any;
  assert.equal(n.identical, false);
  const main = n.methods.changed.find((c: any) => c.method.startsWith("Demo.Stager.Loader::Main"));
  assert.ok(main); assert.equal(main.literal_changed, true); assert.equal(main.il_changed, false);
  assert.deepEqual(main.literals_removed, ["https://c2.example.invalid/stage2"]);
  assert.deepEqual(main.literals_added, ["https://c2.example.invalid/stage9"]);
  assert.ok(n.methods.literal_changed_il_unchanged.some((m: string) => m.startsWith("Demo.Stager.Loader::Main")));
  assert.ok(n.il_hash_only_view.hides_literal_changes_in.length >= 1);
  assert.deepEqual(n.literals.assembly_added, ["https://c2.example.invalid/stage9"]);
  assert.deepEqual(n.pinvokes.added, []);
  parseEvidence(JSON.parse(JSON.stringify(cmp)));
  assert.ok(compareManagedAssemblies(a, a).normalized_result && (compareManagedAssemblies(a, a).normalized_result as any).identical === true);
});

test("added CreateRemoteThread P/Invoke is reported as added method, P/Invoke diff and indicator", { skip: SKIP }, async () => {
  const a = await inspectManagedAssembly(base), b = await inspectManagedAssembly(pinvVariant);
  const n = compareManagedAssemblies(a, b).normalized_result as any;
  assert.ok(n.pinvokes.added.some((s: string) => s.startsWith("kernel32.dll!CreateRemoteThread")));
  assert.ok(n.methods.added.some((m: string) => m.includes("CreateRemoteThread")));
  assert.ok(n.indicators.added.some((s: string) => s.startsWith("pinvoke-createremotethread")));
  assert.deepEqual(n.pinvokes.removed, []);
});

test("non-.NET PE is rejected as not managed with a clear reason", { skip: SKIP || !existsSync(DEMO_EXE) }, async () => {
  const ev = await inspectManagedAssembly(DEMO_EXE);
  const n = ev.normalized_result as any;
  assert.equal(n.managed, false); assert.match(n.reason, /no CLI header/u);
  assert.equal(ev.subject!.digest.sha256, n.artifact.sha256);
  await assert.rejects(inspectManagedAssembly(DEMO_EXE, { requireManaged: true }), NotManagedError);
  assert.throws(() => compareManagedAssemblies(ev, ev), NotManagedError);
});

test("truncated, garbage and empty files do not crash", { skip: SKIP }, async () => {
  const full = readFileSync(base); let partial = 0, rejected = 0;
  for (let n = 100; n < full.length; n += 100) { // every truncation point must yield a valid Evidence record, never a crash
    const t = join(work, `trunc-${n}.dll`); writeFileSync(t, full.subarray(0, n));
    const ev = await inspectManagedAssembly(t); parseEvidence(JSON.parse(JSON.stringify(ev)));
    const r = ev.normalized_result as any;
    if (!r.managed) { rejected++; assert.match(r.reason, /invalid|truncated|CLI|metadata|PE/u); }
    else if (r.issues.length > 0) { partial++; assert.equal(ev.confidence, "derived"); assert.ok(ev.limitations.some((l) => l.startsWith("PARTIAL"))); }
  }
  assert.ok(rejected > 0, "some truncations are rejected with a reason");
  assert.ok(partial > 0, "some truncations are reported as partial with issues");
  const g = join(work, "garbage.bin"); writeFileSync(g, Buffer.concat([Buffer.from("MZ"), Buffer.alloc(300, 0xff)]));
  assert.equal(((await inspectManagedAssembly(g)).normalized_result as any).managed, false);
  const z = join(work, "empty"); writeFileSync(z, "");
  assert.equal(((await inspectManagedAssembly(z)).normalized_result as any).managed, false);
  const txt = join(work, "t.txt"); writeFileSync(txt, "hello");
  assert.match(((await inspectManagedAssembly(txt)).normalized_result as any).reason, /not a PE/u);
});

test("timeout kills the helper", { skip: SKIP }, async () => {
  await assert.rejects(inspectManagedAssembly(base, { timeoutMs: 1 }), /timed out/u);
});

test("deriveIndicators rules (pure)", () => {
  const ind = deriveIndicators(
    [{ caller: "A::M()", opcode: "call", target: "System.Reflection.Assembly::Load(System.Byte[])" }, { caller: "A::M()", opcode: "callvirt", target: "System.Net.WebClient::DownloadString(System.String)" },
     { caller: "A::M()", opcode: "call", target: "System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer(System.IntPtr,System.Type)" }],
    [{ entry_point: "CreateRemoteThread", dll: "kernel32.dll", declaring_method: "N::C()" }]);
  assert.deepEqual(ind.map((i) => i.id).sort(), ["assembly-load", "delegate-from-fnptr", "pinvoke-createremotethread", "web-client"]);
});
