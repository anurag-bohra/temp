import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ANOMALY_CODES } from "@rtk/artifacts";
import { loadRules, triageSample, registeredAnalyzers, type Cond } from "../src/index.ts";

const fx = (n: string) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
const ids = (r: { findings: { rule_id: string }[] }) => r.findings.map((f) => f.rule_id);
const haveGhidra = existsSync(`${process.env.GHIDRA_INSTALL_DIR ?? "/opt/lab/ghidra_12.1.4_PUBLIC"}/support/analyzeHeadless`);
const haveDotnet = (() => { try { execFileSync("dotnet", ["--version"]); return true; } catch { return false; } })();

test("all analyzers are registered", () => { for (const a of ["static-features", "yara", "js-analyzer", "dotnet-analyzer", "archive-inspect", "archive-recurse", "ghidra", "sandbox"]) assert.ok(registeredAnalyzers().includes(a), a); });

test("every anomaly name used by a rule is a real @rtk/artifacts anomaly code", () => {
  const used: string[] = []; const walk = (c: Cond) => { if ("anomaly_any" in c) used.push(...c.anomaly_any); if ("all" in c) c.all.forEach(walk); if ("any" in c) c.any.forEach(walk); if ("not" in c) walk(c.not); };
  for (const r of loadRules().rules) walk(r.when); assert.ok(used.length > 5); assert.deepEqual(used.filter((u) => !(u in ANOMALY_CODES)), []);
});

test("JavaScript/Electron app: taint flows, web preferences and decoded C2 URL drive the findings; patched version is quieter", async () => {
  const v1 = await triageSample(fx("jsapp")); const f1 = ids(v1);
  for (const id of ["EXEC-003", "EXEC-004", "ELE-001", "OBF-001", "NET-001", "NET-004"]) assert.ok(f1.includes(id), `${id} in ${f1}`);
  assert.ok(v1.iocs.some((i) => i.value === "https://c2.example.invalid/task" && i.decoded_from)); assert.ok(v1.ran.includes("js-analyzer"));
  const v2 = await triageSample(fx("jsapp2")); const f2 = ids(v2); assert.equal(f2.includes("EXEC-003"), false, "sender-validated allow-listed handler no longer taints exec"); assert.equal(f2.includes("ELE-001"), false);
  assert.ok(v2.score.score < v1.score.score, `${v2.score.score} < ${v1.score.score}`);
});

test(".NET stager: managed analyzer drives Process::Start, P/Invoke VirtualAlloc, download-then-execute and base64 findings", { skip: !haveDotnet && "dotnet not installed", timeout: 300000 }, async () => {
  const r = await triageSample(fx("Stager.dll")); const f = ids(r);
  for (const id of ["EXEC-001", "INJ-001", "NET-004", "OBF-001", "STG-002", "NET-001"]) assert.ok(f.includes(id), `${id} in ${f}`); assert.ok(r.ran.includes("dotnet-analyzer"));
  assert.ok(r.iocs.some((i) => i.value === "https://c2.example.invalid/stage2"));
});

test("archive: inventory + recursive triage of members; APK passes through", async () => {
  const z = await triageSample(fx("sample.zip"), { depth: 1 }); assert.ok(z.ran.includes("archive-inspect") && z.ran.includes("archive-recurse")); assert.ok(z.evidence.some((e) => e.operation === "triage_archive_children"));
  assert.ok(z.iocs.some((i) => i.value === "https://c2.example.invalid/task"), "IOC found in a member of the zip (JS member analysed as JavaScript)");
  const a = await triageSample(fx("demo.apk")); assert.ok(a.ran.includes("archive-inspect")); assert.equal(a.identity.type, "apk");
});

test("malicious archive (zip-slip + symlink escape + absolute path) is flagged and nothing is extracted outside the scratch dir", async () => {
  const dir = mkdtempSync(join(tmpdir(), "rtk-evilzip-")); const zip = join(dir, "evil.zip");
  execFileSync("python3", ["-c", `import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1],'w')\nz.writestr('../../escape.txt','x')\nz.writestr('/abs/evil.txt','y')\ni=zipfile.ZipInfo('link'); i.create_system=3; i.external_attr=0o120777<<16; z.writestr(i,'/etc/passwd')\nz.writestr('ok.txt','fine')\nz.close()`, zip]);
  const r = await triageSample(zip, { depth: 1 }); assert.ok(ids(r).includes("ARC-001"), `got ${ids(r)}`); assert.equal(existsSync(join(dir, "..", "escape.txt")), false); assert.equal(existsSync("/abs/evil.txt"), false);
});

test("deep mode adds Ghidra-derived imports/strings (opt-in)", { skip: !haveGhidra && "Ghidra not installed", timeout: 300000 }, async () => {
  const r = await triageSample(fx("c2like.elf"), { deep: true }); assert.ok(r.ran.includes("ghidra")); assert.ok(r.facts.tags.has("ghidra")); assert.ok(r.findings.some((f) => f.rule_id === "EXEC-002"));
});

test("sandbox analyzer is denied by static-analysis, and runs (namespace isolation) only with lab-vm + explicit approval", { timeout: 120000 }, async () => {
  const denied = await triageSample(fx("c2like.elf"), { detonate: true }); assert.ok(denied.skipped.some((s) => s.analyzer === "sandbox" && /denied/u.test(s.reason))); assert.equal(denied.ran.includes("sandbox"), false);
  const asked = await triageSample(fx("c2like.elf"), { detonate: true, profile: "lab-vm" }); assert.ok(asked.skipped.some((s) => s.analyzer === "sandbox" && /needs approval/u.test(s.reason)));
  const dir = mkdtempSync(join(tmpdir(), "rtk-sbx-")); const copy = join(dir, "sample"); execFileSync("cp", [fx("c2like.elf"), copy]); execFileSync("chmod", ["755", copy]); writeFileSync(join(dir, ".keep"), "");
  const ran = await triageSample(copy, { detonate: true, profile: "lab-vm", approve: ["sandbox"] });
  if (!ran.ran.includes("sandbox")) { assert.ok(ran.skipped.some((s) => s.analyzer === "sandbox")); return; } // host without usable isolation: reported, not hidden
  assert.ok(ran.facts.tags.has("sandbox-ran")); const ev = ran.evidence.find((e) => e.operation === "run_sandboxed")!; assert.equal(ev.authority, "controlled-replay"); assert.notEqual(ev.environment?.isolation, "virtual-machine");
});
