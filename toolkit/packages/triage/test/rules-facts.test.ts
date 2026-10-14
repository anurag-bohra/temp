import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseEvidence, type Evidence } from "@rtk/evidence";
import { applyRules, evaluate, factsFromEvidence, loadRules, score, validateRules, newFacts, addApi } from "../src/index.ts";

const rea = (n: string): Evidence => parseEvidence(JSON.parse(readFileSync(new URL(`./fixtures/rea/${n}.json`, import.meta.url), "utf8")));
const ghidraSession = (): Evidence[] => (JSON.parse(readFileSync(new URL("./fixtures/rea/ghidra-evidence.json", import.meta.url), "utf8")) as unknown[]).map((x) => parseEvidence(x));

test("REA's real Evidence (JS app, .NET, APK, PE resources, pcap, Go, objdump, layout) is authenticated and turned into facts", () => {
  const evs = ["T1-js-v1", "T6-go", "T8-objdump-symbols", "lab-dn-members", "lab-dn-native", "lab-apk-pkg", "lab-pe", "lab-pcap", "T9a-layout-weak"].map(rea);
  const f = factsFromEvidence(evs); const ids = new Set(f.iocs.all().map((i) => i.value));
  assert.ok(ids.has("https://c2.example.invalid/task"), "base64-decoded JS config URL"); assert.ok(f.iocs.all().find((i) => i.value === "https://c2.example.invalid/task")!.decoded_from);
  assert.ok(ids.has("https://c2.example.invalid/stage2"), ".NET ldstr URL");
  assert.ok(f.apis.has("System.Diagnostics.Process::Start"), "managed call edge qualified by declaring type (the prototype missed this)");
  assert.ok(f.apis.has("VirtualAlloc") && f.apis.has("connect") && f.apis.has("ptrace"));
  assert.ok(f.permissions.has("android.permission.SEND_SMS")); assert.ok(f.tags.has("pe-rcdata-resource")); assert.ok(f.features.hardeningWeak);
  assert.ok(f.sinks.some((s) => s.kind === "child-process") && f.sinks.some((s) => s.kind === "eval") && f.sinks.some((s) => s.kind === "network-request"));
  assert.ok([...ids].some((v) => v.startsWith("http://127.0.0.1:8765/beacon")));
});

test("default rules fire on that Evidence and the score band reflects it", () => {
  const evs = ["T1-js-v1", "lab-dn-members", "lab-dn-native", "lab-apk-pkg", "lab-pe", "T8-objdump-symbols"].map(rea);
  const findings = applyRules(loadRules(), factsFromEvidence(evs)); const ids = findings.map((x) => x.rule_id);
  for (const id of ["NET-001", "EXEC-001", "INJ-001", "EVA-001", "EXEC-002", "OBF-001", "MOB-001", "MOB-002", "STG-001", "STG-002", "NET-004", "EXEC-005", "EXEC-006", "NET-003"]) assert.ok(ids.includes(id), `${id} missing; got ${ids.join(",")}`);
  const s = score(findings); assert.equal(s.band, "highly-suspicious"); assert.match(s.note, /not a malware verdict/);
  for (const f of findings) assert.ok(f.evidence_ids.every((e) => /^ev_[0-9a-f]{64}$/u.test(e)) && f.basis.includes("not a verdict"));
});

test("Ghidra-backed REA session Evidence contributes imports and the C2 string", () => {
  const f = factsFromEvidence(ghidraSession()); assert.ok(f.apis.has("ptrace") && f.apis.has("dup2")); assert.ok(f.iocs.all().some((i) => i.kind === "ipv4" && i.value === "198.51.100.7"));
});

test("rule DSL: all/any/not, validation rejects bad rules, rare cases", () => {
  const f = newFacts(); addApi(f, "connect", "ev_" + "1".repeat(64)); addApi(f, "dup2", "ev_" + "2".repeat(64));
  assert.equal(evaluate({ all: [{ api_any: ["connect"] }, { api_any: ["dup2"] }] }, f).matched, true);
  assert.equal(evaluate({ not: { api_any: ["connect"] } }, f).matched, false); assert.equal(evaluate({ any: [{ api_any: ["nope"] }, { api_all: ["connect", "dup2"] }] }, f).evidence_ids.length, 2);
  assert.throws(() => validateRules({ rules: [{ id: "x", severity: "high", when: { bogus: 1 } }] }), /invalid condition/);
  assert.throws(() => validateRules({ rules: [{ id: "x", severity: "extreme", when: { api_any: [] } }] }), /bad severity/);
  assert.throws(() => validateRules({ rules: [{ id: "x", severity: "low", when: { api_any: [] } }, { id: "x", severity: "low", when: { api_any: [] } }] }), /duplicate/);
  assert.equal(applyRules(loadRules(), newFacts()).length, 0); assert.equal(score([]).band, "no-suspicious-indicators-observed");
});

test("scoring has diminishing returns within a tactic", () => {
  const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ rule_id: `R${i}`, title: "t", tactic: "execution", attack: [], severity: "high" as const, detail: [], evidence_ids: [], basis: "static-indicator-match (not a verdict)" as const }));
  assert.equal(score(mk(1)).score, 6); assert.equal(score(mk(3)).score, 12); // 6 + 3 + 3
});
