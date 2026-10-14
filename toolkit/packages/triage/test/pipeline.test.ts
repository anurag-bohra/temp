import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, copyFileSync, mkdtempSync, readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseBundle, sha256Hex } from "@rtk/evidence";
import { CaseStore, defang, registeredAnalyzers, toCsv, toMarkdown, toMisp, toStix, triageSample, writeCase } from "../src/index.ts";

const fx = (n: string) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
const yaraRules = new URL("../../../../docs/deep-dive/prototype/rea-triage/demo-rules.yar", import.meta.url).pathname;
const haveYara = (() => { try { execFileSync("yara", ["--version"]); return true; } catch { return false; } })();

test("static triage of the C2-like ELF: findings, indicators, evidence links, deterministic bundle", async () => {
  const r = await triageSample(fx("c2like.elf"), { now: () => new Date("2026-01-01T00:00:00Z") });
  const ids = r.findings.map((f) => f.rule_id); for (const id of ["EXEC-002", "EVA-001", "NET-002", "NET-001"]) assert.ok(ids.includes(id), `${id} in ${ids}`);
  assert.ok(r.iocs.some((i) => i.kind === "ipv4" && i.value === "198.51.100.7" && i.classification === "documentation"));
  assert.ok(["suspicious", "highly-suspicious"].includes(r.score.band), r.score.band);
  assert.deepEqual(r.ran, ["static-features"]); assert.equal(r.triageEvidence.operation, "triage_sample");
  const links = (r.triageEvidence.evidence_links as { evidence_id: string }[]).map((l) => l.evidence_id); assert.ok(links.length >= 1 && links.every((l) => r.evidence.some((e) => e.evidence_id === l)));
  const again = await triageSample(fx("c2like.elf"), { now: () => new Date("2026-01-01T00:00:00Z") }); assert.equal(again.bundle.sha256, r.bundle.sha256); // same input -> same bundle bytes
  assert.equal(parseBundle(r.bundle.text).records.length, r.evidence.length);
});

test("weak-hardening ELF reports the hardening finding and no execution findings; hardened differs", async () => {
  const w = await triageSample(fx("vuln-weak.elf")); assert.ok(w.findings.some((f) => f.rule_id === "HRD-001")); assert.equal(w.findings.some((f) => f.tactic === "execution"), false);
  const h = await triageSample(fx("vuln-hard.elf")); assert.equal(h.findings.some((f) => f.rule_id === "HRD-001"), false);
});

test("PE: imports become API facts (VirtualAlloc => INJ-001) and imphash is recorded", async () => {
  const r = await triageSample(fx("demo.exe")); assert.ok(r.findings.some((f) => f.rule_id === "INJ-001")); assert.match(String(r.facts.features.imphash), /^[0-9a-f]{32}$/u);
});

test("policy profiles gate analyzers: locked skips YARA with a reason; static-analysis runs it", { skip: !haveYara && "yara not installed" }, async () => {
  const locked = await triageSample(fx("c2like.elf"), { profile: "locked", yaraRules }); assert.ok(locked.skipped.some((s) => s.analyzer === "yara" && /policy locked: denied/u.test(s.reason))); assert.equal(locked.ran.includes("yara"), false);
  const st = await triageSample(fx("c2like.elf"), { profile: "static-analysis", yaraRules }); assert.ok(st.ran.includes("yara")); assert.ok(st.findings.some((f) => f.rule_id === "SIG-001" && f.detail.some((d) => d.includes("demo_c2_like_elf"))));
});

test("unknown profile rejects", async () => { await assert.rejects(triageSample(fx("c2like.elf"), { profile: "nope" }), /unknown policy profile/); });

test("case writer: all outputs present, manifest hashes verify, STIX/MISP/CSV/Markdown are well formed", async () => {
  const r = await triageSample(fx("c2like.elf"), { now: () => new Date("2026-01-01T00:00:00Z") }); const dir = mkdtempSync(join(tmpdir(), "rtk-case-")); const w = writeCase(r, dir);
  assert.deepEqual(readdirSync(dir).sort(), ["evidence-bundle.json", "iocs.csv", "manifest.json", "misp.json", "report.json", "report.md", "stix.json"]);
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as { files: Record<string, string>; evidence_bundle_sha256: string };
  for (const [n, h] of Object.entries(manifest.files)) assert.equal(sha256Hex(readFileSync(join(dir, n))), h, n); assert.equal(manifest.evidence_bundle_sha256, sha256Hex(readFileSync(join(dir, "evidence-bundle.json"))));
  parseBundle(readFileSync(join(dir, "evidence-bundle.json"), "utf8")); assert.ok(w.files["report.md"]);
  const stix = JSON.parse(readFileSync(join(dir, "stix.json"), "utf8")) as { type: string; objects: { type: string; id: string; pattern?: string; spec_version: string }[] };
  assert.equal(stix.type, "bundle"); assert.ok(stix.objects.every((o) => o.spec_version === "2.1" || o.type === "bundle")); assert.ok(stix.objects.some((o) => o.type === "indicator" && o.pattern!.includes(r.identity.sha256)));
  assert.equal(stix.objects.some((o) => o.pattern?.includes("198.51.100.7")), false, "documentation-range IPs are not exported as indicators by default");
  const misp = JSON.parse(readFileSync(join(dir, "misp.json"), "utf8")) as { Event: { Attribute: { type: string; value: string; to_ids: boolean }[] } }; assert.ok(misp.Event.Attribute.some((a) => a.type === "sha256" && a.value === r.identity.sha256 && a.to_ids));
  assert.ok(misp.Event.Attribute.some((a) => a.type === "ip-dst" && a.value === "198.51.100.7" && a.to_ids === false));
  const md = readFileSync(join(dir, "report.md"), "utf8"); assert.match(md, /not verdicts/u); assert.ok(md.includes("198[.]51[.]100[.]7")); assert.equal(md.includes("`198.51.100.7`"), false, "markdown IOCs are defanged");
  assert.equal(toCsv([{ kind: "url", value: "=HYPERLINK(\"http://x\")", classification: "unknown", contexts: ["c"], evidence_ids: [] }]).split("\n")[1]!.startsWith("url,\"'="), true);
});

test("STIX output parses with the reference python `stix2` library when available", async () => {
  const r = await triageSample(fx("c2like.elf")); const rep = { ...r.report, iocs: [...r.report.iocs, { kind: "domain" as const, value: "evil.example.org", classification: "public" as const, contexts: ["t"], evidence_ids: [r.evidence[0]!.evidence_id] }, { kind: "url" as const, value: "http://203.0.113.9/x?a=b'c", classification: "public" as const, contexts: ["t"], evidence_ids: [] }] };
  const probe = spawnSync("python3", ["-c", "import stix2"]); if (probe.status !== 0) return;
  const out = spawnSync("python3", ["-c", "import sys,json,stix2; b=stix2.parse(sys.stdin.read(), allow_custom=True); print(len(b.objects))"], { input: JSON.stringify(toStix(rep, { includeNonRoutable: true })) });
  assert.equal(out.status, 0, String(out.stderr)); assert.ok(Number(String(out.stdout).trim()) >= 5);
});

test("case store: persists evidence, pivots shared IOCs across samples, exports a bundle that re-parses", async () => {
  const store = new CaseStore(); const dir = mkdtempSync(join(tmpdir(), "rtk-store-")); const copy = join(dir, "variant.elf"); copyFileSync(fx("c2like.elf"), copy); appendFileSync(copy, Buffer.from("padding-to-change-the-hash"));
  const a = await triageSample(fx("c2like.elf"), { store }); const b = await triageSample(copy, { store });
  assert.notEqual(a.identity.sha256, b.identity.sha256); assert.equal(store.samples().length, 2);
  const shared = store.sharedIocs(); const hit = shared.find((s) => s.kind === "ipv4" && s.value === "198.51.100.7"); assert.ok(hit && hit.samples.length === 2);
  assert.deepEqual(store.samplesWithIoc("ipv4", "198.51.100.7").sort(), [a.identity.sha256, b.identity.sha256].sort());
  const ex = store.exportBundle(a.identity.sha256); assert.equal(parseBundle(ex.text).records.length, a.evidence.length); assert.ok(store.findingsFor(a.identity.sha256).length > 0);
  store.close();
});

test("analyzer registry exposes the built-ins", () => { for (const id of ["static-features", "yara"]) assert.ok(registeredAnalyzers().includes(id)); assert.equal(defang("http://a.b"), "hxxp://a[.]b"); assert.equal(typeof toMarkdown, "function"); assert.equal(typeof toMisp, "function"); assert.ok(!existsSync("/nonexistent")); void writeFileSync; });
