import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildBundle, canonicalJson, createEvidence, EvidenceLedger, parseBundle, parseEvidence, serializeBundle } from "../src/index.ts";

const fixture = readFileSync(new URL("./fixtures/rea-bundle.json", import.meta.url), "utf8");

test("canonicalJson sorts keys, drops undefined, nulls undefined array items", () => {
  assert.equal(canonicalJson({ b: 1, a: [undefined, { z: 1, y: undefined }], c: "é" }), '{"a":[null,{"z":1}],"b":1,"c":"é"}');
  assert.throws(() => canonicalJson({ n: NaN }));
  const circ: Record<string, unknown> = {}; circ.self = circ; assert.throws(() => canonicalJson(circ), /Circular/);
});

test("every Evidence ID in a REA-exported bundle is reproduced by this implementation", () => {
  const raw = JSON.parse(fixture) as { records: unknown[] };
  assert.equal(raw.records.length, 26);
  for (const r of raw.records) parseEvidence(r); // throws on any ID mismatch
});

test("tampering with content is detected", () => {
  const raw = JSON.parse(fixture) as { records: Record<string, unknown>[] };
  const r = structuredClone(raw.records[0]!); (r.limitations as string[]).push("tampered");
  assert.throws(() => parseEvidence(r), /ID mismatch/);
});

test("bundle import/export is byte-identical to REA's own export (canonical, sorted, derived collections)", () => {
  const b = parseBundle(fixture);
  const rebuilt = buildBundle({ records: b.records, unknowns: b.unknowns, providers: b.providers as never, artifacts: b.artifacts as never, captures: b.captures, environments: b.environments, scenarios: b.scenarios });
  assert.equal(serializeBundle(rebuilt), fixture);
});

test("createEvidence is deterministic and the ledger deduplicates identical content", () => {
  const mk = () => createEvidence({
    subject: { name: "x", digest: { sha256: "a".repeat(64) }, local_path: "/tmp/x", format: "elf", architecture: "x86_64" },
    provider: { id: "rtk-test", name: "test", version: "1" }, predicate_type: "rtk.test", operation: "demo",
    parameters: { a: 1 }, normalized_result: { ok: true }, confidence: "observed", authority: "shipped-artifact", limitations: ["demo"],
  });
  const a = mk(), b = mk(); assert.equal(a.evidence_id, b.evidence_id);
  const led = new EvidenceLedger(); led.add(a); led.add(b);
  assert.equal(led.size, 1); assert.equal(led.query({ operation: "demo" }).length, 1);
  assert.equal(led.summary().by_confidence.observed, 1);
});

test("ledger summary and filters work over the real REA records", () => {
  const led = new EvidenceLedger(); for (const r of parseBundle(fixture).records) led.add(r);
  assert.equal(led.size, 26);
  const s = led.summary(); assert.ok(s.by_operation.analyze_function !== undefined || Object.keys(s.by_operation).length > 3);
  assert.equal(s.subjects.length >= 1, true);
});
