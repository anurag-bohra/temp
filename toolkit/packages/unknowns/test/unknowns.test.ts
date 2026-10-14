import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createEvidence, EvidenceLedger, parseBundle } from "@rtk/evidence";
import { evidenceQualifies, parseUnknown, RevisionConflict, stableUnknownId, UnknownRegistry } from "../src/index.ts";

const bundle = parseBundle(readFileSync(new URL("../../evidence/test/fixtures/rea-bundle.json", import.meta.url), "utf8"));
const sha = "c".repeat(64);
const ev = (over: Partial<Parameters<typeof createEvidence>[0]> = {}) => createEvidence({
  subject: { name: "t", digest: { sha256: sha }, local_path: null, format: "elf", architecture: "x86_64" },
  provider: { id: "x", name: "x", version: "1" }, predicate_type: "p", operation: "o", parameters: {}, normalized_result: { n: Math.random() },
  confidence: "observed", authority: "shipped-artifact", ...over });

test("REA-exported unknown validates (id, revision digest, invariants) with this implementation", () => {
  const u = parseUnknown(bundle.unknowns[0]);
  assert.equal(u.unknown_id, stableUnknownId(u.question, u.domain, u.scope_digest));
});
test("tampered unknown is rejected", () => {
  const u = structuredClone(bundle.unknowns[0] as Record<string, unknown>); u.severity = "critical";
  assert.throws(() => parseUnknown(u), /digest mismatch/);
});

test("lifecycle: record -> update with optimistic concurrency -> revisions chain", () => {
  const reg = new UnknownRegistry();
  const u1 = reg.record({ question: "Is the C2   address overridden at runtime?", domain: "protocol", severity: "medium", scope_digest: sha, required_authority: "controlled-replay" });
  assert.equal(u1.revision, 1); assert.equal(u1.status, "open");
  assert.equal(stableUnknownId("Is the C2 address overridden at runtime?", "protocol", sha), u1.unknown_id); // whitespace-normalised identity
  const u2 = reg.update({ unknown_id: u1.unknown_id, expected_revision: 1, status: "investigating" });
  assert.equal(u2.previous_revision_digest, u1.revision_digest);
  assert.throws(() => reg.update({ unknown_id: u1.unknown_id, expected_revision: 1, status: "blocked" }), RevisionConflict);
  assert.equal(reg.history(u1.unknown_id).length, 2); assert.equal(reg.open().length, 1);
  assert.throws(() => reg.record({ question: "Is the C2 address overridden at runtime?", domain: "protocol", severity: "low", scope_digest: sha }), /already exists/);
});

test("a controlled-replay unknown cannot be closed by static (shipped-artifact) evidence; replay evidence can", () => {
  const reg = new UnknownRegistry();
  const u = reg.record({ question: "Does the sample beacon?", domain: "behavior", severity: "high", required_authority: "controlled-replay", required_confidence: "observed", required_environment: { id: null, platform: "linux", architecture: null, isolation: "virtual-machine" } });
  const staticEv = reg.ledger.add(ev());
  assert.throws(() => reg.update({ unknown_id: u.unknown_id, expected_revision: 1, status: "resolved", resolution: { disposition: "verified", rationale: "strings show a URL", evidence_ids: [staticEv.evidence_id] } }), /does not qualify/);
  const processEv = reg.ledger.add(ev({ authority: "controlled-replay", environment: { id: "linux-x64", platform: "linux", architecture: "x64", isolation: "process" } }));
  assert.throws(() => reg.update({ unknown_id: u.unknown_id, expected_revision: 1, status: "resolved", resolution: { disposition: "verified", rationale: "ran it", evidence_ids: [processEv.evidence_id] } }), /isolation process < required virtual-machine/);
  const vmEv = reg.ledger.add(ev({ authority: "controlled-replay", environment: { id: "lab", platform: "linux", architecture: "x64", isolation: "virtual-machine" } }));
  const done = reg.update({ unknown_id: u.unknown_id, expected_revision: 1, status: "resolved", resolution: { disposition: "verified", rationale: "replayed in VM", evidence_ids: [vmEv.evidence_id] } });
  assert.equal(done.status, "resolved"); assert.deepEqual(reg.verifyResolution(u.unknown_id), { ok: true, problems: [] });
});

test("withdrawn/out-of-scope need no qualifying evidence; resolved requires a resolution; unknown evidence IDs are rejected", () => {
  const reg = new UnknownRegistry(); const u = reg.record({ question: "Q1", domain: "d", severity: "low" });
  assert.throws(() => reg.update({ unknown_id: u.unknown_id, expected_revision: 1, status: "resolved" }), /requires a resolution/);
  assert.throws(() => reg.update({ unknown_id: u.unknown_id, expected_revision: 1, supporting_evidence_ids: ["ev_" + "0".repeat(64)] }), /not in ledger/);
  const w = reg.update({ unknown_id: u.unknown_id, expected_revision: 1, status: "resolved", resolution: { disposition: "withdrawn", rationale: "not relevant", evidence_ids: [] } });
  assert.equal(w.resolution?.disposition, "withdrawn"); assert.equal(reg.verifyResolution(u.unknown_id).ok, false);
});

test("evidenceQualifies: confidence ordering", () => {
  const e = ev({ confidence: "derived" });
  assert.equal(evidenceQualifies({ required_authority: null, required_confidence: "inferred", required_environment: null }, e).ok, true);
  assert.equal(evidenceQualifies({ required_authority: null, required_confidence: "observed", required_environment: null }, e).ok, false);
});

test("heads import from a REA bundle and re-export", () => {
  const reg = new UnknownRegistry(new EvidenceLedger()); reg.importHeads(bundle.unknowns);
  assert.equal(reg.list().length, 1); assert.equal(reg.exportHeads()[0]!.revision, 1);
});
