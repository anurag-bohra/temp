import { test } from "node:test";
import assert from "node:assert/strict";
import { Registry, BinarySession, ProviderSelectionError, RegistryConfigError, SessionStateError, SnapshotIdentityError, OperationRoutingError } from "../src/index.ts";
import type { AnalysisProvider, Target, ProviderSupport } from "../src/index.ts";
import { parseEvidence } from "@rtk/evidence";

const sha = (c: string) => c.repeat(64);
const T1: Target = { path: "/x/a", sha256: sha("a"), format: "ELF" };
const T2: Target = { path: "/x/b", sha256: sha("b"), format: "PE" };

function fake(id: string, o: { kind?: "deep" | "auxiliary"; ops?: string[]; support?: (t: Target) => ProviderSupport; settings?: Record<string, unknown>; failOpen?: boolean; log?: string[] } = {}): AnalysisProvider {
  let open: Target | null = null;
  return {
    id, name: id.toUpperCase(), version: "1.0", kind: o.kind ?? "deep",
    supports: o.support ?? (() => ({ status: "supported", reason: "ok" })),
    profile: () => ({ settings: o.settings ?? {} }),
    async open(t) { if (o.failOpen) throw new Error("boom"); open = t; o.log?.push(`open:${id}`); },
    async close() { open = null; o.log?.push(`close:${id}`); },
    async call(op, args) { if (!open) throw new Error("not open"); return { by: id, op, args, target: open.sha256 }; },
    operations: () => o.ops ?? ["list_procedures"],
  };
}

test("registration order does not affect selection or identities", async () => {
  const mk = () => [fake("zeta"), fake("alpha"), fake("mid")];
  const r1 = new Registry(mk());
  const r2 = new Registry(mk().reverse());
  assert.deepEqual(r1.identities(), r2.identities());
  assert.deepEqual(r1.identities().map((i) => i.id), ["alpha", "mid", "zeta"]);
  for (const r of [r1, r2]) assert.equal(r.select(T1).entry.meta.id, "alpha");
});

test("auto picks first supporting deep provider, skips aux and unsupported", () => {
  const r = new Registry([
    fake("a-aux", { kind: "auxiliary", ops: ["x"] }),
    fake("b", { support: () => ({ status: "unsupported", reason: "no" }) }),
    fake("c"), fake("d"),
  ]);
  assert.equal(r.select(T1).entry.meta.id, "c");
  assert.equal(r.select(T1).source, "auto");
  const none = new Registry([fake("b", { support: () => ({ status: "unavailable", reason: "x" }) })]);
  assert.throws(() => none.select(T1), (e: any) => e instanceof ProviderSelectionError && e.reason === "no_supported_provider");
});

test("explicit provider failures never fall back", async () => {
  const r = new Registry([
    fake("a"),
    fake("g", { support: () => ({ status: "unavailable", reason: "not installed" }) }),
    fake("h", { support: () => ({ status: "unsupported", reason: "wrong format" }) }),
    fake("i", { failOpen: true }),
    fake("x-aux", { kind: "auxiliary", ops: ["aux_op"] }),
  ]);
  const reason = (id: string) => { try { r.select(T1, id); } catch (e) { return (e as ProviderSelectionError).reason; } return "none"; };
  assert.equal(reason("g"), "provider_unavailable");
  assert.equal(reason("h"), "unsupported_target");
  assert.equal(reason("nope"), "unknown_provider");
  assert.equal(reason("x-aux"), "not_deep_provider");
  const s = new BinarySession(r);
  await assert.rejects(s.open(T1, { provider: "i" }), (e: any) => e.reason === "open_failed");
  assert.equal(s.isOpen(), false);
  assert.equal(s.binding(), null);
  // after the failure the session is still usable
  assert.equal((await s.open(T1, { provider: "a" })).binding.provider_id, "a");
});

test("binding is immutable, recorded, and emits evidence", async () => {
  const s = new BinarySession(new Registry([fake("a", { settings: { depth: 3 } })]));
  const { binding, evidence, reused } = await s.open(T1);
  assert.equal(reused, false);
  assert.throws(() => { (binding as any).provider_id = "evil"; }, TypeError);
  assert.throws(() => { (binding.profile.settings as any).depth = 9; }, TypeError);
  assert.equal(s.binding()!.provider_id, "a");
  const ev = parseEvidence(JSON.parse(JSON.stringify(evidence)));
  assert.equal(ev.operation, "bind_provider");
  assert.equal(ev.provider.id, "rtk-provider-router");
  assert.equal(ev.subject!.digest.sha256, T1.sha256);
  assert.deepEqual((ev.normalized_result as any).analysis_provider_binding.profile_digest, binding.profile_digest);
  assert.equal(binding.selection, "auto");
});

test("switching requires explicit close; reopen same identity reuses binding", async () => {
  const log: string[] = [];
  const s = new BinarySession(new Registry([fake("a", { log }), fake("b", { log })]));
  const first = await s.open(T1);
  const again = await s.open(T1, { provider: "a" }); // auto resolved to a, explicit a: same concrete identity
  assert.equal(again.reused, true);
  assert.equal(again.binding, first.binding);
  assert.equal(log.filter((l) => l === "open:a").length, 1);
  await assert.rejects(s.open(T1, { provider: "b" }), SessionStateError);
  await assert.rejects(s.open(T2), SessionStateError);
  assert.equal(s.binding()!.provider_id, "a");
  await s.close();
  const sw = await s.open(T1, { provider: "b" });
  assert.equal(sw.binding.provider_id, "b");
  assert.equal(sw.binding.selection, "explicit");
  await s.close();
  await s.close(); // idempotent
  await assert.rejects(s.call("list_procedures"), SessionStateError);
});

test("profile change on same target/provider is a switch, not a reuse", async () => {
  let depth = 1;
  const p = fake("a");
  p.profile = () => ({ settings: { depth } });
  const s = new BinarySession(new Registry([p]));
  const b1 = (await s.open(T1)).binding;
  depth = 2;
  await assert.rejects(s.open(T1), SessionStateError);
  await s.close();
  const b2 = (await s.open(T1)).binding;
  assert.notEqual(b1.profile_digest, b2.profile_digest);
});

test("auxiliary routing is by operation name and never overrides deep", async () => {
  const s = new BinarySession(new Registry([
    fake("deep", { ops: ["list_procedures", "xrefs"] }),
    fake("aux1", { kind: "auxiliary", ops: ["graph_query"] }),
    fake("aux2", { kind: "auxiliary", ops: ["dotnet_types"], support: (t) => ({ status: t.format === "PE" ? "supported" : "unsupported", reason: "pe only" }) }),
  ]));
  const { binding } = await s.open(T1);
  assert.deepEqual(binding.auxiliary_providers.map((a) => a.id), ["aux1"]);
  assert.equal(((await s.call("xrefs")) as any).by, "deep");
  assert.equal(((await s.call("graph_query")) as any).by, "aux1");
  await assert.rejects(s.call("dotnet_types"), OperationRoutingError); // aux2 doesn't support ELF
  await s.close();
  await s.open(T2);
  assert.equal(((await s.call("dotnet_types")) as any).by, "aux2");
});

test("auxiliary conflicts are rejected at registry construction", () => {
  assert.throws(() => new Registry([fake("d", { ops: ["xrefs"] }), fake("x", { kind: "auxiliary", ops: ["xrefs"] })]), RegistryConfigError);
  assert.throws(() => new Registry([fake("x", { kind: "auxiliary", ops: ["q"] }), fake("y", { kind: "auxiliary", ops: ["q"] })]), RegistryConfigError);
  assert.throws(() => new Registry([fake("d"), fake("d")]), RegistryConfigError);
  assert.throws(() => new Registry([fake("auto")]), RegistryConfigError);
});

test("snapshot import requires exact sha256 + provider + profile digest", async () => {
  const s = new BinarySession(new Registry([fake("a", { settings: { v: 1 } }), fake("b")]));
  await s.open(T1, { provider: "a" });
  const id = s.snapshotIdentity();
  s.importSnapshot({ ...id, data: { n: 1 } });
  assert.deepEqual(s.snapshot()!.data, { n: 1 });
  for (const [k, v, label] of [["target_sha256", sha("c"), "target sha256"], ["provider_id", "b", "provider"], ["profile_digest", sha("0"), "profile digest"]] as const) {
    assert.throws(() => s.importSnapshot({ ...id, [k]: v, data: {} }), (e: any) => e instanceof SnapshotIdentityError && e.mismatches.some((m: string) => m.startsWith(label)));
  }
});

test("capability inventory", async () => {
  const s = new BinarySession(new Registry([fake("b"), fake("a", { support: () => ({ status: "unsupported", reason: "r" }) })]));
  assert.equal(s.capabilities()[0].support.status, "unknown");
  await s.open(T1, { provider: "b" });
  const inv = s.capabilities();
  assert.deepEqual(inv.map((c) => [c.provider_id, c.support.status, c.selected]), [["a", "unsupported", false], ["b", "supported", true]]);
});

test("concurrent open of two targets in separate sessions (factories)", async () => {
  const reg = new Registry([() => fake("a")]);
  const s1 = new BinarySession(reg), s2 = new BinarySession(reg);
  const [r1, r2] = await Promise.all([s1.open(T1), s2.open(T2)]);
  assert.equal(r1.binding.target_sha256, T1.sha256);
  assert.equal(r2.binding.target_sha256, T2.sha256);
  const [c1, c2] = await Promise.all([s1.call("list_procedures"), s2.call("list_procedures")]);
  assert.equal((c1 as any).target, T1.sha256);
  assert.equal((c2 as any).target, T2.sha256);
  await Promise.all([s1.close(), s2.close()]);
});

test("a shared plain instance cannot serve two sessions at once", async () => {
  const reg = new Registry([fake("a")]);
  const s1 = new BinarySession(reg), s2 = new BinarySession(reg);
  await s1.open(T1);
  await assert.rejects(s2.open(T2), SessionStateError);
  await s1.close();
  await s2.open(T2); // released
  await s2.close();
});

test("concurrent open calls in one session are serialised", async () => {
  const s = new BinarySession(new Registry([fake("a")]));
  const [a, b] = await Promise.allSettled([s.open(T1), s.open(T2)]);
  assert.equal(a.status, "fulfilled");
  assert.equal(b.status, "rejected");
  assert.equal(s.binding()!.target_sha256, T1.sha256);
});
