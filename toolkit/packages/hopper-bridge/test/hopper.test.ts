import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HopperClient, HopperProvider, launchBridge, HopperAuthError, HopperSecurityError, HopperTimeoutError, HopperConnectionError, HopperProtocolError, HopperRemoteError, HopperUnavailableError } from "../src/index.ts";
import { Registry, BinarySession } from "@rtk/provider-router";
import { parseEvidence } from "@rtk/evidence";
import { startFake } from "./fakeHopper.ts";

const TOKEN = "a".repeat(64);
const SHA = "b".repeat(64);
const BRIDGE = join(dirname(fileURLToPath(import.meta.url)), "..", "bridge", "hopper_bridge.py");
const hasPython = (() => { try { execFileSync("python3", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();

test("auth success then request/response against fake Hopper", async () => {
  const f = await startFake({ token: TOKEN });
  try {
    assert.equal(statSync(f.socketPath).mode & 0o777, 0o600);
    const c = await HopperClient.connect({ socketPath: f.socketPath, token: TOKEN });
    assert.equal(f.requests[0].method, "auth");
    assert.equal(f.requests[0].v, 1);
    const r = await c.request("list_procedures");
    assert.deepEqual(r.result, { procedures: [{ entry: "0x1000", name: "main" }] });
    assert.deepEqual(r.limitations, ["fake"]);
    // concurrent requests are matched by id
    const [a, b] = await Promise.all([c.request("ping"), c.request("hello")]);
    assert.deepEqual(a.result, { pong: true });
    assert.equal((b.result as any).protocol, 1);
    await assert.rejects(c.request("xrefs"), (e: any) => e instanceof HopperRemoteError && e.code === "not_implemented");
    c.close();
    await assert.rejects(c.request("ping"), HopperConnectionError);
  } finally { await f.close(); }
});

test("wrong token: auth failure, nothing else is sent", async () => {
  const f = await startFake({ token: TOKEN });
  try {
    await assert.rejects(HopperClient.connect({ socketPath: f.socketPath, token: "c".repeat(64) }), HopperAuthError);
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].method, "auth");
  } finally { await f.close(); }
});

test("client refuses sockets/directories that are not private (token never sent)", async () => {
  const loose = await startFake({ token: TOKEN, socketMode: 0o666 });
  const looseDir = await startFake({ token: TOKEN, dirMode: 0o755 });
  try {
    await assert.rejects(HopperClient.connect({ socketPath: loose.socketPath, token: TOKEN }), HopperSecurityError);
    await assert.rejects(HopperClient.connect({ socketPath: looseDir.socketPath, token: TOKEN }), HopperSecurityError);
    assert.equal(loose.connections + looseDir.connections, 0);
    await assert.rejects(HopperClient.connect({ socketPath: join(tmpdir(), "does-not-exist.sock"), token: TOKEN }), /ENOENT/);
  } finally { await loose.close(); await looseDir.close(); }
});

test("request timeout rejects without killing the connection; late reply ignored", async () => {
  const f = await startFake({ token: TOKEN, delay: { ping: 300 } });
  try {
    const c = await HopperClient.connect({ socketPath: f.socketPath, token: TOKEN });
    await assert.rejects(c.request("ping", {}, { timeoutMs: 50 }), HopperTimeoutError);
    await new Promise((r) => setTimeout(r, 400)); // late response arrives and is dropped
    assert.equal(c.closed, false);
    assert.deepEqual((await c.request("list_procedures")).result, { procedures: [{ entry: "0x1000", name: "main" }] });
    c.close();
  } finally { await f.close(); }
});

test("silent server: auth timeout; garbage reply: protocol error; server death: pending rejected", async () => {
  const s = await startFake({ token: TOKEN, silent: ["auth"] });
  try { await assert.rejects(HopperClient.connect({ socketPath: s.socketPath, token: TOKEN, requestTimeoutMs: 100 }), HopperTimeoutError); } finally { await s.close(); }
  const g = await startFake({ token: TOKEN, garbage: "hello" });
  try {
    const c = await HopperClient.connect({ socketPath: g.socketPath, token: TOKEN });
    await assert.rejects(c.request("hello"), HopperProtocolError);
    assert.equal(c.closed, true);
  } finally { await g.close(); }
  const d = await startFake({ token: TOKEN, silent: ["ping"] });
  try {
    const c = await HopperClient.connect({ socketPath: d.socketPath, token: TOKEN });
    const p = c.request("ping", {}, { timeoutMs: 5000 });
    await new Promise((r) => setTimeout(r, 50));
    await d.close();
    await assert.rejects(p, HopperConnectionError);
  } finally { await d.close().catch(() => {}); }
});

test("provider: open/call/close lifecycle with fake Hopper, evidence is marked unverified", async () => {
  const f = await startFake({ token: TOKEN });
  let stopped = 0;
  try {
    const p = new HopperProvider({ connect: async () => ({ socketPath: f.socketPath, token: TOKEN, stop: async () => { stopped++; } }) });
    assert.equal(p.supports({ path: "/x", sha256: SHA }).status, "supported");
    await p.open({ path: "/x/y", sha256: SHA, name: "y" });
    const ev = parseEvidence(JSON.parse(JSON.stringify(await p.call("list_procedures", {}))));
    assert.equal(ev.provider.id, "rtk-hopper-bridge");
    assert.equal(ev.subject!.digest.sha256, SHA);
    assert.ok(ev.limitations.some((l) => l.startsWith("UNVERIFIED")));
    assert.equal(ev.confidence, "observed");
    assert.equal((await p.call("procedure_pseudo_code", { address: "0x1000" })).confidence, "derived");
    await assert.rejects(p.call("xrefs", { address: "0x1" }), (e: any) => e.code === "not_implemented");
    await assert.rejects(p.call("bogus"), /Unknown operation/);
    await p.close();
    assert.equal(stopped, 1);
    assert.ok(f.requests.some((r) => r.method === "shutdown"));
    await assert.rejects(p.call("list_procedures"), /not open/);
  } finally { await f.close(); }
});

test("provider rejects a document whose sha256 differs; cleans up", async () => {
  const f = await startFake({ token: TOKEN, sha256: "d".repeat(64) });
  let stopped = 0;
  try {
    const p = new HopperProvider({ connect: async () => ({ socketPath: f.socketPath, token: TOKEN, stop: async () => { stopped++; } }) });
    await assert.rejects(p.open({ path: "/x", sha256: SHA }), HopperProtocolError);
    assert.equal(stopped, 1);
  } finally { await f.close(); }
});

test("provider is unavailable when unconfigured or Hopper binary missing; router never falls back", async () => {
  assert.equal(new HopperProvider().supports({ path: "/x", sha256: SHA }).status, "unavailable");
  const missing = new HopperProvider({ launch: { bin: "/nonexistent/Hopper", args: [], script: BRIDGE } });
  assert.equal(missing.supports({ path: "/x", sha256: SHA }).status, "unavailable");
  const reg = new Registry([() => missing]);
  assert.throws(() => reg.select({ path: "/x", sha256: SHA }, "hopper"), /unavailable/);
  await assert.rejects(launchBridge({ bin: "/nonexistent/Hopper", args: [], script: BRIDGE }), HopperUnavailableError);
});

test("provider runs under provider-router BinarySession", async () => {
  const f = await startFake({ token: TOKEN });
  try {
    const s = new BinarySession(new Registry([() => new HopperProvider({ connect: async () => ({ socketPath: f.socketPath, token: TOKEN }) })]));
    const { binding } = await s.open({ path: "/x", sha256: SHA }, { provider: "hopper" });
    assert.equal(binding.provider_id, "hopper");
    assert.equal(binding.profile.settings.verified_against_real_hopper, false);
    assert.equal(((await s.call("list_procedures")) as any).provider.id, "rtk-hopper-bridge");
    await s.close();
  } finally { await f.close(); }
});

// ---- the real Python bridge script, run under plain python3 (NOT inside Hopper): protocol layer only
test("python bridge: launch, auth, protocol errors, not_implemented outside Hopper, kill + cleanup", { skip: !hasPython && "python3 missing" }, async () => {
  const before = readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-hopper-"));
  const h = await launchBridge({ bin: "/usr/bin/env", args: ["python3", "{script}"], script: BRIDGE });
  assert.equal(statSync(h.dir).mode & 0o777, 0o700);
  assert.equal(statSync(h.socketPath).mode & 0o777, 0o600);
  assert.equal(statSync(join(h.dir, "token")).mode & 0o777, 0o600);
  await assert.rejects(HopperClient.connect({ socketPath: h.socketPath, token: "e".repeat(64) }), HopperAuthError);
  const c = await HopperClient.connect({ socketPath: h.socketPath, token: h.token });
  assert.deepEqual((await c.request("ping")).result, { pong: true });
  const hello = (await c.request("hello")).result as any;
  assert.equal(hello.protocol, 1);
  assert.equal(hello.inside_hopper, false);
  await assert.rejects(c.request("list_procedures"), (e: any) => e instanceof HopperRemoteError && e.code === "not_implemented" && /not running inside Hopper/.test(e.message));
  await assert.rejects(c.request("open_document", { path: "/x", sha256: SHA }), (e: any) => e.code === "not_implemented");
  await assert.rejects(c.request("xrefs"), (e: any) => e.code === "not_implemented");
  await assert.rejects(c.request("no_such_method"), (e: any) => e.code === "unknown_method");
  await assert.rejects(c.request("auth", { token: h.token }), (e: any) => e.code === "bad_request");
  c.close();
  // a second connection still works (server accepts sequential clients), then stop kills the group and removes the dir
  const c2 = await HopperClient.connect({ socketPath: h.socketPath, token: h.token });
  await c2.request("ping");
  c2.close();
  await h.stop();
  assert.equal(existsSync(h.dir), false);
  assert.throws(() => process.kill(-h.pid, 0));
  assert.deepEqual(readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-hopper-")), before);
});

test("python bridge: refuses to bind in a non-private directory", { skip: !hasPython && "python3 missing" }, async () => {
  const { mkdtempSync, chmodSync, writeFileSync, rmSync } = await import("node:fs");
  const d = mkdtempSync(join(tmpdir(), "rtk-hopper-bad-"));
  chmodSync(d, 0o755);
  writeFileSync(join(d, "token"), TOKEN, { mode: 0o600 });
  try {
    assert.throws(() => execFileSync("python3", [BRIDGE, "--socket", join(d, "s.sock"), "--token-file", join(d, "token")], { stdio: "pipe" }), /must be mode 0700/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("python bridge: startup failure (host exits early) is reported and cleaned up", { skip: !hasPython && "python3 missing" }, async () => {
  const before = readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-hopper-"));
  await assert.rejects(launchBridge({ bin: "/usr/bin/env", args: ["python3", "-c", "import sys; sys.exit(3)"], script: BRIDGE }), /exited before creating its socket/);
  assert.deepEqual(readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-hopper-")), before);
});
