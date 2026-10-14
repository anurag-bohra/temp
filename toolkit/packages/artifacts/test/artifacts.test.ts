import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import * as asar from "@electron/asar";
import { anomalyCodes, extractArchive, inspectArchive } from "../src/index.ts";
import type { ArchiveReport } from "../src/index.ts";
import { parseEvidence } from "@rtk/evidence";

const SAMPLES = "/tmp/claude-0/-home-user-temp/b1154f5f-19b6-591b-8a67-cb57e20a5c77/scratchpad/samples";
const PY = spawnSync("python3", ["--version"]).status === 0;
const skipPy = PY ? false : "python3 not available";
const root = mkdtempSync(join(tmpdir(), "rtk-art-"));
const arch = join(root, "archives");
before(() => { if (PY) { const r = spawnSync("python3", ["-I", new URL("./support/make_archives.py", import.meta.url).pathname, arch], { encoding: "utf8" }); assert.equal(r.status, 0, r.stderr); } });
after(() => rmSync(root, { recursive: true, force: true }));

const A = (n: string) => join(arch, n);
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
/** recursive snapshot (path, type, size, sha) of everything under dir; used to prove nothing changed outside dest */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d).sort()) {
      const f = join(d, n); const st = lstatSync(f); const rel = relative(dir, f);
      if (st.isDirectory()) { out.push(`d ${rel}`); walk(f); } else if (st.isSymbolicLink()) out.push(`l ${rel}`); else out.push(`f ${rel} ${st.size} ${sha(readFileSync(f))}`);
    }
  };
  walk(dir); return out;
}
/** Fresh sandbox: <sb>/outer/{sibling/keep.txt} and dest at <sb>/outer/a/b/dest so ../../ escapes land inside the snapshotted area. */
function sandbox(): { top: string; dest: string; before: string[] } {
  const top = mkdtempSync(join(root, "sb-")); mkdirSync(join(top, "outer/sibling"), { recursive: true }); writeFileSync(join(top, "outer/sibling/keep.txt"), "keep");
  return { top, dest: join(top, "outer/a/b/dest"), before: snapshot(top) };
}
const R = (ev: { normalized_result: unknown }) => ev.normalized_result as any;
const rep = (ev: { normalized_result: unknown }) => R(ev).archive as ArchiveReport;

async function rejected(file: string, code: string, quotas?: object) {
  const ins = await inspectArchive(A(file), quotas); parseEvidence(JSON.parse(JSON.stringify(ins)));
  assert.ok(anomalyCodes(ins).includes(code), `${file}: inspect should report ${code}, got ${anomalyCodes(ins)}`);
  const sb = sandbox();
  const ex = await extractArchive(A(file), sb.dest, quotas, { policy: "strict" }); const r = R(ex);
  assert.equal(r.status, "failed", `${file} strict extraction must fail`); assert.equal(r.failure.code, code, `${file}: failure code`);
  assert.equal(r.cleaned_up, true); assert.deepEqual(r.manifest, []);
  assert.deepEqual(snapshot(sb.top), sb.before, `${file}: nothing may remain on disk (incl. outside dest)`);
  assert.ok(!existsSync(join(sb.top, "outer/a")), "created parent dirs removed");
  return { ins, ex };
}

test("zip-slip ../../evil.txt: detected, rejected, nothing written anywhere", { skip: skipPy }, async () => {
  await rejected("zipslip.zip", "path-traversal"); assert.ok(!existsSync("/tmp/evil.txt") || readFileSync("/tmp/evil.txt", "utf8") !== "EVIL");
});
test("absolute path entry (/tmp/...) is rejected and not written", { skip: skipPy }, async () => {
  await rejected("absolute.zip", "absolute-path"); assert.ok(!existsSync("/tmp/rtk-test-abs"));
});
test("drive-letter and backslash traversal names are rejected", { skip: skipPy }, async () => {
  await rejected("drive.zip", "drive-letter"); await rejected("backslash-traversal.zip", "path-traversal");
});
test("symlink entry pointing at /etc: symlink + symlink-escape, never created", { skip: skipPy }, async () => {
  const { ins } = await rejected("symlink-etc.zip", "symlink-escape");
  assert.ok(anomalyCodes(ins).includes("symlink"));
  const e = rep(ins).entries[0]!; assert.equal(e.type, "symlink"); assert.equal(e.link_target, "/etc");
});
test("symlink then file-through-symlink escape: detected and refused (strict and skip-bad)", { skip: skipPy }, async () => {
  await rejected("symlink-through.zip", "symlink-escape");
  const ins = await inspectArchive(A("symlink-through.zip")); assert.ok(anomalyCodes(ins).includes("symlink-through"));
  const sb = sandbox(); const r = R(await extractArchive(A("symlink-through.zip"), sb.dest, undefined, { policy: "skip-bad" }));
  assert.equal(r.status, "partial"); assert.deepEqual(r.refusals.map((x: any) => x.code).sort(), ["symlink-escape", "symlink-through"]);
  assert.deepEqual(snapshot(sb.top).filter((s) => !s.includes("dest") && !/outer\/a(\/b)?$/u.test(s)), sb.before); assert.deepEqual(r.manifest, []);
  // internal (non-escaping) symlink followed by a file through it: still refused
  const x = await inspectArchive(A("symlink-internal-through.zip")); assert.ok(anomalyCodes(x).includes("symlink-through")); assert.ok(!anomalyCodes(x).includes("symlink-escape"));
  const sb2 = sandbox(); const r2 = R(await extractArchive(A("symlink-internal-through.zip"), sb2.dest, undefined, { policy: "skip-bad" }));
  assert.ok(r2.refusals.some((q: any) => q.code === "symlink-through")); assert.ok(!existsSync(join(sb2.dest, "inner")));
  assert.ok(existsSync(join(sb2.dest, "sub/real.txt")));
});
test("benign symlink is reported and skipped (never created); rest extracts", { skip: skipPy }, async () => {
  const sb = sandbox(); const r = R(await extractArchive(A("symlink-benign.zip"), sb.dest));
  assert.equal(r.status, "ok"); assert.equal(readFileSync(join(sb.dest, "a.txt"), "utf8"), "A"); assert.ok(!existsSync(join(sb.dest, "alias")));
  assert.ok(r.refusals.some((x: any) => x.code === "symlink" && x.entry === "alias"));
});
test("zip bomb (20 MiB of zeros in ~20 KB): ratio quota, aborted mid-stream, cleaned up", { skip: skipPy }, async () => {
  assert.ok(statSync(A("bomb.zip")).size < 100_000);
  await rejected("bomb.zip", "ratio-exceeded");
});
test("total-size quota enforced while streaming (incompressible data)", { skip: skipPy }, async () => {
  const q = { maxTotalSize: 1024 * 1024 };
  const { ins } = await rejected("bigstored.zip", "total-size-exceeded", q);
  assert.equal(R(ins).quota_breached, "total-size-exceeded"); assert.equal(rep(ins).truncated, true);
});
test("per-entry size quota", { skip: skipPy }, async () => { await rejected("bigstored.zip", "entry-size-exceeded", { maxEntrySize: 100 * 1024 }); });
test("declared-size lie (smaller): stops at declared+1, size-mismatch", { skip: skipPy }, async () => {
  const { ex } = await rejected("lie-small.zip", "size-mismatch"); assert.match(R(ex).failure.detail, /more than its declared 10/u);
});
test("declared-size lie (larger) and lying-small bomb", { skip: skipPy }, async () => { await rejected("lie-large.zip", "size-mismatch"); await rejected("lie-bomb.zip", "size-mismatch"); });
test("CRC mismatch is detected", { skip: skipPy }, async () => { await rejected("crc.zip", "crc-mismatch"); });
test("too many entries: quota checked from the central directory before anything is written", { skip: skipPy }, async () => {
  const { ins } = await rejected("many.zip", "entry-count-exceeded", { maxEntries: 100 });
  assert.equal(rep(ins).entries.length, 0);
  const ok = await inspectArchive(A("many.zip")); assert.equal(rep(ok).entries.length, 200); assert.equal(R(ok).quota_breached, null);
});
test("duplicate names and case-insensitive collisions", { skip: skipPy }, async () => {
  await rejected("dup.zip", "duplicate-name"); await rejected("case.zip", "case-collision");
  const sb = sandbox(); const r = R(await extractArchive(A("dup.zip"), sb.dest, undefined, { policy: "skip-bad" }));
  assert.equal(r.status, "partial"); assert.equal(readFileSync(join(sb.dest, "a.txt"), "utf8"), "one", "first wins, second never overwrites");
});
test("control characters and NUL in names", { skip: skipPy }, async () => { await rejected("ctrl.zip", "control-char"); await rejected("nul.zip", "control-char"); });
test("encrypted (ZipCrypto) entry is detected and not read", { skip: skipPy }, async () => {
  const { ins } = await rejected("enc.zip", "encrypted-entry");
  const e = rep(ins).entries[0]!; assert.equal(e.encrypted, true); assert.equal(e.sha256, null);
});
test("tar with ../, absolute, device node, fifo, symlink, hardlink", { skip: skipPy }, async () => {
  const ins = await inspectArchive(A("evil.tar"));
  for (const c of ["path-traversal", "absolute-path", "device-node", "special-file", "symlink", "symlink-escape", "hardlink", "hardlink-escape"]) assert.ok(anomalyCodes(ins).includes(c), c);
  await rejected("tar-slip.tar", "path-traversal"); await rejected("dev-only.tar", "device-node");
  const sb = sandbox(); const r = R(await extractArchive(A("evil.tar"), sb.dest, undefined, { policy: "skip-bad" }));
  assert.equal(r.status, "partial"); assert.deepEqual(r.manifest.map((m: any) => m.path), ["ok.txt"]);
  assert.deepEqual(snapshot(sb.top).filter((s) => !/outer\/a(\/b(\/dest(\/ok\.txt .*)?)?)?$/u.test(s)), sb.before); assert.ok(!existsSync("/tmp/rtk-test-abs"));
});
test("deep nesting bomb: depth quota reported, not descended", { skip: skipPy }, async () => {
  const ins = await inspectArchive(A("nest8.zip")); assert.ok(anomalyCodes(ins).includes("depth-exceeded"));
  let d = 0, r: ArchiveReport | undefined = rep(ins); while (r) { d = r.depth; r = r.entries.find((e) => e.nested)?.nested; }
  assert.equal(d, 3);
  const deep = await inspectArchive(A("nest8.zip"), { maxDepth: 10 }); assert.ok(!anomalyCodes(deep).includes("depth-exceeded"));
  const strict = R(await extractArchive(A("nest8.zip"), sandbox().dest)); assert.equal(strict.status, "ok", "extraction does not unpack nested archives");
});
test("nested bomb: quota applies inside nested archives with the same budget", { skip: skipPy }, async () => {
  const ins = await inspectArchive(A("bomb-nested.zip")); const a = R(ins).anomalies.find((x: any) => x.code === "ratio-exceeded");
  assert.ok(a); assert.match(a.archive, /bomb-nested\.zip!inner\.zip/u); assert.equal(R(ins).quota_breached, "ratio-exceeded");
});
test("kinds by magic + nested container recursion", { skip: skipPy }, async () => {
  const ins = await inspectArchive(A("kinds.zip")); const k = Object.fromEntries(rep(ins).entries.map((e) => [e.path, e.kind]));
  assert.deepEqual(k, { "a.elf": "elf", "b.exe": "pe", "c.sh": "script", "d.dex": "dex", "e.macho": "macho", "f.txt": "text", "g.class": "java-class", "nested.zip": "zip" });
  const nested = rep(ins).entries.find((e) => e.path === "nested.zip")!.nested!; assert.equal(nested.entries[0]!.kind, "elf"); assert.equal(nested.depth, 1);
});
test("truncated / garbage inputs do not crash", { skip: skipPy }, async () => {
  for (const f of ["truncated.zip", "garbage.bin", "truncated.tar.gz"]) {
    const ins = await inspectArchive(A(f)); parseEvidence(JSON.parse(JSON.stringify(ins))); assert.ok(R(ins).anomalies.length > 0, f);
    const ex = R(await extractArchive(A(f), sandbox().dest)); assert.equal(ex.status, "failed", f); assert.equal(ex.cleaned_up, true);
  }
  assert.ok(anomalyCodes(await inspectArchive(A("garbage.bin"))).includes("unsupported-format"));
});
test("never overwrites existing files (and cleanup does not delete them)", { skip: skipPy }, async () => {
  const sb = sandbox(); mkdirSync(sb.dest, { recursive: true }); writeFileSync(join(sb.dest, "ok.txt"), "precious");
  const snap = snapshot(sb.top);
  const r = R(await extractArchive(A("overwrite.zip"), sb.dest)); assert.equal(r.status, "failed"); assert.equal(r.failure.code, "would-overwrite");
  assert.deepEqual(snapshot(sb.top), snap);
  const r2 = R(await extractArchive(A("overwrite.zip"), sb.dest, undefined, { policy: "skip-bad" })); assert.equal(r2.status, "partial");
  assert.equal(readFileSync(join(sb.dest, "ok.txt"), "utf8"), "precious");
});
test("pre-existing symlinked parent inside dest is refused (file-through-existing-symlink)", { skip: skipPy }, async () => {
  const sb = sandbox(); const outside = join(sb.top, "outer/sibling"); mkdirSync(sb.dest, { recursive: true });
  spawnSync("ln", ["-s", outside, join(sb.dest, "sub")]); const snap = snapshot(sb.top);
  const r = R(await extractArchive(A("symlink-internal-through.zip"), sb.dest, undefined, { policy: "skip-bad" })); // contains sub/real.txt
  assert.ok(r.refusals.some((x: any) => x.code === "symlink-through" && x.entry === "sub/real.txt"));
  assert.deepEqual(snapshot(sb.top).filter((s) => s.includes("sibling")), snap.filter((s) => s.includes("sibling")));
});
test("modes: setuid/exec stripped by default (0600), 0700 only with preserveExec; manifest sha256 matches disk", { skip: skipPy }, async () => {
  const sb = sandbox(); const r = R(await extractArchive(A("modes.zip"), sb.dest));
  assert.equal(r.status, "ok"); assert.equal(statSync(join(sb.dest, "run.sh")).mode & 0o7777, 0o600); assert.equal(statSync(join(sb.dest, "data.bin")).mode & 0o7777, 0o600);
  assert.ok(statSync(sb.dest).mode & 0o700);
  for (const m of r.manifest.filter((x: any) => x.type === "file")) assert.equal(sha(readFileSync(join(sb.dest, m.path))), m.sha256);
  const sb2 = sandbox(); const r2 = R(await extractArchive(A("modes.zip"), sb2.dest, undefined, { preserveExec: true }));
  assert.equal(statSync(join(sb2.dest, "run.sh")).mode & 0o7777, 0o700); assert.equal(r2.manifest.find((m: any) => m.path === "run.sh").mode, "0700");
});
test("tar.gz: legit extraction with manifest, symlink skipped, setuid stripped", { skip: skipPy }, async () => {
  const ins = await inspectArchive(A("legit.tar.gz")); assert.equal(rep(ins).format, "tar.gz");
  assert.deepEqual(rep(ins).entries.map((e) => e.path), ["dir/a.txt", "dir/sub/b.bin", "run.sh", "dir/ln"]);
  assert.equal(rep(ins).entries[1]!.kind, "elf"); assert.equal(rep(ins).entries[2]!.mode, "4755"); assert.ok(R(ins).anomalies.some((a: any) => a.code === "special-mode"));
  const sb = sandbox(); const r = R(await extractArchive(A("legit.tar.gz"), sb.dest));
  assert.equal(r.status, "ok"); assert.equal(readFileSync(join(sb.dest, "dir/a.txt"), "utf8"), "alpha\n"); assert.equal(statSync(join(sb.dest, "run.sh")).mode & 0o7777, 0o600);
  assert.ok(!existsSync(join(sb.dest, "dir/ln"))); assert.equal(r.manifest.filter((m: any) => m.type === "file").length, 3);
  assert.equal(R(await extractArchive(A("legit.tar"), sandbox().dest)).status, "ok");
  assert.equal(readdirSync(tmpdir()).filter((n) => n.startsWith("rtk-gz-")).length, 0, "gzip spool dirs are removed");
});
test("tar.gz bomb: ratio quota aborts the gzip stream", { skip: skipPy }, async () => { await rejected("tarbomb.tar.gz", "ratio-exceeded"); });
test("tar long names (GNU L) and plain .gz single file", { skip: skipPy }, async () => {
  const t = rep(await inspectArchive(A("longname.tar"))); assert.ok(t.entries[0]!.path.length > 270);
  const g = await inspectArchive(A("hello.txt.gz")); assert.equal(rep(g).format, "gzip"); assert.equal(rep(g).entries[0]!.path, "hello.txt"); assert.equal(rep(g).entries[0]!.sha256, sha("hello gzip\n"));
});

// ---- legit real-world samples (skip when the lab samples are absent)
test("demo sample.zip and demo APK", { skip: !existsSync(join(SAMPLES, "sample.zip")) || !existsSync(join(SAMPLES, "apk/demo-unsigned.apk")) }, async () => {
  const z = await inspectArchive(join(SAMPLES, "sample.zip")); assert.equal(R(z).anomalies.length, 0);
  assert.ok(rep(z).entries.some((e) => e.path === "jsapp/src/main.js" && e.kind === "text" && e.sha256));
  const sb = sandbox(); const ex = R(await extractArchive(join(SAMPLES, "sample.zip"), sb.dest)); assert.equal(ex.status, "ok");
  const ref = spawnSync("python3", ["-I", "-c", "import zipfile,sys,hashlib;z=zipfile.ZipFile(sys.argv[1]);print('\\n'.join(n+' '+hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if not n.endswith('/')))", join(SAMPLES, "sample.zip")], { encoding: "utf8" }).stdout.trim().split("\n").sort();
  assert.deepEqual(ex.manifest.filter((m: any) => m.type === "file").map((m: any) => `${m.path} ${m.sha256}`).sort(), ref, "manifest equals python zipfile's view");
  const apk = await inspectArchive(join(SAMPLES, "apk/demo-unsigned.apk")); const a = rep(apk);
  assert.equal(a.flavor, "apk"); assert.equal(a.entries.find((e) => e.path === "classes.dex")!.kind, "dex"); assert.ok(a.entries.some((e) => e.path === "AndroidManifest.xml"));
  assert.equal(apk.subject!.format, "apk");
});

// ---- asar
const pickle = (json: string): Buffer => { const j = Buffer.from(json); const pad = (4 - (j.length % 4)) % 4; const inner = 4 + j.length + pad; const b = Buffer.alloc(16 + j.length + pad); b.writeUInt32LE(4, 0); b.writeUInt32LE(inner + 4, 4); b.writeUInt32LE(inner, 8); b.writeUInt32LE(j.length, 12); j.copy(b, 16); return b; };
test("asar built with @electron/asar: entries, kinds, offsets and integrity hashes verified", async () => {
  const src = join(root, "asar-src"); mkdirSync(join(src, "sub"), { recursive: true });
  writeFileSync(join(src, "a.txt"), "hello\n"); writeFileSync(join(src, "sub/b.js"), "console.log(1)\n"); writeFileSync(join(src, "sub/n.node"), Buffer.concat([Buffer.from("\x7fELF"), Buffer.alloc(60)]));
  const file = join(root, "t.asar"); await asar.createPackage(src, file);
  const ins = await inspectArchive(file); const a = rep(ins);
  assert.equal(a.format, "asar"); assert.equal(R(ins).anomalies.length, 0);
  const files = a.entries.filter((e) => e.type === "file"); assert.deepEqual(files.map((e) => e.path).sort(), ["a.txt", "sub/b.js", "sub/n.node"]);
  assert.equal(a.entries.find((e) => e.path === "sub/n.node")!.kind, "elf");
  // independent verification of offsets: slice raw data region by the header's own offsets
  const raw = readFileSync(file); const hdr = JSON.parse(raw.subarray(16, 16 + raw.readUInt32LE(12)).toString()); const base = 8 + raw.readUInt32LE(4);
  const want = { "a.txt": hdr.files["a.txt"], "sub/b.js": hdr.files.sub.files["b.js"], "sub/n.node": hdr.files.sub.files["n.node"] } as Record<string, any>;
  for (const [p, n] of Object.entries(want)) {
    const bytes = raw.subarray(base + Number(n.offset), base + Number(n.offset) + n.size);
    assert.equal(files.find((e) => e.path === p)!.sha256, sha(bytes), p); assert.equal(sha(bytes), n.integrity.hash, `${p} matches asar integrity`);
  }
  const sb = sandbox(); const ex = R(await extractArchive(file, sb.dest)); assert.equal(ex.status, "ok");
  assert.equal(readFileSync(join(sb.dest, "sub/b.js"), "utf8"), "console.log(1)\n");
  // tamper with the data region: integrity hash no longer matches
  const bad = Buffer.from(raw); bad[base + Number(want["a.txt"].offset)] ^= 1; const bf = join(root, "tampered.asar"); writeFileSync(bf, bad);
  const bi = await inspectArchive(bf); assert.ok(anomalyCodes(bi).includes("integrity-mismatch"));
  const sb2 = sandbox(); assert.equal(R(await extractArchive(bf, sb2.dest)).failure.code, "integrity-mismatch"); assert.ok(!existsSync(sb2.dest));
});
test("asar with out-of-range / overlapping offsets, '..' keys and unpacked files", async () => {
  const hdr = { files: { ok: { size: 4, offset: "0" }, far: { size: 10, offset: "999999" }, ov: { size: 4, offset: "2" }, "../up": { size: 1, offset: "0" }, unp: { size: 3, unpacked: true } } };
  const data = Buffer.from("abcdefgh"); const f = join(root, "weird.asar"); writeFileSync(f, Buffer.concat([pickle(JSON.stringify(hdr)), data]));
  const ins = await inspectArchive(f); const c = anomalyCodes(ins);
  for (const x of ["asar-offset-out-of-range", "asar-overlap", "path-traversal", "asar-unpacked-external"]) assert.ok(c.includes(x), x);
  const sb = sandbox(); const r = R(await extractArchive(f, sb.dest, undefined, { policy: "skip-bad" }));
  assert.equal(r.status, "partial"); assert.ok(r.manifest.length <= 1); assert.deepEqual(snapshot(sb.top).filter((s) => !/outer\/a(\/b(\/dest.*)?)?$/u.test(s)), sb.before);
});

test("CLI: inspect and extract print Evidence JSON and set exit codes", { skip: skipPy }, () => {
  const bin = new URL("../bin/rtk-artifacts.ts", import.meta.url).pathname;
  const a = spawnSync("node", [bin, "inspect", A("kinds.zip")], { encoding: "utf8" }); assert.equal(a.status, 0, a.stderr); assert.equal(JSON.parse(a.stdout).operation, "inspect_archive");
  const b = spawnSync("node", [bin, "inspect", A("zipslip.zip")], { encoding: "utf8" }); assert.equal(b.status, 1);
  const sb = sandbox(); const c = spawnSync("node", [bin, "extract", A("zipslip.zip"), sb.dest, "--policy", "skip-bad"], { encoding: "utf8" }); assert.equal(c.status, 1); assert.equal(JSON.parse(c.stdout).normalized_result.status, "partial");
  assert.equal(spawnSync("node", [bin], { encoding: "utf8" }).status, 2);
});
