import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { identify } from "../src/identify.ts";
import { extractStrings } from "../src/strings.ts";
import { parseElf, parsePe } from "../src/features.ts";
import { extractIocs, IocSet, refang, defang } from "../src/ioc.ts";

const fx = (n: string) => new URL(`./fixtures/${n}`, import.meta.url).pathname;

test("identify: types, hashes agree with sha256sum/md5sum", () => {
  const expect: Record<string, string> = { "c2like.elf": "elf", "demo.exe": "pe", "Stager.dll": "pe", "sample.zip": "zip", "demo.apk": "apk", "m.wasm": "wasm", "app.sqlite": "sqlite", "beacon.pcapng": "pcap", "rootfs.squashfs": "squashfs", jsapp: "js-application" };
  for (const [f, t] of Object.entries(expect)) assert.equal(identify(fx(f)).type, t, f);
  const id = identify(fx("c2like.elf"));
  assert.equal(id.sha256, execFileSync("sha256sum", [fx("c2like.elf")]).toString().split(" ")[0]);
  assert.equal(id.md5, execFileSync("md5sum", [fx("c2like.elf")]).toString().split(" ")[0]);
  assert.equal(id.sha256, createHash("sha256").update(readFileSync(fx("c2like.elf"))).digest("hex"));
  assert.ok(id.entropy > 0 && id.entropy < 8);
});

test("strings: finds the C2 address in the ELF with an offset that points at it", () => {
  const { strings } = extractStrings(fx("c2like.elf")); const s = strings.find((x) => x.value === "198.51.100.7")!; assert.ok(s);
  const buf = readFileSync(fx("c2like.elf")); assert.equal(buf.toString("latin1", s.offset, s.offset + 12), "198.51.100.7");
  const utf16 = extractStrings(fx("Stager.dll")); assert.ok(utf16.strings.some((x) => x.encoding === "utf16le" && x.value.includes("cmd.exe")), "UTF-16 #US literal found");
});

test("ELF parser agrees with nm/readelf on undefined symbols, needed libs, interpreter, hardening", () => {
  const e = parseElf(fx("c2like.elf")); const nm = execFileSync("nm", ["-D", "--undefined-only", fx("c2like.elf")]).toString().split("\n").map((l) => l.trim().split(/\s+/u).pop()!.replace(/@.*/u, "")).filter(Boolean);
  for (const n of nm) assert.ok(e.undefinedSymbols.includes(n), `missing ${n}`);
  for (const n of ["ptrace", "connect", "socket", "dup2", "inet_pton"]) assert.ok(e.undefinedSymbols.includes(n));
  assert.deepEqual(e.needed, ["libc.so.6"]); assert.equal(e.interpreter, "/lib64/ld-linux-x86-64.so.2");
  const weak = parseElf(fx("vuln-weak.elf")), hard = parseElf(fx("vuln-hard.elf"));
  assert.equal(weak.hardening.executableStack, true); assert.equal(weak.hardening.stackCanary, false); assert.equal(weak.hardening.pie, false); assert.equal(weak.hardening.relro, "none");
  assert.equal(hard.hardening.executableStack, false); assert.equal(hard.hardening.stackCanary, true); assert.equal(hard.hardening.pie, true); assert.equal(hard.hardening.relro, "full");
  assert.ok(weak.undefinedSymbols.includes("gets") && weak.undefinedSymbols.includes("strcpy"));
  assert.ok(hard.undefinedSymbols.includes("__strcpy_chk")); // FORTIFY replaced strcpy
  assert.ok(e.sections.some((s) => s.name === ".text" && s.executable && s.entropy > 0));
  assert.throws(() => parseElf(fx("demo.exe")), /not an ELF/);
});
// These match REA's own results for the same binaries (inspect_binary_layout: weak canary false / exec stack true; hard canary true / relro Full / PIE) — see 27-manual-test-log T9.

test("PE parser: imports agree with mingw objdump -p; .NET flag; imphash is stable", () => {
  const p = parsePe(fx("demo.exe")); assert.equal(p.pe32plus, true); assert.equal(p.isDotNet, false); assert.ok(p.hasResources);
  const all = p.imports.flatMap((i) => i.functions);
  for (const f of ["VirtualAlloc", "LoadLibraryA"]) assert.ok(all.includes(f), f);
  let objdump = ""; try { objdump = execFileSync("x86_64-w64-mingw32-objdump", ["-p", fx("demo.exe")]).toString(); } catch { /* optional cross-check */ }
  if (objdump) { const theirs = [...objdump.matchAll(/^\s+[0-9a-f]+\s+[0-9a-f]+\s+\d+\s+(\S+)\s*$/gmu)].map((m) => m[1]!); const dlls = [...objdump.matchAll(/DLL Name: (\S+)/gu)].map((m) => m[1]!.toLowerCase());
    assert.deepEqual(p.imports.map((i) => i.dll.toLowerCase()).sort(), dlls.sort()); for (const f of theirs.slice(0, 20)) if (/^[A-Za-z_]/u.test(f)) assert.ok(all.includes(f), `objdump import ${f} missing`); }
  assert.match(p.imphash!, /^[0-9a-f]{32}$/u); assert.equal(p.imphash, parsePe(fx("demo.exe")).imphash);
  const dn = parsePe(fx("Stager.dll")); assert.equal(dn.isDotNet, true); assert.ok(dn.imports.some((i) => i.dll.toLowerCase() === "mscoree.dll"));
  assert.throws(() => parsePe(fx("c2like.elf")), /not a PE/);
});

test("IOC extraction: URLs, hosts, IPs with classification, base64/hex decoding, defang/refang, no filename false positives", () => {
  const set = new IocSet(); const o = { context: "t", evidenceId: "ev_" + "a".repeat(64) };
  extractIocs("beacon to hxxps://c2[.]example[.]invalid/task and 198.51.100.7, 10.1.2.3, 127.0.0.1 and 8.8.8.8 mail bad@evil.example.org index.js config.json x.dll", set, o);
  const have = (k: string, v: string) => set.all().find((i) => i.kind === k && i.value === v);
  assert.ok(have("url", "https://c2.example.invalid/task")); assert.equal(have("domain", "c2.example.invalid")!.classification, "example-domain");
  assert.equal(have("ipv4", "198.51.100.7")!.classification, "documentation"); assert.equal(have("ipv4", "10.1.2.3")!.classification, "private"); assert.equal(have("ipv4", "127.0.0.1")!.classification, "loopback"); assert.equal(have("ipv4", "8.8.8.8")!.classification, "public");
  assert.ok(have("email", "bad@evil.example.org")); assert.equal(set.all().some((i) => i.kind === "domain" && /^(index\.js|config\.json|x\.dll)$/u.test(i.value)), false);
  const s2 = new IocSet(); extractIocs("aHR0cHM6Ly9jMi5leGFtcGxlLmludmFsaWQvdGFzaw==", s2, o); const u = s2.all().find((i) => i.kind === "url")!; assert.equal(u.value, "https://c2.example.invalid/task"); assert.ok(u.decoded_from);
  const s3 = new IocSet(); extractIocs(Buffer.from("http://198.51.100.9/x").toString("hex"), s3, o); assert.ok(s3.all().some((i) => i.value === "http://198.51.100.9/x"));
  assert.equal(refang("hxxp://a[.]b"), "http://a.b"); assert.equal(defang("http://a.b"), "hxxp://a[.]b");
  const s4 = new IocSet(); extractIocs("a".repeat(40) + " " + "0123456789abcdef".repeat(4) + " HKLM\\Software\\Microsoft\\Windows\\Run C:\\Users\\x\\AppData\\evil.exe", s4, o);
  assert.ok(s4.all().some((i) => i.kind === "sha256")); assert.ok(s4.all().some((i) => i.kind === "registry-key")); assert.ok(s4.all().some((i) => i.kind === "windows-path"));
});
