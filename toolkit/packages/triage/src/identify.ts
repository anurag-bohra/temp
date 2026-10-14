import { closeSync, fstatSync, openSync, readSync, readdirSync, statSync, existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { extname, join } from "node:path";

export type SampleType = "elf" | "pe" | "pe-dotnet" | "macho" | "macho-fat" | "zip" | "apk" | "jar" | "ooxml" | "ipa" | "gzip" | "tar" | "asar" | "wasm" | "sqlite" | "pcap" | "pdf" | "ole" | "dex" | "squashfs" | "javascript" | "script" | "text" | "directory" | "js-application" | "unknown";
export interface Identity { path: string; type: SampleType; size: number; md5: string; sha1: string; sha256: string; entropy: number; magic: string; notes: string[] }

export const shannonEntropy = (buf: Uint8Array): number => {
  if (buf.length === 0) return 0; const c = new Array<number>(256).fill(0); for (const b of buf) c[b]!++;
  let h = 0; for (const n of c) if (n) { const p = n / buf.length; h -= p * Math.log2(p); } return Math.round(h * 1000) / 1000;
};
const hashes = (path: string): { md5: string; sha1: string; sha256: string; size: number; head: Buffer; entropy: number } => {
  const fd = openSync(path, "r"); const md5 = createHash("md5"), sha1 = createHash("sha1"), sha256 = createHash("sha256"); const counts = new Array<number>(256).fill(0);
  const buf = Buffer.alloc(1 << 20); let size = 0; let head = Buffer.alloc(0);
  try { for (;;) { const n = readSync(fd, buf, 0, buf.length, null); if (n === 0) break; const chunk = buf.subarray(0, n); if (size === 0) head = Buffer.from(chunk.subarray(0, 4096)); md5.update(chunk); sha1.update(chunk); sha256.update(chunk); for (const b of chunk) counts[b]!++; size += n; } } finally { closeSync(fd); }
  let h = 0; for (const n of counts) if (n) { const p = n / size; h -= p * Math.log2(p); }
  return { md5: md5.digest("hex"), sha1: sha1.digest("hex"), sha256: sha256.digest("hex"), size, head, entropy: size ? Math.round(h * 1000) / 1000 : 0 };
};

const isMostlyText = (b: Buffer): boolean => { if (b.length === 0) return false; let ok = 0; for (const x of b) if (x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127) || x >= 128) ok++; return ok / b.length > 0.95 && !b.includes(0); };

/** Cheap ZIP member-name probe (reads the central directory names only) to separate apk/jar/ooxml/ipa from plain zip. */
export function zipMemberNames(path: string, max = 5000): string[] {
  const fd = openSync(path, "r"); try {
    const size = fstatSync(fd).size; const tail = Buffer.alloc(Math.min(size, 66000)); readSync(fd, tail, 0, tail.length, size - tail.length);
    const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06])); if (eocd < 0) return [];
    const count = tail.readUInt16LE(eocd + 10), cdSize = tail.readUInt32LE(eocd + 12), cdOff = tail.readUInt32LE(eocd + 16);
    if (cdSize > 64 << 20) return []; const cd = Buffer.alloc(cdSize); readSync(fd, cd, 0, cdSize, cdOff);
    const names: string[] = []; let p = 0;
    for (let i = 0; i < Math.min(count, max) && p + 46 <= cd.length; i++) { const nl = cd.readUInt16LE(p + 28), el = cd.readUInt16LE(p + 30), cl = cd.readUInt16LE(p + 32); names.push(cd.toString("utf8", p + 46, p + 46 + nl)); p += 46 + nl + el + cl; }
    return names;
  } finally { closeSync(fd); }
}

function classify(path: string, head: Buffer, notes: string[]): { type: SampleType; magic: string } {
  const h = head; const ext = extname(path).toLowerCase();
  if (h.length >= 4 && h.readUInt32BE(0) === 0x7f454c46) return { type: "elf", magic: "7f454c46" };
  if (h.length >= 0x40 && h[0] === 0x4d && h[1] === 0x5a) {
    const lfanew = h.readUInt32LE(0x3c); notes.push(`e_lfanew=0x${lfanew.toString(16)}`);
    return { type: "pe", magic: "MZ" }; // .NET refinement happens in features (needs the optional header)
  }
  if (h.length >= 4) {
    const be = h.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(be)) return { type: "macho", magic: be.toString(16) };
    if (be === 0xcafebabe && h.length >= 8 && h.readUInt32BE(4) < 40) return { type: "macho-fat", magic: "cafebabe" };
    if (h.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])) || h.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x05, 0x06]))) {
      let names: string[] = []; try { names = zipMemberNames(path); } catch { notes.push("zip central directory unreadable"); }
      const has = (n: string) => names.includes(n);
      if (has("AndroidManifest.xml") && names.some((n) => /^classes\d*\.dex$/u.test(n))) return { type: "apk", magic: "PK" };
      if (names.some((n) => /^Payload\/[^/]+\.app\//u.test(n))) return { type: "ipa", magic: "PK" };
      if (has("[Content_Types].xml")) return { type: "ooxml", magic: "PK" };
      if (has("META-INF/MANIFEST.MF") || ext === ".jar") return { type: "jar", magic: "PK" };
      return { type: "zip", magic: "PK" };
    }
    if (h[0] === 0x1f && h[1] === 0x8b) return { type: "gzip", magic: "1f8b" };
    if (h.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d]))) return { type: "wasm", magic: "0061736d" };
    if (h.subarray(0, 4).equals(Buffer.from("hsqs"))) return { type: "squashfs", magic: "hsqs" };
    if (h.subarray(0, 4).toString("latin1") === "dex\n") return { type: "dex", magic: "dex" };
    if (h.subarray(0, 5).toString("latin1") === "%PDF-") return { type: "pdf", magic: "%PDF-" };
    if (h.subarray(0, 4).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0]))) return { type: "ole", magic: "d0cf11e0" };
    if (h.subarray(0, 16).toString("latin1") === "SQLite format 3\0") return { type: "sqlite", magic: "SQLite" };
    if ([0xd4c3b2a1, 0xa1b2c3d4, 0x0a0d0d0a].includes(be)) return { type: "pcap", magic: be.toString(16) };
    if (h.readUInt32LE(0) === 4 && h.length > 20 && h.subarray(16, 24).toString("latin1").startsWith('{"files"')) return { type: "asar", magic: "pickle+json" };
  }
  if (h.length >= 262 && h.subarray(257, 262).toString("latin1") === "ustar") return { type: "tar", magic: "ustar" };
  if (isMostlyText(h)) {
    if (h.subarray(0, 2).toString() === "#!") return { type: "script", magic: "#!" };
    if ([".js", ".mjs", ".cjs"].includes(ext)) return { type: "javascript", magic: "text" };
    return { type: "text", magic: "text" };
  }
  return { type: "unknown", magic: h.subarray(0, 4).toString("hex") };
}

export function identify(path: string): Identity {
  const st = statSync(path);
  if (st.isDirectory()) {
    const notes: string[] = []; const pkg = join(path, "package.json"); let type: SampleType = "directory";
    if (existsSync(pkg)) { try { const j = JSON.parse(readFileSync(pkg, "utf8")) as { main?: string; dependencies?: Record<string, string> }; notes.push(`package.json name=${(j as { name?: string }).name ?? "?"}`); type = "js-application"; } catch { notes.push("package.json unreadable"); } }
    else if (readdirSync(path).some((f) => /\.(m?js|cjs)$/u.test(f))) type = "js-application";
    return { path, type, size: 0, md5: "", sha1: "", sha256: "", entropy: 0, magic: "directory", notes };
  }
  if (!st.isFile()) throw new Error(`not a regular file or directory: ${path}`);
  const hs = hashes(path); const notes: string[] = []; const c = classify(path, hs.head, notes);
  return { path, type: c.type, size: hs.size, md5: hs.md5, sha1: hs.sha1, sha256: hs.sha256, entropy: hs.entropy, magic: c.magic, notes };
}
