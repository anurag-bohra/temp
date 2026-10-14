import type { Quotas, RawEntry, EntryType } from "./types.ts";
import type { Source } from "./source.ts";
import { chunks } from "./source.ts";
import type { Listing } from "./zip.ts";
import { looksLikeTarHeader } from "./kind.ts";

const cstr = (b: Buffer): string => { const z = b.indexOf(0); return b.subarray(0, z < 0 ? b.length : z).toString("utf8"); };
function num(b: Buffer): number {
  if (b[0]! & 0x80) { let v = 0n; for (let i = 1; i < b.length; i++) v = (v << 8n) | BigInt(b[i]!); return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(v); }
  const s = cstr(b).trim(); return s === "" ? 0 : parseInt(s, 8);
}
function parsePax(data: Buffer): Record<string, string> {
  const out: Record<string, string> = {}; let p = 0;
  while (p < data.length) {
    const sp = data.indexOf(0x20, p); if (sp < 0) break;
    const len = parseInt(data.subarray(p, sp).toString("ascii"), 10); if (!(len > 0) || p + len > data.length) break;
    const rec = data.subarray(sp + 1, p + len - 1).toString("utf8"); const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    p += len;
  }
  return out;
}

export function readTar(src: Source, q: Quotas): Listing {
  const out: Listing = { format: "tar", entries: [], anomalies: [], truncated: false };
  let pos = 0; let pax: Record<string, string> = {}; let longName: string | null = null, longLink: string | null = null;
  while (pos + 512 <= src.size) {
    const h = src.read(pos, 512);
    if (h.every((x) => x === 0)) break;
    if (!looksLikeTarHeader(h)) { out.anomalies.push({ code: "corrupt-archive", entry: null, detail: `invalid tar header (checksum) at offset ${pos}` }); break; }
    const typeflag = String.fromCharCode(h[156] || 0x30);
    let size = num(h.subarray(124, 136));
    const magic = h.subarray(257, 262).toString("latin1");
    let name = cstr(h.subarray(0, 100)); if (magic === "ustar") { const pre = cstr(h.subarray(345, 500)); if (pre) name = pre + "/" + name; }
    let linkname = cstr(h.subarray(157, 257));
    const dataStart = pos + 512;
    if (typeflag === "x" || typeflag === "g" || typeflag === "L" || typeflag === "K") {
      if (size > 1024 * 1024 || dataStart + size > src.size) { out.anomalies.push({ code: "corrupt-archive", entry: null, detail: `oversized or truncated ${typeflag} extension header at ${pos}` }); break; }
      const data = src.read(dataStart, size);
      if (typeflag === "x") pax = parsePax(data); else if (typeflag === "L") longName = cstr(data); else if (typeflag === "K") longLink = cstr(data);
      pos = dataStart + Math.ceil(size / 512) * 512; continue;
    }
    if (pax.path !== undefined) name = pax.path; else if (longName !== null) name = longName;
    if (pax.linkpath !== undefined) linkname = pax.linkpath; else if (longLink !== null) linkname = longLink;
    if (pax.size !== undefined) size = parseInt(pax.size, 10) || 0;
    pax = {}; longName = null; longLink = null;
    if (out.entries.length >= q.maxEntries) { out.anomalies.push({ code: "entry-count-exceeded", entry: null, detail: `more than ${q.maxEntries} entries`, fatal: true }); out.truncated = true; break; }
    let type: EntryType = "file";
    switch (typeflag) { case "0": case "7": break; case "1": type = "hardlink"; break; case "2": type = "symlink"; break; case "3": case "4": type = "device"; break; case "5": type = "dir"; break; case "6": type = "fifo"; break; default: type = "other"; }
    const hasData = type === "file" || type === "other";
    const entry: RawEntry = {
      index: out.entries.length, name, type, declaredSize: hasData ? size : null, compressedSize: hasData ? size : null, mode: num(h.subarray(100, 108)) & 0o7777,
      linkTarget: type === "symlink" || type === "hardlink" ? linkname : null, encrypted: false, crc32: null, method: "stored", flags: [], stream: null,
    };
    if (type === "other" && typeflag !== "S") entry.flags.push({ code: "special-file", detail: `unsupported tar typeflag ${JSON.stringify(typeflag)}` });
    if (hasData && type === "file") {
      if (dataStart + size > src.size) { entry.flags.push({ code: "size-mismatch", detail: `header declares ${size} bytes but only ${Math.max(0, src.size - dataStart)} remain (truncated archive)` }); out.entries.push(entry); out.truncated = true; break; }
      entry.stream = () => chunks(src, dataStart, size);
    }
    out.entries.push(entry);
    pos = dataStart + (hasData ? Math.ceil(size / 512) * 512 : 0);
  }
  return out;
}
