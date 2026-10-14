import type { Quotas, RawEntry, EntryType } from "./types.ts";
import type { Source } from "./source.ts";
import { chunks } from "./source.ts";
import type { Listing } from "./zip.ts";

interface Node { files?: Record<string, Node>; size?: number; offset?: string; unpacked?: boolean; executable?: boolean; link?: string; integrity?: { algorithm: string; hash: string; blockSize?: number; blocks?: string[] } }

/** Parse an Electron .asar: [u32=4][u32 headerPickleSize][u32 payload][u32 jsonLen][json][file data...]. Own parser (the format is tiny); @electron/asar is only used by tests to build fixtures. */
export function readAsar(src: Source, q: Quotas): Listing {
  const out: Listing = { format: "asar", entries: [], anomalies: [], truncated: false };
  const bad = (detail: string) => { out.anomalies.push({ code: "corrupt-archive", entry: null, detail }); return out; };
  const h = src.read(0, 16);
  if (h.length < 16 || h.readUInt32LE(0) !== 4) return bad("not an asar (bad size-pickle marker)");
  const hp = h.readUInt32LE(4), inner = h.readUInt32LE(8), jl = h.readUInt32LE(12);
  if (hp !== inner + 4 || jl > inner || 8 + hp > src.size || hp > 64 * 1024 * 1024) return bad("asar header sizes are inconsistent or exceed the file");
  let root: Node;
  try { root = JSON.parse(src.read(16, jl).toString("utf8")) as Node; } catch { return bad("asar header is not valid JSON"); }
  if (!root || typeof root !== "object" || typeof root.files !== "object") return bad("asar header has no file tree");
  const dataBase = 8 + hp;
  const ranges: { start: number; end: number; idx: number }[] = [];
  const walk = (node: Node, prefix: string, depth: number): void => {
    if (depth > 64) { out.anomalies.push({ code: "depth-exceeded", entry: prefix, detail: "asar directory tree deeper than 64" }); return; }
    for (const [key, n] of Object.entries(node.files ?? {})) {
      if (out.entries.length >= q.maxEntries) { if (!out.truncated) out.anomalies.push({ code: "entry-count-exceeded", entry: null, detail: `more than ${q.maxEntries} entries`, fatal: true }); out.truncated = true; return; }
      const name = prefix ? `${prefix}/${key}` : key;
      const idx = out.entries.length;
      if (n && typeof n === "object" && n.files) { out.entries.push({ index: idx, name: name + "/", type: "dir", declaredSize: null, compressedSize: null, mode: 0o755, linkTarget: null, encrypted: false, crc32: null, method: "none", flags: [], stream: null }); walk(n, name, depth + 1); continue; }
      if (n && typeof n.link === "string") { out.entries.push({ index: idx, name, type: "symlink", declaredSize: null, compressedSize: null, mode: 0o777, linkTarget: n.link, encrypted: false, crc32: null, method: "none", flags: [], stream: null }); continue; }
      const type: EntryType = "file";
      const e: RawEntry = { index: idx, name, type, declaredSize: null, compressedSize: null, mode: n?.executable ? 0o755 : 0o644, linkTarget: null, encrypted: false, crc32: null, method: "stored", flags: [], stream: null };
      out.entries.push(e);
      const size = n?.size;
      if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) { e.flags.push({ code: "corrupt-data", detail: "asar file entry has no valid size" }); continue; }
      e.declaredSize = size; e.compressedSize = size;
      if (n.unpacked) { e.flags.push({ code: "asar-unpacked-external", detail: "file is stored outside the archive (<name>.asar.unpacked); not read" }); continue; }
      const off = typeof n.offset === "string" && /^\d+$/u.test(n.offset) ? Number(n.offset) : NaN;
      if (!Number.isSafeInteger(off)) { e.flags.push({ code: "asar-offset-out-of-range", detail: `invalid offset ${JSON.stringify(n.offset)}` }); continue; }
      if (dataBase + off + size > src.size) { e.flags.push({ code: "asar-offset-out-of-range", detail: `range [${off}, ${off + size}) lies outside the archive data region (${src.size - dataBase} bytes)` }); continue; }
      ranges.push({ start: off, end: off + size, idx });
      if (n.integrity && typeof n.integrity.hash === "string" && /^sha256$/iu.test(n.integrity.algorithm ?? "")) e.expectedSha256 = n.integrity.hash.toLowerCase();
      e.stream = () => chunks(src, dataBase + off, size);
    }
  };
  walk(root, "", 0);
  ranges.sort((a, b) => a.start - b.start || a.end - b.end);
  for (let i = 1; i < ranges.length; i++) {
    const a = ranges[i - 1]!, b = ranges[i]!;
    if (b.start < a.end && b.end > b.start && a.end > a.start) for (const r of [a, b]) {
      const e = out.entries[r.idx]!; if (!e.flags.some((f) => f.code === "asar-overlap")) e.flags.push({ code: "asar-overlap", detail: `data range overlaps entry ${JSON.stringify(out.entries[(r === a ? b : a).idx]!.name)}` });
    }
  }
  return out;
}
