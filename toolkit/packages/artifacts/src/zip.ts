import { createInflateRaw, inflateRawSync } from "node:zlib";
import { Readable } from "node:stream";
import type { Quotas, RawEntry, EntryType, AnomalyCode } from "./types.ts";
import { EntryError } from "./types.ts";
import type { Source } from "./source.ts";
import { chunks } from "./source.ts";

export interface Listing { format: string; entries: RawEntry[]; anomalies: { code: AnomalyCode; entry: string | null; detail: string; fatal?: boolean }[]; truncated: boolean }

const u64 = (b: Buffer, o: number): number => { const v = b.readBigUInt64LE(o); return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(v); };

async function* deflated(src: Source, start: number, len: number): AsyncGenerator<Buffer> {
  const inflater = createInflateRaw();
  const feeder = Readable.from(chunks(src, start, len), { objectMode: true });
  feeder.on("error", (e) => inflater.destroy(e));
  feeder.pipe(inflater);
  try { for await (const c of inflater) yield c as Buffer; }
  catch (e) { throw new EntryError("corrupt-data", `deflate stream error: ${(e as Error).message}`); }
  finally { feeder.destroy(); inflater.destroy(); }
}

export function isZip(head: Buffer): boolean { return head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && (head[2] === 3 || head[2] === 5 || head[2] === 7); }

export function readZip(src: Source, q: Quotas): Listing {
  const out: Listing = { format: "zip", entries: [], anomalies: [], truncated: false };
  const corrupt = (detail: string) => { out.anomalies.push({ code: "corrupt-archive", entry: null, detail }); return out; };
  if (src.size < 22) return corrupt("file too small for a zip end-of-central-directory record");
  const tailLen = Math.min(src.size, 22 + 0xffff); const tail = src.read(src.size - tailLen, tailLen);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === 0x06054b50 && i + 22 + tail.readUInt16LE(i + 20) <= tail.length) { eocd = i; break; }
  }
  if (eocd < 0) return corrupt("no end-of-central-directory record");
  const eocdPos = src.size - tailLen + eocd;
  let total = tail.readUInt16LE(eocd + 10), cdSize = tail.readUInt32LE(eocd + 12), cdOff = tail.readUInt32LE(eocd + 16);
  if (total === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
    const loc = eocdPos >= 20 ? src.read(eocdPos - 20, 20) : Buffer.alloc(0);
    if (loc.length === 20 && loc.readUInt32LE(0) === 0x07064b50) {
      const z = u64(loc, 8); const rec = src.read(z, 56);
      if (rec.length === 56 && rec.readUInt32LE(0) === 0x06064b50) { total = u64(rec, 32); cdSize = u64(rec, 40); cdOff = u64(rec, 48); }
      else return corrupt("bad zip64 end-of-central-directory record");
    } else return corrupt("zip64 markers present but no zip64 locator");
  }
  if (total > q.maxEntries) {
    out.anomalies.push({ code: "entry-count-exceeded", entry: null, detail: `archive declares ${total} entries (quota ${q.maxEntries})`, fatal: true });
    out.truncated = true; return out;
  }
  if (cdOff + cdSize > src.size || cdSize > 256 * 1024 * 1024) return corrupt("central directory lies outside the file");
  const cd = src.read(cdOff, cdSize);
  let p = 0;
  for (let i = 0; i < total; i++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) { corrupt(`central directory entry ${i} is malformed (offset ${p})`); break; }
    const madeBy = cd.readUInt16LE(p + 4), flags = cd.readUInt16LE(p + 8), method = cd.readUInt16LE(p + 10), crc = cd.readUInt32LE(p + 16);
    let csize = cd.readUInt32LE(p + 20), usize = cd.readUInt32LE(p + 24);
    const nl = cd.readUInt16LE(p + 28), xl = cd.readUInt16LE(p + 30), cl = cd.readUInt16LE(p + 32);
    const extAttr = cd.readUInt32LE(p + 38); let lho = cd.readUInt32LE(p + 42);
    if (p + 46 + nl + xl + cl > cd.length) { corrupt(`central directory entry ${i} overruns the directory`); break; }
    const nameBuf = cd.subarray(p + 46, p + 46 + nl);
    const name = (flags & 0x800) ? nameBuf.toString("utf8") : nameBuf.toString("latin1");
    const extra = cd.subarray(p + 46 + nl, p + 46 + nl + xl);
    for (let e = 0; e + 4 <= extra.length;) { // zip64 extended info
      const id = extra.readUInt16LE(e), sz = extra.readUInt16LE(e + 2);
      if (id === 1) { let o = e + 4; if (usize === 0xffffffff && o + 8 <= e + 4 + sz) { usize = u64(extra, o); o += 8; } if (csize === 0xffffffff && o + 8 <= e + 4 + sz) { csize = u64(extra, o); o += 8; } if (lho === 0xffffffff && o + 8 <= e + 4 + sz) { lho = u64(extra, o); } }
      e += 4 + sz;
    }
    p += 46 + nl + xl + cl;
    const unixMode = (madeBy >> 8) === 3 ? (extAttr >>> 16) : null;
    const fmt = unixMode === null ? 0 : unixMode & 0o170000;
    let type: EntryType = "file";
    if (fmt === 0o120000) type = "symlink"; else if (fmt === 0o040000 || name.endsWith("/")) type = "dir";
    else if (fmt === 0o020000 || fmt === 0o060000) type = "device"; else if (fmt === 0o010000) type = "fifo"; else if (fmt !== 0 && fmt !== 0o100000) type = "other";
    const encrypted = (flags & 1) !== 0 || method === 99;
    const entry: RawEntry = {
      index: i, name, type, declaredSize: usize, compressedSize: csize, mode: unixMode === null ? null : unixMode & 0o7777, linkTarget: null, encrypted,
      crc32: (flags & 8) && crc === 0 ? crc : crc, method: method === 0 ? "stored" : method === 8 ? "deflate" : `method-${method}`, flags: [], stream: null,
    };
    if (encrypted) entry.flags.push({ code: "encrypted-entry", detail: method === 99 ? "WinZip AES encrypted entry" : "traditional (ZipCrypto) encrypted entry; contents not read" });
    // local header cross-check (central-vs-local disagreement is a known parser-differential trick)
    const lh = src.read(lho, 30);
    if (lh.length < 30 || lh.readUInt32LE(0) !== 0x04034b50) { entry.flags.push({ code: "corrupt-data", detail: `no local file header at offset ${lho}` }); out.entries.push(entry); continue; }
    const lnl = lh.readUInt16LE(26), lxl = lh.readUInt16LE(28);
    const lname = src.read(lho + 30, lnl);
    if (!lname.equals(nameBuf)) entry.flags.push({ code: "local-header-mismatch", detail: `local header name ${JSON.stringify(lname.toString("latin1"))} differs from central directory name` });
    const dataStart = lho + 30 + lnl + lxl;
    if (type === "file" || type === "symlink") {
      if (dataStart + csize > src.size) { entry.flags.push({ code: "corrupt-data", detail: "entry data extends past end of file" }); }
      else if (!encrypted && (method === 0 || method === 8)) {
        entry.stream = method === 0 ? () => chunks(src, dataStart, csize) : () => deflated(src, dataStart, csize);
      } else if (!encrypted) entry.flags.push({ code: "unsupported-compression", detail: `compression method ${method} is not supported` });
      if (type === "symlink" && entry.stream && csize <= 65536) {
        try { const raw = src.read(dataStart, csize); entry.linkTarget = (method === 0 ? raw : inflateRawSync(raw, { maxOutputLength: q.maxNameLength + 1 })).toString("utf8"); } catch { entry.flags.push({ code: "corrupt-data", detail: "unreadable symlink target" }); }
      }
    }
    if (type === "dir") entry.stream = null;
    out.entries.push(entry);
  }
  if (out.entries.length !== total && !out.anomalies.some((a) => a.code === "corrupt-archive")) out.anomalies.push({ code: "entry-count-mismatch", entry: null, detail: `declared ${total}, parsed ${out.entries.length}` });
  return out;
}
