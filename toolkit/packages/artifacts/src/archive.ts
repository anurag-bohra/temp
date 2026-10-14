import { posix } from "node:path";
import type { Anomaly, AnomalyCode, Quotas, RawEntry } from "./types.ts";
import { ANOMALY_CODES, FATAL_CODES } from "./types.ts";
import type { Source } from "./source.ts";
import { bufferSource } from "./source.ts";
import { detectKind, looksLikeTarHeader } from "./kind.ts";
import type { Kind } from "./kind.ts";
import type { Budget } from "./consume.ts";
import { readZip } from "./zip.ts";
import type { Listing } from "./zip.ts";
import { readTar } from "./tar.ts";
import { readAsar } from "./asar.ts";
import { gunzipSource } from "./gzip.ts";

export interface Opened { format: string; entries: RawEntry[]; anomalies: Anomaly[]; truncated: boolean; close(): void }

export const mkAnomaly = (code: AnomalyCode, entry: string | null, detail: string, archive: string, fatal?: boolean): Anomaly =>
  ({ code, severity: ANOMALY_CODES[code].severity, entry, detail, archive, fatal: fatal ?? FATAL_CODES.includes(code) });

export const CONTAINER_KINDS: readonly Kind[] = ["zip", "gzip", "tar", "asar"];

/** Pick a reader by magic bytes (never by extension) and list the archive. gzip is decompressed (quota-enforced) and, if it holds a tar, listed as tar.gz. */
export async function openContainer(src: Source, budget: Budget, archive: string, opts: { toFile: boolean; nameHint?: string }): Promise<Opened> {
  const q = budget.quotas;
  const head = src.read(0, 8192);
  const kind = detectKind(head);
  const lift = (l: Listing, fmt: string, close: () => void): Opened => ({
    format: fmt, entries: l.entries, truncated: l.truncated, close,
    anomalies: l.anomalies.map((a) => mkAnomaly(a.code, a.entry, a.detail, archive, a.fatal)),
  });
  switch (kind) {
    case "zip": return lift(readZip(src, q), "zip", () => {});
    case "tar": return lift(readTar(src, q), "tar", () => {});
    case "asar": return lift(readAsar(src, q), "asar", () => {});
    case "gzip": {
      const inner = await gunzipSource(src, budget, { toFile: opts.toFile });
      if (!inner) return { format: "gzip", entries: [], truncated: true, close() {}, anomalies: [mkAnomaly("nested-too-large", null, "decompressed gzip stream exceeds the nested-buffer limit", archive)] };
      const ih = inner.source.read(0, 512);
      if (looksLikeTarHeader(ih) || detectKind(ih) === "tar") return lift(readTar(inner.source, q), "tar.gz", () => inner.close());
      // single compressed file
      const name = (opts.nameHint ?? "data").replace(/\.(gz|tgz)$/iu, "") || "data";
      const isrc = inner.source;
      const entry: RawEntry = {
        index: 0, name, type: "file", declaredSize: inner.size, compressedSize: src.size, mode: null, linkTarget: null, encrypted: false, crc32: null, method: "gzip", flags: [],
        stream: async function* () { for (let o = 0; o < inner.size; o += 65536) yield isrc.read(o, Math.min(65536, inner.size - o)); },
      };
      return { format: "gzip", entries: [entry], truncated: false, anomalies: [], close: () => inner.close() };
    }
    default:
      return { format: "unknown", entries: [], truncated: false, close() {}, anomalies: [mkAnomaly("unsupported-format", null, `not a supported archive (detected: ${kind}); supported: zip/jar/apk/ipa/aar/docx, tar, tar.gz, gzip, asar`, archive)] };
  }
}

export { bufferSource };

/** Split a raw entry name into path segments the way an extractor would: both separators, no empty or "." segments. */
export function segmentsOf(name: string): string[] { return name.replace(/\\/gu, "/").split("/").filter((s) => s !== "" && s !== "."); }

export interface Analysis { anomalies: Anomaly[]; byEntry: Map<number, Anomaly[]> }

/** Names, links, duplicates, collisions, modes: everything decidable from the listing alone. */
export function analyzeListing(entries: RawEntry[], q: Quotas, archive: string): Analysis {
  const anomalies: Anomaly[] = []; const byEntry = new Map<number, Anomaly[]>();
  const add = (e: RawEntry, code: AnomalyCode, detail: string) => { const a = mkAnomaly(code, e.name, detail, archive); anomalies.push(a); const l = byEntry.get(e.index) ?? []; l.push(a); byEntry.set(e.index, l); };
  const exact = new Map<string, number>(); const folded = new Map<string, number>(); const symlinks = new Set<string>();
  for (const e of entries) {
    const n = e.name;
    for (const f of e.flags) add(e, f.code, f.detail);
    if (n === "") add(e, "empty-name", "entry has an empty name");
    if (n.length > q.maxNameLength) add(e, "name-too-long", `name is ${n.length} chars (quota ${q.maxNameLength})`);
    if (/[\u0000-\u001f\u007f]/u.test(n)) add(e, "control-char", `name contains control/NUL character(s): ${JSON.stringify(n).slice(0, 120)}`);
    if (n.startsWith("/") || n.startsWith("\\")) add(e, "absolute-path", `absolute path ${JSON.stringify(n).slice(0, 120)}`);
    if (/^[A-Za-z]:/u.test(n)) add(e, "drive-letter", `drive-letter path ${JSON.stringify(n).slice(0, 120)}`);
    const segs = segmentsOf(n);
    if (segs.includes("..")) add(e, "path-traversal", `path contains '..' segment: ${JSON.stringify(n).slice(0, 120)}`);
    if (n.includes("\\")) add(e, "backslash-separator", "name contains backslash (treated as a separator)");
    const norm = segs.join("/");
    if (e.type !== "dir" || norm !== "") {
      if (exact.has(norm)) add(e, "duplicate-name", `same path as entry #${exact.get(norm)}`);
      else {
        exact.set(norm, e.index);
        const fk = norm.normalize("NFC").toLowerCase();
        if (folded.has(fk)) add(e, "case-collision", `collides case-insensitively with entry #${folded.get(fk)}`); else folded.set(fk, e.index);
      }
    }
    if (e.mode !== null && (e.mode & 0o7000) !== 0 && e.type === "file") add(e, "special-mode", `setuid/setgid/sticky bits (mode ${(e.mode & 0o7777).toString(8)}) will be stripped`);
    if (e.type === "device") add(e, "device-node", "device node entry");
    if (e.type === "fifo") add(e, "special-file", "FIFO entry");
    if (e.type === "symlink") {
      add(e, "symlink", `symlink -> ${JSON.stringify(e.linkTarget)}`);
      const t = e.linkTarget ?? "";
      const base = segs.slice(0, -1).join("/");
      const joined = t.startsWith("/") || /^[A-Za-z]:/u.test(t) ? null : posix.normalize(posix.join(base || ".", t.replace(/\\/gu, "/")));
      if (joined === null || joined === ".." || joined.startsWith("../") || t === "") add(e, "symlink-escape", `symlink target ${JSON.stringify(t)} resolves outside the extraction root`);
      symlinks.add(norm);
    }
    if (e.type === "hardlink") {
      add(e, "hardlink", `hardlink -> ${JSON.stringify(e.linkTarget)}`);
      const t = e.linkTarget ?? "";
      if (t.startsWith("/") || segmentsOf(t).includes("..")) add(e, "hardlink-escape", `hardlink target ${JSON.stringify(t)} points outside the extraction root`);
    }
  }
  // file/dir entries whose path passes through an earlier symlink entry
  const seen = new Set<string>();
  for (const e of entries) {
    const segs = segmentsOf(e.name);
    for (let i = 1; i < segs.length; i++) if (symlinks.has(segs.slice(0, i).join("/")) && seen.has(segs.slice(0, i).join("/"))) { add(e, "symlink-through", `path passes through symlink entry ${JSON.stringify(segs.slice(0, i).join("/"))}`); break; }
    if (e.type === "symlink") seen.add(segs.join("/"));
  }
  return { anomalies, byEntry };
}

export const isBlocking = (c: AnomalyCode): boolean => ANOMALY_CODES[c].blocking;
