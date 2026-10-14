import { createHash } from "node:crypto";
import { basename, resolve } from "node:path";
import { createEvidence } from "@rtk/evidence";
import type { Evidence } from "@rtk/evidence";
import type { Anomaly, Quotas, RawEntry } from "./types.ts";
import { EntryError, QuotaError, resolveQuotas } from "./types.ts";
import { bufferSource, fileSource } from "./source.ts";
import type { Source } from "./source.ts";
import { analyzeListing, CONTAINER_KINDS, isBlocking, mkAnomaly, openContainer, segmentsOf } from "./archive.ts";
import { Budget, consumeEntry } from "./consume.ts";
import { detectKind } from "./kind.ts";
import type { Kind } from "./kind.ts";

export const PROVIDER = { id: "rtk-artifacts", name: "RTK safe archive inspection and extraction", version: "1" };

export interface EntryReport {
  path: string; type: string; kind: Kind | null; size: number | null; declared_size: number | null; compressed_size: number | null;
  crc32: string | null; sha256: string | null; mode: string | null; link_target: string | null; encrypted: boolean; method: string;
  anomalies: string[]; nested?: ArchiveReport; nested_note?: string;
}
export interface ArchiveReport {
  format: string; flavor: string | null; depth: number;
  entries: EntryReport[]; truncated: boolean;
  totals: { entries: number; files: number; dirs: number; links: number; uncompressed_bytes: number; compressed_bytes: number; by_kind: Record<string, number> };
}

interface Ctx { budget: Budget; q: Quotas; anomalies: Anomaly[]; aborted: { v: boolean } }

function flavorOf(format: string, entries: RawEntry[]): string | null {
  if (format !== "zip") return null;
  const n = new Set(entries.map((e) => e.name));
  const has = (p: string) => n.has(p), starts = (p: string) => entries.some((e) => e.name.startsWith(p));
  if (has("AndroidManifest.xml") && has("classes.dex")) return "apk";
  if (has("AndroidManifest.xml") && has("classes.jar")) return "aar";
  if (starts("Payload/") && entries.some((e) => /^Payload\/[^/]+\.app\//u.test(e.name))) return "ipa";
  if (has("[Content_Types].xml")) return starts("word/") ? "docx" : starts("xl/") ? "xlsx" : starts("ppt/") ? "pptx" : "ooxml";
  if (has("META-INF/MANIFEST.MF")) return "jar";
  return null;
}

async function inspectSource(src: Source, ctx: Ctx, depth: number, chain: string, nameHint: string): Promise<ArchiveReport> {
  const opened = await openContainer(src, ctx.budget, chain, { toFile: depth === 0, nameHint });
  try {
    ctx.anomalies.push(...opened.anomalies);
    const an = analyzeListing(opened.entries, ctx.q, chain); ctx.anomalies.push(...an.anomalies);
    const report: ArchiveReport = { format: opened.format, flavor: flavorOf(opened.format, opened.entries), depth, entries: [], truncated: opened.truncated, totals: { entries: opened.entries.length, files: 0, dirs: 0, links: 0, uncompressed_bytes: 0, compressed_bytes: 0, by_kind: {} } };
    if (opened.anomalies.some((a) => a.fatal)) ctx.aborted.v = true;
    for (const e of opened.entries) {
      const codes = (an.byEntry.get(e.index) ?? []).map((a) => a.code);
      const er: EntryReport = {
        path: e.name, type: e.type, kind: null, size: null, declared_size: e.declaredSize, compressed_size: e.compressedSize,
        crc32: e.crc32 === null ? null : (e.crc32 >>> 0).toString(16).padStart(8, "0"), sha256: null,
        mode: e.mode === null ? null : (e.mode & 0o7777).toString(8).padStart(4, "0"), link_target: e.linkTarget, encrypted: e.encrypted, method: e.method, anomalies: codes,
      };
      report.entries.push(er);
      if (e.type === "dir") report.totals.dirs++; else if (e.type === "symlink" || e.type === "hardlink") report.totals.links++; else report.totals.files++;
      if (e.compressedSize) report.totals.compressed_bytes += e.compressedSize;
      if (ctx.aborted.v) continue;
      if (e.type !== "file" || !e.stream) continue;
      // read the content (streaming, quota-enforced): hash, kind, and buffer nested containers for recursion
      let nestedBufs: Buffer[] | null = null; let nestedBytes = 0; let first = true; let noteNested: string | undefined;
      try {
        const c = await consumeEntry(e, ctx.budget, (chunk) => {
          if (first) {
            first = false; const k = detectKind(chunk);
            if (CONTAINER_KINDS.includes(k)) {
              if (depth + 1 > ctx.q.maxDepth) { ctx.anomalies.push(mkAnomaly("depth-exceeded", e.name, `nested ${k} at depth ${depth + 1} exceeds the depth quota ${ctx.q.maxDepth}; not descended`, chain)); er.anomalies.push("depth-exceeded"); noteNested = "depth quota reached"; }
              else nestedBufs = [];
            }
          }
          if (nestedBufs) { nestedBytes += chunk.length; if (nestedBytes > ctx.q.maxNestedBytes) { nestedBufs = null; noteNested = "nested archive larger than maxNestedBytes; not inspected"; ctx.anomalies.push(mkAnomaly("nested-too-large", e.name, noteNested, chain)); er.anomalies.push("nested-too-large"); } else nestedBufs.push(chunk); }
        });
        er.size = c.size; er.sha256 = c.sha256; er.kind = detectKind(c.head);
        report.totals.uncompressed_bytes += c.size; report.totals.by_kind[er.kind] = (report.totals.by_kind[er.kind] ?? 0) + 1;
        if (noteNested) er.nested_note = noteNested;
        if (nestedBufs) {
          const buf = Buffer.concat(nestedBufs);
          er.nested = await inspectSource(bufferSource(buf), ctx, depth + 1, `${chain}!${e.name}`, basename(e.name));
          if (ctx.aborted.v) report.truncated = true;
        }
      } catch (err) {
        if (err instanceof QuotaError) { const a = mkAnomaly(err.code, e.name, err.message, chain, true); ctx.anomalies.push(a); er.anomalies.push(err.code); report.truncated = true; ctx.aborted.v = true; }
        else if (err instanceof EntryError) { ctx.anomalies.push(mkAnomaly(err.code, e.name, err.message, chain)); er.anomalies.push(err.code); }
        else throw err;
      }
    }
    return report;
  } finally { opened.close(); }
}

function fileSha256(src: Source): string {
  const h = createHash("sha256"); for (let o = 0; o < src.size; o += 1 << 20) h.update(src.read(o, 1 << 20)); return h.digest("hex");
}

export const ARCHIVE_LIMITATIONS = [
  "Static inspection only: entries are decompressed in memory/streams to hash and classify them, nothing is executed and nothing is written to disk (gzip top-level streams are spooled to a private temp file that is deleted).",
  "Format support: zip (+jar/apk/ipa/aar/docx by structure), tar, tar.gz/gzip, asar. Not supported: 7z, rar, xz, bzip2, zip multi-volume, zip AES decryption, zip methods other than stored/deflate, tar sparse/multi-volume.",
  "Encrypted zip entries are reported but their contents are not read (so they cannot be hashed, classified or recursed into).",
  "Kinds are by magic bytes and a text heuristic over the first 8 KiB; 'pe' means an MZ header only (managed/native not distinguished).",
  "Nested archives are inspected recursively up to quotas.maxDepth; deeper ones and ones over maxNestedBytes are reported but not opened. Total-size and ratio quotas are shared across nesting.",
  "Zip entry names without the UTF-8 flag are decoded as Latin-1 (not CP437); Info-ZIP unicode-path extra fields are ignored.",
  "Quota breaches stop the inspection (truncated=true); entries after the breach are listed but not hashed.",
];

export async function inspectArchive(path: string, quotas?: Partial<Quotas>): Promise<Evidence> {
  const q = resolveQuotas(quotas); const abs = resolve(path);
  const src = fileSource(abs);
  try {
    const sha = fileSha256(src);
    const ctx: Ctx = { budget: new Budget(q), q, anomalies: [], aborted: { v: false } };
    const report = await inspectSource(src, ctx, 0, basename(abs), basename(abs));
    const sev = { high: 0, medium: 0, low: 0, info: 0 }; for (const a of ctx.anomalies) sev[a.severity]++;
    return createEvidence({
      subject: { name: basename(abs), digest: { sha256: sha }, local_path: abs, format: report.flavor ?? report.format, architecture: null },
      provider: PROVIDER, predicate_type: "rtk.artifacts", operation: "inspect_archive", parameters: { quotas: q },
      normalized_result: { archive: report, anomalies: ctx.anomalies, anomaly_counts: sev, quota_breached: ctx.anomalies.find((a) => a.fatal)?.code ?? null, safe_to_extract_strict: !ctx.anomalies.some((a) => a.fatal || isBlocking(a.code)) },
      confidence: "observed", authority: "shipped-artifact", limitations: ARCHIVE_LIMITATIONS,
      locations: report.entries.filter((e) => e.sha256).map((e) => ({ kind: "archive-entry", path: e.path, sha256: e.sha256, size: e.size })),
    });
  } finally { src.close(); }
}

/** Flatten helper for callers: every anomaly code present in an inspection Evidence. */
export function anomalyCodes(ev: Evidence): string[] { return [...new Set(((ev.normalized_result as { anomalies: Anomaly[] }).anomalies).map((a) => a.code))]; }
export { segmentsOf };
