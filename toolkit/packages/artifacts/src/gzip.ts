import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Budget } from "./consume.ts";
import { EntryError, QuotaError } from "./types.ts";
import type { Source } from "./source.ts";
import { bufferSource, chunks, fileSource } from "./source.ts";

export interface Gunzipped { source: Source; size: number; close(): void }

/**
 * Decompress a gzip stream with quotas enforced while streaming (total budget + ratio).
 * `toFile` spools to a private 0700 temp dir (for top-level archives), otherwise buffers in memory up to `maxBytes`.
 * Returns null when buffering would exceed maxBytes (caller records nested-too-large).
 */
export async function gunzipSource(src: Source, budget: Budget, opts: { toFile: boolean; maxBytes?: number }): Promise<Gunzipped | null> {
  const q = budget.quotas;
  const gz = createGunzip();
  const feeder = Readable.from(chunks(src, 0, src.size), { objectMode: true });
  feeder.on("error", (e) => gz.destroy(e)); feeder.pipe(gz);
  let size = 0; const bufs: Buffer[] = []; let dir: string | null = null; let fd = -1; let file = "";
  const cleanup = () => { if (fd >= 0) { try { closeSync(fd); } catch { /* */ } fd = -1; } if (dir) rmSync(dir, { recursive: true, force: true }); dir = null; };
  try {
    if (opts.toFile) { dir = mkdtempSync(join(tmpdir(), "rtk-gz-")); file = join(dir, "inner"); fd = openSync(file, "wx", 0o600); }
    for await (const c of gz as AsyncIterable<Buffer>) {
      size += c.length; // not added to budget.total: the inner entries are counted when they are consumed
      if (size > q.maxEntrySize) throw new QuotaError("entry-size-exceeded", `gzip stream exceeds ${q.maxEntrySize} bytes`);
      if (budget.total + size > q.maxTotalSize) throw new QuotaError("total-size-exceeded", `total uncompressed size exceeds ${q.maxTotalSize} bytes`);
      if (size > q.ratioMinBytes && size / Math.max(1, src.size) > q.maxRatio) throw new QuotaError("ratio-exceeded", `gzip ratio exceeds ${q.maxRatio}:1 (${size} bytes from ${src.size})`);
      if (opts.toFile) writeSync(fd, c); else { if (size > (opts.maxBytes ?? q.maxNestedBytes)) { cleanup(); return null; } bufs.push(c); }
    }
  } catch (e) {
    cleanup();
    if (e instanceof QuotaError) throw e;
    throw new EntryError("corrupt-data", `gzip error: ${(e as Error).message}`);
  } finally { feeder.destroy(); gz.destroy(); }
  if (opts.toFile) { closeSync(fd); fd = -1; const s = fileSource(file); return { source: s, size, close() { s.close(); cleanup(); } }; }
  const b = Buffer.concat(bufs); return { source: bufferSource(b), size, close() {} };
}
