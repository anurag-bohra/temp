import { crc32 as zcrc32 } from "node:zlib";
import { createHash } from "node:crypto";
import type { Quotas, RawEntry } from "./types.ts";
import { EntryError, QuotaError } from "./types.ts";

export class Budget {
  total = 0;
  quotas: Quotas;
  constructor(q: Quotas) { this.quotas = q; }
}

export interface Consumed { size: number; sha256: string; head: Buffer }

/**
 * Stream an entry's decompressed bytes, enforcing quotas AS BYTES ARRIVE (declared sizes are never trusted):
 * actual > declared aborts immediately, per-entry / total / ratio quotas abort mid-stream, CRC / integrity are
 * verified at the end. `onChunk` may throw to abort (e.g. write failure).
 */
export async function consumeEntry(entry: RawEntry, budget: Budget, onChunk?: (c: Buffer) => void | Promise<void>): Promise<Consumed> {
  if (!entry.stream) throw new EntryError("corrupt-data", "entry has no readable data");
  const q = budget.quotas;
  const hash = createHash("sha256"); const heads: Buffer[] = []; let headLen = 0;
  let size = 0, crc = 0;
  const csize = Math.max(1, entry.compressedSize ?? 1);
  const gen = entry.stream();
  try {
    for await (const chunk of gen) {
      size += chunk.length;
      if (entry.declaredSize !== null && size > entry.declaredSize) throw new EntryError("size-mismatch", `entry produced more than its declared ${entry.declaredSize} bytes (stopped at ${size})`);
      if (size > q.maxEntrySize) throw new QuotaError("entry-size-exceeded", `entry exceeds ${q.maxEntrySize} bytes`);
      budget.total += chunk.length;
      if (budget.total > q.maxTotalSize) throw new QuotaError("total-size-exceeded", `total uncompressed size exceeds ${q.maxTotalSize} bytes`);
      if (size > q.ratioMinBytes && size / csize > q.maxRatio) throw new QuotaError("ratio-exceeded", `compression ratio exceeds ${q.maxRatio}:1 (${size} bytes from ${csize} compressed)`);
      hash.update(chunk); crc = zcrc32(chunk, crc);
      if (headLen < 8192) { heads.push(chunk); headLen += chunk.length; }
      if (onChunk) await onChunk(chunk);
    }
  } finally { await gen.return(undefined); }
  if (entry.declaredSize !== null && size !== entry.declaredSize) throw new EntryError("size-mismatch", `entry declared ${entry.declaredSize} bytes but contained ${size}`);
  if (entry.crc32 !== null && (crc >>> 0) !== (entry.crc32 >>> 0)) throw new EntryError("crc-mismatch", `CRC32 ${(crc >>> 0).toString(16)} != declared ${(entry.crc32 >>> 0).toString(16)}`);
  const sha256 = hash.digest("hex");
  if (entry.expectedSha256 && entry.expectedSha256 !== sha256) throw new EntryError("integrity-mismatch", `sha256 ${sha256} != archive-recorded ${entry.expectedSha256}`);
  return { size, sha256, head: Buffer.concat(heads).subarray(0, 8192) };
}
