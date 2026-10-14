import { closeSync, openSync, readSync, statSync } from "node:fs";

export interface FoundString { value: string; offset: number; encoding: "ascii" | "utf16le" }
export interface StringOptions { minLength?: number; maxStrings?: number; maxBytes?: number; utf16?: boolean }

/** Bounded ASCII + UTF-16LE string extraction (like `strings -a` + `-el`). Reports truncation. */
export function extractStrings(path: string, o: StringOptions = {}): { strings: FoundString[]; truncated: boolean; scannedBytes: number } {
  const min = o.minLength ?? 6, maxStrings = o.maxStrings ?? 20000, maxBytes = o.maxBytes ?? 64 << 20;
  const size = Math.min(statSync(path).size, maxBytes); const fd = openSync(path, "r"); const out: FoundString[] = []; let truncated = size < statSync(path).size;
  try {
    const chunk = Buffer.alloc(1 << 20); let pos = 0, carryA = "", carryAStart = 0; let carryU = "", carryUStart = 0; let prev = Buffer.alloc(0);
    const pushA = (v: string, off: number) => { if (v.length >= min) { if (out.length >= maxStrings) { truncated = true; return false; } out.push({ value: v, offset: off, encoding: "ascii" }); } return true; };
    const pushU = (v: string, off: number) => { if (v.length >= min) { if (out.length >= maxStrings) { truncated = true; return false; } out.push({ value: v, offset: off, encoding: "utf16le" }); } return true; };
    while (pos < size) {
      const n = readSync(fd, chunk, 0, Math.min(chunk.length, size - pos), pos); if (n <= 0) break; const buf = chunk.subarray(0, n);
      for (let i = 0; i < n; i++) { const b = buf[i]!; if ((b >= 0x20 && b < 0x7f) || b === 9) { if (!carryA) carryAStart = pos + i; carryA += String.fromCharCode(b); } else { if (carryA && !pushA(carryA, carryAStart)) return { strings: out, truncated, scannedBytes: pos + i }; carryA = ""; } }
      if (o.utf16 !== false) {
        const joined = Buffer.concat([prev, buf]); const base = pos - prev.length;
        for (let i = 0; i + 1 < joined.length; i += 2) { /* aligned scan; second pass handles odd alignment */ const lo = joined[i]!, hi = joined[i + 1]!; if (hi === 0 && ((lo >= 0x20 && lo < 0x7f) || lo === 9)) { if (!carryU) carryUStart = base + i; carryU += String.fromCharCode(lo); } else { if (carryU && !pushU(carryU, carryUStart)) return { strings: out, truncated, scannedBytes: pos }; carryU = ""; } }
        prev = joined.length % 2 === 1 ? joined.subarray(joined.length - 1) : Buffer.alloc(0);
      }
      pos += n;
    }
    if (carryA) pushA(carryA, carryAStart); if (carryU) pushU(carryU, carryUStart);
  } finally { closeSync(fd); }
  return { strings: out, truncated, scannedBytes: size };
}
