import { closeSync, fstatSync, openSync, readSync } from "node:fs";

export interface Source { size: number; read(pos: number, len: number): Buffer; close(): void }

export function fileSource(path: string): Source {
  const fd = openSync(path, "r");
  const size = fstatSync(fd).size;
  return {
    size,
    read(pos, len) {
      len = Math.max(0, Math.min(len, size - pos)); const b = Buffer.alloc(len); let off = 0;
      while (off < len) { const n = readSync(fd, b, off, len - off, pos + off); if (n <= 0) break; off += n; }
      return off === len ? b : b.subarray(0, off);
    },
    close() { try { closeSync(fd); } catch { /* already closed */ } },
  };
}
export function bufferSource(buf: Buffer): Source {
  return { size: buf.length, read: (pos, len) => buf.subarray(Math.max(0, pos), Math.max(0, Math.min(buf.length, pos + len))), close() {} };
}
export async function* chunks(src: Source, start: number, length: number, chunkSize = 64 * 1024): AsyncGenerator<Buffer> {
  let off = 0;
  while (off < length) {
    const b = src.read(start + off, Math.min(chunkSize, length - off));
    if (b.length === 0) return;
    off += b.length; yield b;
    if (off % (chunkSize * 16) === 0) await new Promise<void>((r) => setImmediate(r)); // let timers/aborts run on huge inputs
  }
}
