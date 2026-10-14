export type Kind = "elf" | "pe" | "macho" | "dex" | "java-class" | "script" | "zip" | "gzip" | "tar" | "asar" | "xz" | "bzip2" | "7z" | "rar" | "sqlite" | "pdf" | "image" | "wasm" | "xml" | "text" | "empty" | "data";

export function looksLikeTarHeader(b: Buffer): boolean {
  if (b.length < 512) return false;
  let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : b[i]!;
  const field = b.subarray(148, 156).toString("latin1").replace(/\0.*$/su, "").trim();
  if (!/^[0-7]+$/u.test(field) || parseInt(field, 8) !== sum) return false;
  return b[0] !== 0;
}
function looksLikeAsar(b: Buffer): boolean {
  if (b.length < 20 || b.readUInt32LE(0) !== 4) return false;
  const hp = b.readUInt32LE(4), inner = b.readUInt32LE(8), jl = b.readUInt32LE(12);
  return hp >= 8 && inner + 4 <= hp + 0 && jl <= inner && (b[16] === 0x7b);
}
/** Classify by magic bytes (never by extension). `head` should be the first >= 512 bytes (more is fine). */
export function detectKind(head: Buffer): Kind {
  const n = head.length; if (n === 0) return "empty";
  const u32be = n >= 4 ? head.readUInt32BE(0) : 0;
  if (n >= 4 && u32be === 0x7f454c46) return "elf";
  if (n >= 4 && head.subarray(0, 4).toString("latin1") === "dex\n") return "dex";
  if (n >= 4 && (u32be === 0xfeedface || u32be === 0xfeedfacf || u32be === 0xcefaedfe || u32be === 0xcffaedfe)) return "macho";
  if (n >= 8 && u32be === 0xcafebabe) return head.readUInt32BE(4) < 45 ? "macho" : "java-class";
  if (n >= 2 && head[0] === 0x4d && head[1] === 0x5a) return "pe";
  if (n >= 2 && head[0] === 0x23 && head[1] === 0x21) return "script";
  if (n >= 4 && head[0] === 0x50 && head[1] === 0x4b && ((head[2] === 3 && head[3] === 4) || (head[2] === 5 && head[3] === 6) || (head[2] === 7 && head[3] === 8))) return "zip";
  if (n >= 3 && head[0] === 0x1f && head[1] === 0x8b && head[2] === 8) return "gzip";
  if (looksLikeAsar(head)) return "asar";
  if (n >= 262 && head.subarray(257, 262).toString("latin1") === "ustar") return "tar";
  if (looksLikeTarHeader(head)) return "tar";
  if (n >= 6 && head.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))) return "xz";
  if (n >= 3 && head.subarray(0, 3).toString("latin1") === "BZh") return "bzip2";
  if (n >= 6 && head.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))) return "7z";
  if (n >= 6 && head.subarray(0, 4).toString("latin1") === "Rar!") return "rar";
  if (n >= 15 && head.subarray(0, 15).toString("latin1") === "SQLite format 3") return "sqlite";
  if (n >= 5 && head.subarray(0, 5).toString("latin1") === "%PDF-") return "pdf";
  if (n >= 4 && head.subarray(0, 4).equals(Buffer.from([0, 0x61, 0x73, 0x6d]))) return "wasm";
  if ((n >= 8 && u32be === 0x89504e47) || (n >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) || (n >= 4 && head.subarray(0, 3).toString("latin1") === "GIF")) return "image";
  // text heuristic over the first 8 KiB: no NUL, few control chars, valid-ish UTF-8
  const s = head.subarray(0, Math.min(n, 8192)); let bad = 0;
  for (const c of s) { if (c === 0) return "data"; if (c < 9 || (c > 13 && c < 32)) bad++; }
  if (bad / s.length > 0.02) return "data";
  const txt = s.toString("utf8").trimStart();
  if (txt.startsWith("<?xml") || txt.startsWith("<manifest")) return "xml";
  return "text";
}
