/** IOC extraction from string literals, including recursive base64 / hex decoding. */

export type IocKind = "url" | "ip";
export interface IocHit { kind: IocKind; value: string; encoding: string[] }

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s'"`<>\\)\]}]+/giu;
const IP_RE = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)/gu;
const B64_RE = /^[A-Za-z0-9+/_-]{12,}={0,2}$/u;
const HEX_RE = /^(?:[0-9a-fA-F]{2}){8,}$/u;
export const MAX_DECODE_DEPTH = 3;

function validIp(s: string): boolean {
  const parts = s.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/u.test(p) && Number(p) <= 255 && (p === "0" || !p.startsWith("0")));
}

export function tryDecodeBase64(s: string): string | null {
  const t = s.trim();
  if (!B64_RE.test(t)) return null;
  const norm = t.replace(/-/gu, "+").replace(/_/gu, "/");
  if (norm.replace(/=+$/u, "").length % 4 === 1) return null;
  const buf = Buffer.from(norm, "base64");
  if (buf.length < 6) return null;
  let printable = 0;
  for (const b of buf) if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) printable++;
  if (printable / buf.length < 0.85) return null;
  return buf.toString("latin1");
}

export function tryDecodeHex(s: string): string | null {
  const t = s.trim();
  if (!HEX_RE.test(t)) return null;
  const buf = Buffer.from(t, "hex");
  let printable = 0;
  for (const b of buf) if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) printable++;
  return printable / buf.length >= 0.85 ? buf.toString("latin1") : null;
}

/** Scan a literal; decoded layers are scanned recursively up to MAX_DECODE_DEPTH. */
export function scanLiteral(s: string, encoding: string[] = [], out: IocHit[] = []): IocHit[] {
  if (s.length > 200_000) return out;
  for (const m of s.matchAll(URL_RE)) out.push({ kind: "url", value: m[0].replace(/[.,;]+$/u, ""), encoding });
  for (const m of s.matchAll(IP_RE)) if (validIp(m[0])) out.push({ kind: "ip", value: m[0], encoding });
  if (encoding.length < MAX_DECODE_DEPTH) {
    const b = tryDecodeBase64(s);
    if (b !== null) scanLiteral(b, [...encoding, "base64"], out);
    const h = tryDecodeHex(s);
    if (h !== null) scanLiteral(h, [...encoding, "hex"], out);
  }
  return out;
}
