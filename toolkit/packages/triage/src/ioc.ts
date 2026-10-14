// IOC extraction and normalisation: URLs, domains, IPs, emails, hashes, registry keys, with defang/refang,
// bounded base64/hex decoding, classification of non-routable/example values, and evidence provenance.
export type IocKind = "url" | "domain" | "ipv4" | "ipv6" | "email" | "md5" | "sha1" | "sha256" | "registry-key" | "windows-path" | "unix-path" | "embedded-resource" | "toolchain";
export type IocClass = "public" | "private" | "loopback" | "link-local" | "documentation" | "reserved" | "example-domain" | "unknown";
export interface Ioc { kind: IocKind; value: string; classification: IocClass; decoded_from?: string; contexts: string[]; evidence_ids: string[] }

export const refang = (s: string): string => s.replace(/\[\.\]|\(\.\)|\{\.\}/gu, ".").replace(/\bhxxp(s?)/giu, "http$1").replace(/\[:\]|\[:\/\/\]/gu, (m) => (m === "[:]" ? ":" : "://")).replace(/\[at\]|\(at\)/giu, "@");
export const defang = (s: string): string => s.replace(/^http/iu, "hxxp").replace(/\./gu, "[.]");

const ipv4Class = (ip: string): IocClass => {
  const [a, b, c] = ip.split(".").map(Number) as [number, number, number];
  if (a === 127) return "loopback"; if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private"; if (a === 169 && b === 254) return "link-local";
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return "documentation";
  if (a === 0 || a >= 224 || (a === 100 && b >= 64 && b <= 127)) return "reserved"; return "public";
};
const EXAMPLE_TLDS = new Set(["invalid", "example", "test", "localhost"]);
const EXAMPLE_DOMAINS = new Set(["example.com", "example.net", "example.org"]);
const domainClass = (d: string): IocClass => { const l = d.toLowerCase(); const tld = l.split(".").pop()!; return EXAMPLE_TLDS.has(tld) || EXAMPLE_DOMAINS.has(l) || [...EXAMPLE_DOMAINS].some((e) => l.endsWith("." + e)) ? "example-domain" : "public"; };
const FILE_EXT_NOT_TLD = new Set(["js", "ts", "json", "dll", "exe", "so", "dylib", "png", "jpg", "gif", "css", "html", "htm", "txt", "xml", "md", "py", "c", "h", "cs", "cpp", "java", "class", "dex", "jar", "zip", "pdf", "sh", "bat", "ps1", "sys", "lib", "o", "a", "pyc", "map", "log", "ini", "cfg", "conf", "yml", "yaml", "toml", "bin", "dat", "db", "sqlite", "wasm", "svg", "ico", "ttf", "woff", "woff2", "proto", "node", "pak", "asar", "plist", "mf", "sf", "rsa", "properties", "gz", "tar", "tgz", "mjs", "cjs", "tsx", "jsx", "vue", "lock", "gradle", "kt", "swift", "m", "rs", "go", "rb", "pl", "php", "lua", "res", "arsc", "obj", "pdb", "mui", "manifest", "config", "resx", "csproj", "sln", "nupkg", "msi", "cab", "dmg", "pkg", "iso", "img", "elf", "cache", "tmp", "bak", "old", "orig", "new", "in", "out", "def", "tmpl", "tpl", "so1", "so2", "so6", "so3", "ko", "rc", "idl", "tlb", "ocx", "scr", "cpl", "drv", "efi"]);
const TLD_OK = /^(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$/u;

const URL_RE = /\b(?:https?|ftp|wss?):\/\/[^\s"'<>\\^`{}|]+/giu;
const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.]*\d)/gu;
const IPV6_RE = /(?<![:\w])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![:\w])/giu;
const DOMAIN_RE = /(?<![\w.@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?![\w-])/giu;
const EMAIL_RE = /[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,24}/giu;
const HASH_RE = /(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])/giu;
const REGKEY_RE = /\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\[^\s"'<>|]{3,200}/gu;
const WINPATH_RE = /\b[A-Za-z]:\\(?:[^\\\s"'<>|:*?]{1,64}\\){1,8}[^\\\s"'<>|:*?]{1,64}/gu;
const B64_RE = /^[A-Za-z0-9+/]{16,}={0,2}$/u; const HEX_RE = /^(?:[0-9a-f]{2}){12,}$/iu;

export interface ExtractOptions { maxDecodeDepth?: number; allowDomains?: string[]; context: string; evidenceId: string }
export class IocSet {
  readonly #m = new Map<string, Ioc>();
  add(kind: IocKind, value: string, classification: IocClass, context: string, evidenceId: string, decoded_from?: string): void {
    const k = `${kind}|${value}`; const ex = this.#m.get(k);
    if (ex) { if (!ex.contexts.includes(context)) ex.contexts.push(context); if (!ex.evidence_ids.includes(evidenceId)) ex.evidence_ids.push(evidenceId); return; }
    this.#m.set(k, { kind, value, classification, contexts: [context], evidence_ids: [evidenceId], ...(decoded_from ? { decoded_from } : {}) });
  }
  all(): Ioc[] { return [...this.#m.values()].sort((a, b) => (a.kind + a.value < b.kind + b.value ? -1 : 1)); }
  get size(): number { return this.#m.size; }
}

/** Extract indicators from one text value. Decodes base64/hex payloads that decode to printable text (bounded depth). */
export function extractIocs(textIn: string, set: IocSet, o: ExtractOptions, depth = 0, decodedFrom?: string): void {
  if (!textIn || textIn.length > 1 << 20) return; const text = refang(textIn); const allow = new Set((o.allowDomains ?? []).map((d) => d.toLowerCase()));
  const add = (kind: IocKind, v: string, cls: IocClass) => set.add(kind, v, cls, o.context, o.evidenceId, decodedFrom);
  const urlHosts = new Set<string>();
  for (const m of text.matchAll(URL_RE)) {
    const u = m[0].replace(/[.,;:)\]]+$/u, ""); add("url", u, "unknown");
    try { const host = new URL(u).hostname; urlHosts.add(host.toLowerCase()); if (/^\d+\.\d+\.\d+\.\d+$/u.test(host)) add("ipv4", host, ipv4Class(host)); else if (host.includes(".") && !allow.has(host.toLowerCase())) add("domain", host.toLowerCase(), domainClass(host)); } catch { /* malformed URL kept as url only */ }
  }
  for (const m of text.matchAll(IPV4_RE)) add("ipv4", m[0], ipv4Class(m[0]));
  for (const m of text.matchAll(IPV6_RE)) add("ipv6", m[0].toLowerCase(), "unknown");
  for (const m of text.matchAll(EMAIL_RE)) { add("email", m[0].toLowerCase(), "unknown"); }
  for (const m of text.matchAll(DOMAIN_RE)) {
    const d = m[0].toLowerCase(); const tld = d.split(".").pop()!; if (!TLD_OK.test(tld) || FILE_EXT_NOT_TLD.has(tld) || /^\d+(\.\d+)+$/u.test(d) || allow.has(d) || urlHosts.has(d)) continue;
    if (d.split(".").length < 2 || d.length > 253) continue; add("domain", d, domainClass(d));
  }
  for (const m of text.matchAll(HASH_RE)) add(m[0].length === 64 ? "sha256" : m[0].length === 40 ? "sha1" : "md5", m[0].toLowerCase(), "unknown");
  for (const m of text.matchAll(REGKEY_RE)) add("registry-key", m[0], "unknown");
  for (const m of text.matchAll(WINPATH_RE)) add("windows-path", m[0], "unknown");
  const maxDepth = o.maxDecodeDepth ?? 2;
  if (depth < maxDepth) {
    for (const tok of text.split(/[\s"'`,;()[\]{}<>|]+/u)) {
      if (tok.length < 16 || tok.length > 1 << 16) continue; let dec: string | null = null;
      if (HEX_RE.test(tok)) dec = tryPrintable(Buffer.from(tok, "hex")); else if (B64_RE.test(tok) && tok.length % 4 === 0) dec = tryPrintable(Buffer.from(tok, "base64"));
      if (dec && dec !== tok) extractIocs(dec, set, o, depth + 1, decodedFrom ?? tok.slice(0, 64));
    }
  }
}
const tryPrintable = (b: Buffer): string | null => { if (b.length < 6) return null; const s = b.toString("utf8"); return /^[\x09\x0a\x0d\x20-\x7e]+$/u.test(s) ? s : null; };
