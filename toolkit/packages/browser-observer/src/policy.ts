import { createHash } from "node:crypto";

export const DEFAULT_ALLOW_HOSTS = ["localhost", "127.0.0.1", "[::1]"] as const;
export const DEFAULT_REDACT_HEADERS = ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"] as const;
export const REDACTED = "[REDACTED]";

export interface HostRule { host: string; port: string | null }

/** Parse "host" or "host:port" (IPv6 as "[::1]" or "[::1]:8080"). */
export function parseHostRule(entry: string): HostRule {
  const s = entry.trim().toLowerCase();
  if (!s || /[\/\s@]/u.test(s)) throw new Error(`invalid allowHosts entry ${JSON.stringify(entry)}: use host or host:port`);
  const m6 = /^(\[[0-9a-f:.]+\])(?::(\d+))?$/u.exec(s);
  if (m6) return { host: m6[1], port: m6[2] ?? null };
  const m = /^([^:]+)(?::(\d+))?$/u.exec(s);
  if (!m) throw new Error(`invalid allowHosts entry ${JSON.stringify(entry)}`);
  return { host: m[1], port: m[2] ?? null };
}

export interface Decision { allowed: boolean; reason: string }

/** Egress decision for a URL. Only http(s)/ws(s) to allowlisted hosts, plus local-only data:/blob:/about:blank. */
export function decide(rawUrl: string, rules: HostRule[]): Decision {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return { allowed: false, reason: "unparseable-url" }; }
  const proto = u.protocol;
  if (proto === "data:" || proto === "blob:") return { allowed: true, reason: "local-scheme" };
  if (proto === "about:") return { allowed: u.href === "about:blank", reason: u.href === "about:blank" ? "local-scheme" : "blocked-scheme" };
  if (!["http:", "https:", "ws:", "wss:"].includes(proto)) return { allowed: false, reason: `blocked-scheme:${proto.replace(":", "")}` };
  const port = u.port || (proto === "http:" || proto === "ws:" ? "80" : "443");
  const host = u.hostname.toLowerCase();
  for (const r of rules) if (r.host === host && (r.port === null || r.port === port)) return { allowed: true, reason: "allowlisted" };
  return { allowed: false, reason: "not-in-egress-allowlist" };
}

export function redactHeaders(h: Record<string, string>, names: ReadonlySet<string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of Object.keys(h).sort()) out[k] = names.has(k.toLowerCase()) ? REDACTED : h[k];
  return out;
}

export const sha256 = (b: string | Uint8Array): string => createHash("sha256").update(b).digest("hex");
