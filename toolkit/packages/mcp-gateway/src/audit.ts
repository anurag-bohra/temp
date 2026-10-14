// Tamper-evident audit log: JSONL, each line hash-chained to the previous one (sha256 over canonical JSON of the line sans `hash`).
import { appendFileSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalDigest } from "@rtk/evidence";

export const GENESIS = "0".repeat(64);
export interface AuditEntry {
  ts: string; method: string; tool: string | null; args_digest: string | null; decision: string; reasons: string[]; result_sha256: string | null; prev_hash: string; hash: string;
}
export type AuditInput = Omit<AuditEntry, "ts" | "prev_hash" | "hash" | "reasons"> & { reasons?: string[]; ts?: string };

export const entryHash = (e: Omit<AuditEntry, "hash">): string => canonicalDigest(e);

export class AuditLog {
  readonly path: string; private head: string;
  constructor(path: string) {
    this.path = path; mkdirSync(dirname(path), { recursive: true });
    this.head = GENESIS;
    if (existsSync(path)) { const v = verifyAuditLog(path); if (!v.ok) throw new Error(`refusing to append to a corrupt audit log (${path}): line ${v.error?.line}: ${v.error?.reason}`); this.head = v.head; }
  }
  get headHash(): string { return this.head; }
  append(input: AuditInput): AuditEntry {
    const base = { ts: input.ts ?? new Date().toISOString(), method: input.method, tool: input.tool, args_digest: input.args_digest, decision: input.decision, reasons: input.reasons ?? [], result_sha256: input.result_sha256, prev_hash: this.head };
    const entry: AuditEntry = { ...base, hash: entryHash(base) };
    appendFileSync(this.path, JSON.stringify(entry) + "\n"); this.head = entry.hash;
    return entry;
  }
}

export interface AuditVerification { ok: boolean; lines: number; head: string; error?: { line: number; reason: string } }
/** Verify the hash chain. `expectedHead` (stored out-of-band) additionally detects truncation / tail deletion. */
export function verifyAuditLog(path: string, expectedHead?: string): AuditVerification {
  const text = readFileSync(path, "utf8"); const lines = text.split("\n"); if (lines[lines.length - 1] === "") lines.pop();
  let prev = GENESIS; let n = 0;
  for (const [i, line] of lines.entries()) {
    n = i + 1; let e: AuditEntry;
    try { e = JSON.parse(line) as AuditEntry; } catch { return { ok: false, lines: n, head: prev, error: { line: n, reason: "not valid JSON" } }; }
    const keys = ["ts", "method", "tool", "args_digest", "decision", "reasons", "result_sha256", "prev_hash", "hash"];
    if (keys.some((k) => !(k in e)) || Object.keys(e).length !== keys.length) return { ok: false, lines: n, head: prev, error: { line: n, reason: "unexpected or missing fields" } };
    if (e.prev_hash !== prev) return { ok: false, lines: n, head: prev, error: { line: n, reason: "prev_hash does not match the previous entry (line removed, reordered or inserted)" } };
    const { hash, ...rest } = e;
    if (entryHash(rest) !== hash) return { ok: false, lines: n, head: prev, error: { line: n, reason: "hash mismatch (entry content modified)" } };
    prev = hash;
  }
  if (expectedHead !== undefined && expectedHead !== prev) return { ok: false, lines: n, head: prev, error: { line: n, reason: "chain head differs from expected head (log truncated or extended)" } };
  return { ok: true, lines: n, head: prev };
}
