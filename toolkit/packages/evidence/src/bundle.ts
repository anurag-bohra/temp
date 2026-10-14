import { canonicalJson } from "./canonical.ts";
import { type Evidence, parseEvidence } from "./evidence.ts";

export interface BundleParts {
  records: Evidence[];
  unknowns?: unknown[];
  providers?: { id: string; name: string; version: string | null }[];
  artifacts?: { architecture: string | null; digest: { sha256: string }; format: string | null }[];
  captures?: unknown[]; environments?: unknown[]; scenarios?: unknown[];
}
export interface Bundle { artifacts: unknown[]; captures: unknown[]; environments: unknown[]; providers: unknown[]; records: Evidence[]; scenarios: unknown[]; unknowns: unknown[] }

const byKey = <T>(items: T[], key: (t: T) => string): T[] => [...items].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));

/** Deterministic bundle: derived artifacts/providers, order-insensitive collections sorted, canonical JSON bytes (REA-compatible). */
export function buildBundle(parts: BundleParts): Bundle {
  const seen = new Set<string>();
  for (const r of parts.records) { if (seen.has(r.evidence_id)) throw new Error("Evidence bundle contains duplicate record IDs"); seen.add(r.evidence_id); }
  const providers = new Map<string, { id: string; name: string; version: string | null }>();
  const artifacts = new Map<string, { architecture: string | null; digest: { sha256: string }; format: string | null }>();
  for (const r of parts.records) {
    providers.set(canonicalJson(r.provider), r.provider);
    if (r.subject) artifacts.set(r.subject.digest.sha256 + canonicalJson([r.subject.format, r.subject.architecture]), { architecture: r.subject.architecture, digest: r.subject.digest, format: r.subject.format });
  }
  for (const p of parts.providers ?? []) providers.set(canonicalJson(p), p);
  for (const a of parts.artifacts ?? []) artifacts.set(a.digest.sha256 + canonicalJson([a.format, a.architecture]), a);
  return {
    artifacts: byKey([...artifacts.values()], (a) => a.digest.sha256 + (a.format ?? "") + (a.architecture ?? "")),
    captures: parts.captures ?? [], environments: parts.environments ?? [],
    providers: byKey([...providers.values()], (p) => p.id + "\0" + (p.version ?? "")),
    records: byKey(parts.records, (r) => r.evidence_id),
    scenarios: parts.scenarios ?? [],
    unknowns: byKey(parts.unknowns ?? [], (u) => canonicalJson(u)),
  };
}
export const serializeBundle = (b: Bundle): string => canonicalJson(b);

/** Import: authenticates every record's ID; rejects duplicates. Accepts REA-exported bundles. */
export function parseBundle(text: string): Bundle {
  const raw = JSON.parse(text) as Partial<Bundle>;
  for (const k of ["artifacts", "captures", "environments", "providers", "records", "scenarios", "unknowns"] as const)
    if (!Array.isArray(raw[k])) throw new Error(`bundle.${k} must be an array`);
  const records = raw.records!.map((r) => parseEvidence(r));
  return { ...(raw as Bundle), records };
}
