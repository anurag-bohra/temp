import { type Evidence, parseEvidence } from "./evidence.ts";

export interface EvidenceFilter { operation?: string; subject_sha256?: string; provider_id?: string; confidence?: Evidence["confidence"]; authority?: Evidence["authority"] }

/** In-memory, deduplicating ledger (identical content => identical ID => one record). */
export class EvidenceLedger {
  readonly #records = new Map<string, Evidence>();
  add(e: unknown): Evidence {
    const parsed = parseEvidence(e);
    if (!this.#records.has(parsed.evidence_id)) this.#records.set(parsed.evidence_id, Object.freeze(parsed) as Evidence);
    return this.#records.get(parsed.evidence_id)!;
  }
  get(id: string): Evidence | undefined { return this.#records.get(id); }
  has(id: string): boolean { return this.#records.has(id); }
  get size(): number { return this.#records.size; }
  all(): Evidence[] { return [...this.#records.values()]; }
  query(f: EvidenceFilter = {}): Evidence[] {
    return this.all().filter((e) =>
      (f.operation === undefined || e.operation === f.operation) &&
      (f.subject_sha256 === undefined || e.subject?.digest.sha256 === f.subject_sha256) &&
      (f.provider_id === undefined || e.provider.id === f.provider_id) &&
      (f.confidence === undefined || e.confidence === f.confidence) &&
      (f.authority === undefined || e.authority === f.authority));
  }
  summary(): { total: number; by_operation: Record<string, number>; by_confidence: Record<string, number>; subjects: string[] } {
    const by_operation: Record<string, number> = {}, by_confidence: Record<string, number> = {}; const subjects = new Set<string>();
    for (const e of this.#records.values()) { by_operation[e.operation] = (by_operation[e.operation] ?? 0) + 1; by_confidence[e.confidence] = (by_confidence[e.confidence] ?? 0) + 1; if (e.subject) subjects.add(e.subject.digest.sha256); }
    return { total: this.#records.size, by_operation, by_confidence, subjects: [...subjects].sort() };
  }
  clear(): void { this.#records.clear(); }
}
