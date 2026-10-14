// @rtk/unknowns — residual-Unknown registry: immutable revisions, optimistic concurrency, evidence-qualified resolution.
// Identity/digest rules are byte-compatible with REA (verified against a real REA export): 
//   unknown_id       = "unk_" + sha256(canonical{domain.trim(), question(whitespace-collapsed), scope_digest})
//   revision_digest  = sha256(canonical(record without revision_digest))
// The *resolution rule* (what Evidence may close an Unknown) is this package's implementation of the behaviour
// observed in REA (static string-search Evidence was refused for a controlled-replay Unknown); REA's exact rule is in its application layer.
import { z } from "zod";
import { type Authority, type Confidence, type Evidence, EvidenceLedger, canonicalDigest, createEvidence } from "@rtk/evidence";

const hex64 = z.string().regex(/^[a-f0-9]{64}$/u);
const evId = z.string().regex(/^ev_[a-f0-9]{64}$/u);
const unkId = z.string().regex(/^unk_[a-f0-9]{64}$/u);
const text = z.string().trim().min(1);
const AUTH = ["shipped-artifact", "controlled-replay", "historical-reference", "external-service", "analyst-inference"] as const;
export const STATUS = ["open", "investigating", "blocked", "contradicted", "resolved"] as const;
export const SEVERITY = ["low", "medium", "high", "critical"] as const;
const envReq = z.strictObject({ id: z.string().min(1).nullable(), platform: z.string().min(1).nullable(), architecture: z.string().min(1).nullable(), isolation: z.enum(["none", "process", "container", "virtual-machine"]).nullable() });
const probe = z.strictObject({ operation: z.string().min(1), rationale: text });
const relationship = z.strictObject({ type: z.enum(["depends-on", "related-to", "contradicts"]), unknown_id: unkId });
const resolution = z.discriminatedUnion("disposition", [
  z.strictObject({ disposition: z.literal("verified"), rationale: text, evidence_ids: z.array(evId).min(1) }),
  z.strictObject({ disposition: z.enum(["withdrawn", "out-of-scope"]), rationale: text, evidence_ids: z.array(evId) }),
]);
export const unknownSchema = z.strictObject({
  unknown_id: unkId, revision: z.number().int().min(1), previous_revision_digest: hex64.nullable(), revision_digest: hex64, scope_digest: hex64.nullable(),
  question: text, status: z.enum(STATUS), severity: z.enum(SEVERITY), domain: text,
  supporting_evidence_ids: z.array(evId), contradicting_evidence_ids: z.array(evId),
  required_authority: z.enum(AUTH).nullable(), required_confidence: z.enum(["observed", "derived", "inferred"]), required_environment: envReq.nullable(),
  recommended_probes: z.array(probe), relationships: z.array(relationship), resolution: resolution.nullable(), mutation_evidence_ids: z.array(evId).min(1),
});
export type Unknown = z.infer<typeof unknownSchema>;

export const stableUnknownId = (question: string, domain: string, scopeDigest: string | null): string =>
  `unk_${canonicalDigest({ domain: domain.trim(), question: question.replace(/\s+/gu, " ").trim(), scope_digest: scopeDigest })}`;
export const computeRevisionDigest = (u: Omit<Unknown, "revision_digest">): string => canonicalDigest(u);

/** Structural + integrity validation of a stored revision (works on REA-exported unknowns). */
export function parseUnknown(input: unknown): Unknown {
  const u = unknownSchema.parse(input);
  const { revision_digest, ...rest } = u;
  if (computeRevisionDigest(rest) !== revision_digest) throw new Error("revision digest mismatch");
  if (u.unknown_id !== stableUnknownId(u.question, u.domain, u.scope_digest)) throw new Error("unknown_id does not match immutable identity");
  if ((u.revision === 1) !== (u.previous_revision_digest === null)) throw new Error("only the first revision has no predecessor");
  if ((u.status === "resolved") !== (u.resolution !== null)) throw new Error("only resolved unknowns carry a resolution");
  if (u.status === "contradicted" && u.contradicting_evidence_ids.length === 0) throw new Error("contradicted status requires contradicting evidence");
  if (u.relationships.some((r) => r.unknown_id === u.unknown_id)) throw new Error("an unknown cannot relate to itself");
  for (const ids of [u.supporting_evidence_ids, u.contradicting_evidence_ids, u.mutation_evidence_ids]) if (new Set(ids).size !== ids.length) throw new Error("evidence IDs must be unique");
  if (u.supporting_evidence_ids.some((id) => u.contradicting_evidence_ids.includes(id))) throw new Error("evidence cannot both support and contradict");
  return u;
}

const CONF_RANK: Record<Confidence, number> = { inferred: 0, derived: 1, observed: 2 };
const ISO_RANK = { none: 0, process: 1, container: 2, "virtual-machine": 3 } as const;
export interface Qualification { ok: boolean; problems: string[] }
/** Does this Evidence qualify to close the Unknown? (authority equal, confidence >=, environment requirement met). */
export function evidenceQualifies(u: Pick<Unknown, "required_authority" | "required_confidence" | "required_environment">, e: Evidence): Qualification {
  const problems: string[] = [];
  if (u.required_authority !== null && e.authority !== u.required_authority) problems.push(`authority ${e.authority} != required ${u.required_authority}`);
  if (CONF_RANK[e.confidence] < CONF_RANK[u.required_confidence]) problems.push(`confidence ${e.confidence} < required ${u.required_confidence}`);
  const r = u.required_environment;
  if (r !== null) {
    const env = e.environment;
    if (env === null) problems.push("evidence has no environment but one is required");
    else {
      if (r.id !== null && env.id !== r.id) problems.push(`environment id ${env.id} != ${r.id}`);
      if (r.platform !== null && env.platform !== r.platform) problems.push(`platform ${env.platform} != ${r.platform}`);
      if (r.architecture !== null && env.architecture !== r.architecture) problems.push(`architecture ${env.architecture} != ${r.architecture}`);
      if (r.isolation !== null) { const have = ISO_RANK[env.isolation as keyof typeof ISO_RANK]; if (have === undefined || have < ISO_RANK[r.isolation]) problems.push(`isolation ${env.isolation} < required ${r.isolation}`); }
    }
  }
  return { ok: problems.length === 0, problems };
}

export interface RecordInput {
  question: string; domain: string; severity: Unknown["severity"]; scope_digest?: string | null;
  required_authority?: Unknown["required_authority"]; required_confidence?: Confidence; required_environment?: Unknown["required_environment"];
  recommended_probes?: { operation: string; rationale: string }[]; relationships?: Unknown["relationships"];
  supporting_evidence_ids?: string[]; contradicting_evidence_ids?: string[];
}
export interface UpdateInput { unknown_id: string; expected_revision: number; status?: Unknown["status"]; severity?: Unknown["severity"]; supporting_evidence_ids?: string[]; contradicting_evidence_ids?: string[]; recommended_probes?: RecordInput["recommended_probes"]; relationships?: Unknown["relationships"]; resolution?: Unknown["resolution"] }

export class RevisionConflict extends Error {}

export class UnknownRegistry {
  readonly #heads = new Map<string, Unknown>();
  readonly #history = new Map<string, Unknown[]>();
  readonly ledger: EvidenceLedger;
  constructor(ledger: EvidenceLedger = new EvidenceLedger()) { this.ledger = ledger; }

  #mutationEvidence(action: string, payload: unknown): string {
    return this.ledger.add(createEvidence({
      provider: { id: "rtk-unknown-registry", name: "RTK residual unknown registry", version: "1" }, predicate_type: "rtk.unknown-mutation", operation: action,
      parameters: payload, normalized_result: { action }, confidence: "observed", authority: "analyst-inference",
      limitations: ["Records an analyst-declared change to the unknown registry, not an observation of the target."],
    })).evidence_id;
  }
  #seal(rest: Omit<Unknown, "revision_digest">): Unknown { const u = { ...rest, revision_digest: computeRevisionDigest(rest) }; return parseUnknown(u); }
  #checkIds(ids: string[]): void { for (const id of ids) if (!this.ledger.has(id)) throw new Error(`unknown Evidence ID ${id} (not in ledger)`); }

  record(input: RecordInput): Unknown {
    const scope = input.scope_digest ?? null; const id = stableUnknownId(input.question, input.domain, scope);
    if (this.#heads.has(id)) throw new Error(`unknown ${id} already exists; use update`);
    this.#checkIds([...(input.supporting_evidence_ids ?? []), ...(input.contradicting_evidence_ids ?? [])]);
    const mutation = this.#mutationEvidence("record_unknown", { question: input.question, domain: input.domain });
    const u = this.#seal({
      unknown_id: id, revision: 1, previous_revision_digest: null, scope_digest: scope, question: input.question.trim(), status: "open", severity: input.severity, domain: input.domain.trim(),
      supporting_evidence_ids: input.supporting_evidence_ids ?? [], contradicting_evidence_ids: input.contradicting_evidence_ids ?? [],
      required_authority: input.required_authority ?? null, required_confidence: input.required_confidence ?? "observed", required_environment: input.required_environment ?? null,
      recommended_probes: input.recommended_probes ?? [], relationships: input.relationships ?? [], resolution: null, mutation_evidence_ids: [mutation],
    });
    this.#heads.set(id, u); this.#history.set(id, [u]); return u;
  }

  update(input: UpdateInput): Unknown {
    const head = this.#heads.get(input.unknown_id); if (!head) throw new Error(`no such unknown ${input.unknown_id}`);
    if (head.revision !== input.expected_revision) throw new RevisionConflict(`expected revision ${input.expected_revision} but head is ${head.revision}`);
    const status = input.status ?? head.status; const resolutionIn = input.resolution === undefined ? head.resolution : input.resolution;
    if (status === "resolved") {
      if (!resolutionIn) throw new Error("resolved status requires a resolution");
      if (resolutionIn.disposition === "verified") {
        this.#checkIds(resolutionIn.evidence_ids);
        const bad = resolutionIn.evidence_ids.flatMap((eid) => { const q = evidenceQualifies(head, this.ledger.get(eid)!); return q.ok ? [] : [`${eid.slice(0, 14)}…: ${q.problems.join("; ")}`]; });
        if (bad.length) throw new Error(`evidence does not qualify to verify this unknown: ${bad.join(" | ")}`);
      }
    }
    const supporting = input.supporting_evidence_ids ?? head.supporting_evidence_ids, contradicting = input.contradicting_evidence_ids ?? head.contradicting_evidence_ids;
    this.#checkIds([...supporting, ...contradicting]);
    const mutation = this.#mutationEvidence("update_unknown", { unknown_id: head.unknown_id, from: head.revision, status });
    const { revision_digest, ...headRest } = head;
    const next = this.#seal({
      ...headRest, revision: head.revision + 1, previous_revision_digest: revision_digest, status, severity: input.severity ?? head.severity,
      supporting_evidence_ids: supporting, contradicting_evidence_ids: contradicting, recommended_probes: input.recommended_probes ?? head.recommended_probes,
      relationships: input.relationships ?? head.relationships, resolution: status === "resolved" ? resolutionIn : null, mutation_evidence_ids: [...head.mutation_evidence_ids, mutation],
    });
    this.#heads.set(head.unknown_id, next); this.#history.get(head.unknown_id)!.push(next); return next;
  }

  /** Re-validate a head: structural integrity + (for verified) current qualification of every resolving Evidence. */
  verifyResolution(unknown_id: string): Qualification {
    const u = this.#heads.get(unknown_id); if (!u) return { ok: false, problems: ["no such unknown"] };
    try { parseUnknown(u); } catch (e) { return { ok: false, problems: [String((e as Error).message)] }; }
    if (u.status !== "resolved" || u.resolution?.disposition !== "verified") return { ok: false, problems: [`status is ${u.status}${u.resolution ? ` (${u.resolution.disposition})` : ""}, not verified`] };
    const problems = u.resolution.evidence_ids.flatMap((eid) => { const e = this.ledger.get(eid); return e ? evidenceQualifies(u, e).problems : [`evidence ${eid.slice(0, 14)}… missing from ledger`]; });
    return { ok: problems.length === 0, problems };
  }
  get(id: string): Unknown | undefined { return this.#heads.get(id); }
  history(id: string): Unknown[] { return [...(this.#history.get(id) ?? [])]; }
  list(filter: { status?: Unknown["status"] } = {}): Unknown[] { return [...this.#heads.values()].filter((u) => !filter.status || u.status === filter.status).sort((a, b) => (a.unknown_id < b.unknown_id ? -1 : 1)); }
  open(): Unknown[] { return this.list().filter((u) => u.status !== "resolved"); }
  /** Import validated heads (e.g. from a REA bundle). Does not require their mutation Evidence to be in the ledger. */
  importHeads(unknowns: unknown[]): void { for (const raw of unknowns) { const u = parseUnknown(raw); this.#heads.set(u.unknown_id, u); this.#history.set(u.unknown_id, [u]); } }
  exportHeads(): Unknown[] { return this.list(); }
}
export type { Authority };
